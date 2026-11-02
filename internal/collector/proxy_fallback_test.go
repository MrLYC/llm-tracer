package collector

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

type memPipeAddr string

func (a memPipeAddr) Network() string { return "tcp" }
func (a memPipeAddr) String() string  { return string(a) }

type memPipeListener struct {
	addr   memPipeAddr
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemPipeListener(addr string) *memPipeListener {
	return &memPipeListener{
		addr:   memPipeAddr(addr),
		ch:     make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
}

func (l *memPipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.ch:
		return c, nil
	}
}

func (l *memPipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memPipeListener) Addr() net.Addr { return l.addr }

func (l *memPipeListener) Dial() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	c1, c2 := net.Pipe()
	select {
	case <-l.closed:
		_ = c1.Close()
		_ = c2.Close()
		return nil, net.ErrClosed
	case l.ch <- c2:
		return c1, nil
	}
}

// TestHTTPProxyCaptureMode verifies that Collector exposes an HTTP/HTTPS MITM proxy
// (configurable via SetProxyListen / --proxy-listen) that captures both plain HTTP
// and HTTPS CONNECT LLM traffic.
func TestHTTPProxyCaptureMode(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer st.Close()
	corr := correlator.NewCorrelator(mon)

	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	col.SetProxyListen("127.0.0.1:18888")
	require.Equal(t, "127.0.0.1:18888", col.ProxyListen())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	certPath, keyPath := writeSelfSignedCertFiles(t, dir)
	srvCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-proxy-1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"captured via http proxy"}}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}}`))
	})

	plainLn := newMemPipeListener("127.0.0.1:28080")
	defer plainLn.Close()
	plainSrv := &http.Server{Handler: mux}
	go func() { _ = plainSrv.Serve(plainLn) }()
	defer plainSrv.Close()

	rawTLSLn := newMemPipeListener("127.0.0.1:28443")
	defer rawTLSLn.Close()
	tlsLn := tls.NewListener(rawTLSLn, &tls.Config{Certificates: []tls.Certificate{srvCert}})
	tlsSrv := &http.Server{Handler: mux}
	go func() { _ = tlsSrv.Serve(tlsLn) }()
	defer tlsSrv.Close()

	tapLn := newMemPipeListener("127.0.0.1:18888")
	defer tapLn.Close()

	dialer := func(_, addr string) (net.Conn, error) {
		switch addr {
		case "127.0.0.1:18888":
			return tapLn.Dial()
		case "127.0.0.1:28080":
			return plainLn.Dial()
		case "127.0.0.1:28443":
			return rawTLSLn.Dial()
		default:
			return nil, fmt.Errorf("unexpected dial addr %s", addr)
		}
	}

	tap, err := NewLoopbackTap(
		dir,
		func(connID string, dir parser.Direction, data []byte) {
			col.IngestRawChunk(os.Getpid(), os.Getpid(), connID, dir, data, "loopback_tap")
		},
		WithTapListener(tapLn),
		WithTapDialer(dialer),
		WithTapMonitor(mon),
	)
	require.NoError(t, err)
	defer tap.Close()
	col.mu.Lock()
	col.loopbackTap = tap
	col.mu.Unlock()

	require.Equal(t, "http://127.0.0.1:18888", col.ProxyURL())
	require.NotEmpty(t, col.CABundlePath())

	proxyURL, err := url.Parse(col.ProxyURL())
	require.NoError(t, err)

	caPEM, err := os.ReadFile(col.CABundlePath())
	require.NoError(t, err)
	rootPool := x509.NewCertPool()
	require.True(t, rootPool.AppendCertsFromPEM(caPEM))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: rootPool},
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer(network, addr)
			},
		},
	}

	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"hello via proxy"}]}`
	resp1, err := client.Post("http://127.0.0.1:28080/v1/chat/completions", "application/json", strings.NewReader(reqBody))
	require.NoError(t, err)
	_, _ = io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	resp2, err := client.Post("https://127.0.0.1:28443/v1/chat/completions", "application/json", strings.NewReader(reqBody))
	require.NoError(t, err)
	_, _ = io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	require.Eventually(t, func() bool {
		col.Flush()
		return countPersistedStoreEvents(t, st) >= 2
	}, 3*time.Second, 20*time.Millisecond, "both HTTP and HTTPS proxy requests must be captured")
}

// TestLaunchPlanProxyFallbackLastResortAndParentProxyPreservation verifies:
//  1. When eBPF or runtime-specific hooks (PYTHONPATH, NODE_OPTIONS, JAVA_TOOL_OPTIONS, LD_PRELOAD)
//     are available, HTTP_PROXY/HTTPS_PROXY are NOT overwritten and parent proxy env vars remain intact.
//  2. When all other injection methods are unavailable, HTTP_PROXY/HTTPS_PROXY are injected as the
//     last-resort fallback and parent proxy settings are synced to LoopbackTap.
func TestLaunchPlanProxyFallbackLastResortAndParentProxyPreservation(t *testing.T) {
	parentEnv := []string{
		"PATH=/usr/bin:/bin",
		"HTTP_PROXY=http://parent-proxy.internal:8080",
		"HTTPS_PROXY=http://parent-proxy.internal:8443",
		"ALL_PROXY=socks5://parent-proxy.internal:1080",
		"NO_PROXY=localhost,127.0.0.1,.corp.example",
	}

	t.Run("preserve_parent_proxy_when_other_hooks_available", func(t *testing.T) {
		cases := []struct {
			name string
			in   launchPlanInput
		}{
			{
				name: "ebpf_non_intrusive_gotls",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/local/bin/go-agent"},
					BinPath:       "/usr/local/bin/go-agent",
					GoTarget:      &ProbeTarget{GoVersion: "go1.26.5", Symbols: map[string]uint64{"crypto/tls.(*Conn).Write": 0x1000}},
					EBPFActive:    true,
					AutoIntrusive: true,
					GOOS:          "linux",
					TapActive:     true,
					ProxyURL:      "http://127.0.0.1:43111",
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  "/tmp/ca.pem",
				},
			},
			{
				name: "python_with_pyhook",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/python3", "agent.py"},
					BinPath:       "/usr/bin/python3",
					AutoIntrusive: true,
					GOOS:          "linux",
					PyHookDir:     "/tmp/hooks/pyhook",
					TapActive:     true,
					ProxyURL:      "http://127.0.0.1:43111",
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  "/tmp/ca.pem",
				},
			},
			{
				name: "node_with_nodehook",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/node", "agent.js"},
					BinPath:       "/usr/bin/node",
					AutoIntrusive: true,
					GOOS:          "linux",
					NodeHookJS:    "/tmp/hooks/node_hook.cjs",
					TapActive:     true,
					ProxyURL:      "http://127.0.0.1:43111",
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  "/tmp/ca.pem",
				},
			},
			{
				name: "jvm_with_javaagent",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/java", "-jar", "app.jar"},
					BinPath:       "/usr/bin/java",
					AutoIntrusive: true,
					GOOS:          "linux",
					JavaAgentJar:  "/tmp/hooks/llm_tracer_java.jar",
					TapActive:     true,
					ProxyURL:      "http://127.0.0.1:43111",
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  "/tmp/ca.pem",
				},
			},
			{
				name: "native_dynamic_libssl_with_ld_preload",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/curl", "https://api.openai.com/v1/models"},
					BinPath:       "/usr/bin/curl",
					Profile:       &BinaryProfile{ResolvedELF: "/usr/bin/curl", TLSStack: "dynamic-libssl"},
					AutoIntrusive: true,
					GOOS:          "linux",
					PreloadPath:   "/tmp/hooks/libllmtracer_ssl.so",
					TapActive:     true,
					ProxyURL:      "http://127.0.0.1:43111",
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  "/tmp/ca.pem",
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				plan := planLaunch(tc.in)
				env := applyLaunchPlan(nil, tc.in, plan, parentEnv)
				require.NotContains(t, plan.IntrusiveMethods, "env:HTTPS_PROXY")
				require.Equal(t, "http://parent-proxy.internal:8080", lookupEnvVar(env, "HTTP_PROXY"), "parent HTTP_PROXY must be preserved")
				require.Equal(t, "http://parent-proxy.internal:8443", lookupEnvVar(env, "HTTPS_PROXY"), "parent HTTPS_PROXY must be preserved")
				require.Equal(t, "socks5://parent-proxy.internal:1080", lookupEnvVar(env, "ALL_PROXY"), "parent ALL_PROXY must be preserved")
				require.Equal(t, "localhost,127.0.0.1,.corp.example", lookupEnvVar(env, "NO_PROXY"), "parent NO_PROXY must be preserved")
			})
		}
	})

	t.Run("fallback_to_proxy_env_when_other_methods_unavailable", func(t *testing.T) {
		dir := t.TempDir()
		mon, err := selfmon.NewMonitor(dir)
		require.NoError(t, err)
		defer mon.Close()
		st, err := store.NewStore(dir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer st.Close()
		corr := correlator.NewCorrelator(mon)
		col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, col.Start(ctx))
		defer col.Stop()

		fallbackProxyURL := "http://127.0.0.1:43111"
		fallbackCAPath := "/tmp/hooks/ca.pem"

		cases := []struct {
			name string
			in   launchPlanInput
		}{
			{
				name: "python_without_pyhook",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/python3", "agent.py"},
					BinPath:       "/usr/bin/python3",
					AutoIntrusive: true,
					GOOS:          "linux",
					PyHookDir:     "", // PyHook unavailable
					TapActive:     true,
					ProxyURL:      fallbackProxyURL,
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  fallbackCAPath,
				},
			},
			{
				name: "node_without_nodehook",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/node", "agent.js"},
					BinPath:       "/usr/bin/node",
					AutoIntrusive: true,
					GOOS:          "linux",
					NodeHookJS:    "", // NodeHook unavailable
					TapActive:     true,
					ProxyURL:      fallbackProxyURL,
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  fallbackCAPath,
				},
			},
			{
				name: "jvm_without_javaagent",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/bin/java", "-jar", "app.jar"},
					BinPath:       "/usr/bin/java",
					AutoIntrusive: true,
					GOOS:          "linux",
					JavaAgentJar:  "", // JavaAgent unavailable
					TapActive:     true,
					ProxyURL:      fallbackProxyURL,
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  fallbackCAPath,
				},
			},
			{
				name: "native_stripped_rustls",
				in: launchPlanInput{
					CmdArgs:       []string{"/usr/local/bin/rust-agent"},
					BinPath:       "/usr/local/bin/rust-agent",
					Profile:       &BinaryProfile{ResolvedELF: "/usr/local/bin/rust-agent", TLSStack: "stripped-embedded-tls"},
					AutoIntrusive: true,
					GOOS:          "linux",
					TapActive:     true,
					ProxyURL:      fallbackProxyURL,
					ProxyHost:     "127.0.0.1",
					ProxyPort:     "43111",
					CABundlePath:  fallbackCAPath,
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				plan := planLaunch(tc.in)
				env := applyLaunchPlan(col, tc.in, plan, parentEnv)
				require.Contains(t, plan.IntrusiveMethods, "env:HTTPS_PROXY")
				require.Contains(t, plan.IntrusiveMethods, "env:HTTP_PROXY")
				require.Contains(t, plan.IntrusiveMethods, "loopback_tap")
				require.Equal(t, fallbackProxyURL, lookupEnvVar(env, "HTTPS_PROXY"))
				require.Equal(t, fallbackProxyURL, lookupEnvVar(env, "https_proxy"))
				require.Equal(t, fallbackProxyURL, lookupEnvVar(env, "HTTP_PROXY"))
				require.Equal(t, fallbackProxyURL, lookupEnvVar(env, "http_proxy"))
				require.Empty(t, lookupEnvVar(env, "ALL_PROXY"))
				require.Empty(t, lookupEnvVar(env, "NO_PROXY"))

				// Verify LoopbackTap inherited the parent process's proxy configuration!
				upCfg := col.UpstreamProxyConfig()
				require.Equal(t, "http://parent-proxy.internal:8080", upCfg.HTTPProxy)
				require.Equal(t, "http://parent-proxy.internal:8443", upCfg.HTTPSProxy)
				require.Equal(t, "socks5://parent-proxy.internal:1080", upCfg.AllProxy)
				require.Equal(t, "localhost,127.0.0.1,.corp.example", upCfg.NoProxy)
			})
		}
	})
}

// TestLoopbackTapRespectsParentUpstreamProxy verifies that LoopbackTap chains both plain HTTP
// and HTTPS CONNECT traffic through the parent process's configured upstream proxy (including
// Basic Auth and NO_PROXY rules) while preventing self-proxy loops.
func TestLoopbackTapRespectsParentUpstreamProxy(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCertFiles(t, dir)
	srvCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	// 1. Start mock upstream LLM backend (both plain HTTP and TLS)
	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-chained","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"via parent proxy"}}]}`))
	})
	plainBackendLn := newMemPipeListener("10.10.0.1:80")
	defer plainBackendLn.Close()
	plainBackend := &http.Server{Handler: backendMux}
	go func() { _ = plainBackend.Serve(plainBackendLn) }()
	defer plainBackend.Close()

	rawTLSBackendLn := newMemPipeListener("10.10.0.1:443")
	defer rawTLSBackendLn.Close()
	tlsBackendLn := tls.NewListener(rawTLSBackendLn, &tls.Config{Certificates: []tls.Certificate{srvCert}})
	tlsBackend := &http.Server{Handler: backendMux}
	go func() { _ = tlsBackend.Serve(tlsBackendLn) }()
	defer tlsBackend.Close()

	plainBackendAddr := "10.10.0.1:80"
	tlsBackendAddr := "10.10.0.1:443"

	// 2. Start a parent proxy server that counts HTTP forward & CONNECT requests and redirects
	//    external hostname "api.openai.example:80" / "api.openai.example:443" to the local mock backends.
	var parentHTTPForwardCount atomic.Int32
	var parentConnectCount atomic.Int32
	var parentAuthSawBasic atomic.Bool

	parentLn := newMemPipeListener("127.0.0.1:17890")
	defer parentLn.Close()
	tapLn := newMemPipeListener("127.0.0.1:18890")
	defer tapLn.Close()

	dialer := func(_, addr string) (net.Conn, error) {
		switch addr {
		case "127.0.0.1:18890":
			return tapLn.Dial()
		case "127.0.0.1:17890":
			return parentLn.Dial()
		case plainBackendAddr:
			return plainBackendLn.Dial()
		case tlsBackendAddr:
			return rawTLSBackendLn.Dial()
		default:
			return nil, fmt.Errorf("unexpected dial addr %s", addr)
		}
	}

	parentTransport := &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return dialer(network, addr)
		},
	}

	go func() {
		for {
			conn, err := parentLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if strings.HasPrefix(req.Header.Get("Proxy-Authorization"), "Basic ") {
					parentAuthSawBasic.Store(true)
				}
				if req.Method == http.MethodConnect {
					parentConnectCount.Add(1)
					upConn, err := dialer("tcp", tlsBackendAddr)
					if err != nil {
						_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
						return
					}
					defer upConn.Close()
					_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
					done := make(chan struct{}, 2)
					go func() { _, _ = io.Copy(upConn, br); done <- struct{}{} }()
					go func() { _, _ = io.Copy(c, upConn); done <- struct{}{} }()
					<-done
					return
				}
				parentHTTPForwardCount.Add(1)
				req.RequestURI = ""
				req.URL.Scheme = "http"
				req.URL.Host = plainBackendAddr
				resp, err := parentTransport.RoundTrip(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				_ = resp.Write(c)
			}(conn)
		}
	}()

	parentProxyURL := "http://user:pass@" + parentLn.Addr().String()

	// 3. Start LoopbackTap with parent upstream proxy configuration
	hooksDir := t.TempDir()
	var capturedWriteChunks atomic.Int32
	var capturedReadChunks atomic.Int32
	tap, err := NewLoopbackTap(
		hooksDir,
		func(_ string, dir parser.Direction, data []byte) {
			if len(data) == 0 {
				return
			}
			if dir == parser.DirWrite {
				capturedWriteChunks.Add(1)
			} else {
				capturedReadChunks.Add(1)
			}
		},
		WithTapListener(tapLn),
		WithTapDialer(dialer),
		WithTapInsecure(true),
		WithTapUpstreamProxy(ParseUpstreamProxyEnv([]string{
			"HTTP_PROXY=" + parentProxyURL,
			"HTTPS_PROXY=" + parentProxyURL,
			"NO_PROXY=.direct.example,10.99.0.0/16",
		}, "")),
	)
	require.NoError(t, err)
	defer tap.Close()

	// Verify NO_PROXY matching rules
	uBypassDomain, _ := url.Parse("https://sub.direct.example:443/v1/chat/completions")
	puBypass1, err := tap.resolveUpstreamProxy(uBypassDomain)
	require.NoError(t, err)
	require.Nil(t, puBypass1, "domain in NO_PROXY must bypass upstream proxy")

	uBypassCIDR, _ := url.Parse("https://10.99.1.25:443/v1/chat/completions")
	puBypass2, err := tap.resolveUpstreamProxy(uBypassCIDR)
	require.NoError(t, err)
	require.Nil(t, puBypass2, "IP in NO_PROXY CIDR must bypass upstream proxy")

	// Verify self-loop prevention
	selfCfg := ParseUpstreamProxyEnv([]string{"HTTPS_PROXY=" + tap.ProxyURL()}, tap.ProxyURL())
	require.Empty(t, selfCfg.HTTPSProxy, "must strip upstream proxy pointing to LoopbackTap itself")

	tapURL, err := url.Parse(tap.ProxyURL())
	require.NoError(t, err)
	caPEM, err := os.ReadFile(tap.CABundlePath())
	require.NoError(t, err)
	rootPool := x509.NewCertPool()
	require.True(t, rootPool.AppendCertsFromPEM(caPEM))

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(tapURL),
			TLSClientConfig: &tls.Config{RootCAs: rootPool},
			DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer(network, addr)
			},
		},
	}

	// 4. Send plain HTTP request to external host -> LoopbackTap -> parent HTTP_PROXY -> plainBackend
	respHTTP, err := client.Post("http://api.openai.example/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gpt-4o"}`))
	require.NoError(t, err)
	bodyHTTP, _ := io.ReadAll(respHTTP.Body)
	_ = respHTTP.Body.Close()
	require.Equal(t, http.StatusOK, respHTTP.StatusCode)
	require.Contains(t, string(bodyHTTP), "via parent proxy")
	require.Equal(t, int32(1), parentHTTPForwardCount.Load(), "plain HTTP request must be forwarded via parent HTTP_PROXY")

	// 5. Send HTTPS request to external host -> LoopbackTap MITM -> parent HTTPS_PROXY (CONNECT) -> tlsBackend
	respHTTPS, err := client.Post("https://api.openai.example/v1/chat/completions", "application/json", strings.NewReader(`{"model":"gpt-4o"}`))
	require.NoError(t, err)
	bodyHTTPS, _ := io.ReadAll(respHTTPS.Body)
	_ = respHTTPS.Body.Close()
	require.Equal(t, http.StatusOK, respHTTPS.StatusCode)
	require.Contains(t, string(bodyHTTPS), "via parent proxy")
	require.Equal(t, int32(1), parentConnectCount.Load(), "HTTPS request must tunnel via parent HTTPS_PROXY CONNECT")
	require.True(t, parentAuthSawBasic.Load(), "parent proxy must receive Basic Proxy-Authorization header")

	require.GreaterOrEqual(t, capturedWriteChunks.Load(), int32(2))
	require.GreaterOrEqual(t, capturedReadChunks.Load(), int32(2))
}
