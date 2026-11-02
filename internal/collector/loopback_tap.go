package collector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

// UpstreamProxyConfig stores the parent process proxy configuration so LoopbackTap can
// chain outbound HTTP and HTTPS traffic through the parent proxy while respecting NO_PROXY.
type UpstreamProxyConfig struct {
	HTTPProxy  string
	HTTPSProxy string
	AllProxy   string
	NoProxy    string
}

// ParseUpstreamProxyEnv extracts HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, and NO_PROXY from an
// environment variable slice, ignoring any proxy entry that points back to selfAddr.
func ParseUpstreamProxyEnv(env []string, selfAddr string) UpstreamProxyConfig {
	getCI := func(upper, lower string) string {
		if v := strings.TrimSpace(lookupEnvVar(env, upper)); v != "" {
			return v
		}
		return strings.TrimSpace(lookupEnvVar(env, lower))
	}
	cfg := UpstreamProxyConfig{
		HTTPProxy:  getCI("HTTP_PROXY", "http_proxy"),
		HTTPSProxy: getCI("HTTPS_PROXY", "https_proxy"),
		AllProxy:   getCI("ALL_PROXY", "all_proxy"),
		NoProxy:    getCI("NO_PROXY", "no_proxy"),
	}
	return sanitizeUpstreamProxyConfig(cfg, selfAddr)
}

func normalizeProxyHostPort(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			return strings.ToLower(strings.TrimSpace(u.Host))
		}
	}
	return strings.ToLower(s)
}

func sanitizeUpstreamProxyConfig(cfg UpstreamProxyConfig, selfAddr string) UpstreamProxyConfig {
	selfHP := normalizeProxyHostPort(selfAddr)
	isSelf := func(p string) bool {
		if p == "" || selfHP == "" {
			return false
		}
		return normalizeProxyHostPort(p) == selfHP
	}
	if isSelf(cfg.HTTPProxy) {
		cfg.HTTPProxy = ""
	}
	if isSelf(cfg.HTTPSProxy) {
		cfg.HTTPSProxy = ""
	}
	if isSelf(cfg.AllProxy) {
		cfg.AllProxy = ""
	}
	return cfg
}

// LoopbackTap is an ephemeral local HTTP + HTTPS MITM proxy used as fallback for static-pie (codex/rustls)
// and Go (crypto/tls) binaries that bypass libc LD_PRELOAD and ptrace.
type LoopbackTap struct {
	ln            net.Listener
	listenAddr    string
	addr          string
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	caPath        string
	upstreamProxy UpstreamProxyConfig
	insecure      bool
	mon           *selfmon.Monitor
	dialFunc      func(network, address string) (net.Conn, error)
	certMu        sync.Mutex
	certMap       map[string]*tls.Certificate
	seq           atomic.Uint64
	onChunk       func(connID string, dir parser.Direction, data []byte)
}

type LoopbackTapOption func(*LoopbackTap)

// WithTapListener supplies a pre-constructed net.Listener (such as an in-memory pipe listener
// in restricted sandboxes) instead of calling net.Listen("tcp", ...).
func WithTapListener(ln net.Listener) LoopbackTapOption {
	return func(t *LoopbackTap) {
		if ln != nil {
			t.ln = ln
			t.addr = ln.Addr().String()
		}
	}
}

// WithTapDialer configures a custom outbound dialer for LoopbackTap.
func WithTapDialer(dialFunc func(network, address string) (net.Conn, error)) LoopbackTapOption {
	return func(t *LoopbackTap) {
		t.dialFunc = dialFunc
	}
}

// WithTapListenAddr configures the TCP address LoopbackTap listens on (default "127.0.0.1:0").
func WithTapListenAddr(listenAddr string) LoopbackTapOption {
	return func(t *LoopbackTap) {
		if strings.TrimSpace(listenAddr) != "" {
			t.listenAddr = strings.TrimSpace(listenAddr)
		}
	}
}

// WithTapUpstreamProxy configures the parent process upstream proxy settings for LoopbackTap.
func WithTapUpstreamProxy(cfg UpstreamProxyConfig) LoopbackTapOption {
	return func(t *LoopbackTap) {
		t.SetUpstreamProxyConfig(cfg)
	}
}

// WithTapInsecure configures whether LoopbackTap skips upstream TLS certificate verification
// for non-loopback targets (default false).
func WithTapInsecure(insecure bool) LoopbackTapOption {
	return func(t *LoopbackTap) {
		t.SetInsecure(insecure)
	}
}

// WithTapMonitor attaches a selfmon.Monitor so upstream TLS verification failures are recorded.
func WithTapMonitor(mon *selfmon.Monitor) LoopbackTapOption {
	return func(t *LoopbackTap) {
		t.mon = mon
	}
}

func NewLoopbackTap(hooksDir string, onChunk func(connID string, dir parser.Direction, data []byte), opts ...LoopbackTapOption) (*LoopbackTap, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "LLM-Tracer Ephemeral Local CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	// Append system CA bundle if present so upstream verification inside target process still trusts public CAs
	var combinedPEM bytes.Buffer
	for _, sysCAPath := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/cert.pem",
	} {
		if sysCA, err := os.ReadFile(sysCAPath); err == nil && len(sysCA) > 0 {
			combinedPEM.Write(sysCA)
			combinedPEM.WriteByte('\n')
			break
		}
	}
	combinedPEM.Write(caPEM)
	caPath := filepath.Join(hooksDir, "llm_tracer_ca_bundle.pem")
	if err := writeArtifactNoFollow(caPath, combinedPEM.Bytes(), 0o644); err != nil {
		return nil, err
	}

	tap := &LoopbackTap{
		listenAddr:    "127.0.0.1:0",
		caCert:        caCert,
		caKey:         caKey,
		caPath:        caPath,
		upstreamProxy: ParseUpstreamProxyEnv(os.Environ(), ""),
		certMap:       make(map[string]*tls.Certificate),
		onChunk:       onChunk,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(tap)
		}
	}
	if tap.ln == nil {
		listenAddr := strings.TrimSpace(tap.listenAddr)
		if listenAddr == "" {
			listenAddr = "127.0.0.1:0"
		}
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			return nil, err
		}
		tap.ln = ln
		tap.addr = ln.Addr().String()
	}
	tap.SetUpstreamProxyConfig(sanitizeUpstreamProxyConfig(tap.UpstreamProxyConfig(), tap.addr))
	go tap.serve()
	return tap, nil
}

func (t *LoopbackTap) dialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	if t != nil && t.dialFunc != nil {
		return t.dialFunc(network, address)
	}
	return net.DialTimeout(network, address, timeout)
}

// SetUpstreamProxyConfig updates the parent process proxy configuration used for outbound chaining.
func (t *LoopbackTap) SetUpstreamProxyConfig(cfg UpstreamProxyConfig) {
	if t == nil {
		return
	}
	t.certMu.Lock()
	t.upstreamProxy = sanitizeUpstreamProxyConfig(cfg, t.addr)
	t.certMu.Unlock()
}

// UpstreamProxyConfig returns a copy of the configured parent process proxy configuration.
func (t *LoopbackTap) UpstreamProxyConfig() UpstreamProxyConfig {
	if t == nil {
		return UpstreamProxyConfig{}
	}
	t.certMu.Lock()
	defer t.certMu.Unlock()
	return t.upstreamProxy
}

// SetInsecure controls whether upstream TLS verification is skipped for non-loopback targets.
func (t *LoopbackTap) SetInsecure(insecure bool) {
	t.certMu.Lock()
	t.insecure = insecure
	t.certMu.Unlock()
}

// Insecure reports whether upstream TLS verification is skipped for non-loopback targets.
func (t *LoopbackTap) Insecure() bool {
	t.certMu.Lock()
	defer t.certMu.Unlock()
	return t.insecure
}

func (t *LoopbackTap) ProxyURL() string {
	return "http://" + t.addr
}

func (t *LoopbackTap) HostPort() (string, string) {
	h, p, err := net.SplitHostPort(t.addr)
	if err != nil {
		return "127.0.0.1", ""
	}
	return h, p
}

func (t *LoopbackTap) CABundlePath() string {
	return t.caPath
}

func (t *LoopbackTap) Close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
}

func (t *LoopbackTap) serve() {
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			return
		}
		go t.handleConn(conn)
	}
}

func (t *LoopbackTap) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		t.handleConnect(clientConn, req.Host)
		return
	}
	t.forwardPlainHTTP(clientConn, req)
}

func (t *LoopbackTap) forwardPlainHTTP(clientConn net.Conn, req *http.Request) {
	connID := fmt.Sprintf("tap_%d", t.seq.Add(1))
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	reqBytes, _ := dumpHTTPRequestWire(req)
	if len(reqBytes) > 0 && t.onChunk != nil {
		t.onChunk(connID, parser.DirWrite, reqBytes)
	}

	tr := &http.Transport{
		DisableCompression: false,
		TLSClientConfig:    t.upstreamTLSConfig(req.URL.Hostname()),
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return t.dialTimeout(network, addr, 5*time.Second)
		},
	}
	if pu, err := t.resolveUpstreamProxy(req.URL); err == nil && pu != nil {
		scheme := strings.ToLower(strings.TrimSpace(pu.Scheme))
		if scheme == "socks5" || scheme == "socks5h" {
			tr.DialContext = func(_ context.Context, _, addr string) (net.Conn, error) {
				return t.dialViaUpstreamProxy(pu, addr)
			}
		} else {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var respHead bytes.Buffer
	fmt.Fprintf(&respHead, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(&respHead, "%s: %s\r\n", k, v)
		}
	}
	respHead.WriteString("\r\n")
	_, _ = clientConn.Write(respHead.Bytes())

	var respBodyBuf bytes.Buffer
	buf := make([]byte, 16384)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			_, _ = clientConn.Write(buf[:n])
			respBodyBuf.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	if t.onChunk != nil {
		var wireResp bytes.Buffer
		fmt.Fprintf(&wireResp, "HTTP/1.1 %s\r\n", resp.Status)
		for k, vv := range resp.Header {
			if strings.EqualFold(k, "Transfer-Encoding") || strings.EqualFold(k, "Content-Length") {
				continue
			}
			for _, v := range vv {
				fmt.Fprintf(&wireResp, "%s: %s\r\n", k, v)
			}
		}
		fmt.Fprintf(&wireResp, "Content-Length: %d\r\n\r\n", respBodyBuf.Len())
		wireResp.Write(respBodyBuf.Bytes())
		t.onChunk(connID, parser.DirRead, wireResp.Bytes())
	}
}

func (t *LoopbackTap) handleConnect(clientConn net.Conn, targetHost string) {
	targetHost, hostOnly := parseConnectAuthority(targetHost)
	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	leafCert, err := t.getOrCreateLeafCert(hostOnly)
	if err != nil {
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := tlsClient.Handshake(); err != nil {
		return
	}
	defer tlsClient.Close()

	upConn, err := t.dialUpstreamTLS(targetHost, hostOnly)
	if err != nil {
		return
	}
	defer upConn.Close()

	connID := fmt.Sprintf("taptls_%d", t.seq.Add(1))
	var clientEOF atomic.Bool
	var upReadBytes atomic.Int64
	upDone := make(chan struct{})

	go func() {
		buf := make([]byte, 32768)
		for {
			n, err := tlsClient.Read(buf)
			if n > 0 {
				if t.onChunk != nil {
					cp := make([]byte, n)
					copy(cp, buf[:n])
					t.onChunk(connID, parser.DirWrite, cp)
				}
				_, _ = upConn.Write(buf[:n])
			}
			if err != nil {
				clientEOF.Store(true)
				if upReadBytes.Load() > 0 {
					_ = upConn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				} else {
					_ = upConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				}
				break
			}
		}
	}()
	go func() {
		defer close(upDone)
		buf := make([]byte, 32768)
		for {
			n, err := upConn.Read(buf)
			if n > 0 {
				upReadBytes.Add(int64(n))
				if t.onChunk != nil {
					cp := make([]byte, n)
					copy(cp, buf[:n])
					t.onChunk(connID, parser.DirRead, cp)
				}
				_, _ = tlsClient.Write(buf[:n])
				if clientEOF.Load() {
					_ = upConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				}
			}
			if err != nil {
				break
			}
		}
	}()
	<-upDone
}

// parseConnectAuthority normalizes a CONNECT authority or host string into "host:port" (with IPv6 brackets)
// and the bare host literal/domain without brackets or port.
func parseConnectAuthority(rawTarget string) (targetHostPort, hostOnly string) {
	s := strings.TrimSpace(rawTarget)
	if h, p, err := net.SplitHostPort(s); err == nil && p != "" {
		hostOnly = strings.Trim(h, "[]")
		return net.JoinHostPort(hostOnly, p), hostOnly
	}
	hostOnly = strings.Trim(s, "[]")
	return net.JoinHostPort(hostOnly, "443"), hostOnly
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSpace(host)
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	} else {
		h = strings.Trim(h, "[]")
	}
	if idx := strings.IndexByte(h, '%'); idx != -1 {
		h = h[:idx]
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (t *LoopbackTap) shouldSkipUpstreamVerify(hostOnly string) bool {
	if isLoopbackHost(hostOnly) {
		return true
	}
	return t.Insecure()
}

func (t *LoopbackTap) upstreamTLSConfig(hostOnly string) *tls.Config {
	_, cleanHost := parseConnectAuthority(hostOnly)
	return &tls.Config{
		ServerName:         cleanHost,
		InsecureSkipVerify: t.shouldSkipUpstreamVerify(cleanHost),
		NextProtos:         []string{"http/1.1"},
	}
}

type bufferedTapConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedTapConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type customProxyDialer func(network, address string) (net.Conn, error)

func (d customProxyDialer) Dial(network, address string) (net.Conn, error) {
	return d(network, address)
}

func (t *LoopbackTap) resolveUpstreamProxy(targetURL *url.URL) (*url.URL, error) {
	if targetURL == nil || isLoopbackHost(targetURL.Host) {
		return nil, nil
	}
	cfg := t.UpstreamProxyConfig()
	httpP := strings.TrimSpace(cfg.HTTPProxy)
	if httpP == "" {
		httpP = strings.TrimSpace(cfg.AllProxy)
	}
	if httpP == "" {
		httpP = strings.TrimSpace(cfg.HTTPSProxy)
	}
	httpsP := strings.TrimSpace(cfg.HTTPSProxy)
	if httpsP == "" {
		httpsP = strings.TrimSpace(cfg.AllProxy)
	}
	if httpsP == "" {
		httpsP = strings.TrimSpace(cfg.HTTPProxy)
	}
	if httpP == "" && httpsP == "" {
		return nil, nil
	}
	if matchesNoProxy(targetURL.Host, cfg.NoProxy) {
		return nil, nil
	}
	rawProxy := httpP
	if strings.EqualFold(targetURL.Scheme, "https") && httpsP != "" {
		rawProxy = httpsP
	}
	if rawProxy == "" {
		return nil, nil
	}
	if !strings.Contains(rawProxy, "://") {
		rawProxy = "http://" + rawProxy
	}
	pu, err := url.Parse(rawProxy)
	if err != nil || pu == nil || strings.TrimSpace(pu.Host) == "" {
		return nil, err
	}
	if normalizeProxyHostPort(pu.Host) == normalizeProxyHostPort(t.addr) {
		return nil, nil
	}
	return pu, nil
}

func matchesNoProxy(targetHost, noProxy string) bool {
	noProxy = strings.TrimSpace(noProxy)
	if noProxy == "" {
		return false
	}
	if noProxy == "*" {
		return true
	}
	hostOnly := strings.TrimSpace(targetHost)
	portOnly := ""
	if h, p, err := net.SplitHostPort(hostOnly); err == nil {
		hostOnly = strings.Trim(h, "[]")
		portOnly = p
	} else {
		hostOnly = strings.Trim(hostOnly, "[]")
	}
	hostLower := strings.ToLower(hostOnly)
	targetIP := net.ParseIP(hostOnly)

	for _, token := range strings.Split(noProxy, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if token == "*" {
			return true
		}
		tokHost := token
		tokPort := ""
		if h, p, err := net.SplitHostPort(token); err == nil {
			tokHost = strings.Trim(h, "[]")
			tokPort = p
		} else {
			tokHost = strings.Trim(tokHost, "[]")
		}
		if tokPort != "" && portOnly != "" && tokPort != portOnly {
			continue
		}
		if targetIP != nil {
			if _, ipNet, err := net.ParseCIDR(tokHost); err == nil && ipNet.Contains(targetIP) {
				return true
			}
			if tokIP := net.ParseIP(tokHost); tokIP != nil && tokIP.Equal(targetIP) {
				return true
			}
		}
		tokLower := strings.ToLower(strings.TrimPrefix(tokHost, "*"))
		if tokLower == hostLower {
			return true
		}
		if strings.HasPrefix(tokLower, ".") {
			if hostLower == tokLower[1:] || strings.HasSuffix(hostLower, tokLower) {
				return true
			}
		} else if strings.HasSuffix(hostLower, "."+tokLower) {
			return true
		}
	}
	return false
}

func (t *LoopbackTap) dialViaUpstreamProxy(pu *url.URL, targetHost string) (net.Conn, error) {
	if pu == nil || strings.TrimSpace(pu.Host) == "" {
		return nil, fmt.Errorf("empty upstream proxy URL")
	}
	scheme := strings.ToLower(strings.TrimSpace(pu.Scheme))
	if scheme == "" {
		scheme = "http"
	}
	proxyHost := strings.TrimSpace(pu.Host)
	if _, _, err := net.SplitHostPort(proxyHost); err != nil {
		defaultPort := "80"
		switch scheme {
		case "https":
			defaultPort = "443"
		case "socks5", "socks5h":
			defaultPort = "1080"
		}
		proxyHost = net.JoinHostPort(strings.Trim(proxyHost, "[]"), defaultPort)
	}

	if scheme == "socks5" || scheme == "socks5h" {
		var auth *proxy.Auth
		if pu.User != nil {
			pwd, _ := pu.User.Password()
			auth = &proxy.Auth{
				User:     pu.User.Username(),
				Password: pwd,
			}
		}
		var forward proxy.Dialer = &net.Dialer{Timeout: 5 * time.Second}
		if t != nil && t.dialFunc != nil {
			forward = customProxyDialer(t.dialFunc)
		}
		dialer, err := proxy.SOCKS5("tcp", proxyHost, auth, forward)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", targetHost)
	}

	rawConn, err := t.dialTimeout("tcp", proxyHost, 5*time.Second)
	if err != nil {
		return nil, err
	}
	proxyConn := rawConn
	if scheme == "https" {
		tlsProxy := tls.Client(rawConn, t.upstreamTLSConfig(pu.Hostname()))
		if err := tlsProxy.Handshake(); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		proxyConn = tlsProxy
	}

	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetHost, targetHost)
	if pu.User != nil {
		pwd, _ := pu.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(pu.User.Username() + ":" + pwd))
		fmt.Fprintf(&reqBuf, "Proxy-Authorization: Basic %s\r\n", cred)
	}
	reqBuf.WriteString("\r\n")

	if _, err := io.WriteString(proxyConn, reqBuf.String()); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	br := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = proxyConn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT %s returned status %s", targetHost, resp.Status)
	}
	if br.Buffered() > 0 {
		return &bufferedTapConn{Conn: proxyConn, r: io.MultiReader(br, proxyConn)}, nil
	}
	return proxyConn, nil
}

func (t *LoopbackTap) dialUpstreamTLS(targetHost, hostOnly string) (*tls.Conn, error) {
	if _, _, err := net.SplitHostPort(strings.TrimSpace(targetHost)); err != nil {
		targetHost, _ = parseConnectAuthority(targetHost)
	}
	if strings.TrimSpace(hostOnly) == "" {
		_, hostOnly = parseConnectAuthority(targetHost)
	} else {
		_, hostOnly = parseConnectAuthority(hostOnly)
	}
	tlsCfg := t.upstreamTLSConfig(hostOnly)
	targetURL := &url.URL{Scheme: "https", Host: targetHost}
	if pu, err := t.resolveUpstreamProxy(targetURL); err == nil && pu != nil {
		if proxyConn, err := t.dialViaUpstreamProxy(pu, targetHost); err == nil {
			tlsConn := tls.Client(proxyConn, tlsCfg)
			if err := tlsConn.Handshake(); err == nil {
				return tlsConn, nil
			}
			_ = proxyConn.Close()
		}
	}
	if t.dialFunc != nil {
		rawConn, err := t.dialFunc("tcp", targetHost)
		if err != nil {
			t.recordUpstreamTLSFailure(targetHost, hostOnly, err)
			return nil, err
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			_ = rawConn.Close()
			t.recordUpstreamTLSFailure(targetHost, hostOnly, err)
			return nil, err
		}
		return tlsConn, nil
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", targetHost, tlsCfg)
	if err != nil {
		t.recordUpstreamTLSFailure(targetHost, hostOnly, err)
		return nil, err
	}
	return conn, nil
}

func (t *LoopbackTap) recordUpstreamTLSFailure(targetHost, hostOnly string, err error) {
	if t.mon == nil || err == nil {
		return
	}
	t.mon.RecordWarn(
		selfmon.StageProbe,
		"loopback_tap_upstream_tls",
		fmt.Sprintf("upstream TLS verify/dial failed for %s: %v (hint: use --tap-insecure if behind a corporate MITM proxy or self-signed gateway)", targetHost, err),
		map[string]any{
			"target":   targetHost,
			"host":     hostOnly,
			"insecure": t.Insecure(),
			"hint":     "--tap-insecure",
		},
	)
}

func (t *LoopbackTap) getOrCreateLeafCert(host string) (*tls.Certificate, error) {
	_, host = parseConnectAuthority(host)
	t.certMu.Lock()
	defer t.certMu.Unlock()
	if c, ok := t.certMap[host]; ok {
		return c, nil
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, t.caCert, &priv.PublicKey, t.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der, t.caCert.Raw},
		PrivateKey:  priv,
	}
	t.certMap[host] = cert
	return cert, nil
}

func dumpHTTPRequestWire(req *http.Request) ([]byte, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}
	var b bytes.Buffer
	pathAndQuery := req.URL.RequestURI()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, pathAndQuery)
	fmt.Fprintf(&b, "Host: %s\r\n", req.Host)
	for k, vv := range req.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(bodyBytes))
	b.Write(bodyBytes)
	return b.Bytes(), nil
}
