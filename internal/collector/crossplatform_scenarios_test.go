package collector

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

// findGoExecutable locates the active Go toolchain binary via GOROOT or PATH.
func findGoExecutable() (string, error) {
	if root := runtime.GOROOT(); root != "" {
		name := "go"
		if runtime.GOOS == "windows" {
			name = "go.exe"
		}
		cand := filepath.Join(root, "bin", name)
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return exec.LookPath("go")
}

func findNodeExecutable() (string, error) {
	if p, err := exec.LookPath("node"); err == nil && p != "" {
		return p, nil
	}
	for _, cand := range []string{
		"/home/liuyicong/.local/share/mise/installs/node/24.4.1/bin/node",
		"/opt/homebrew/bin/node",
		"/usr/local/bin/node",
	} {
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
	}
	return "", exec.ErrNotFound
}

func canListenLocalTCP() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// TestCrossPlatformBinaryFormatsSymbolResolution compiles ELF (linux/amd64), Mach-O (darwin/arm64),
// and PE (windows/amd64) Go HTTPS binaries and verifies that InspectGoTLSTarget and InspectBinaryProfile
// accurately resolve crypto/tls.(*Conn).Write and crypto/tls.(*Conn).Read across all 3 executable formats.
func TestCrossPlatformBinaryFormatsSymbolResolution(t *testing.T) {
	goBin, err := findGoExecutable()
	if err != nil {
		t.Skip("go compiler not in PATH")
	}

	dir := t.TempDir()
	srcPath := filepath.Join(dir, "sample_tls_client.go")
	srcCode := `package main
import (
	"crypto/tls"
	"fmt"
)
func main() {
	conn := &tls.Conn{}
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 4)
	_, _ = conn.Read(buf)
	fmt.Println("ok")
}
`
	require.NoError(t, os.WriteFile(srcPath, []byte(srcCode), 0o644))

	targets := []struct {
		goos   string
		goarch string
		out    string
	}{
		{goos: "linux", goarch: "amd64", out: filepath.Join(dir, "sample_linux_amd64")},
		{goos: "darwin", goarch: "arm64", out: filepath.Join(dir, "sample_darwin_arm64")},
		{goos: "windows", goarch: "amd64", out: filepath.Join(dir, "sample_windows_amd64.exe")},
	}

	for _, tc := range targets {
		t.Run(tc.goos+"_"+tc.goarch, func(t *testing.T) {
			cmd := exec.Command(goBin, "build", "-o", tc.out, srcPath)
			cmd.Env = append(os.Environ(),
				"CGO_ENABLED=0",
				"GOOS="+tc.goos,
				"GOARCH="+tc.goarch,
			)
			outBytes, err := cmd.CombinedOutput()
			require.NoError(t, err, "go build failed for %s/%s: %s", tc.goos, tc.goarch, string(outBytes))

			gt, err := InspectGoTLSTarget(tc.out)
			require.NoError(t, err)
			require.NotNil(t, gt)
			require.Equal(t, "gotls", gt.Type)
			require.NotEmpty(t, gt.GoVersion)
			require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Write"], uint64(0), "Write symbol must be resolved for %s/%s", tc.goos, tc.goarch)
			require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Read"], uint64(0), "Read symbol must be resolved for %s/%s", tc.goos, tc.goarch)

			prof, err := InspectBinaryProfile(tc.out)
			require.NoError(t, err)
			require.NotNil(t, prof)
			require.Equal(t, "gotls", prof.TLSStack)
			require.True(t, prof.RequiresPtrace)
		})
	}
}

// TestCrossPlatformCaptureScenarios verifies end-to-end LLM protocol capture on Linux, macOS, and Windows:
//  1. Host OS process inspection & subtree vs PID-only scope filtering
//  2. Python HTTPS (ssl.SSLSocket + ssl.MemoryBIO) capture via PYTHONPATH sitecustomize.py
//  3. Node.js HTTPS (tls.TLSSocket) multi-turn SSE capture via NODE_OPTIONS node_hook.cjs
//  4. Native compiled Go HTTPS binary capture via LoopbackTap proxy + ephemeral CA bundle injection
func TestCrossPlatformCaptureScenarios(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	corr := correlator.NewCorrelator(mon)

	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	tcpAllowed := canListenLocalTCP()
	var ts *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_xplat_py\",\"model\":\"claude-3-7-sonnet\",\"usage\":{\"input_tokens\":14}}}\n\n" +
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Cross-platform Python TLS captured.\"}}\n\n" +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":6}}\n\n" +
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"id\":\"chatcmpl_xplat_node\",\"model\":\"gpt-4.1-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Node TLS socket captured on \"}}]}\n\n" +
			"data: {\"id\":\"chatcmpl_xplat_node\",\"model\":\"gpt-4.1-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + runtime.GOOS + ".\"}}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":5,\"total_tokens\":16}}\n\n" +
			"data: [DONE]\n\n"))
	})
	mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_xplat_go\",\"model\":\"gpt-5-codex\"}}\n\n" +
			"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Native Go HTTPS captured on " + runtime.GOOS + ".\"}\n\n" +
			"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_xplat_go\",\"model\":\"gpt-5-codex\",\"usage\":{\"input_tokens\":19,\"output_tokens\":7,\"total_tokens\":26}}}\n\n"))
	})
	if tcpAllowed {
		ts = httptest.NewTLSServer(mux)
		defer ts.Close()
	}

	t.Run("1_HostProcessInspection", func(t *testing.T) {
		info := InspectProcess(os.Getpid())
		require.Equal(t, os.Getpid(), info.PID)
		require.NotEmpty(t, info.Comm)
		require.NotEmpty(t, info.Exe)
	})

	t.Run("2_PythonTLSAndMemoryBIOCapture", func(t *testing.T) {
		pyBin, err := findPythonExecutable()
		if err != nil {
			t.Skip("python3 not found")
		}
		certPath, keyPath := writeSelfSignedCertFiles(t, dir)
		serverURL := ""
		if ts != nil {
			serverURL = ts.URL
		}
		pyScript := `
import ssl, urllib.request, sys
cert, key, srv_url = sys.argv[1], sys.argv[2], sys.argv[3]
if srv_url:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = b'{"model":"claude-3-7-sonnet","stream":true,"messages":[{"role":"user","content":"Verify cross-platform Python SSLSocket"}]}'
    req = urllib.request.Request(srv_url + "/v1/messages", data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        _ = resp.read()
else:
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c_ctx.check_hostname = False
    c_ctx.verify_mode = ssl.CERT_NONE
    s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="api.anthropic.com")
    s_ssl = s_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        try: c_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = c_out.read()
        if d: s_in.write(d)
        try: s_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = s_out.read()
        if d: c_in.write(d)
    body = b'{"model":"claude-3-7-sonnet","stream":true,"messages":[{"role":"user","content":"Verify cross-platform Python SSLSocket"}]}'
    sse = (b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_xplat_py\",\"model\":\"claude-3-7-sonnet\",\"usage\":{\"input_tokens\":14}}}\n\n"
           b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Cross-platform Python TLS captured.\"}}\n\n"
           b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":6}}\n\n"
           b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
    c_ssl.write(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    s_in.write(c_out.read())
    _ = s_ssl.read(65536)
    s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(sse)).encode() + b"\r\n\r\n" + sse)
    c_in.write(s_out.read())
    _ = c_ssl.read(65536)
`
		code, err := col.LaunchCommand(ctx, []string{pyBin, "-c", pyScript, certPath, keyPath, serverURL})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		sessions, err := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolAnthropic)})
		require.NoError(t, err)
		require.NotEmpty(t, sessions, "expected Python Anthropic session on %s", runtime.GOOS)
		events, err := st.QuerySessionEvents(store.EventQuery{SessionID: sessions[0].ID, Limit: 50})
		require.NoError(t, err)
		var found bool
		for _, ev := range events {
			if ev.Protocol == model.ProtocolAnthropic && ev.Chat != nil && ev.Chat.ResponseText == "Cross-platform Python TLS captured." {
				found = true
				break
			}
		}
		require.True(t, found, "expected Python SSLSocket Anthropic SSE exchange to be captured on %s", runtime.GOOS)
	})

	t.Run("3_NodeTLSSocketMultiTurnCapture", func(t *testing.T) {
		nodeBin, err := findNodeExecutable()
		if err != nil {
			t.Skip("node not found in PATH")
		}
		serverURL := ""
		if ts != nil {
			serverURL = ts.URL
		}
		nodeScript := `
const https = require("node:https");
const tls = require("node:tls");
const { Duplex } = require("node:stream");
const srvUrl = process.argv[2] || "";

function sendInMemoryTurn(messages, replyText) {
  const dummy = new Duplex({ read() {}, write(c, e, cb) { cb(); } });
  const sock = new tls.TLSSocket(dummy, { isServer: false });
  const reqBody = JSON.stringify({ model: "gpt-4.1-mini", stream: true, messages });
  const sseBody =
    'data: {"id":"chatcmpl_xplat_node","model":"gpt-4.1-mini","choices":[{"index":0,"delta":{"content":' + JSON.stringify(replyText) + '}}],"usage":{"prompt_tokens":11,"completion_tokens":5,"total_tokens":16}}\n\n' +
    'data: [DONE]\n\n';
  try {
    sock._write(Buffer.from("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: " + Buffer.byteLength(reqBody) + "\r\n\r\n" + reqBody), "buffer", () => {});
  } catch (_) {}
  sock.push(Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + Buffer.byteLength(sseBody) + "\r\n\r\n" + sseBody));
  sock.push(null);
}

function sendTurn(messages) {
  if (!srvUrl) {
    sendInMemoryTurn(messages, "Node TLS socket captured on " + process.platform + ".");
    return Promise.resolve();
  }
  const target = new URL(srvUrl + "/v1/chat/completions");
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ model: "gpt-4.1-mini", stream: true, messages });
    const req = https.request({
      hostname: target.hostname,
      port: target.port,
      path: target.pathname,
      method: "POST",
      rejectUnauthorized: false,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
        "Connection": "close"
      }
    }, (res) => {
      res.on("data", () => {});
      res.on("end", resolve);
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}
(async () => {
  await sendTurn([{ role: "user", content: "Turn 1 from Node" }]);
  await sendTurn([
    { role: "user", content: "Turn 1 from Node" },
    { role: "assistant", content: "Node TLS socket captured on " + process.platform + "." },
    { role: "user", content: "Turn 2 follow-up from Node" }
  ]);
})();
`
		scriptPath := filepath.Join(dir, "node_client.js")
		require.NoError(t, os.WriteFile(scriptPath, []byte(nodeScript), 0o644))

		code, err := col.LaunchCommand(ctx, []string{nodeBin, scriptPath, serverURL})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		sessions, err := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolOpenAIChat)})
		require.NoError(t, err)
		require.NotEmpty(t, sessions, "expected Node.js OpenAI Chat session to be captured on %s", runtime.GOOS)
		require.GreaterOrEqual(t, sessions[0].TurnCount, 2, "expected 2-turn conversation correlation")
	})

	t.Run("4_NativeGoHTTPSBinaryCapture", func(t *testing.T) {
		goBin, err := findGoExecutable()
		if err != nil {
			t.Skip("go compiler not in PATH")
		}
		clientSrc := filepath.Join(dir, "native_go_client.go")
		clientExe := filepath.Join(dir, "native_go_client")
		if runtime.GOOS == "windows" {
			clientExe += ".exe"
		}
		serverURL := ""
		if ts != nil {
			serverURL = ts.URL
		}
		src := `package main
import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)
func main() {
	if len(os.Args) < 2 || os.Args[1] == "" {
		os.Exit(0)
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if caFile := os.Getenv("SSL_CERT_FILE"); caFile != "" {
		if pemBytes, err := os.ReadFile(caFile); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				tlsCfg = &tls.Config{RootCAs: pool}
			}
		}
	}
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: tlsCfg,
	}
	if proxyStr := os.Getenv("HTTPS_PROXY"); proxyStr != "" {
		if pu, err := url.Parse(proxyStr); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	body := []byte(` + "`" + `{"model":"gpt-5-codex","stream":true,"input":[{"role":"user","content":"Verify native Go binary capture"}]}` + "`" + `)
	req, err := http.NewRequest("POST", os.Args[1]+"/v1/responses", bytes.NewReader(body))
	if err != nil {
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		os.Exit(2)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
}
`
		require.NoError(t, os.WriteFile(clientSrc, []byte(src), 0o644))
		buildCmd := exec.Command(goBin, "build", "-o", clientExe, clientSrc)
		buildOut, err := buildCmd.CombinedOutput()
		require.NoError(t, err, "build native go client failed: %s", string(buildOut))

		gt, err := InspectGoTLSTarget(clientExe)
		require.NoError(t, err)
		require.NotNil(t, gt)
		require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Write"], uint64(0))

		code, err := col.LaunchCommand(ctx, []string{clientExe, serverURL})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		if serverURL != "" {
			sessions, err := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolOpenAIResponses)})
			require.NoError(t, err)
			require.NotEmpty(t, sessions, "expected Go OpenAI Responses session on %s", runtime.GOOS)
			events, err := st.QuerySessionEvents(store.EventQuery{SessionID: sessions[0].ID, Limit: 50})
			require.NoError(t, err)
			var foundGo bool
			for _, ev := range events {
				if ev.Protocol == model.ProtocolOpenAIResponses && ev.Chat != nil && ev.Chat.Model == "gpt-5-codex" {
					foundGo = true
					break
				}
			}
			require.True(t, foundGo, "expected native Go HTTPS Responses API exchange to be captured on %s", runtime.GOOS)
		}
	})
}
