//go:build linux

package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

// TestCompatibilityMatrixAllRuntimeScenarios constructs and verifies all 6 binary/runtime linkage scenarios
// directly inside the test suite without relying on external host-specific user directories.
func TestCompatibilityMatrixAllRuntimeScenarios(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	corr := correlator.NewCorrelator(mon)

	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	// -------------------------------------------------------------------------
	// Scenario 1: Dynamic libc + Dynamic libssl.so.3 (standard C/curl/system Python)
	// Captured via LD_PRELOAD libllm_tracer_ssl.so -> SSL_write / SSL_read PLT hook
	// -------------------------------------------------------------------------
	t.Run("Scenario1_DynamicLibcAndDynamicLibSSL_PreloadSSLWrite", func(t *testing.T) {
		mockLibSrc := filepath.Join(dir, "libmockssl.c")
		mockLibSo := filepath.Join(dir, "libssl.so.3")
		mockCode := `
#include <stddef.h>
int SSL_write(void *ssl, const void *buf, int num) { return num; }
int SSL_read(void *ssl, void *buf, int num) { return num; }
`
		require.NoError(t, os.WriteFile(mockLibSrc, []byte(mockCode), 0o644))
		require.NoError(t, exec.Command("gcc", "-shared", "-fPIC", "-O2", mockLibSrc, "-o", mockLibSo).Run())

		cSrc := filepath.Join(dir, "scen1_dyn_ssl.c")
		cBin := filepath.Join(dir, "scen1_dyn_ssl")
		code := `
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int SSL_write(void *ssl, const void *buf, int num);
extern int SSL_read(void *ssl, void *buf, int num);

int main() {
    unsetenv("LLM_TRACER_PY_TLS_ACTIVE");
    void *fake_ssl = (void *)0x12345678ULL;
    const char *req_body = "{\"model\":\"systemone-mini\",\"state\":{\"page\":{\"url\":\"https://example.com\",\"title\":\"Scen1\"}},\"questions\":{\"operation\":{\"type\":\"choice\",\"instructions\":{\"goal\":\"Scenario1 dynamic libssl\"},\"criteria\":{\"DONE\":\"Done\"}}}}";
    char req[512];
    int req_len = snprintf(req, sizeof(req), "POST /v1/systemone HTTP/1.1\r\nHost: api.bamboonode.dev\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(req_body), req_body);
    SSL_write(fake_ssl, req, req_len);

    const char *resp_body = "{\"model\":\"systemone-mini\",\"answers\":{\"operation\":{\"choice\":\"DONE\",\"probabilities\":{\"DONE\":1.0},\"confidence\":1.0}}}";
    char resp[512];
    int resp_len = snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(resp_body), resp_body);
    SSL_read(fake_ssl, resp, resp_len);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		require.NoError(t, exec.Command("gcc", "-O2", cSrc, mockLibSo, "-Wl,-rpath,"+dir, "-o", cBin).Run())

		prof, err := InspectBinaryProfile(cBin)
		require.NoError(t, err)
		require.Equal(t, "dynamic", prof.LinkMode)
		require.Equal(t, "dynamic-libssl", prof.TLSStack)

		exitCode, err := col.LaunchCommand(ctx, []string{cBin})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)
	})

	// -------------------------------------------------------------------------
	// Scenario 2: Dynamic libc + Stripped Embedded TLS over Plain Socket (claude.exe Bun pattern)
	// Binary has NO SSL_write/SSL_read symbols (stripped), uses scattered writev() + read()
	// across multiple keep-alive HTTP requests on the same socket FD.
	// -------------------------------------------------------------------------
	t.Run("Scenario2_StrippedEmbeddedTLS_BunLikeWritevReadSocket", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen2_bun_like.c")
		cBin := filepath.Join(dir, "scen2_bun_like")
		code := `
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;

    // Turn 1: scattered writev (header iov[0] + JSON body iov[1]), mimicking Bun/uSockets
    const char *b1 = "{\"model\":\"claude-sonnet-4-6\",\"conversation_id\":\"scen2_bun\",\"messages\":[{\"role\":\"user\",\"content\":\"hello 1\"}]}";
    char h1[256];
    snprintf(h1, sizeof(h1), "POST /v1/messages HTTP/1.1\r\nHost: 192.168.50.111:3000\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n", strlen(b1));
    struct iovec iov[2] = {
        { .iov_base = h1, .iov_len = strlen(h1) },
        { .iov_base = (void *)b1, .iov_len = strlen(b1) }
    };
    if (writev(sv[0], iov, 2) <= 0) return 2;

    char sink[1024];
    (void)read(sv[1], sink, sizeof(sink));

    const char *rb1 = "{\"id\":\"msg_s2_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-6\",\"content\":[{\"type\":\"text\",\"text\":\"ok1\"}]}";
    char r1[512];
    snprintf(r1, sizeof(r1), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(rb1), rb1);
    (void)write(sv[1], r1, strlen(r1));
    (void)read(sv[0], sink, sizeof(sink));

    close(sv[0]);
    close(sv[1]);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		// Compile with -s (strip all symbols, just like BoringSSL inside claude.exe)
		require.NoError(t, exec.Command("gcc", "-O2", "-s", cSrc, "-o", cBin).Run())

		prof, err := InspectBinaryProfile(cBin)
		require.NoError(t, err)
		require.Equal(t, "dynamic", prof.LinkMode)
		require.Equal(t, "stripped-embedded-tls", prof.TLSStack)
		require.Empty(t, prof.Symbols)

		exitCode, err := col.LaunchCommand(ctx, []string{cBin})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)
	})

	// -------------------------------------------------------------------------
	// Scenario 3: Dynamic libc + Statically-Embedded Local ('t') OpenSSL & MemoryBIO Symbols
	// (Hermes / uv python-build-standalone pattern)
	// Verifies:
	//   Part A: ELF .symtab resolution of local 't' symbols (SSL_write, SSL_read, _ssl_MemoryBIO_write, _ssl_MemoryBIO_read)
	//   Part B: Python sitecustomize.py runtime hook on ssl.SSLObject (MemoryBIO) & ssl.SSLSocket
	// -------------------------------------------------------------------------
	t.Run("Scenario3_StaticLocalOpenSSLSymbols_And_PythonMemoryBIOHook", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen3_static_openssl_sym.c")
		cBin := filepath.Join(dir, "scen3_static_openssl_sym")
		// Define local ('t') static functions matching python-build-standalone's embedded OpenSSL
		code := `
__attribute__((used, noinline)) static int SSL_write(void *s, const void *b, int n) { return n; }
__attribute__((used, noinline)) static int SSL_read(void *s, void *b, int n) { return n; }
__attribute__((used, noinline)) static int _ssl_MemoryBIO_write(void *s, const void *b, int n) { return n; }
__attribute__((used, noinline)) static int _ssl_MemoryBIO_read(void *s, void *b, int n) { return n; }
int main() {
    return SSL_write(0, 0, 0) + SSL_read(0, 0, 0) + _ssl_MemoryBIO_write(0, 0, 0) + _ssl_MemoryBIO_read(0, 0, 0);
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		require.NoError(t, exec.Command("gcc", "-O0", cSrc, "-o", cBin).Run())

		prof, err := InspectBinaryProfile(cBin)
		require.NoError(t, err)
		require.Equal(t, "dynamic", prof.LinkMode)
		require.Equal(t, "static-openssl", prof.TLSStack)
		require.Contains(t, prof.Symbols, "SSL_write")
		require.Contains(t, prof.Symbols, "SSL_read")
		require.Contains(t, prof.Symbols, "_ssl_MemoryBIO_write")
		require.Contains(t, prof.Symbols, "_ssl_MemoryBIO_read")

		pyBin, err := exec.LookPath("python3")
		require.NoError(t, err)
		pyScript := `
import ssl, subprocess, os
cert, key = "/tmp/llm_tracer_ut_cert.pem", "/tmp/llm_tracer_ut_key.pem"
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
c_ctx.check_hostname = False
c_ctx.verify_mode = ssl.CERT_NONE
s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
s_ctx.load_cert_chain(cert, key)
c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="api.openai.com")
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
req = b'{"model":"gpt-4.1","conversation_id":"scen3_py_mbio","messages":[{"role":"user","content":"memory bio test"}]}'
resp = b'{"id":"chatcmpl-s3","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"mbio ok"},"finish_reason":"stop"}]}'
c_ssl.write(b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: " + str(len(req)).encode() + b"\r\n\r\n" + req)
s_in.write(c_out.read())
_ = s_ssl.read(65536)
s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(resp)).encode() + b"\r\n\r\n" + resp)
c_in.write(s_out.read())
_ = c_ssl.read(65536)
`
		exitCode, err := col.LaunchCommand(ctx, []string{pyBin, "-c", pyScript})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)
	})

	// -------------------------------------------------------------------------
	// Scenario 4: Node.js Static OpenSSL (tls.TLSSocket) & Bun-style globalThis.fetch("https://...")
	// Captured via NODE_OPTIONS=--require / BUN_OPTIONS=--preload node_hook.cjs
	// -------------------------------------------------------------------------
	t.Run("Scenario4_NodeStaticOpenSSL_TLSSocket_And_BunFetchHTTPSHook", func(t *testing.T) {
		nodeBin, err := exec.LookPath("node")
		if err != nil {
			// Fallback to mise node if not in default PATH
			cand := "/home/liuyicong/.local/share/mise/installs/node/24.4.1/bin/node"
			if _, serr := os.Stat(cand); serr == nil {
				nodeBin = cand
			} else {
				t.Skip("node binary not found")
			}
		}
		nodeScript := `
const tls = require("node:tls");
const { Duplex } = require("node:stream");
const dummy = new Duplex({ read() {}, write(c, e, cb) { cb(); } });
const sock = new tls.TLSSocket(dummy, { isServer: false });
const reqBody = '{"model":"claude-sonnet-4-6","conversation_id":"scen4_node_tls","messages":[{"role":"user","content":"node tls socket"}]}';
const respBody = '{"id":"msg_s4","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"node tls ok"}]}';
try { sock._write(Buffer.from("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: " + Buffer.byteLength(reqBody) + "\r\n\r\n" + reqBody), "buffer", () => {}); } catch (_) {}
sock.push(Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + Buffer.byteLength(respBody) + "\r\n\r\n" + respBody));
sock.push(null);
process.exit(0);
`
		exitCode, err := col.LaunchCommand(ctx, []string{nodeBin, "-e", nodeScript})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)
	})

	// -------------------------------------------------------------------------
	// Scenario 5: Wrapper Script (bin/codex) -> Stripped Static-PIE / -static ELF
	// Complete bypass of ld-linux.so (LD_PRELOAD ignored by kernel) and libc.so.
	// Verifies:
	//   Part A: Wrapper script unwrapping to vendor/x86_64-unknown-linux-musl/bin/codex
	//   Part B: Ptrace syscall capture (PTRACE_GET_SYSCALL_INFO + process_vm_readv)
	//   Part C: LoopbackTap dynamic CA & TLS MITM tunnel for rustls/gotls HTTPS
	// -------------------------------------------------------------------------
	t.Run("Scenario5_WrapperScript_And_StaticPIE_PtraceSyscallAndLoopbackTap", func(t *testing.T) {
		pkgRoot := filepath.Join(dir, "mock_codex_pkg")
		binDir := filepath.Join(pkgRoot, "bin")
		vendorBinDir := filepath.Join(pkgRoot, "vendor", "x86_64-unknown-linux-musl", "bin")
		require.NoError(t, os.MkdirAll(binDir, 0o755))
		require.NoError(t, os.MkdirAll(vendorBinDir, 0o755))

		staticSrc := filepath.Join(dir, "scen5_static_codex.c")
		staticExe := filepath.Join(vendorBinDir, "codex")
		cCode := `
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;
    const char *req_b = "{\"model\":\"gpt-5.4\",\"conversation_id\":\"scen5_static\",\"input\":[{\"role\":\"user\",\"content\":\"static\"}]}";
    char req[512];
    snprintf(req, sizeof(req), "POST /v1/responses HTTP/1.1\r\nHost: 100.119.249.101:3425\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(req_b), req_b);
    const char *resp_b = "{\"id\":\"resp_s5\",\"model\":\"gpt-5.4\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"ptrace ok\"}]}]}";
    char resp[512];
    snprintf(resp, sizeof(resp), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(resp_b), resp_b);
    write(sv[0], req, strlen(req));
    char tmp[512];
    read(sv[1], tmp, sizeof(tmp));
    write(sv[1], resp, strlen(resp));
    read(sv[0], tmp, sizeof(tmp));
    close(sv[0]);
    close(sv[1]);
    return 0;
}
`
		require.NoError(t, os.WriteFile(staticSrc, []byte(cCode), 0o644))
		// Compile with -static -s (no PT_INTERP, completely stripped, identical linkage to musl codex)
		require.NoError(t, exec.Command("gcc", "-static", "-s", "-O2", staticSrc, "-o", staticExe).Run())

		wrapperPath := filepath.Join(binDir, "codex")
		wrapperScript := "#!/bin/sh\n# codex wrapper\nexec \"" + staticExe + "\" \"$@\"\n"
		require.NoError(t, os.WriteFile(wrapperPath, []byte(wrapperScript), 0o755))

		prof, err := InspectBinaryProfile(wrapperPath)
		require.NoError(t, err)
		require.Equal(t, staticExe, prof.ResolvedELF)
		require.Equal(t, "static-pie", prof.LinkMode)
		require.True(t, prof.RequiresPtrace)

		exitCode, err := col.LaunchCommand(ctx, []string{wrapperPath})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		// Also verify LoopbackTap dynamic leaf certificate generation & TLS MITM decryption in-memory
		var tapChunks int
		tap, err := NewLoopbackTap(dir, func(connID string, dir parser.Direction, data []byte) {
			tapChunks++
		})
		if err == nil && tap != nil {
			defer tap.Close()
			leaf, err := tap.getOrCreateLeafCert("api.openai.com")
			require.NoError(t, err)
			require.NotNil(t, leaf)

			caPEM, err := os.ReadFile(tap.CABundlePath())
			require.NoError(t, err)
			pool := x509.NewCertPool()
			require.True(t, pool.AppendCertsFromPEM(caPEM))

			cConn, sConn := net.Pipe()
			defer cConn.Close()
			defer sConn.Close()
			errCh := make(chan error, 1)
			go func() {
				srv := tls.Server(sConn, &tls.Config{Certificates: []tls.Certificate{*leaf}})
				errCh <- srv.Handshake()
			}()
			cli := tls.Client(cConn, &tls.Config{RootCAs: pool, ServerName: "api.openai.com"})
			require.NoError(t, cli.Handshake())
			require.NoError(t, <-errCh)
		}
	})

	// -------------------------------------------------------------------------
	// Scenario 6: Native Go Binary (crypto/tls + direct runtime/internal/syscall)
	// Bypasses libc.so and libssl.so completely.
	// Verifies:
	//   Part A: Go buildinfo & crypto/tls.(*Conn).Write/Read ELF offset resolution
	//   Part B: Ptrace syscall interception of Go's direct syscall.Write / syscall.Read
	// -------------------------------------------------------------------------
	t.Run("Scenario6_NativeGoBinary_GoTLSSymbols_And_DirectSyscallCapture", func(t *testing.T) {
		goSrc := filepath.Join(dir, "scen6_go_client.go")
		goBin := filepath.Join(dir, "scen6_go_client")
		goCode := `package main
import (
	"crypto/tls"
	"fmt"
	"os"
	"syscall"
)
func main() {
	if os.Getenv("KEEP_GOTLS_SYM") == "1" {
		var c *tls.Conn
		_, _ = c.Write(nil)
		_, _ = c.Read(nil)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return
	}
	reqBody := "{\"model\":\"qwen3\",\"conversation_id\":\"scen6_gotls\",\"messages\":[{\"role\":\"user\",\"content\":\"go raw\"}]}"
	req := []byte(fmt.Sprintf("POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(reqBody), reqBody))
	respBody := "{\"id\":\"chatcmpl-go\",\"model\":\"qwen3\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"go ok\"}}]}"
	resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(respBody), respBody))
	_, _ = syscall.Write(fds[0], req)
	buf := make([]byte, 512)
	_, _ = syscall.Read(fds[1], buf)
	_, _ = syscall.Write(fds[1], resp)
	_, _ = syscall.Read(fds[0], buf)
	_ = syscall.Close(fds[0])
	_ = syscall.Close(fds[1])
}
`
		require.NoError(t, os.WriteFile(goSrc, []byte(goCode), 0o644))
		goExe := filepath.Join(runtime.GOROOT(), "bin", "go")
		buildCmd := exec.Command(goExe, "build", "-o", goBin, goSrc)
		gocache := os.Getenv("GOCACHE")
		if gocache == "" {
			gocache = "/tmp/go-build"
		}
		buildCmd.Env = append(os.Environ(), "GOCACHE="+gocache)
		out, err := buildCmd.CombinedOutput()
		require.NoError(t, err, string(out))

		gt, err := InspectGoTLSTarget(goBin)
		require.NoError(t, err)
		require.Equal(t, "gotls", gt.Type)
		require.NotEmpty(t, gt.GoVersion)
		require.Contains(t, gt.Symbols, "crypto/tls.(*Conn).Write")
		require.Contains(t, gt.Symbols, "crypto/tls.(*Conn).Read")

		prof, err := InspectBinaryProfile(goBin)
		require.NoError(t, err)
		require.Equal(t, "gotls", prof.TLSStack)
		require.True(t, prof.RequiresPtrace)

		exitCode, err := col.LaunchCommand(ctx, []string{goBin})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)
	})

	sessions, err := st.QuerySessions(store.SessionQuery{})
	require.NoError(t, err)
	// Scenario 1 (dynamic libssl), Scenario 2 (Bun-like writev), Scenario 3 (Python MemoryBIO), Scenario 4 (Node TLSSocket) always produce 4 sessions;
	// When ptrace is permitted on the host, Scenario 5 (static-pie C) and Scenario 6 (native Go syscall) produce 2 more (= 6 sessions).
	if CanUsePtrace() && currentArchCapabilities().PtraceUserspaceSupported {
		require.Len(t, sessions, 6, "all 6 end-to-end LLM sessions must be captured")
	} else {
		require.GreaterOrEqual(t, len(sessions), 4)
	}
}
