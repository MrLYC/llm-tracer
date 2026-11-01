package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

func TestHelperSleepProcess(t *testing.T) {
	if os.Getenv("LLM_TRACER_TEST_HELPER_SLEEP") != "1" {
		return
	}
	time.Sleep(3 * time.Second)
}

func TestPIDSubtreeVsPIDOnlyAndExeFilter(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)

	myPID := os.Getpid()
	selfExe, err := os.Executable()
	require.NoError(t, err)
	// Spawn a short helper child process so we have a real child PID on Linux, macOS, and Windows
	sleepCmd := exec.Command(selfExe, "-test.run=^TestHelperSleepProcess$")
	sleepCmd.Env = append(os.Environ(), "LLM_TRACER_TEST_HELPER_SLEEP=1")
	require.NoError(t, sleepCmd.Start())
	defer func() {
		_ = sleepCmd.Process.Kill()
		_ = sleepCmd.Wait()
	}()
	childPID := sleepCmd.Process.Pid

	// 1. Default PID mode (PIDOnly = false): parent PID matches both parent AND child PID!
	ptSubtree := NewProcessTracker(model.ScopeFilter{
		PIDs:    []int{myPID},
		PIDOnly: false,
	}, mon)
	_, okSelf := ptSubtree.MatchAndEnrich(myPID, model.ProcessInfo{})
	require.True(t, okSelf)
	_, okChild := ptSubtree.MatchAndEnrich(childPID, model.ProcessInfo{})
	require.True(t, okChild, "child process must be matched by default when --pid is specified without --pid-only")

	// 2. PIDOnly = true: only matches myPID, rejects childPID!
	ptSingle := NewProcessTracker(model.ScopeFilter{
		PIDs:    []int{myPID},
		PIDOnly: true,
	}, mon)
	_, okSelfSingle := ptSingle.MatchAndEnrich(myPID, model.ProcessInfo{})
	require.True(t, okSelfSingle)
	_, okChildSingle := ptSingle.MatchAndEnrich(childPID, model.ProcessInfo{})
	require.False(t, okChildSingle, "child process must be rejected when --pid-only is true")
}

func TestCollectorLaunchCommandAndOpenSSLSymbols(t *testing.T) {
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

	// Note: inside strict sandbox AF_UNIX listen on dir works if path is short
	err = col.Start(ctx)
	require.NoError(t, err)
	defer col.Stop()

	if runtime.GOOS == "linux" {
		probes := col.Probes()
		require.NotEmpty(t, probes)
		require.Contains(t, probes[0].Symbols, "SSL_write")
		require.Contains(t, probes[0].Symbols, "SSL_read")
	}

	selfExe, err := os.Executable()
	require.NoError(t, err)

	// Launch a subprocess via LaunchCommand
	exitCode, err := col.LaunchCommand(ctx, []string{selfExe, "-test.run=^$"})
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	// Launch a real Python 3 OpenSSL TLS 1.3 subprocess if python3/python is available
	pyBin, pyErr := findPythonExecutable()
	if pyErr == nil && pyBin != "" {
		certPath, keyPath := writeSelfSignedCertFiles(t, dir)
		pyScript := `
import ssl, sys
cert, key = sys.argv[1], sys.argv[2]
c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
c_ctx.check_hostname = False
c_ctx.verify_mode = ssl.CERT_NONE
s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
s_ctx.load_cert_chain(cert, key)
c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="api.bamboonode.dev")
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
body = b'{"model":"systemone-mini","state":{"page":{"url":"https://example.com","title":"Example"}},"questions":{"operation":{"type":"choice","instructions":{"goal":"Verify preload hook"},"criteria":{"DONE":"Done"}}}}'
resp = b'{"model":"systemone-mini","answers":{"operation":{"choice":"DONE","probabilities":{"DONE":1.0},"confidence":1.0}}}'
c_ssl.write(b"POST /v1/systemone HTTP/1.1\r\nHost: api.bamboonode.dev\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
s_in.write(c_out.read())
_ = s_ssl.read(65536)
s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(resp)).encode() + b"\r\n\r\n" + resp)
c_in.write(s_out.read())
_ = c_ssl.read(65536)
`
		code, err := col.LaunchCommand(ctx, []string{pyBin, "-c", pyScript, certPath, keyPath})
		require.NoError(t, err)
		require.Equal(t, 0, code)
		sessions, err := st.QuerySessions(store.SessionQuery{})
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		require.Equal(t, "Verify preload hook", sessions[0].Goal)
	}

	stats := mon.Stats()
	require.Greater(t, stats.TotalOK, int64(0))
}

func findPythonExecutable() (string, error) {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil && p != "" {
			// Verify it is real Python 3 (and not Windows Store stub)
			if out, err := exec.Command(p, "-c", "import ssl; print(ssl.OPENSSL_VERSION)").CombinedOutput(); err == nil && len(out) > 0 {
				return p, nil
			}
		}
	}
	return "", exec.ErrNotFound
}

func writeSelfSignedCertFiles(t *testing.T, dir string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost", "api.bamboonode.dev", "api.openai.com", "api.anthropic.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "test_cert.pem")
	keyPath := filepath.Join(dir, "test_key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certPath, keyPath
}
