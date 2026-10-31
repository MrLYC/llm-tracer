package collector

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func TestPIDSubtreeVsPIDOnlyAndExeFilter(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)

	myPID := os.Getpid()
	// Spawn a short sleep child process so we have a real child PID in /proc
	sleepCmd := exec.Command("sleep", "2")
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

	// Verify OpenSSL probe targets were discovered
	probes := col.Probes()
	require.NotEmpty(t, probes)
	require.Contains(t, probes[0].Symbols, "SSL_write")
	require.Contains(t, probes[0].Symbols, "SSL_read")

		// Launch a subprocess via LaunchCommand
		exitCode, err := col.LaunchCommand(ctx, []string{"sh", "-c", "exit 0"})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		// Launch a real Python 3 OpenSSL TLS 1.3 subprocess if /usr/bin/python3 is available
		if _, err := os.Stat("/usr/bin/python3"); err == nil {
			pyScript := `
import ssl, json, subprocess, os
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
			code, err := col.LaunchCommand(ctx, []string{"/usr/bin/python3", "-c", pyScript})
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
