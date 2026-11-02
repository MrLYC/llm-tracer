package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func TestHelperSleepProcess(t *testing.T) {
	if os.Getenv("LLM_TRACER_TEST_HELPER_SLEEP") != "1" {
		return
	}
	time.Sleep(3 * time.Second)
}

// TestHelperNoop is the target of child processes that only need to start and
// exit 0. Selecting it with -test.run=^TestHelperNoop$ avoids the
// "testing: warning: no tests to run" line that an empty -test.run pattern
// writes onto the parent package's stdout.
func TestHelperNoop(t *testing.T) {
	if f := flag.Lookup("test.run"); f != nil && f.Value.String() == "^TestHelperNoop$" {
		os.Exit(0)
	}
}

func TestPIDSubtreeVsPIDOnlyAndExeFilter(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

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
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
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
	exitCode, err := col.LaunchCommand(ctx, []string{selfExe, "-test.run=^TestHelperNoop$"})
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

func TestCollectorHookPermissionsAndLoopbackTapTLS(t *testing.T) {
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
	col.SetIngestToken("unit-test-ingest-token")
	require.Equal(t, "unit-test-ingest-token", col.IngestToken())
	require.False(t, col.TapInsecure())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	// 1. Verify tls.bin and tls.sock permissions are restricted to 0o600
	if runtime.GOOS != "windows" {
		hooksInfo, err := os.Lstat(filepath.Join(dir, "hooks"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), hooksInfo.Mode().Perm())

		pipeInfo, err := os.Stat(col.pipePath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), pipeInfo.Mode().Perm())
		if col.sockPath != "" {
			sockInfo, err := os.Stat(col.sockPath)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), sockInfo.Mode().Perm())
		}
	}

	// Verify Source registry is populated with the 4 adapters
	sources := col.Sources()
	require.Len(t, sources, 4)
	sourceNames := make([]string, 0, len(sources))
	for _, s := range sources {
		sourceNames = append(sourceNames, s.Name())
	}
	require.ElementsMatch(t, []string{"pipe", "unixsock", "loopback_tap", "ebpf"}, sourceNames)

	// Verify SetIngestToken does not leak LLM_TRACER_INGEST_TOKEN into LaunchAttachPlan.InjectedEnv
	if selfExe, err := os.Executable(); err == nil {
		if plan, _, err := col.PlanLaunchCommand([]string{selfExe, "-test.run=^TestHelperNoop$"}); err == nil && plan != nil {
			require.NotContains(t, plan.InjectedEnv, "LLM_TRACER_INGEST_TOKEN")
		}
	}

	// 2. Verify LoopbackTap upstream TLS verification behavior (loopback vs non-loopback & SetInsecure)
	certPath, keyPath := writeSelfSignedCertFiles(t, dir)
	srvCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)

	tap, tapErr := NewLoopbackTap(dir, nil, WithTapMonitor(mon))
	if tapErr != nil {
		tap = &LoopbackTap{
			mon:     mon,
			certMap: make(map[string]*tls.Certificate),
		}
	} else {
		defer tap.Close()
	}
	require.False(t, tap.Insecure())

	// Verify loopback host detection and IPv6 authority parsing
	require.True(t, isLoopbackHost("127.0.0.1"))
	require.True(t, isLoopbackHost("127.0.0.2:8443"))
	require.True(t, isLoopbackHost("localhost"))
	require.True(t, isLoopbackHost("::1"))
	require.True(t, isLoopbackHost("[::1]:443"))
	require.False(t, isLoopbackHost("127.evil.com"), "127.evil.com must not be treated as loopback")
	require.False(t, isLoopbackHost("127.0.0.1.evil.com"))
	require.False(t, isLoopbackHost("[2001:db8::1]:443"))

	targetHP, hostOnly := parseConnectAuthority("[::1]:443")
	require.Equal(t, "[::1]:443", targetHP)
	require.Equal(t, "::1", hostOnly)
	targetHPNoPort, hostOnlyNoPort := parseConnectAuthority("[::1]")
	require.Equal(t, "[::1]:443", targetHPNoPort)
	require.Equal(t, "::1", hostOnlyNoPort)
	require.Equal(t, "::1", tap.upstreamTLSConfig("[::1]:443").ServerName)
	require.True(t, tap.upstreamTLSConfig("[::1]:443").InsecureSkipVerify)
	require.False(t, tap.upstreamTLSConfig("127.evil.com").InsecureSkipVerify)

	handshakeViaPipe := func(hostOnly string) error {
		cConn, sConn := net.Pipe()
		defer cConn.Close()
		defer sConn.Close()
		srvDone := make(chan struct{})
		go func() {
			defer close(srvDone)
			srv := tls.Server(sConn, &tls.Config{
				Certificates: []tls.Certificate{srvCert},
				MaxVersion:   tls.VersionTLS12,
			})
			_ = srv.Handshake()
			_, _ = io.Copy(io.Discard, sConn)
		}()
		cli := tls.Client(cConn, tap.upstreamTLSConfig(hostOnly))
		err := cli.Handshake()
		_ = cConn.Close()
		_ = sConn.Close()
		<-srvDone
		return err
	}

	// Loopback host (127.0.0.1) is allowed to skip verification for local self-signed test servers
	require.NoError(t, handshakeViaPipe("127.0.0.1"))
	require.NoError(t, handshakeViaPipe("localhost"))
	require.NoError(t, handshakeViaPipe("[::1]:443"))

	// Non-loopback hosts (api.openai.com and 127.evil.com) must fail verification against self-signed cert by default
	require.Error(t, handshakeViaPipe("api.openai.com"), "non-loopback upstream with untrusted cert must fail when insecure is false")
	require.Error(t, handshakeViaPipe("127.evil.com"), "127.evil.com with untrusted cert must fail when insecure is false")

	// Enabling insecure mode allows non-loopback self-signed upstream
	tap.SetInsecure(true)
	require.True(t, tap.Insecure())
	require.NoError(t, handshakeViaPipe("api.openai.com"))
	require.NoError(t, handshakeViaPipe("127.evil.com"))

	// If TCP loopback sockets are permitted in the current environment, also verify dialUpstreamTLS on 127.0.0.1:0
	if rawLn, lnErr := net.Listen("tcp", "127.0.0.1:0"); lnErr == nil {
		tlsLn := tls.NewListener(rawLn, &tls.Config{Certificates: []tls.Certificate{srvCert}})
		defer tlsLn.Close()
		go func() {
			for {
				c, err := tlsLn.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					if tc, ok := conn.(*tls.Conn); ok {
						_ = tc.Handshake()
					}
				}(c)
			}
		}()
		srvAddr := rawLn.Addr().String()
		tap.SetInsecure(false)
		connLoop, err := tap.dialUpstreamTLS(srvAddr, "127.0.0.1")
		require.NoError(t, err)
		_ = connLoop.Close()
		warnBefore := mon.Stats().TotalWarn
		_, err = tap.dialUpstreamTLS(srvAddr, "api.openai.com")
		require.Error(t, err)
		require.Greater(t, mon.Stats().TotalWarn, warnBefore, "upstream TLS verification failure must record selfmon warning")
		_, err = tap.dialUpstreamTLS(srvAddr, "127.evil.com")
		require.Error(t, err)
		tap.SetInsecure(true)
		connInsec, err := tap.dialUpstreamTLS(srvAddr, "api.openai.com")
		require.NoError(t, err)
		_ = connInsec.Close()
	}
	tap.recordUpstreamTLSFailure("127.evil.com:443", "127.evil.com", io.ErrUnexpectedEOF)
	warnEvents, qErr := mon.QueryEvents(selfmon.Query{Status: selfmon.StatusWarn, Stage: selfmon.StageProbe, Limit: 10})
	require.NoError(t, qErr)
	require.NotEmpty(t, warnEvents)
	require.Contains(t, warnEvents[0].Error, "--tap-insecure")

	// 3. Verify O_NOFOLLOW symlink protection and cross-UID chown / permission reclamation
	if runtime.GOOS != "windows" {
		victimFile := filepath.Join(dir, "victim.txt")
		require.NoError(t, os.WriteFile(victimFile, []byte("keep-intact"), 0o600))
		symlinkPipe := filepath.Join(dir, "symlink_tls.bin")
		require.NoError(t, os.Symlink(victimFile, symlinkPipe))

		require.Error(t, initPipeFileNoFollow(symlinkPipe, 0o600, -1), "initPipeFileNoFollow must reject symlink")
		require.Error(t, applyPipePermissionsNoFollow(symlinkPipe, 0o666, -1), "applyPipePermissionsNoFollow must reject symlink")
		victimData, err := os.ReadFile(victimFile)
		require.NoError(t, err)
		require.Equal(t, "keep-intact", string(victimData), "symlink target must not be truncated")
		victimStat, err := os.Stat(victimFile)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), victimStat.Mode().Perm(), "symlink target permissions must not be modified")

		// Simulate cross-UID target matched via process selector and verify chown preference + reclamation
		selfExe, err := os.Executable()
		require.NoError(t, err)
		sleepCmd := exec.Command(selfExe, "-test.run=^TestHelperSleepProcess$")
		sleepCmd.Env = append(os.Environ(), "LLM_TRACER_TEST_HELPER_SLEEP=1")
		require.NoError(t, sleepCmd.Start())
		defer func() {
			_ = sleepCmd.Process.Kill()
			_ = sleepCmd.Wait()
		}()
		targetPID := sleepCmd.Process.Pid
		require.Eventually(t, func() bool {
			info := InspectProcess(targetPID)
			return strings.Contains(info.Cmdline, "TestHelperSleepProcess") || strings.Contains(info.Comm, "TestHelperSleepProcess")
		}, 2*time.Second, 10*time.Millisecond, "sleepCmd must be visible in process table with Cmdline")

		origLookupUID := lookupProcessUID
		origGetEUID := getEffectiveUID
		origChownFile := chownFileFunc
		origLchownSock := lchownSocketFunc
		defer func() {
			lookupProcessUID = origLookupUID
			getEffectiveUID = origGetEUID
			chownFileFunc = origChownFile
			lchownSocketFunc = origLchownSock
		}()

		getEffectiveUID = func() int { return 1000 }
		crossUIDActive := true
		lookupProcessUID = func(pid int) (int, bool) {
			if pid == targetPID && crossUIDActive {
				return 2002, true
			}
			return 1000, true
		}

		// 3a. When chown succeeds, prefer chown to target UID (2002) and keep mode 0o600
		col.permMu.Lock()
		col.channelRelaxed = false
		col.channelTargetUID = -1
		col.permMu.Unlock()

		var chownedUIDs []int
		var chownMu sync.Mutex
		chownFileFunc = func(_ *os.File, _ string, uid int) error {
			chownMu.Lock()
			chownedUIDs = append(chownedUIDs, uid)
			chownMu.Unlock()
			return nil
		}
		lchownSocketFunc = func(_ string, uid int) error {
			return nil
		}
		require.Eventually(t, func() bool {
			col.UpdateScope(model.ScopeFilter{Cmds: []string{"TestHelperSleepProcess"}})
			chownMu.Lock()
			defer chownMu.Unlock()
			for _, u := range chownedUIDs {
				if u == 2002 {
					return true
				}
			}
			return false
		}, 10*time.Second, 50*time.Millisecond, "cross-UID target matched by --cmd must trigger chown to target UID")
		pipeInfo, err := os.Stat(col.pipePath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), pipeInfo.Mode().Perm(), "mode must stay 0600 when chown to target UID succeeds")

		// 3b. When target disappears, reclaim ownership to selfUID (1000) and restore hooksDir to 0o700
		crossUIDActive = false
		col.ensureHookChannelPermissions(nil)
		chownMu.Lock()
		lastUID := chownedUIDs[len(chownedUIDs)-1]
		chownMu.Unlock()
		require.Equal(t, 1000, lastUID, "disappearing cross-UID target must reclaim ownership to selfUID")
		hooksInfo, err := os.Lstat(filepath.Join(dir, "hooks"))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o700), hooksInfo.Mode().Perm())

		// 3c. When chown is not permitted (e.g. non-root), refuse world-readable 0o666 and keep mode 0o600
		col.Stop()
		require.NoError(t, initPipeFileNoFollow(col.pipePath, 0o600, -1))
		crossUIDActive = true
		chownFileFunc = func(_ *os.File, _ string, _ int) error {
			return os.ErrPermission
		}
		lchownSocketFunc = func(_ string, _ int) error {
			return os.ErrPermission
		}
		col.ensureHookChannelPermissions(nil)
		pipeInfo, err = os.Stat(col.pipePath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), pipeInfo.Mode().Perm())

		crossUIDActive = false
		col.ensureHookChannelPermissions(nil)
		pipeInfo, err = os.Stat(col.pipePath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), pipeInfo.Mode().Perm(), "relaxed 0666 mode must be reclaimed to 0600 when target disappears")
	}
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
		DNSNames:     []string{"localhost", "api.bamboonode.dev", "api.openai.com", "api.anthropic.com", "127.evil.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
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
