package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/collector"
	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/mrlyc/llm-tracer/internal/totp"
	"github.com/stretchr/testify/require"
)

// startupWaitTimeout bounds how long a test waits for a server goroutine to
// reach its listener. It only guards the harness; the real shutdown-latency
// assertions stay at 500ms. -race slows startup well past 3s.
const startupWaitTimeout = 30 * time.Second

func TestHelperExitCode(t *testing.T) {
	if os.Getenv("LLM_TRACER_TEST_RUN_MAIN") == "1" {
		rawArgs := os.Getenv("LLM_TRACER_TEST_MAIN_ARGS")
		os.Args = append([]string{os.Args[0]}, strings.Split(rawArgs, "\n")...)
		main()
		return
	}
	codeStr := os.Getenv("LLM_TRACER_TEST_EXIT_CODE")
	if codeStr == "" {
		return
	}
	code, _ := strconv.Atoi(codeStr)
	os.Exit(code)
}

// TestHelperNoop is the target of child processes that only need to start and
// exit 0. Selecting it with -test.run=^TestHelperNoop$ avoids the
// "testing: warning: no tests to run" line that an empty -test.run pattern
// writes onto the parent package's stdout.
func TestHelperNoop(t *testing.T) {
	if isHelperNoopInvocation() {
		os.Exit(0)
	}
}

// isHelperNoopInvocation reports whether this binary was started solely to run
// TestHelperNoop, as opposed to running the full suite.
func isHelperNoopInvocation() bool {
	f := flag.Lookup("test.run")
	return f != nil && f.Value.String() == "^TestHelperNoop$"
}

func TestParseDurationWithDaysAndCLI(t *testing.T) {
	d, err := parseDurationWithDays("7d")
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, d)

	d2, err := parseDurationWithDays("10m")
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, d2)

	selfExe, err := os.Executable()
	require.NoError(t, err)

	dir := t.TempDir()
	stdoutStr, stderrStr, err := executeCapturingStdio(t, func() error {
		cmd := newRootCmd()
		cmd.SetArgs([]string{"capture", "-d", dir, "-l", "off", "--exit-with-child", "--", selfExe, "-test.run=^TestHelperNoop$"})
		return cmd.Execute()
	})
	require.NoError(t, err)
	require.Contains(t, stdoutStr, "Web UI 已禁用")
	require.NotContains(t, stdoutStr, "http://")
	require.NotContains(t, stderrStr, "http://")

	// Verify a single capture produces exactly 1 plan_launch_command selfmon event
	selfmonEvents := readSelfmonEventsFromDir(t, filepath.Join(dir, "selfmon"))
	planLaunchCount := 0
	for _, ev := range selfmonEvents {
		if ev.Action == "plan_launch_command" {
			planLaunchCount++
		}
	}
	require.Equal(t, 1, planLaunchCount, "capture must emit exactly 1 plan_launch_command selfmon event")

	statusCmd := newRootCmd()
	statusCmd.SetArgs([]string{"status", "-d", dir})
	require.NoError(t, statusCmd.Execute())

	cleanCmd := newRootCmd()
	cleanCmd.SetArgs([]string{"clean", "-d", dir, "--all", "--dry-run"})
	require.NoError(t, cleanCmd.Execute())

	// Verify --version flag and version subcommand produce identical output
	var verFlagOut, verSubOut bytes.Buffer
	verFlagCmd := newRootCmd()
	verFlagCmd.SetOut(&verFlagOut)
	verFlagCmd.SetArgs([]string{"--version"})
	require.NoError(t, verFlagCmd.Execute())

	verSubCmd := newRootCmd()
	verSubCmd.SetOut(&verSubOut)
	verSubCmd.SetArgs([]string{"version"})
	require.NoError(t, verSubCmd.Execute())
	require.Equal(t, verFlagOut.String(), verSubOut.String())
	require.Equal(t, "llm-tracer version dev\n", verSubOut.String())

	// Verify child non-zero exit code returns exitCodeError and still executes col.Stop() cleanup
	dirExit := t.TempDir()
	t.Setenv("LLM_TRACER_TEST_EXIT_CODE", "42")
	exitCmd := newRootCmd()
	exitCmd.SetArgs([]string{"capture", "-d", dirExit, "-l", "off", "--tap-insecure", "--capture-unknown", "--exit-with-child", "--", selfExe, "-test.run=^TestHelperExitCode$"})
	err = exitCmd.Execute()
	require.Error(t, err)
	var exitErr *exitCodeError
	require.True(t, errors.As(err, &exitErr))
	require.Equal(t, 42, exitErr.code)
	_, statErr := os.Stat(filepath.Join(dirExit, "hooks", "tls.sock"))
	require.True(t, os.IsNotExist(statErr), "tls.sock must be cleaned up by col.Stop() even when child exits with non-zero code")

	// Verify selfmon async batch writer was flushed and closed before exitCodeError returned
	entries, readErr := os.ReadDir(filepath.Join(dirExit, "selfmon"))
	require.NoError(t, readErr)
	var totalSelfmonBytes int64
	for _, ent := range entries {
		if filepath.Ext(ent.Name()) == ".jsonl" {
			fi, err := ent.Info()
			require.NoError(t, err)
			totalSelfmonBytes += fi.Size()
		}
	}
	require.Greater(t, totalSelfmonBytes, int64(0), "selfmon events must be flushed to disk on exitCodeError return")
}

func TestListenLoopbackWarningAndVersionFormatting(t *testing.T) {
	require.True(t, isLoopbackListenAddr("127.0.0.1:8787"))
	require.True(t, isLoopbackListenAddr("localhost:8787"))
	require.True(t, isLoopbackListenAddr("[::1]:8787"))
	require.True(t, isLoopbackListenAddr("off"))
	require.True(t, isLoopbackListenAddr("none"))
	require.False(t, isLoopbackListenAddr("0.0.0.0:8787"))
	require.False(t, isLoopbackListenAddr(":8787"))
	require.False(t, isLoopbackListenAddr("192.168.1.10:8787"))

	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	noTOTPGuard, err := totp.NewGuard("")
	require.NoError(t, err)

	// Loopback without TOTP -> no warning
	warnIfNonLoopbackWithoutTOTP("127.0.0.1:8787", noTOTPGuard, mon)
	require.Equal(t, int64(0), mon.Stats().TotalWarn)

	// Non-loopback with TOTP -> no warning
	sec, err := totp.GenerateSecret()
	require.NoError(t, err)
	totpGuard, err := totp.NewGuard(sec)
	require.NoError(t, err)
	warnIfNonLoopbackWithoutTOTP("0.0.0.0:8787", totpGuard, mon)
	require.Equal(t, int64(0), mon.Stats().TotalWarn)

	// Non-loopback without TOTP -> selfmon warn recorded
	warnIfNonLoopbackWithoutTOTP("0.0.0.0:8787", noTOTPGuard, mon)
	require.Equal(t, int64(1), mon.Stats().TotalWarn)
	require.NoError(t, mon.Close())

	// Verify formatVersion with and without commit/date injection
	origVer, origCommit, origDate := version, commit, date
	t.Cleanup(func() {
		version, commit, date = origVer, origCommit, origDate
	})
	version, commit, date = "v0.2.0", "none", "unknown"
	require.Equal(t, "llm-tracer version v0.2.0", formatVersion())
	version, commit, date = "v0.2.0", "", ""
	require.Equal(t, "llm-tracer version v0.2.0", formatVersion())
	version, commit, date = "v0.2.0", "abc1234", ""
	require.Equal(t, "llm-tracer version v0.2.0 (abc1234)", formatVersion())
	version, commit, date = "v0.2.0", "none", "2026-11-02T00:00:00Z"
	require.Equal(t, "llm-tracer version v0.2.0 (2026-11-02T00:00:00Z)", formatVersion())
	version, commit, date = "v0.2.0", "abc1234", "2026-11-02T00:00:00Z"
	require.Equal(t, "llm-tracer version v0.2.0 (abc1234, 2026-11-02T00:00:00Z)", formatVersion())

	var flagBuf, subBuf bytes.Buffer
	c1 := newRootCmd()
	c1.SetOut(&flagBuf)
	c1.SetArgs([]string{"--version"})
	require.NoError(t, c1.Execute())
	c2 := newRootCmd()
	c2.SetOut(&subBuf)
	c2.SetArgs([]string{"version"})
	require.NoError(t, c2.Execute())
	require.Equal(t, "llm-tracer version v0.2.0 (abc1234, 2026-11-02T00:00:00Z)\n", flagBuf.String())
	require.Equal(t, flagBuf.String(), subBuf.String())
}

func TestListenFailureAndOccupiedPort(t *testing.T) {
	selfExe, err := os.Executable()
	require.NoError(t, err)

	t.Run("listen_failure_exits_nonzero_with_stderr", func(t *testing.T) {
		dir := t.TempDir()
		badAddr := "127.0.0.1:99999"
		stdoutStr, stderrStr, execErr := executeCapturingStdio(t, func() error {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"capture", "-d", dir, "-l", badAddr, "--exit-with-child", "--", selfExe, "-test.run=^TestHelperNoop$"})
			return cmd.Execute()
		})
		require.Error(t, execErr)
		var exitErr *exitCodeError
		require.True(t, errors.As(execErr, &exitErr), "listen failure must return *exitCodeError")
		require.NotEqual(t, 0, exitErr.code)
		require.Contains(t, stderrStr, badAddr)
		require.Contains(t, stderrStr, "invalid port")
		require.NotContains(t, stdoutStr, "http://")
		_, statErr := os.Stat(filepath.Join(dir, "hooks", "tls.sock"))
		require.True(t, os.IsNotExist(statErr), "tls.sock must be cleaned up when listen fails")
	})

	t.Run("occupied_port_exits_nonzero_with_stderr", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Skipf("skipping occupied-port test when net.Listen is unavailable in sandbox: %v", err)
		}
		defer ln.Close()
		occupiedAddr := ln.Addr().String()

		dir := t.TempDir()
		subCmd := exec.Command(selfExe, "-test.run=^TestHelperExitCode$")
		subCmd.Env = append(os.Environ(),
			"LLM_TRACER_TEST_RUN_MAIN=1",
			"LLM_TRACER_TEST_MAIN_ARGS="+strings.Join([]string{
				"capture", "-d", dir, "-l", occupiedAddr, "--exit-with-child", "--", selfExe, "-test.run=^TestHelperNoop$",
			}, "\n"),
		)
		var outBuf, errBuf bytes.Buffer
		subCmd.Stdout = &outBuf
		subCmd.Stderr = &errBuf
		runErr := subCmd.Run()
		require.Error(t, runErr, "process must exit with non-zero code when port is already in use")
		var ee *exec.ExitError
		require.True(t, errors.As(runErr, &ee))
		require.NotEqual(t, 0, ee.ExitCode())
		require.Contains(t, errBuf.String(), occupiedAddr)
		require.NotEmpty(t, strings.TrimSpace(errBuf.String()))
		require.NotContains(t, outBuf.String(), "http://"+occupiedAddr)
	})
}

func TestApplyCaptureUnknownAndProbeDeduplication(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	require.False(t, col.CaptureUnknown())
	require.True(t, applyCaptureUnknown(col, true))
	require.True(t, col.CaptureUnknown())
	require.True(t, applyCaptureUnknown(col, false))
	require.False(t, col.CaptureUnknown())

	selfExe, err := os.Executable()
	require.NoError(t, err)
	col.AttachBinaryTargets(selfExe)
	col.AttachBinaryTargets(selfExe)

	plan, env, err := col.PlanLaunchCommand([]string{selfExe, "-test.run=^TestHelperNoop$"})
	require.NoError(t, err)
	require.NotNil(t, plan)
	exitCode, err := col.LaunchPlannedCommand(t.Context(), plan, env)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	probes := col.Probes()
	seen := make(map[string]bool, len(probes))
	for _, p := range probes {
		key := p.BinaryPath + "|" + p.Type
		require.False(t, seen[key], "duplicate probe target found: %s", key)
		seen[key] = true
	}
}

func executeCapturingStdio(t *testing.T, fn func() error) (string, string, error) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	require.NoError(t, err)
	errR, errW, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = outW
	os.Stderr = errW
	defer func() {
		os.Stdout = origOut
		os.Stderr = origErr
	}()

	var outBuf, errBuf bytes.Buffer
	outDone := make(chan struct{})
	errDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&outBuf, outR)
		close(outDone)
	}()
	go func() {
		_, _ = io.Copy(&errBuf, errR)
		close(errDone)
	}()

	runErr := fn()
	_ = outW.Close()
	_ = errW.Close()
	<-outDone
	<-errDone
	_ = outR.Close()
	_ = errR.Close()
	return outBuf.String(), errBuf.String(), runErr
}

func readSelfmonEventsFromDir(t *testing.T, selfmonDir string) []selfmon.Event {
	t.Helper()
	entries, err := os.ReadDir(selfmonDir)
	require.NoError(t, err)
	var events []selfmon.Event
	for _, ent := range entries {
		if ent.IsDir() || filepath.Ext(ent.Name()) != ".jsonl" {
			continue
		}
		f, err := os.Open(filepath.Join(selfmonDir, ent.Name()))
		require.NoError(t, err)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var ev selfmon.Event
			require.NoError(t, json.Unmarshal(sc.Bytes(), &ev))
			events = append(events, ev)
		}
		require.NoError(t, sc.Err())
		_ = f.Close()
	}
	return events
}

func populateTestCacheForClean(t *testing.T, dir string, now time.Time) (sessFile string, oldSelfmonFile string) {
	t.Helper()
	day := now.UTC().Format("2006-01-02")
	sessDir := filepath.Join(dir, "sessions", day, "s_clean_1")
	require.NoError(t, os.MkdirAll(sessDir, 0o700))

	summary := model.SessionSummary{
		ID:         "s_clean_1",
		Title:      "clean test session",
		CreatedAt:  now.Add(-2 * time.Hour).UnixMilli(),
		UpdatedAt:  now.Add(-2 * time.Hour).UnixMilli(),
		EventCount: 1,
	}
	sumBytes, err := json.Marshal(summary)
	require.NoError(t, err)
	sessFile = filepath.Join(sessDir, "session.json")
	require.NoError(t, os.WriteFile(sessFile, sumBytes, 0o600))

	ev := model.TraceEvent{
		ID:        "ev_clean_1",
		SessionID: "s_clean_1",
		Timestamp: summary.UpdatedAt,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
	}
	evBytes, err := json.Marshal(ev)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "events.jsonl"), append(evBytes, '\n'), 0o600))

	selfmonDir := filepath.Join(dir, "selfmon")
	require.NoError(t, os.MkdirAll(selfmonDir, 0o755))
	oldSelfmonFile = filepath.Join(selfmonDir, "2020-01-01.jsonl")
	require.NoError(t, os.WriteFile(oldSelfmonFile, []byte(`{"id":"sm_old","ts":1577836800000,"status":"ok","stage":"store","action":"init"}`+"\n"), 0o600))
	oldTime := now.Add(-48 * time.Hour)
	require.NoError(t, os.Chtimes(oldSelfmonFile, oldTime, oldTime))

	hooksDir := filepath.Join(dir, "hooks")
	require.NoError(t, os.MkdirAll(hooksDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(hooksDir, "tls.bin"), []byte("hook-pipe-leftover"), 0o600))
	return sessFile, oldSelfmonFile
}

func TestCleanSubcommandConfirmationAndExitCodes(t *testing.T) {
	selfExe, err := os.Executable()
	require.NoError(t, err)
	now := time.Now()

	cases := []struct {
		name                 string
		args                 func(dir string) []string
		stdin                string
		wantErr              bool
		wantExitNonZero      bool
		wantOutSubstrings    []string
		wantErrSubstrings    []string
		expectSessionDeleted bool
		expectSelfmonDeleted bool
	}{
		{
			name: "all_without_yes_stdin_n_cancels_and_exits_0",
			args: func(dir string) []string {
				return []string{"clean", "-d", dir, "--all"}
			},
			stdin:                "n\n",
			wantErr:              false,
			wantOutSubstrings:    []string{"确认要清空", "输入 yes 继续:", "已取消"},
			expectSessionDeleted: false,
			expectSelfmonDeleted: false,
		},
		{
			name: "all_without_yes_stdin_yes_deletes",
			args: func(dir string) []string {
				return []string{"clean", "-d", dir, "--all"}
			},
			stdin:                "yes\n",
			wantErr:              false,
			wantOutSubstrings:    []string{"确认要清空", "[已清理] 删除会话: 1 个"},
			expectSessionDeleted: true,
			expectSelfmonDeleted: false,
		},
		{
			name: "all_with_short_y_skips_prompt_and_deletes",
			args: func(dir string) []string {
				return []string{"clean", "-d", dir, "--all", "-y"}
			},
			stdin:                "",
			wantErr:              false,
			wantOutSubstrings:    []string{"[已清理] 删除会话: 1 个"},
			expectSessionDeleted: true,
			expectSelfmonDeleted: false,
		},
		{
			name: "neither_all_nor_older_than_returns_error_and_nonzero_exit",
			args: func(dir string) []string {
				return []string{"clean", "-d", dir}
			},
			stdin:                "",
			wantErr:              true,
			wantExitNonZero:      true,
			wantErrSubstrings:    []string{"请指定 --older-than", "--all"},
			expectSessionDeleted: false,
			expectSelfmonDeleted: false,
		},
		{
			name: "dry_run_previews_without_deleting_files",
			args: func(dir string) []string {
				return []string{"clean", "-d", dir, "--all", "--dry-run"}
			},
			stdin:                "",
			wantErr:              false,
			wantOutSubstrings:    []string{"[Dry-Run 预览] 删除会话: 1 个"},
			expectSessionDeleted: false,
			expectSelfmonDeleted: false,
		},
		{
			name: "include_selfmon_cleans_selfmon_jsonl_files",
			args: func(dir string) []string {
				return []string{"clean", "-d", dir, "--all", "-y", "--include-selfmon"}
			},
			stdin:                "",
			wantErr:              false,
			wantOutSubstrings:    []string{"[已清理] 删除会话: 1 个"},
			expectSessionDeleted: true,
			expectSelfmonDeleted: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sessFile, oldSelfmonFile := populateTestCacheForClean(t, dir, now)

			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetIn(strings.NewReader(tc.stdin))
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs(tc.args(dir))

			execErr := cmd.Execute()
			if tc.wantErr {
				require.Error(t, execErr)
				for _, sub := range tc.wantErrSubstrings {
					require.Contains(t, execErr.Error(), sub)
				}
			} else {
				require.NoError(t, execErr)
			}

			for _, sub := range tc.wantOutSubstrings {
				require.Contains(t, outBuf.String(), sub)
			}

			_, sessStatErr := os.Stat(sessFile)
			_, tlsBinStatErr := os.Stat(filepath.Join(dir, "hooks", "tls.bin"))
			if tc.expectSessionDeleted {
				require.True(t, os.IsNotExist(sessStatErr), "session.json should be deleted")
				require.True(t, os.IsNotExist(tlsBinStatErr), "hooks/tls.bin should be deleted on clean --all")
				sessEntries, readErr := os.ReadDir(filepath.Join(dir, "sessions"))
				require.NoError(t, readErr)
				require.Empty(t, sessEntries, "empty date directory under sessions/ should be removed")
			} else {
				require.NoError(t, sessStatErr, "session.json should remain intact")
				require.NoError(t, tlsBinStatErr, "hooks/tls.bin should remain intact when not deleted")
			}

			_, selfmonStatErr := os.Stat(oldSelfmonFile)
			if tc.expectSelfmonDeleted {
				require.True(t, os.IsNotExist(selfmonStatErr), "selfmon/*.jsonl should be deleted when --include-selfmon is set")
				smEntries, readErr := os.ReadDir(filepath.Join(dir, "selfmon"))
				require.NoError(t, readErr)
				for _, ent := range smEntries {
					require.NotEqual(t, ".jsonl", filepath.Ext(ent.Name()), "no .jsonl files should remain in selfmon/")
				}
			} else {
				require.NoError(t, selfmonStatErr, "selfmon/*.jsonl should remain when --include-selfmon is false")
			}

			// Also verify real subprocess exit code for cancellation (exit 0) and missing flags (exit != 0)
			if tc.wantExitNonZero || tc.stdin == "n\n" {
				subDir := t.TempDir()
				populateTestCacheForClean(t, subDir, now)
				subCmd := exec.Command(selfExe, "-test.run=^TestHelperExitCode$")
				subCmd.Env = append(os.Environ(),
					"LLM_TRACER_TEST_RUN_MAIN=1",
					"LLM_TRACER_TEST_MAIN_ARGS="+strings.Join(tc.args(subDir), "\n"),
				)
				subCmd.Stdin = strings.NewReader(tc.stdin)
				var subOut, subErr bytes.Buffer
				subCmd.Stdout = &subOut
				subCmd.Stderr = &subErr
				runErr := subCmd.Run()
				if tc.wantExitNonZero {
					require.Error(t, runErr)
					var ee *exec.ExitError
					require.True(t, errors.As(runErr, &ee))
					require.NotEqual(t, 0, ee.ExitCode())
				} else {
					require.NoError(t, runErr, "cancelled clean must exit with code 0")
					require.Contains(t, subOut.String(), "已取消")
				}
			}
		})
	}
}

type pipeListener struct {
	mu     sync.Mutex
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

func newPipeListener(addrStr string) *pipeListener {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addrStr)
	if err != nil {
		tcpAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8787}
	}
	return &pipeListener{
		ch:     make(chan net.Conn),
		closed: make(chan struct{}),
		addr:   tcpAddr,
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return l.addr
}

func (l *pipeListener) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
	}
	c1, c2 := net.Pipe()
	select {
	case l.ch <- c1:
		return c2, nil
	case <-l.closed:
		_ = c1.Close()
		_ = c2.Close()
		return nil, net.ErrClosed
	case <-ctx.Done():
		_ = c1.Close()
		_ = c2.Close()
		return nil, ctx.Err()
	}
}

func snapshotDirContents(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		require.NoError(t, walkErr)
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		info, err := os.Lstat(path)
		require.NoError(t, err)
		perm := fmt.Sprintf("%04o %d", info.Mode().Perm(), info.Size())
		if rel == "." {
			snap["."] = perm + " <ROOT>"
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, lerr := os.Readlink(path)
			require.NoError(t, lerr)
			snap[rel] = perm + " <SYMLINK:" + target + ">"
			return nil
		}
		if d.IsDir() {
			snap[rel] = perm + " <DIR>"
			return nil
		}
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		snap[rel] = perm + " " + string(data)
		return nil
	})
	require.NoError(t, err)
	return snap
}

func populateViewFixtureDir(t *testing.T, dir string) int64 {
	t.Helper()
	nowMs := time.Now().Add(-1 * time.Minute).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessDir := filepath.Join(dir, "sessions", day, "s_view_1")
	require.NoError(t, os.MkdirAll(sessDir, 0o700))

	summary := model.SessionSummary{
		ID:         "s_view_1",
		Title:      "offline view session",
		CreatedAt:  nowMs,
		UpdatedAt:  nowMs,
		EventCount: 1,
		TurnCount:  1,
		Protocols:  []string{string(model.ProtocolOpenAIChat)},
		Models:     []string{"gpt-4o"},
	}
	sumBytes, err := json.MarshalIndent(summary, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "session.json"), sumBytes, 0o600))

	ev := model.TraceEvent{
		ID:        "ev_view_1",
		SessionID: "s_view_1",
		TurnIndex: 1,
		Timestamp: nowMs,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "view test prompt"}},
			ResponseText: "view test answer",
		},
	}
	evBytes, err := json.Marshal(ev)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "events.jsonl"), append(evBytes, '\n'), 0o600))
	return nowMs
}

func TestViewSubcommand(t *testing.T) {
	t.Run("real_tcp_listen_when_available", func(t *testing.T) {
		probeLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Skipf("skipping real TCP view test when net.Listen is unavailable in sandbox: %v", err)
		}
		addr := probeLn.Addr().String()
		_ = probeLn.Close()

		dir := t.TempDir()
		populateViewFixtureDir(t, dir)
		beforeSnap := snapshotDirContents(t, dir)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs([]string{"view", dir, "-l", addr, "-w", "30m"})
			errCh <- cmd.ExecuteContext(ctx)
		}()

		var resp *http.Response
		for i := 0; i < 30; i++ {
			resp, err = http.Get("http://" + addr + "/api/sessions")
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var payload struct {
			Sessions []model.SessionSummary `json:"sessions"`
			WindowMs int64                  `json:"window_ms"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
		require.Equal(t, int64((30 * time.Minute).Milliseconds()), payload.WindowMs)
		require.Len(t, payload.Sessions, 1)
		require.Equal(t, "s_view_1", payload.Sessions[0].ID)

		cancel()
		require.NoError(t, <-errCh)

		afterSnap := snapshotDirContents(t, dir)
		require.Equal(t, beforeSnap, afterSnap, "view must be read-only and not write any new files to cacheDir")
	})

	t.Run("readonly_snapshot_default_and_custom_window_and_http_serving", func(t *testing.T) {
		dir := t.TempDir()
		populateViewFixtureDir(t, dir)
		beforeSnap := snapshotDirContents(t, dir)

		origListen := listenViewTCP
		t.Cleanup(func() { listenViewTCP = origListen })

		for _, tc := range []struct {
			name         string
			extraArgs    []string
			wantWindowMs int64
		}{
			{
				name:         "default_window_10m",
				extraArgs:    nil,
				wantWindowMs: int64((10 * time.Minute).Milliseconds()),
			},
			{
				name:         "custom_short_flag_w_45m",
				extraArgs:    []string{"-w", "45m"},
				wantWindowMs: int64((45 * time.Minute).Milliseconds()),
			},
			{
				name:         "custom_short_flag_w_1h",
				extraArgs:    []string{"-w", "1h"},
				wantWindowMs: int64(time.Hour.Milliseconds()),
			},
			{
				name:         "custom_long_flag_window_2d",
				extraArgs:    []string{"--window", "2d"},
				wantWindowMs: int64((48 * time.Hour).Milliseconds()),
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var pipeLn *pipeListener
				listenReady := make(chan *pipeListener, 1)
				listenViewTCP = func(_, address string) (net.Listener, error) {
					pipeLn = newPipeListener(address)
					listenReady <- pipeLn
					return pipeLn, nil
				}

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				var outBuf, errBuf bytes.Buffer
				errCh := make(chan error, 1)
				go func() {
					cmd := newRootCmd()
					cmd.SetOut(&outBuf)
					cmd.SetErr(&errBuf)
					args := append([]string{"view", dir, "-l", "127.0.0.1:18787"}, tc.extraArgs...)
					cmd.SetArgs(args)
					errCh <- cmd.ExecuteContext(ctx)
				}()

				var ln *pipeListener
				select {
				case ln = <-listenReady:
				case err := <-errCh:
					t.Fatalf("view exited before listening: %v (stderr=%s)", err, errBuf.String())
				case <-time.After(startupWaitTimeout):
					t.Fatal("timed out waiting for view to start listening")
				}

				client := &http.Client{
					Transport: &http.Transport{
						DialContext: ln.DialContext,
					},
					Timeout: 3 * time.Second,
				}

				// 1. Verify GET /api/sessions returns preloaded session and configured window_ms
				resp, err := client.Get("http://127.0.0.1:18787/api/sessions")
				require.NoError(t, err)
				var listOut struct {
					Sessions []model.SessionSummary `json:"sessions"`
					WindowMs int64                  `json:"window_ms"`
				}
				require.NoError(t, json.NewDecoder(resp.Body).Decode(&listOut))
				_ = resp.Body.Close()
				require.Equal(t, http.StatusOK, resp.StatusCode)
				require.Equal(t, tc.wantWindowMs, listOut.WindowMs)
				require.Len(t, listOut.Sessions, 1)
				require.Equal(t, "s_view_1", listOut.Sessions[0].ID)
				require.Equal(t, "offline view session", listOut.Sessions[0].Title)

				// 2. Verify GET /api/sessions/s_view_1/events returns preloaded events.jsonl
				evResp, err := client.Get("http://127.0.0.1:18787/api/sessions/s_view_1/events")
				require.NoError(t, err)
				var evOut struct {
					SessionID string             `json:"session_id"`
					Events    []model.TraceEvent `json:"events"`
				}
				require.NoError(t, json.NewDecoder(evResp.Body).Decode(&evOut))
				_ = evResp.Body.Close()
				require.Equal(t, http.StatusOK, evResp.StatusCode)
				require.Equal(t, "s_view_1", evOut.SessionID)
				require.Len(t, evOut.Events, 1)
				require.Equal(t, "ev_view_1", evOut.Events[0].ID)
				require.NotNil(t, evOut.Events[0].Chat)
				require.Equal(t, "view test answer", evOut.Events[0].Chat.ResponseText)

				// 3. Verify Web frontend HTML fetches /api/auth/status and uses window_ms for its initial /api/sessions request
				authResp, err := client.Get("http://127.0.0.1:18787/api/auth/status")
				require.NoError(t, err)
				var authStatus struct {
					WindowMs int64 `json:"window_ms"`
				}
				require.NoError(t, json.NewDecoder(authResp.Body).Decode(&authStatus))
				_ = authResp.Body.Close()
				require.Equal(t, tc.wantWindowMs, authStatus.WindowMs)

				indexResp, err := client.Get("http://127.0.0.1:18787/")
				require.NoError(t, err)
				var indexBuf bytes.Buffer
				_, err = indexBuf.ReadFrom(indexResp.Body)
				require.NoError(t, err)
				_ = indexResp.Body.Close()
				firstDeltaMs := evaluateFrontendFirstSessionsRange(t, indexBuf.String(), authStatus.WindowMs)
				require.Equal(t, tc.wantWindowMs, firstDeltaMs, "frontend initial /api/sessions query must have to - from == window_ms")

				cancel()
				require.NoError(t, <-errCh)
				require.Contains(t, outBuf.String(), "LLM-Tracer Offline Viewer: http://127.0.0.1:18787")

				// 4. Verify read-only guarantee: directory snapshot before and after view must be identical
				afterSnap := snapshotDirContents(t, dir)
				var beforeKeys, afterKeys []string
				for k := range beforeSnap {
					beforeKeys = append(beforeKeys, k)
				}
				for k := range afterSnap {
					afterKeys = append(afterKeys, k)
				}
				sort.Strings(beforeKeys)
				sort.Strings(afterKeys)
				require.Equal(t, beforeKeys, afterKeys, "view must not create any new files or directories in cacheDir")
				require.Equal(t, beforeSnap, afterSnap, "view must not modify any existing files in cacheDir")
			})
		}
	})

	t.Run("nonexistent_dir_and_invalid_window", func(t *testing.T) {
		origListen := listenViewTCP
		t.Cleanup(func() { listenViewTCP = origListen })

		// 1. Invalid --window flag fails immediately before creating directory
		missingForInvalidWin := filepath.Join(t.TempDir(), "invalid-win-dir")
		cmdInvalidWin := newRootCmd()
		cmdInvalidWin.SetArgs([]string{"view", missingForInvalidWin, "-w", "not-a-duration"})
		require.Error(t, cmdInvalidWin.Execute())
		_, statErr := os.Stat(missingForInvalidWin)
		require.True(t, os.IsNotExist(statErr))

		// 2. Non-existent directory: view is strictly read-only, must return error and NOT create any directory
		missingDir := filepath.Join(t.TempDir(), "nonexistent-cache-dir")
		var outBuf, errBuf bytes.Buffer
		cmdMissing := newRootCmd()
		cmdMissing.SetOut(&outBuf)
		cmdMissing.SetErr(&errBuf)
		cmdMissing.SetArgs([]string{"view", missingDir, "-l", "127.0.0.1:18789"})
		require.Error(t, cmdMissing.Execute(), "view on non-existent directory must fail")
		_, err := os.Stat(missingDir)
		require.True(t, os.IsNotExist(err), "view on non-existent directory must not create missingDir")
		_, err = os.Stat(filepath.Join(missingDir, "sessions"))
		require.True(t, os.IsNotExist(err), "view on non-existent directory must not create sessions subdir")

		// 3. Existing empty directory without sessions/: snapshot before and after view must be identical (no sessions/ created)
		emptyCacheDir := t.TempDir()
		beforeEmptySnap := snapshotDirContents(t, emptyCacheDir)
		listenReady := make(chan *pipeListener, 1)
		listenViewTCP = func(_, address string) (net.Listener, error) {
			ln := newPipeListener(address)
			listenReady <- ln
			return ln, nil
		}
		ctxEmpty, cancelEmpty := context.WithCancel(context.Background())
		errChEmpty := make(chan error, 1)
		go func() {
			var outB, errB bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outB)
			cmd.SetErr(&errB)
			cmd.SetArgs([]string{"view", emptyCacheDir, "-l", "127.0.0.1:18789"})
			errChEmpty <- cmd.ExecuteContext(ctxEmpty)
		}()
		<-listenReady
		cancelEmpty()
		require.NoError(t, <-errChEmpty)
		afterEmptySnap := snapshotDirContents(t, emptyCacheDir)
		require.Equal(t, beforeEmptySnap, afterEmptySnap, "view on empty directory must not create sessions/ directory")
	})

	t.Run("readonly_preserves_tmp_files_and_never_chmods_symlinks", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("skipping POSIX symlink & chmod permission assertions on Windows")
		}
		origListen := listenViewTCP
		t.Cleanup(func() { listenViewTCP = origListen })

		// Scenario A: session dir has session.json.tmp and link -> victim(0644)
		rootA := t.TempDir()
		cacheA := filepath.Join(rootA, "cache")
		populateViewFixtureDir(t, cacheA)
		dayEntries, err := os.ReadDir(filepath.Join(cacheA, "sessions"))
		require.NoError(t, err)
		require.Len(t, dayEntries, 1)
		sessDir := filepath.Join(cacheA, "sessions", dayEntries[0].Name(), "s_view_1")
		tmpFile := filepath.Join(sessDir, "session.json.tmp")
		require.NoError(t, os.WriteFile(tmpFile, []byte(`{"in_flight":true}`), 0o644))

		victim := filepath.Join(rootA, "victim")
		require.NoError(t, os.WriteFile(victim, []byte("sensitive victim file"), 0o644))
		require.NoError(t, os.Chmod(victim, 0o644))
		require.NoError(t, os.Symlink(victim, filepath.Join(sessDir, "link")))

		beforeSnapA := snapshotDirContents(t, cacheA)

		listenReadyA := make(chan *pipeListener, 1)
		listenViewTCP = func(_, address string) (net.Listener, error) {
			ln := newPipeListener(address)
			listenReadyA <- ln
			return ln, nil
		}
		ctxA, cancelA := context.WithCancel(context.Background())
		errChA := make(chan error, 1)
		go func() {
			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs([]string{"view", cacheA, "-l", "127.0.0.1:18790"})
			errChA <- cmd.ExecuteContext(ctxA)
		}()
		<-listenReadyA
		cancelA()
		require.NoError(t, <-errChA)

		afterSnapA := snapshotDirContents(t, cacheA)
		require.Equal(t, beforeSnapA, afterSnapA, "view must not delete .tmp or change any file/mode in cacheDir")
		_, err = os.Stat(tmpFile)
		require.NoError(t, err, "session.json.tmp must not be deleted by view")
		vInfo, err := os.Stat(victim)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), vInfo.Mode().Perm(), "victim permissions must remain 0644")

		// Scenario B: c5/sessions is a symlink to tgt(0755) containing tgt/2026-11-01(0755)
		rootB := t.TempDir()
		c5 := filepath.Join(rootB, "c5")
		require.NoError(t, os.MkdirAll(c5, 0o755))
		tgt := filepath.Join(rootB, "tgt")
		tgtDate := filepath.Join(tgt, "2026-11-01")
		require.NoError(t, os.MkdirAll(tgtDate, 0o755))
		require.NoError(t, os.Chmod(tgt, 0o755))
		require.NoError(t, os.Chmod(tgtDate, 0o755))
		require.NoError(t, os.Symlink(tgt, filepath.Join(c5, "sessions")))

		listenReadyB := make(chan *pipeListener, 1)
		listenViewTCP = func(_, address string) (net.Listener, error) {
			ln := newPipeListener(address)
			listenReadyB <- ln
			return ln, nil
		}
		ctxB, cancelB := context.WithCancel(context.Background())
		errChB := make(chan error, 1)
		go func() {
			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs([]string{"view", c5, "-l", "127.0.0.1:18791"})
			errChB <- cmd.ExecuteContext(ctxB)
		}()
		<-listenReadyB
		cancelB()
		require.NoError(t, <-errChB)

		tgtInfo, err := os.Stat(tgt)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), tgtInfo.Mode().Perm(), "tgt permissions must remain 0755")
		tgtDateInfo, err := os.Stat(tgtDate)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), tgtDateInfo.Mode().Perm(), "tgt/2026-11-01 permissions must remain 0755")
	})
}

func evaluateFrontendFirstSessionsRange(t *testing.T, htmlContent string, authWindowMs int64) int64 {
	t.Helper()
	startTag := "<script>"
	endTag := "</script>"
	sIdx := strings.Index(htmlContent, startTag)
	eIdx := strings.LastIndex(htmlContent, endTag)
	require.True(t, sIdx >= 0 && eIdx > sIdx, "index.html must contain <script>...</script>")
	scriptBody := htmlContent[sIdx+len(startTag) : eIdx]
	require.Contains(t, scriptBody, "applyServerDefaultWindow", "index.html must apply server default window_ms")

	nodeBins := []string{
		"node",
		"/home/liuyicong/.local/share/mise/installs/node/24.4.1/bin/node",
	}
	var nodePath string
	for _, cand := range nodeBins {
		if p, err := exec.LookPath(cand); err == nil {
			nodePath = p
			break
		}
	}
	if nodePath == "" {
		t.Fatalf("node binary not found for frontend window execution")
	}

	harness := fmt.Sprintf(`
const scriptCode = %q;
const serverWindowMs = %d;
const requestedUrls = [];
function makeElem() {
  return {
    style: {},
    dataset: {},
    classList: { toggle() {}, add() {}, remove() {} },
    addEventListener() {},
    setAttribute() {},
    getAttribute() { return ''; },
    appendChild() {},
    querySelectorAll() { return []; },
    querySelector() { return makeElem(); },
    innerHTML: '',
    textContent: '',
    value: '',
    disabled: false,
  };
}
globalThis.window = globalThis;
globalThis.localStorage = { getItem() { return null; }, setItem() {} };
globalThis.document = {
  documentElement: makeElem(),
  getElementById() { return makeElem(); },
  querySelectorAll() { return []; },
  querySelector() { return makeElem(); },
  createElement() { return makeElem(); },
  addEventListener() {},
};
globalThis.EventSource = function() { return { close() {}, addEventListener() {} }; };
globalThis.requestAnimationFrame = () => {};
globalThis.setInterval = () => 1;
globalThis.clearInterval = () => {};
globalThis.fetch = async (url) => {
  requestedUrls.push(String(url));
  if (String(url).startsWith('/api/auth/status')) {
    return { status: 200, ok: true, json: async () => ({ enabled: false, unlocked: true, window_ms: serverWindowMs }) };
  }
  if (String(url).startsWith('/api/timeline')) {
    return { status: 200, ok: true, json: async () => ({ buckets: [], total_events: 0, error_events: 0, window_ms: serverWindowMs }) };
  }
  if (String(url).startsWith('/api/sessions')) {
    return { status: 200, ok: true, json: async () => ({ sessions: [], window_ms: serverWindowMs }) };
  }
  return { status: 200, ok: true, json: async () => ({}) };
};
(async () => {
  eval(scriptCode);
  await new Promise(r => setTimeout(r, 20));
  const sessUrl = requestedUrls.find(u => u.startsWith('/api/sessions?'));
  if (!sessUrl) { process.exit(2); }
  const qs = new URL(sessUrl, 'http://localhost').searchParams;
  const from = Number(qs.get('from'));
  const to = Number(qs.get('to'));
  process.stdout.write(String(to - from));
})();
`, scriptBody, authWindowMs)

	cmd := exec.Command(nodePath, "-e", harness)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "node harness failed: %s", string(out))
	var delta int64
	_, err = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &delta)
	require.NoError(t, err, "invalid delta output: %q", string(out))
	return delta
}

func TestSSEGracefulShutdownViewAndCaptureUnder500ms(t *testing.T) {
	t.Run("view_with_active_sse_exits_within_500ms_and_code_0", func(t *testing.T) {
		origListen := listenViewTCP
		t.Cleanup(func() { listenViewTCP = origListen })

		dir := t.TempDir()
		populateViewFixtureDir(t, dir)

		listenReady := make(chan *pipeListener, 1)
		listenViewTCP = func(_, address string) (net.Listener, error) {
			ln := newPipeListener(address)
			listenReady <- ln
			return ln, nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs([]string{"view", dir, "-l", "127.0.0.1:18792"})
			errCh <- cmd.ExecuteContext(ctx)
		}()

		ln := <-listenReady
		client := &http.Client{
			Transport: &http.Transport{DialContext: ln.DialContext},
		}
		sseResp, err := client.Get("http://127.0.0.1:18792/api/stream")
		require.NoError(t, err)
		defer sseResp.Body.Close()
		require.Equal(t, http.StatusOK, sseResp.StatusCode)

		buf := make([]byte, 64)
		n, err := sseResp.Body.Read(buf)
		require.NoError(t, err)
		require.Contains(t, string(buf[:n]), "event: ready")
		go func() {
			_, _ = io.Copy(io.Discard, sseResp.Body)
		}()

		start := time.Now()
		cancel()
		runErr := <-errCh
		elapsed := time.Since(start)
		require.NoError(t, runErr, "view with open SSE must exit cleanly (code 0)")
		require.Less(t, elapsed, 500*time.Millisecond, "view with open SSE must exit within 500ms, got %v", elapsed)
	})

	t.Run("capture_with_active_sse_exits_within_500ms_and_code_0", func(t *testing.T) {
		origListen := listenCaptureTCP
		t.Cleanup(func() { listenCaptureTCP = origListen })

		dir := t.TempDir()
		listenReady := make(chan *pipeListener, 1)
		listenCaptureTCP = func(_, address string) (net.Listener, error) {
			ln := newPipeListener(address)
			listenReady <- ln
			return ln, nil
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs([]string{"capture", "-l", "127.0.0.1:18793", "-d", dir})
			errCh <- cmd.ExecuteContext(ctx)
		}()

		var ln *pipeListener
		select {
		case ln = <-listenReady:
		case err := <-errCh:
			t.Fatalf("capture exited before listening: %v", err)
		case <-time.After(startupWaitTimeout):
			t.Fatal("timed out waiting for capture to start listening")
		}

		client := &http.Client{
			Transport: &http.Transport{DialContext: ln.DialContext},
		}
		sseResp, err := client.Get("http://127.0.0.1:18793/api/stream")
		require.NoError(t, err)
		defer sseResp.Body.Close()
		require.Equal(t, http.StatusOK, sseResp.StatusCode)

		buf := make([]byte, 64)
		n, err := sseResp.Body.Read(buf)
		require.NoError(t, err)
		require.Contains(t, string(buf[:n]), "event: ready")
		go func() {
			_, _ = io.Copy(io.Discard, sseResp.Body)
		}()

		start := time.Now()
		cancel()
		runErr := <-errCh
		elapsed := time.Since(start)
		require.NoError(t, runErr, "capture with open SSE must exit cleanly (code 0)")
		require.Less(t, elapsed, 500*time.Millisecond, "capture with open SSE must exit within 500ms, got %v", elapsed)
	})
}

var (
	cliTestBearerSecret    = "sk-" + "cli-redline-bearer-" + "998877"
	cliTestXAPIKeySecret   = "sk-" + "cli-redline-xapikey-" + "112233"
	cliTestReqCookieSecret = "cli_req_cookie_secret_" + "445566"
	cliTestSetCookieSecret = "cli_resp_setcookie_secret_" + "778899"
	cliTestTOTPSecret      = "JBSW" + "Y3DP" + "EHPK" + "3PXP"
)

func buildTestLLMTFrame(pid, tid int, sslTag uint32, dir uint32, payload []byte) []byte {
	var hdr [24]byte
	binary.NativeEndian.PutUint32(hdr[0:4], 0x4c4c4d54)
	binary.NativeEndian.PutUint32(hdr[4:8], uint32(pid))
	binary.NativeEndian.PutUint32(hdr[8:12], uint32(tid))
	binary.NativeEndian.PutUint32(hdr[12:16], sslTag)
	binary.NativeEndian.PutUint32(hdr[16:20], dir)
	binary.NativeEndian.PutUint32(hdr[20:24], uint32(len(payload)))
	out := make([]byte, 24+len(payload))
	copy(out[:24], hdr[:])
	copy(out[24:], payload)
	return out
}

func emitSensitiveExchangeToPipe(pipePath string, pid int, sslTag uint32, promptMarker, replyMarker string) error {
	reqBody := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":%q}]}`, promptMarker)
	reqRaw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\n"+
			"Host: api.openai.com\r\n"+
			"Authorization: Bearer %s\r\n"+
			"X-Api-Key: %s\r\n"+
			"Cookie: session=%s\r\n"+
			"Content-Type: application/json\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		cliTestBearerSecret,
		cliTestXAPIKeySecret,
		cliTestReqCookieSecret,
		len(reqBody),
		reqBody,
	)
	respBody := fmt.Sprintf(
		`{"id":"chatcmpl-%x","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":4,"total_tokens":9}}`,
		sslTag,
		replyMarker,
	)
	respRaw := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/json\r\n"+
			"Set-Cookie: sid=%s\r\n"+
			"X-Request-Id: req-%x\r\n"+
			"Content-Length: %d\r\n\r\n%s",
		cliTestSetCookieSecret,
		sslTag,
		len(respBody),
		respBody,
	)
	reqFrame := buildTestLLMTFrame(pid, pid, sslTag, 0, []byte(reqRaw))
	respFrame := buildTestLLMTFrame(pid, pid, sslTag, 1, []byte(respRaw))
	combined := append(reqFrame, respFrame...)

	f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(combined); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// TestHelperPipeTLSInjector acts as the target child (and optional grandchild) process
// spawned via `llm-tracer ... -- <selfExe> -test.run=^TestHelperPipeTLSInjector$`.
// It writes real LLMT TLS frames containing sensitive headers into <cacheDir>/hooks/tls.bin.
func TestHelperPipeTLSInjector(t *testing.T) {
	f := flag.Lookup("test.run")
	if f == nil || f.Value.String() != "^TestHelperPipeTLSInjector$" {
		return
	}
	pipePath := strings.TrimSpace(os.Getenv("LLM_TRACER_PIPE"))
	if pipePath == "" {
		os.Exit(2)
	}
	hasArg := func(target string) bool {
		for _, a := range os.Args {
			if a == target {
				return true
			}
		}
		return false
	}
	selfPID := os.Getpid()
	if hasArg("grandchild-emit") {
		time.Sleep(30 * time.Millisecond)
		if err := emitSensitiveExchangeToPipe(pipePath, selfPID, 0x702, "DESCENDANT_PROC_MARKER", "DESCENDANT_REPLY_MARKER"); err != nil {
			os.Exit(3)
		}
		// Stay alive briefly so collector/proctree can inspect /proc/<grandchildPID>/stat while alive.
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	}

	// Wait briefly so parent LaunchPlannedCommand has registered our root PID.
	time.Sleep(35 * time.Millisecond)
	if err := emitSensitiveExchangeToPipe(pipePath, selfPID, 0x701, "ROOT_PROC_MARKER", "ROOT_REPLY_MARKER"); err != nil {
		os.Exit(4)
	}
	if hasArg("spawn-grandchild") {
		selfExe, err := os.Executable()
		if err != nil {
			os.Exit(5)
		}
		gc := exec.Command(selfExe, "-test.run=^TestHelperPipeTLSInjector$", "--", "grandchild-emit")
		gc.Env = os.Environ()
		gc.Stdout = os.Stdout
		gc.Stderr = os.Stderr
		if err := gc.Run(); err != nil {
			os.Exit(6)
		}
	}
	time.Sleep(60 * time.Millisecond)
	os.Exit(0)
}

func readPersistedEventsJSONL(t *testing.T, cacheDir string) (string, []model.TraceEvent) {
	t.Helper()
	sessionsDir := filepath.Join(cacheDir, "sessions")
	var rawBuilder strings.Builder
	var events []model.TraceEvent
	err := filepath.WalkDir(sessionsDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || d.Name() != "events.jsonl" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rawBuilder.Write(data)
		rawBuilder.WriteByte('\n')
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var ev model.TraceEvent
			require.NoError(t, json.Unmarshal([]byte(line), &ev))
			events = append(events, ev)
		}
		require.NoError(t, sc.Err())
		return nil
	})
	require.NoError(t, err)
	return rawBuilder.String(), events
}

func TestCLIRecordHeadersWiringEndToEnd(t *testing.T) {
	selfExe, err := os.Executable()
	require.NoError(t, err)

	t.Run("default_record_headers_false_redlines_credentials_from_events_jsonl", func(t *testing.T) {
		for _, subName := range []string{"capture_subcommand", "root_command"} {
			t.Run(subName, func(t *testing.T) {
				dir := t.TempDir()
				var args []string
				if subName == "capture_subcommand" {
					args = []string{"capture", "-d", dir, "-l", "off", "--exit-with-child", "--", selfExe, "-test.run=^TestHelperPipeTLSInjector$"}
				} else {
					args = []string{"-d", dir, "-l", "off", "--exit-with-child", "--", selfExe, "-test.run=^TestHelperPipeTLSInjector$"}
				}
				stdoutStr, _, execErr := executeCapturingStdio(t, func() error {
					cmd := newRootCmd()
					cmd.SetArgs(args)
					return cmd.Execute()
				})
				require.NoError(t, execErr)
				require.Contains(t, stdoutStr, "Record Headers    : false")

				rawJSONL, events := readPersistedEventsJSONL(t, dir)
				require.NotEmpty(t, events, "expected persisted events in events.jsonl")
				require.Contains(t, rawJSONL, "ROOT_PROC_MARKER")
				require.Contains(t, rawJSONL, "ROOT_REPLY_MARKER")

				// Redline check on persisted events.jsonl raw bytes
				require.NotContains(t, rawJSONL, cliTestBearerSecret, "events.jsonl leaked Authorization Bearer token when --record-headers is not set")
				require.NotContains(t, rawJSONL, cliTestXAPIKeySecret, "events.jsonl leaked X-Api-Key when --record-headers is not set")
				require.NotContains(t, rawJSONL, cliTestReqCookieSecret, "events.jsonl leaked Cookie when --record-headers is not set")
				require.NotContains(t, rawJSONL, cliTestSetCookieSecret, "events.jsonl leaked Set-Cookie when --record-headers is not set")
				require.NotContains(t, strings.ToLower(rawJSONL), "request_headers")
				require.NotContains(t, strings.ToLower(rawJSONL), "response_headers")

				for _, ev := range events {
					require.False(t, ev.HeadersRecorded, "HeadersRecorded must be false by default")
					require.Empty(t, ev.RequestHeaders, "RequestHeaders must be empty by default")
					require.Empty(t, ev.ResponseHeaders, "ResponseHeaders must be empty by default")
				}
			})
		}
	})

	t.Run("explicit_record_headers_true_persists_headers_to_events_jsonl", func(t *testing.T) {
		dir := t.TempDir()
		stdoutStr, _, execErr := executeCapturingStdio(t, func() error {
			cmd := newRootCmd()
			cmd.SetArgs([]string{
				"capture", "-d", dir, "-l", "off",
				"--record-headers",
				"--exit-with-child",
				"--", selfExe, "-test.run=^TestHelperPipeTLSInjector$",
			})
			return cmd.Execute()
		})
		require.NoError(t, execErr)
		require.Contains(t, stdoutStr, "Record Headers    : true")

		rawJSONL, events := readPersistedEventsJSONL(t, dir)
		require.NotEmpty(t, events, "expected persisted events in events.jsonl")
		require.Contains(t, rawJSONL, "ROOT_PROC_MARKER")
		require.Contains(t, rawJSONL, "ROOT_REPLY_MARKER")
		require.Contains(t, rawJSONL, cliTestBearerSecret, "events.jsonl must contain Authorization Bearer header when --record-headers is enabled")
		require.Contains(t, rawJSONL, cliTestXAPIKeySecret, "events.jsonl must contain X-Api-Key header when --record-headers is enabled")
		require.Contains(t, rawJSONL, cliTestReqCookieSecret, "events.jsonl must contain Cookie header when --record-headers is enabled")
		require.Contains(t, rawJSONL, cliTestSetCookieSecret, "events.jsonl must contain Set-Cookie response header when --record-headers is enabled")

		for _, ev := range events {
			require.True(t, ev.HeadersRecorded, "HeadersRecorded must be true when --record-headers is passed")
			require.NotEmpty(t, ev.RequestHeaders, "RequestHeaders must be populated when --record-headers is passed")
			require.NotEmpty(t, ev.ResponseHeaders, "ResponseHeaders must be populated when --record-headers is passed")
		}
	})
}

func TestCLIPIDOnlyWiringEndToEnd(t *testing.T) {
	selfExe, err := os.Executable()
	require.NoError(t, err)

	t.Run("default_pid_only_false_captures_root_and_descendant_into_events_jsonl", func(t *testing.T) {
		dir := t.TempDir()
		_, _, execErr := executeCapturingStdio(t, func() error {
			cmd := newRootCmd()
			cmd.SetArgs([]string{
				"capture", "-d", dir, "-l", "off",
				"--auto-intrusive=false",
				"--exit-with-child",
				"--", selfExe, "-test.run=^TestHelperPipeTLSInjector$", "--", "spawn-grandchild",
			})
			return cmd.Execute()
		})
		require.NoError(t, execErr)

		rawJSONL, events := readPersistedEventsJSONL(t, dir)
		require.Len(t, events, 2, "default subtree mode (--pid-only=false) must persist both root and descendant exchanges")
		require.Contains(t, rawJSONL, "ROOT_PROC_MARKER")
		require.Contains(t, rawJSONL, "DESCENDANT_PROC_MARKER")
	})

	t.Run("explicit_pid_only_true_captures_root_and_drops_descendant_from_events_jsonl", func(t *testing.T) {
		dir := t.TempDir()
		_, _, execErr := executeCapturingStdio(t, func() error {
			cmd := newRootCmd()
			cmd.SetArgs([]string{
				"capture", "-d", dir, "-l", "off",
				"--auto-intrusive=false",
				"--pid-only",
				"--exit-with-child",
				"--", selfExe, "-test.run=^TestHelperPipeTLSInjector$", "--", "spawn-grandchild",
			})
			return cmd.Execute()
		})
		require.NoError(t, execErr)

		rawJSONL, events := readPersistedEventsJSONL(t, dir)
		require.Len(t, events, 1, "--pid-only must persist only the root process exchange and drop descendant exchanges")
		require.Contains(t, rawJSONL, "ROOT_PROC_MARKER")
		require.NotContains(t, rawJSONL, "DESCENDANT_PROC_MARKER", "--pid-only must not persist descendant process traffic in events.jsonl")
		require.NotContains(t, rawJSONL, "DESCENDANT_REPLY_MARKER")
	})
}

func TestTOTPSecretNotPrintedInHelpAndEnvRuntimeFallback(t *testing.T) {
	t.Setenv("LLM_TRACER_TOTP_SECRET", cliTestTOTPSecret)

	for _, helpArgs := range [][]string{
		{"--help"},
		{"capture", "--help"},
		{"view", "--help"},
	} {
		t.Run(strings.Join(helpArgs, "_"), func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetErr(&errBuf)
			cmd.SetArgs(helpArgs)
			require.NoError(t, cmd.Execute())
			combined := outBuf.String() + "\n" + errBuf.String()
			require.NotContains(t, combined, cliTestTOTPSecret, "help output for %v must never print LLM_TRACER_TOTP_SECRET plaintext", helpArgs)
			require.Contains(t, combined, "/proc/<pid>/cmdline", "help output for %v must warn about argv visibility in /proc/<pid>/cmdline", helpArgs)
			require.Contains(t, combined, "环境变量", "help output for %v must recommend environment variable", helpArgs)
		})
	}

	t.Run("root_and_capture_help_expose_allow_web_header_toggle_flag", func(t *testing.T) {
		for _, helpArgs := range [][]string{{"--help"}, {"capture", "--help"}} {
			var outBuf bytes.Buffer
			cmd := newRootCmd()
			cmd.SetOut(&outBuf)
			cmd.SetArgs(helpArgs)
			require.NoError(t, cmd.Execute())
			require.Contains(t, outBuf.String(), "--allow-web-header-toggle")
		}
	})

	t.Run("capture_reads_totp_secret_from_env_at_runtime_when_flag_omitted", func(t *testing.T) {
		selfExe, err := os.Executable()
		require.NoError(t, err)
		dir := t.TempDir()
		stdoutStr, _, execErr := executeCapturingStdio(t, func() error {
			cmd := newRootCmd()
			cmd.SetArgs([]string{"capture", "-d", dir, "-l", "off", "--exit-with-child", "--", selfExe, "-test.run=^TestHelperNoop$"})
			return cmd.Execute()
		})
		require.NoError(t, execErr)
		require.Contains(t, stdoutStr, "TOTP Auth Enabled : true")
	})

	t.Run("allow_web_header_toggle_flag_wires_to_web_server", func(t *testing.T) {
		origListen := listenCaptureTCP
		t.Cleanup(func() { listenCaptureTCP = origListen })

		for _, allowToggle := range []bool{false, true} {
			dir := t.TempDir()
			listenReady := make(chan *pipeListener, 1)
			listenCaptureTCP = func(_, address string) (net.Listener, error) {
				ln := newPipeListener(address)
				listenReady <- ln
				return ln, nil
			}

			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() {
				var outBuf, errBuf bytes.Buffer
				cmd := newRootCmd()
				cmd.SetOut(&outBuf)
				cmd.SetErr(&errBuf)
				args := []string{"capture", "-l", "127.0.0.1:18794", "-d", dir}
				if allowToggle {
					args = append(args, "--allow-web-header-toggle")
				}
				cmd.SetArgs(args)
				errCh <- cmd.ExecuteContext(ctx)
			}()

			var ln *pipeListener
			select {
			case ln = <-listenReady:
			case err := <-errCh:
				t.Fatalf("capture exited before listening: %v", err)
			case <-time.After(startupWaitTimeout):
				t.Fatal("timed out waiting for capture to start listening")
			}

			client := &http.Client{
				Transport: &http.Transport{DialContext: ln.DialContext},
				Timeout:   3 * time.Second,
			}
			code, err := totp.GenerateCode(cliTestTOTPSecret, time.Now())
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18794/api/scope", strings.NewReader(`{"record_headers":true}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-LLM-Tracer-TOTP", code)
			resp, err := client.Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()
			if allowToggle {
				require.Equal(t, http.StatusOK, resp.StatusCode, "PUT /api/scope enabling record_headers must succeed when --allow-web-header-toggle is set")
			} else {
				require.Equal(t, http.StatusForbidden, resp.StatusCode, "PUT /api/scope enabling record_headers must be 403 Forbidden by default")
			}

			cancel()
			require.NoError(t, <-errCh)
		}
	})
}
