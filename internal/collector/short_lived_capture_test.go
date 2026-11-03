package collector

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func TestShortLived60SubprocessesCapture(t *testing.T) {
	// 1. Deterministic 60/60 test where short-lived child process is observed while alive,
	// exits completely, and then 60 exchanges from its PID are drained from hooks/tls.bin.
	t.Run("exited_child_ancestry_cache_60_of_60", func(t *testing.T) {
		dir := t.TempDir()
		mon, err := selfmon.NewMonitor(dir)
		require.NoError(t, err)
		defer mon.Close()
		st, err := store.NewStore(dir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()
		corr := correlator.NewCorrelator(mon)

		selfPID := os.Getpid()
		col, err := NewCollector(dir, model.ScopeFilter{PIDs: []int{selfPID}, PIDOnly: false}, corr, st, mon)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, col.Start(ctx))
		defer col.Stop()

		selfExe, err := os.Executable()
		require.NoError(t, err)
		childCmd := exec.Command(selfExe, "-test.run=^TestHelperSleepProcess$")
		childCmd.Env = append(os.Environ(), "LLM_TRACER_TEST_HELPER_SLEEP=1")
		require.NoError(t, childCmd.Start())
		childPID := childCmd.Process.Pid

		// Poll to ensure childPID is visible in OS process table and resolves to selfPID before caching
		require.Eventually(t, func() bool {
			return readPPID(childPID) == selfPID && readProcessStartTime(childPID) > 0
		}, 3*time.Second, 10*time.Millisecond, "child process PPID and non-zero startTime must resolve")

		// First sight of childPID while alive caches its ancestor chain (childPID -> selfPID)
		infoAlive, okAlive := col.tracker.MatchAndEnrich(childPID, model.ProcessInfo{PID: childPID})
		require.True(t, okAlive, "live child process must match scope")
		require.NotEmpty(t, infoAlive.Comm)

		// Terminate childPID and wait for it to completely disappear from the OS process table
		_ = childCmd.Process.Kill()
		_ = childCmd.Wait()
		time.Sleep(20 * time.Millisecond)

		var buf bytes.Buffer
		for i := 1; i <= 60; i++ {
			reqF, respF := buildOpenAIExchangeFrames(childPID, uint32(0x1000+i), i)
			buf.Write(reqF)
			buf.Write(respF)
		}

		pipePath := filepath.Join(dir, "hooks", "tls.bin")
		f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_APPEND, 0o600)
		require.NoError(t, err)
		_, err = f.Write(buf.Bytes())
		require.NoError(t, err)
		require.NoError(t, f.Sync())
		require.NoError(t, f.Close())

		require.Eventually(t, func() bool {
			col.Flush()
			return countPersistedStoreEvents(t, st) == 60
		}, 10*time.Second, 50*time.Millisecond, "expected 60/60 events from exited short-lived child process via ancestry cache")
	})

	// 2. End-to-end 60 sequential short-lived python3 subprocess loop under bash LaunchCommand
	if runtime.GOOS != "windows" {
		pyBin, pyErr := findPythonExecutable()
		bashBin, bashErr := exec.LookPath("bash")
		if pyErr == nil && pyBin != "" && bashErr == nil && bashBin != "" {
			t.Run("bash_60_short_lived_python_subprocesses_e2e", func(t *testing.T) {
				dir := t.TempDir()
				mon, err := selfmon.NewMonitor(dir)
				require.NoError(t, err)
				defer mon.Close()
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

				emitScript := filepath.Join(dir, "emit_once.py")
				emitPy := `import os, struct, sys
d = sys.argv[1]
pid = os.getpid()
req_body = b'{"model":"gpt-4o","messages":[{"role":"user","content":"short-lived-60"}]}'
req = (b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n"
       b"Authorization: Bearer sk-AUTHSECRET-abcdef\r\nContent-Type: application/json\r\n"
       b"Content-Length: " + str(len(req_body)).encode() + b"\r\n\r\n" + req_body)
resp_body = b'{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}'
resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(resp_body)).encode() + b"\r\n\r\n" + resp_body)
p = os.path.join(d, "hooks", "tls.bin")
with open(p, "ab") as f:
    for dr, payload in ((0, req), (1, resp)):
        f.write(struct.pack("=IIIIII", 0x4c4c4d54, pid, pid, 0xabc, dr, len(payload)) + payload)
`
				require.NoError(t, os.WriteFile(emitScript, []byte(emitPy), 0o600))

				loopCmd := fmt.Sprintf("for i in $(seq 1 60); do %q %q %q; done", pyBin, emitScript, dir)
				exitCode, err := col.LaunchCommand(ctx, []string{bashBin, "-c", loopCmd})
				require.NoError(t, err)
				require.Equal(t, 0, exitCode)

				require.Eventually(t, func() bool {
					col.Flush()
					return countPersistedStoreEvents(t, st) == 60
				}, 2*time.Second, 20*time.Millisecond, "expected 60/60 short-lived python subprocess exchanges to be persisted")
			})
		}
	}
}

func TestOutOfScopeDropRecordedAndRateLimitedInSelfmon(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	corr := correlator.NewCorrelator(mon)

	selfPID := os.Getpid()
	col, err := NewCollector(dir, model.ScopeFilter{
		PIDs:    []int{selfPID},
		PIDOnly: true,
	}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	pipePath := filepath.Join(dir, "hooks", "tls.bin")
	f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)

	// Write 30 out-of-scope exchanges (60 frames) from PID 999991 and 1 exchange (2 frames) from PID 999992
	for i := 1; i <= 30; i++ {
		reqF, respF := buildOpenAIExchangeFrames(999991, uint32(0x2000+i), i)
		_, err = f.Write(reqF)
		require.NoError(t, err)
		_, err = f.Write(respF)
		require.NoError(t, err)
	}
	reqOther, respOther := buildOpenAIExchangeFrames(999992, 0x3001, 99)
	_, err = f.Write(reqOther)
	require.NoError(t, err)
	_, err = f.Write(respOther)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	col.Flush()

	// Out-of-scope frames must not be persisted
	require.Equal(t, 0, countPersistedStoreEvents(t, st))

	// Selfmon must record ingest_out_of_scope_dropped warnings, rate-limited per PID
	events, err := mon.QueryEvents(selfmon.Query{
		Stage:  selfmon.StageTracker,
		Status: selfmon.StatusWarn,
		Limit:  100,
	})
	require.NoError(t, err)

	dropsByPID := make(map[int]int)
	totalDropsFor999991 := 0
	for _, ev := range events {
		if ev.Action == "ingest_out_of_scope_dropped" {
			dropsByPID[ev.PID]++
			if ev.PID == 999991 {
				if cnt, ok := ev.Detail["dropped_count"].(int); ok {
					totalDropsFor999991 += cnt
				} else if cntF, ok := ev.Detail["dropped_count"].(float64); ok {
					totalDropsFor999991 += int(cntF)
				}
			}
		}
	}

	require.GreaterOrEqual(t, dropsByPID[999991], 1, "expected selfmon ingest_out_of_scope_dropped event for PID 999991")
	require.LessOrEqual(t, dropsByPID[999991], 5, "expected per-PID rate-limiting to prevent log spam for 60 rapid drops from PID 999991")
	require.Equal(t, 60, totalDropsFor999991, "aggregated dropped_count for PID 999991 must equal 60 frames")
	require.GreaterOrEqual(t, dropsByPID[999992], 1, "expected selfmon ingest_out_of_scope_dropped event for PID 999992")
}
