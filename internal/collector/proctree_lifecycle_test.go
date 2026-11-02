package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func startRealSleepProcess(t *testing.T) *exec.Cmd {
	t.Helper()
	selfExe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(selfExe, "-test.run=^TestHelperSleepProcess$")
	cmd.Env = append(os.Environ(), "LLM_TRACER_TEST_HELPER_SLEEP=1")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return cmd
}

func killAndWaitProcessGone(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	pid := cmd.Process.Pid
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, alive := inspectLiveIdentity(pid); !alive {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process pid=%d still reported alive after kill+wait", pid)
}

// TestProcessTrackerLifecycle_ExitedShortLivedChildInFlightStillInScope verifies D1 regression protection:
// when a short-lived child process exits before its in-flight hook frames are processed (and before its PID
// is reused or evicted by RefreshSubtree), both IsInScope/MatchAndEnrich and end-to-end pipe ingestion
// still accept the exited child's traffic.
func TestProcessTrackerLifecycle_ExitedShortLivedChildInFlightStillInScope(t *testing.T) {
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
		PIDOnly: false,
	}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	childCmd := startRealSleepProcess(t)
	childPID := childCmd.Process.Pid
	childStart := readProcessStartTime(childPID)
	require.Greater(t, childStart, uint64(0), "live child process must have a non-zero startTime")

	// Observe child while alive so its (pid, startTime) ancestry and process info are cached.
	infoAlive, okAlive := col.tracker.MatchAndEnrich(childPID, model.ProcessInfo{PID: childPID})
	require.True(t, okAlive, "live child of rootPID must be in scope")
	require.True(t, col.tracker.IsInScope(childPID), "IsInScope must be true for live child")
	require.NotEmpty(t, infoAlive.Comm)

	// Child exits before in-flight hook frames arrive.
	killAndWaitProcessGone(t, childCmd)

	// In-flight check after child exit (before RefreshSubtree eviction or PID reuse):
	require.True(t, col.tracker.IsInScope(childPID), "exited short-lived child must remain in scope for in-flight frames")
	infoExited, okExited := col.tracker.MatchAndEnrich(childPID, model.ProcessInfo{PID: childPID})
	require.True(t, okExited, "MatchAndEnrich must accept in-flight frame from exited short-lived child")
	require.Equal(t, infoAlive.Comm, infoExited.Comm, "cached ProcessInfo must be preserved for exited short-lived child")

	// End-to-end pipe ingestion for the exited child PID must succeed.
	pipePath := filepath.Join(dir, "hooks", "tls.bin")
	f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	reqF, respF := buildOpenAIExchangeFrames(childPID, 0x7001, 1)
	_, err = f.Write(reqF)
	require.NoError(t, err)
	_, err = f.Write(respF)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	col.Flush()
	require.Equal(t, 1, countPersistedStoreEvents(t, st), "in-flight exchange from exited short-lived child must be persisted")
}

// TestProcessTrackerLifecycle_PIDReuseByUnrelatedProcessRejected verifies that when an in-scope
// child process exits and its PID is reused by a new unrelated process with a different startTime,
// IsInScope and MatchAndEnrich immediately reject the reused PID and evict the old generation's cache.
func TestProcessTrackerLifecycle_PIDReuseByUnrelatedProcessRejected(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()

	// Start a dedicated real process as the capture root so other children of the test binary
	// are genuine out-of-scope (unrelated) OS processes.
	rootCmd := startRealSleepProcess(t)
	rootPID := rootCmd.Process.Pid

	pt := NewProcessTracker(model.ScopeFilter{
		PIDs:    []int{rootPID},
		PIDOnly: false,
	}, mon)
	defer pt.Close()

	// Generation 1: a real process starts earlier, giving a real OS startTime S1, and then exits.
	gen1Cmd := startRealSleepProcess(t)
	gen1Start := readProcessStartTime(gen1Cmd.Process.Pid)
	require.Greater(t, gen1Start, uint64(0))
	killAndWaitProcessGone(t, gen1Cmd)

	// Advance wall clock beyond 1 OS clock tick (10ms on Linux CLK_TCK=100) so Generation 2 gets S2 > S1.
	time.Sleep(40 * time.Millisecond)

	// Generation 2: a real unrelated process (parent is os.Getpid(), NOT rootPID) is now running at reusedPID with startTime S2.
	unrelatedCmd := startRealSleepProcess(t)
	reusedPID := unrelatedCmd.Process.Pid
	gen2Start := readProcessStartTime(reusedPID)
	require.Greater(t, gen2Start, uint64(0))
	require.NotEqual(t, gen1Start, gen2Start, "generation 1 and generation 2 real processes must have distinct OS startTimes")

	// Populate tracker caches as if reusedPID had previously been an in-scope child of rootPID during Generation 1 (startTime = gen1Start).
	oldKey := procKey{pid: reusedPID, startTime: gen1Start}
	pt.mu.Lock()
	pt.lastSeenStart[reusedPID] = gen1Start
	pt.trackedPIDs[oldKey] = rootPID
	pt.ancestryCache[oldKey] = []int{rootPID}
	pt.procCache[oldKey] = model.ProcessInfo{
		PID:     reusedPID,
		PPID:    rootPID,
		Comm:    "gen1-in-scope-child",
		Cmdline: "gen1-in-scope-child --secret-work",
	}
	pt.mu.Unlock()

	// Because reusedPID is now occupied by a live unrelated process with startTime == gen2Start != gen1Start,
	// both IsInScope and MatchAndEnrich must reject it and evict the stale Generation 1 cache entries!
	require.False(t, pt.IsInScope(reusedPID), "PID reused by an unrelated process with a new startTime must NOT be in scope")
	infoGen2, matched := pt.MatchAndEnrich(reusedPID, model.ProcessInfo{PID: reusedPID})
	require.False(t, matched, "MatchAndEnrich must reject unrelated process that reused an exited child's PID")
	require.NotEqual(t, "gen1-in-scope-child", infoGen2.Comm, "stale procCache from previous PID generation must not leak into reused PID")

	pt.mu.RLock()
	_, oldTrackedStillPresent := pt.trackedPIDs[oldKey]
	_, oldAncStillPresent := pt.ancestryCache[oldKey]
	_, oldProcStillPresent := pt.procCache[oldKey]
	pt.mu.RUnlock()
	require.False(t, oldTrackedStillPresent, "stale trackedPIDs entry for old (pid, startTime) must be evicted on PID reuse")
	require.False(t, oldAncStillPresent, "stale ancestryCache entry for old (pid, startTime) must be evicted on PID reuse")
	require.False(t, oldProcStillPresent, "stale procCache entry for old (pid, startTime) must be evicted on PID reuse")
}

// TestProcessTrackerLifecycle_CacheEvictedWhenProcessDisappears verifies that RefreshSubtree
// actively reclaims trackedPIDs, ancestryCache, procCache, and lastSeenStart entries once child processes exit,
// preventing unbounded map growth and ensuring exited children are no longer considered in scope after refresh.
func TestProcessTrackerLifecycle_CacheEvictedWhenProcessDisappears(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()

	selfPID := os.Getpid()
	pt := NewProcessTracker(model.ScopeFilter{
		PIDs:    []int{selfPID},
		PIDOnly: false,
	}, mon)
	defer pt.Close()

	const numChildren = 3
	cmds := make([]*exec.Cmd, numChildren)
	childKeys := make([]procKey, numChildren)
	for i := 0; i < numChildren; i++ {
		cmds[i] = startRealSleepProcess(t)
		pid := cmds[i].Process.Pid
		st := readProcessStartTime(pid)
		require.Greater(t, st, uint64(0))
		childKeys[i] = procKey{pid: pid, startTime: st}

		_, ok := pt.MatchAndEnrich(pid, model.ProcessInfo{PID: pid})
		require.True(t, ok, "live child process %d must match scope", pid)
		require.True(t, pt.IsInScope(pid))
	}
	pt.RefreshSubtree()

	// Verify all 3 children are present in tracker caches while alive.
	pt.mu.RLock()
	for _, ck := range childKeys {
		_, hasTrk := pt.trackedPIDs[ck]
		_, hasAnc := pt.ancestryCache[ck]
		_, hasProc := pt.procCache[ck]
		require.True(t, hasTrk, "expected trackedPIDs entry for live child %+v", ck)
		require.True(t, hasAnc, "expected ancestryCache entry for live child %+v", ck)
		require.True(t, hasProc, "expected procCache entry for live child %+v", ck)
	}
	aliveTrackedLen := len(pt.trackedPIDs)
	aliveAncestryLen := len(pt.ancestryCache)
	aliveProcLen := len(pt.procCache)
	pt.mu.RUnlock()

	require.GreaterOrEqual(t, aliveTrackedLen, numChildren+1)
	require.GreaterOrEqual(t, aliveAncestryLen, numChildren)
	require.GreaterOrEqual(t, aliveProcLen, numChildren)

	// Terminate all 3 child processes and wait for them to disappear from the OS process table.
	for i := 0; i < numChildren; i++ {
		killAndWaitProcessGone(t, cmds[i])
	}

	// RefreshSubtree must evict all disappeared child PIDs from every internal map.
	pt.RefreshSubtree()

	pt.mu.RLock()
	for _, ck := range childKeys {
		_, hasTrk := pt.trackedPIDs[ck]
		_, hasAnc := pt.ancestryCache[ck]
		_, hasProc := pt.procCache[ck]
		_, hasLast := pt.lastSeenStart[ck.pid]
		require.False(t, hasTrk, "disappeared child %+v must be evicted from trackedPIDs", ck)
		require.False(t, hasAnc, "disappeared child %+v must be evicted from ancestryCache", ck)
		require.False(t, hasProc, "disappeared child %+v must be evicted from procCache", ck)
		require.False(t, hasLast, "disappeared child pid=%d must be evicted from lastSeenStart", ck.pid)
	}
	afterTrackedLen := len(pt.trackedPIDs)
	afterAncestryLen := len(pt.ancestryCache)
	afterProcLen := len(pt.procCache)
	pt.mu.RUnlock()

	require.LessOrEqual(t, afterTrackedLen, aliveTrackedLen-numChildren, "trackedPIDs map length must shrink after children exit and RefreshSubtree runs")
	require.LessOrEqual(t, afterAncestryLen, aliveAncestryLen-numChildren, "ancestryCache map length must shrink after children exit and RefreshSubtree runs")
	require.LessOrEqual(t, afterProcLen, aliveProcLen-numChildren, "procCache map length must shrink after children exit and RefreshSubtree runs")

	// After RefreshSubtree eviction, exited PIDs must report out-of-scope.
	for _, ck := range childKeys {
		require.False(t, pt.IsInScope(ck.pid), "evicted exited child pid=%d must not be in scope", ck.pid)
		_, inScope := pt.MatchAndEnrich(ck.pid, model.ProcessInfo{PID: ck.pid})
		require.False(t, inScope, "MatchAndEnrich must return false for evicted exited child pid=%d", ck.pid)
	}
}

func TestParseProcStatPPIDAndStartTime_CommWithSpacesAndParens(t *testing.T) {
	// Field 2 (comm) contains spaces and nested parentheses ')'; parser must split after the final ')'.
	statLine := "72 (my (weird) ) worker) S 41 72 41 0 -1 4194304 120 0 0 0 1 2 0 0 20 0 1 0 987654321 1234567 100"
	ppid, startTime := parseProcStatPPIDAndStartTime(statLine)
	require.Equal(t, 41, ppid)
	require.Equal(t, uint64(987654321), startTime)
}
