package collector

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func TestAutoInjectLiveBackoffCapsAttemptsWithinSixSeconds(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer st.Close()
	corr := correlator.NewCorrelator(mon)

	targetPID := os.Getpid()
	col, err := NewCollector(dir, model.ScopeFilter{
		PIDs:    []int{targetPID},
		PIDOnly: true,
	}, corr, st, mon)
	require.NoError(t, err)
	defer ResetInjectBackoff(col)

	// Force live injection to fail deterministically and quickly (no runtimeHooks initialized).
	col.mu.Lock()
	col.runtimeHooks = nil
	col.mu.Unlock()

	// Simulate 6 seconds of 1s periodic ticks (plus initial burst) calling InjectRunningPID concurrently.
	deadline := time.Now().Add(6 * time.Second)
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				_, _ = col.InjectRunningPID(targetPID)
				time.Sleep(250 * time.Millisecond)
			}
		}()
	}
	wg.Wait()

	require.NoError(t, mon.Flush())
	evs, err := mon.QueryEvents(selfmon.Query{
		Stage: selfmon.StageProbe,
		Limit: 500,
	})
	require.NoError(t, err)

	var (
		injectAttempts int
		backoffEvents  int
	)
	for _, ev := range evs {
		if ev.PID != targetPID && ev.Detail["pid"] != float64(targetPID) && ev.Detail["pid"] != targetPID {
			continue
		}
		switch ev.Action {
		case "inject_running_pid":
			if ev.Status == selfmon.StatusError {
				injectAttempts++
			}
		case "inject_backoff":
			backoffEvents++
		}
	}

	t.Logf("6s window: inject_running_pid attempts=%d, inject_backoff events=%d", injectAttempts, backoffEvents)
	require.GreaterOrEqual(t, injectAttempts, 1, "must attempt injection at least once")
	require.LessOrEqual(t, injectAttempts, 3, "within 6 seconds the same PID must not be injected more than 3 times")
	require.GreaterOrEqual(t, backoffEvents, 1, "must record inject_backoff selfmon events")
}
