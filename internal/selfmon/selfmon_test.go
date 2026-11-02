package selfmon

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSelfmonRecordAndQuery(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	m.RecordOK(StageProbe, "attach_uprobe", map[string]any{"lib": "libssl.so.3"})
	m.RecordWarn(StageStream, "half_open_stream", "missing request", nil)
	m.RecordError(StageParser, "parse_json", errors.New("unexpected EOF"), map[string]any{"pid": 99})

	st := m.Stats()
	require.Equal(t, int64(1), st.TotalOK)
	require.Equal(t, int64(1), st.TotalWarn)
	require.Equal(t, int64(1), st.TotalError)
	require.NotNil(t, st.LastError)
	require.Equal(t, "unexpected EOF", st.LastError.Error)

	errEvs, err := m.QueryEvents(Query{Status: StatusError})
	require.NoError(t, err)
	require.Len(t, errEvs, 1)
	require.Equal(t, StageParser, errEvs[0].Stage)
}

func TestSubscribeConcurrentRecordAndCancel(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	const (
		writers     = 8
		subscribers = 16
		iterations  = 300
	)

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				m.RecordWarn(StageStream, "concurrent_warn", "test warn", map[string]any{
					"worker": id,
					"iter":   i,
					"path":   "/v1/chat/completions?key=secret123",
				})
			}
		}(w)
	}

	for s := 0; s < subscribers; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				ch, unsub := m.Subscribe()
				select {
				case <-ch:
				default:
				}
				unsub()
				// Calling unsub multiple times must be idempotent and safe.
				unsub()
			}
		}()
	}

	wg.Wait()
	require.NoError(t, m.Flush())
}

func TestAsyncWriterBatchFlushAndClose(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)

	const total = 600
	for i := 0; i < total; i++ {
		m.RecordOK(StageParser, "parse_chunk", map[string]any{"seq": i})
	}

	require.NoError(t, m.Flush())
	// Idempotent Close / Stop calls from multiple goroutines.
	var closeWg sync.WaitGroup
	for i := 0; i < 4; i++ {
		closeWg.Add(1)
		go func() {
			defer closeWg.Done()
			require.NoError(t, m.Close())
			m.Stop()
		}()
	}
	closeWg.Wait()
	require.NoError(t, m.Flush())

	// Re-open monitor on same dir to verify all events were flushed to disk.
	m2, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m2.Stop()

	st := m2.Stats()
	require.Equal(t, int64(total), st.TotalOK)

	evs, err := m2.QueryEvents(Query{Limit: total + 10})
	require.NoError(t, err)
	require.Len(t, evs, total)
}

func TestAsyncWriterQueueOverflowDropsAndCounts(t *testing.T) {
	dir := t.TempDir()
	const queueCap = 8
	m, err := newMonitor(dir, queueCap, false)
	require.NoError(t, err)

	const totalSent = 20
	for i := 0; i < totalSent; i++ {
		m.RecordWarn(StageStream, "burst_warn", "queue pressure", map[string]any{"idx": i})
	}

	snapBefore := m.Metrics()
	require.Equal(t, queueCap, snapBefore.QueueLength)
	require.Equal(t, queueCap, snapBefore.QueueCapacity)
	require.Equal(t, int64(totalSent-queueCap), snapBefore.DroppedEvents)
	require.Equal(t, int64(totalSent), snapBefore.TotalWarn)
	require.Equal(t, int64(totalSent), snapBefore.ByStage[StageStream].Warn)

	// Start background writer and flush remaining queued events.
	go m.writeLoop()
	require.NoError(t, m.Flush())

	snapAfter := m.Metrics()
	require.Equal(t, 0, snapAfter.QueueLength)
	require.Equal(t, int64(totalSent-queueCap), snapAfter.DroppedEvents)

	// QueryEvents merges disk events with hot memory events so no hot event is lost.
	evs, err := m.QueryEvents(Query{Limit: 50, Stage: StageStream})
	require.NoError(t, err)
	require.Len(t, evs, totalSent)

	require.NoError(t, m.Close())
	// Recording after Close increments DroppedEvents without blocking or panicking.
	m.RecordOK(StageProbe, "after_close", nil)
	require.Equal(t, int64(totalSent-queueCap+1), m.Metrics().DroppedEvents)
}

func TestRedactSensitiveDetailAndFileMode0600(t *testing.T) {
	dir := t.TempDir()
	selfmonDir := filepath.Join(dir, "selfmon")
	require.NoError(t, os.MkdirAll(selfmonDir, 0o755))

	// Pre-create today's jsonl file with permissive 0644 mode to verify it gets tightened to 0600.
	day := time.Now().UTC().Format("2006-01-02")
	jsonlPath := filepath.Join(selfmonDir, day+".jsonl")
	require.NoError(t, os.WriteFile(jsonlPath, nil, 0o644))
	require.NoError(t, os.Chmod(jsonlPath, 0o644))

	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	callerDetail := map[string]any{
		"host":          "generativelanguage.googleapis.com",
		"path":          "/v1beta/models/gemini-pro:streamGenerateContent?alt=sse&key=test_key_val_999",
		"url":           "https://storage.googleapis.com/bucket/obj?X-Goog-Signature=sig_hex_secret&X-Amz-Signature=amz_sig_secret&code=oauth_code_abc&ok=1#" + "access_tok" + "en=test_frag_val_789",
		"api_key":       "sk-direct-secret-value",
		"conn_key":      "42:keep_conn_key",
		"nested":        map[string]any{"endpoint": "/oauth/callback?code=nested_oauth_code&state=123"},
		"redirect_urls": []string{"https://example.com/cb?token=slice_token_xyz&mode=test"},
	}

	ev := m.RecordWarn(StageStream, "unknown_protocol_dropped", "unknown protocol traffic", callerDetail)
	// Caller's original map must not be mutated.
	require.Contains(t, callerDetail["path"], "test_key_val_999")

	// Returned event Detail must be redacted.
	require.Equal(t, "/v1beta/models/gemini-pro:streamGenerateContent?alt=sse&key=[REDACTED]", ev.Detail["path"])
	require.Equal(t, "[REDACTED]", ev.Detail["api_key"])
	require.Equal(t, "42:keep_conn_key", ev.Detail["conn_key"])

	require.NoError(t, m.Flush())

	info, err := os.Stat(jsonlPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "selfmon jsonl file permissions must be 0600")
	}

	rawBytes, err := os.ReadFile(jsonlPath)
	require.NoError(t, err)
	rawContent := string(rawBytes)

	for _, secret := range []string{
		"test_key_val_999",
		"sig_hex_secret",
		"amz_sig_secret",
		"oauth_code_abc",
		"test_frag_val_789",
		"sk-direct-secret-value",
		"nested_oauth_code",
		"slice_token_xyz",
	} {
		require.False(t, strings.Contains(rawContent, secret), "leaked secret %q in selfmon jsonl: %s", secret, rawContent)
	}
	require.Contains(t, rawContent, "key=[REDACTED]")
	require.Contains(t, rawContent, "code=[REDACTED]")
	require.Contains(t, rawContent, "42:keep_conn_key")
}

func TestMetricsSnapshotAndDiskErrors(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	m.RecordOK(StageProbe, "probe_ok", nil)
	m.RecordWarn(StageStream, "stream_warn", "warn1", nil)
	m.RecordError(StageStore, "store_err", errors.New("disk full"), nil)
	require.NoError(t, m.Flush())

	// Create a directory at tomorrow's jsonl path so rotating to tomorrow deterministically fails with EISDIR.
	tomorrow := time.Now().UTC().Add(24 * time.Hour)
	tomorrowDay := tomorrow.Format("2006-01-02")
	badPath := filepath.Join(dir, "selfmon", tomorrowDay+".jsonl")
	require.NoError(t, os.MkdirAll(badPath, 0o755))

	m.Record(Event{
		Timestamp: tomorrow.UnixMilli(),
		Status:    StatusWarn,
		Stage:     StageParser,
		Action:    "parse_warn",
		Error:     "warn2",
	})
	err = m.Flush()
	require.Error(t, err)

	metrics := m.Metrics()
	require.Equal(t, int64(1), metrics.TotalOK)
	require.Equal(t, int64(2), metrics.TotalWarn)
	require.Equal(t, int64(1), metrics.TotalError)
	require.Equal(t, int64(1), metrics.ByStage[StageProbe].OK)
	require.Equal(t, int64(1), metrics.ByStage[StageStream].Warn)
	require.Equal(t, int64(1), metrics.ByStage[StageParser].Warn)
	require.Equal(t, int64(1), metrics.ByStage[StageStore].Error)
	require.GreaterOrEqual(t, metrics.DiskErrors, int64(1))

	st := m.Stats()
	require.Equal(t, metrics.DiskErrors, st.DiskErrors)
	require.Equal(t, metrics.DroppedEvents, st.DroppedEvents)
}

func TestPriorityQuotaPreservesErrorAndWarnWhenOKFloodsQueue(t *testing.T) {
	dir := t.TempDir()
	// Use default queue size (4096) with reserved priority quota (512), writer paused initially.
	m, err := newMonitor(dir, DefaultWriteQueueSize, false)
	require.NoError(t, err)

	normalCap := DefaultWriteQueueSize - DefaultPriorityQueueQuota
	const okFlood = DefaultWriteQueueSize + 1000 // 5096 OK events (> 3584 normal capacity)
	for i := 0; i < okFlood; i++ {
		m.RecordOK(StageStream, "flood_ok", map[string]any{"seq": i})
	}

	snapAfterOK := m.Metrics()
	require.Equal(t, normalCap, snapAfterOK.QueueLength)
	require.Equal(t, DefaultWriteQueueSize, snapAfterOK.QueueCapacity)
	require.Equal(t, int64(okFlood-normalCap), snapAfterOK.DroppedEvents)
	require.Equal(t, int64(okFlood-normalCap), snapAfterOK.DroppedByStatus[StatusOK])
	require.Equal(t, int64(0), snapAfterOK.DroppedByStatus[StatusWarn])
	require.Equal(t, int64(0), snapAfterOK.DroppedByStatus[StatusError])

	// Now record critical warn and error events while the OK queue is 100% full.
	warnEv := m.RecordWarn(StageProbe, "probe_degraded", "uretprobe fallback", map[string]any{"arch": "arm64"})
	errEv := m.RecordError(StageParser, "critical_parse_error", errors.New("corrupted frame"), map[string]any{"conn": "c1"})

	// Flood more OK events after the error event; they must be dropped without affecting the error event.
	for i := 0; i < 500; i++ {
		m.RecordOK(StageStream, "post_error_ok", map[string]any{"seq": i})
	}

	snapBeforeFlush := m.Metrics()
	require.Equal(t, int64(0), snapBeforeFlush.DroppedByStatus[StatusWarn], "warn must use reserved priority quota")
	require.Equal(t, int64(0), snapBeforeFlush.DroppedByStatus[StatusError], "error must use reserved priority quota")
	require.Equal(t, normalCap+2, snapBeforeFlush.QueueLength)

	// Start writer, flush to disk, and close.
	go m.writeLoop()
	require.NoError(t, m.Flush())
	require.NoError(t, m.Close())

	// 1. Query from the original monitor.
	errResults, err := m.QueryEvents(Query{Status: StatusError})
	require.NoError(t, err)
	require.Len(t, errResults, 1)
	require.Equal(t, errEv.ID, errResults[0].ID)
	require.Equal(t, "critical_parse_error", errResults[0].Action)
	require.Equal(t, "corrupted frame", errResults[0].Error)

	// 2. Re-open a fresh Monitor from disk to prove the error/warn events were persisted to the JSONL file.
	m2, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m2.Stop()

	diskErrs, err := m2.QueryEvents(Query{Status: StatusError})
	require.NoError(t, err)
	require.Len(t, diskErrs, 1)
	require.Equal(t, errEv.ID, diskErrs[0].ID)
	require.Equal(t, "corrupted frame", diskErrs[0].Error)

	diskWarns, err := m2.QueryEvents(Query{Status: StatusWarn})
	require.NoError(t, err)
	require.Len(t, diskWarns, 1)
	require.Equal(t, warnEv.ID, diskWarns[0].ID)
}

func TestDroppedByStatusCountsAccurately(t *testing.T) {
	dir := t.TempDir()
	const queueCap = 16 // calcPriorityQuota(16) = 2 -> normalCap = 14, prioCap = 2
	m, err := newMonitor(dir, queueCap, false)
	require.NoError(t, err)

	// 1. Send 20 OK events: 14 queued in writeCh, 6 dropped.
	for i := 0; i < 20; i++ {
		m.RecordOK(StageTracker, "ok_evt", nil)
	}
	// 2. Send 5 Warn events: writeCh is full, so 2 queued in prioCh, 3 dropped.
	for i := 0; i < 5; i++ {
		m.RecordWarn(StageStream, "warn_evt", "w", nil)
	}
	// 3. Send 4 Error events: both writeCh and prioCh are full, so 4 dropped.
	for i := 0; i < 4; i++ {
		m.RecordError(StageStore, "err_evt", errors.New("e"), nil)
	}

	met := m.Metrics()
	require.Equal(t, queueCap, met.QueueLength)
	require.Equal(t, queueCap, met.QueueCapacity)
	require.Equal(t, int64(6), met.DroppedByStatus[StatusOK])
	require.Equal(t, int64(3), met.DroppedByStatus[StatusWarn])
	require.Equal(t, int64(4), met.DroppedByStatus[StatusError])
	require.Equal(t, int64(13), met.DroppedEvents)

	st := m.Stats()
	require.Equal(t, met.DroppedByStatus, st.DroppedByStatus)
	require.Equal(t, int64(13), st.DroppedEvents)

	go m.writeLoop()
	require.NoError(t, m.Flush())
	require.NoError(t, m.Close())

	// Recording after Close also increments per-status drop counters.
	m.RecordError(StageStore, "err_after_close", errors.New("closed"), nil)
	m.RecordWarn(StageStream, "warn_after_close", "closed", nil)
	m.RecordOK(StageProbe, "ok_after_close", nil)

	metAfter := m.Metrics()
	require.Equal(t, int64(7), metAfter.DroppedByStatus[StatusOK])
	require.Equal(t, int64(4), metAfter.DroppedByStatus[StatusWarn])
	require.Equal(t, int64(5), metAfter.DroppedByStatus[StatusError])
	require.Equal(t, int64(16), metAfter.DroppedEvents)
}

func TestQueryEventsHotWindowSkipsFlush(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	var hookCalls atomic.Int64
	m.hookMu.Lock()
	m.onFlush = func() {
		hookCalls.Add(1)
	}
	m.hookMu.Unlock()

	m.RecordOK(StageProbe, "attach", nil)
	m.RecordWarn(StageStream, "slow_stream", "high latency", nil)
	m.RecordError(StageParser, "bad_json", errors.New("syntax error"), nil)

	// 1. Default query (last 10m) is fully covered by the hot window -> 0 Flush calls.
	evs, err := m.QueryEvents(Query{})
	require.NoError(t, err)
	require.Len(t, evs, 3)
	require.Equal(t, int64(0), hookCalls.Load(), "hot-window covered query must not trigger Flush")
	require.Equal(t, int64(0), m.flushCount.Load())
	require.Equal(t, int64(0), m.queryFlushCount.Load())

	// 2. Filtered query in hot window -> 0 Flush calls.
	errEvs, err := m.QueryEvents(Query{Status: StatusError, Stage: StageParser})
	require.NoError(t, err)
	require.Len(t, errEvs, 1)
	require.Equal(t, int64(0), hookCalls.Load())

	// 3. Query with older From but small Limit already satisfied by hot window -> 0 Flush calls.
	limitedEvs, err := m.QueryEvents(Query{
		From:  time.Now().Add(-2 * time.Hour).UnixMilli(),
		Limit: 2,
	})
	require.NoError(t, err)
	require.Len(t, limitedEvs, 2)
	require.Equal(t, int64(0), hookCalls.Load())

	// 4. Query asking for history older than hot window with Limit > hot matches -> triggers Flush once.
	histEvs, err := m.QueryEvents(Query{
		From:  time.Now().Add(-2 * time.Hour).UnixMilli(),
		Limit: 100,
	})
	require.NoError(t, err)
	require.Len(t, histEvs, 3)
	require.Equal(t, int64(1), hookCalls.Load(), "query beyond hot window must trigger Flush")
	require.Equal(t, int64(1), m.queryFlushCount.Load())
}

func TestFlushAndQueryFlushTimeoutDoNotHang(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)

	blockCh := make(chan struct{})
	var unblockOnce sync.Once
	t.Cleanup(func() {
		// require.FailNow can exit before the explicit cleanup below; always
		// release the writer first so Windows can remove the open log file.
		unblockOnce.Do(func() { close(blockCh) })
		_ = m.Close()
	})

	m.mu.Lock()
	m.queryFlushTimeout = 30 * time.Millisecond
	m.mu.Unlock()

	enteredWrite := make(chan struct{}, 1)
	m.hookMu.Lock()
	m.onWriteBatch = func([]Event) {
		select {
		case enteredWrite <- struct{}{}:
		default:
		}
		<-blockCh
	}
	m.hookMu.Unlock()

	// Trigger a batch write that blocks inside writeBatchToDisk.
	m.RecordError(StageStore, "slow_disk_write", errors.New("io stall"), nil)
	<-enteredWrite

	// 1. Direct FlushWithTimeout returns ErrFlushTimeout promptly instead of hanging.
	start := time.Now()
	flushErr := m.FlushWithTimeout(25 * time.Millisecond)
	elapsed := time.Since(start)
	require.ErrorIs(t, flushErr, ErrFlushTimeout)
	require.Less(t, elapsed, 2*time.Second)
	require.GreaterOrEqual(t, m.flushTimeouts.Load(), int64(1))

	// 2. QueryEvents needing disk times out on Flush without hanging and still returns hot events.
	qStart := time.Now()
	evs, qErr := m.QueryEvents(Query{
		From:  time.Now().Add(-2 * time.Hour).UnixMilli(),
		Limit: 50,
	})
	qElapsed := time.Since(qStart)
	require.NoError(t, qErr)
	require.Less(t, qElapsed, 2*time.Second)
	require.Len(t, evs, 1)
	require.Equal(t, "slow_disk_write", evs[0].Action)
	require.GreaterOrEqual(t, m.flushTimeouts.Load(), int64(2))

	// Unblock writer and verify clean shutdown.
	unblockOnce.Do(func() { close(blockCh) })
	require.NoError(t, m.FlushWithTimeout(time.Second))
}

func TestRedactSensitivePathReplacesHomeDirWithTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	require.NotEmpty(t, home)

	require.Equal(t, "~", RedactSensitivePath(home))
	require.Equal(t, "~/.cache/llm-tracer/selfmon/2026-11-02.jsonl?token=[REDACTED]",
		RedactSensitivePath(home+"/.cache/llm-tracer/selfmon/2026-11-02.jsonl?token=my_secret_tok"))
	require.Equal(t, "file://~/.config/gcloud/application_default_credentials.json",
		RedactSensitivePath("file://"+home+"/.config/gcloud/application_default_credentials.json"))
	// Sibling path sharing prefix but not directory boundary must not be altered.
	sibling := home + "_other/secret/file.txt"
	require.Equal(t, sibling, RedactSensitivePath(sibling))

	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	ev := m.RecordOK(StageProbe, "build_ssl_hook", map[string]any{
		"so_path":   home + "/.cache/llm-tracer/hooks/libssl_hook.so",
		"sock_path": home + "/.cache/llm-tracer/run/collector.sock?key=abc",
	})
	require.Equal(t, "~/.cache/llm-tracer/hooks/libssl_hook.so", ev.Detail["so_path"])
	require.Equal(t, "~/.cache/llm-tracer/run/collector.sock?key=[REDACTED]", ev.Detail["sock_path"])
}

func TestSelfHealReopensRemovedOrReplacedLogFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows: windows mandatory file locks disallow removing an open log file")
	}
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	day := time.Now().UTC().Format("2006-01-02")
	jsonlPath := filepath.Join(dir, "selfmon", day+".jsonl")

	// 1. Normal writes without external removal/replacement must NOT reopen the log file.
	for i := 0; i < 5; i++ {
		m.RecordOK(StageProbe, "initial_event", map[string]any{"seq": i})
	}
	require.NoError(t, m.Flush())
	for i := 5; i < 10; i++ {
		m.RecordOK(StageTracker, "steady_state_event", map[string]any{"seq": i})
	}
	require.NoError(t, m.Flush())
	require.Equal(t, int64(0), m.ReopenCount(), "normal writes must not reopen the active log file")

	warnsBefore, err := m.QueryEvents(Query{Status: StatusWarn})
	require.NoError(t, err)
	require.Empty(t, warnsBefore, "no selfmon_logfile_reopened warning should be emitted during normal writes")

	// 2. External removal (simulating Store.Clean with IncludeSelfmon=true removing today's .jsonl).
	require.NoError(t, os.Remove(jsonlPath))
	_, statErr := os.Stat(jsonlPath)
	require.True(t, os.IsNotExist(statErr))

	evAfterRemove1 := m.RecordOK(StageParser, "after_remove_ok", map[string]any{"step": 1})
	evAfterRemove2 := m.RecordError(StageStore, "after_remove_err", errors.New("post-clean error"), map[string]any{"step": 2})
	require.NoError(t, m.Flush())

	infoAfterRemove, err := os.Stat(jsonlPath)
	require.NoError(t, err, "today's .jsonl must be recreated on disk after self-heal")
	require.Equal(t, os.FileMode(0o600), infoAfterRemove.Mode().Perm())
	require.Equal(t, int64(1), m.ReopenCount(), "removing active .jsonl must trigger exactly 1 reopen")

	rawAfterRemoveBytes, err := os.ReadFile(jsonlPath)
	require.NoError(t, err)
	rawAfterRemove := string(rawAfterRemoveBytes)
	require.Contains(t, rawAfterRemove, evAfterRemove1.ID)
	require.Contains(t, rawAfterRemove, "after_remove_ok")
	require.Contains(t, rawAfterRemove, evAfterRemove2.ID)
	require.Contains(t, rawAfterRemove, "after_remove_err")
	require.Contains(t, rawAfterRemove, "selfmon_logfile_reopened")
	require.Contains(t, rawAfterRemove, "logfile_missing")

	// Verify the selfmon_logfile_reopened warn event is observable via QueryEvents and Stats.
	warnsAfterRemove, err := m.QueryEvents(Query{Status: StatusWarn})
	require.NoError(t, err)
	require.Len(t, warnsAfterRemove, 1)
	require.Equal(t, "selfmon_logfile_reopened", warnsAfterRemove[0].Action)
	require.Equal(t, StageStore, warnsAfterRemove[0].Stage)
	require.Equal(t, "logfile_missing", warnsAfterRemove[0].Detail["reason"])
	require.Equal(t, int64(1), m.Stats().TotalWarn)

	// Subsequent normal write after self-heal must not reopen again.
	m.RecordOK(StageProbe, "steady_after_reopen", nil)
	require.NoError(t, m.Flush())
	require.Equal(t, int64(1), m.ReopenCount())

	// 3. External file replacement (removed and recreated with a new inode at the same path).
	seedLine := `{"id":"sm_external_seed","ts":1700000000000,"status":"ok","stage":"probe","action":"external_seed"}` + "\n"
	require.NoError(t, os.Remove(jsonlPath))
	require.NoError(t, os.WriteFile(jsonlPath, []byte(seedLine), 0o600))
	infoReplaced, err := os.Stat(jsonlPath)
	require.NoError(t, err)
	require.False(t, os.SameFile(infoAfterRemove, infoReplaced), "replaced file must have a different underlying file identity/inode")

	evAfterReplace := m.RecordOK(StageCorrelator, "after_replace_ok", map[string]any{"step": 3})
	require.NoError(t, m.Flush())

	require.Equal(t, int64(2), m.ReopenCount(), "replacing active .jsonl with new inode must trigger reopen")

	rawAfterReplaceBytes, err := os.ReadFile(jsonlPath)
	require.NoError(t, err)
	rawAfterReplace := string(rawAfterReplaceBytes)
	require.Contains(t, rawAfterReplace, "external_seed", "existing content of replaced file must be preserved via O_APPEND")
	require.Contains(t, rawAfterReplace, evAfterReplace.ID, "subsequent events must be written to the replaced file on disk")
	require.Contains(t, rawAfterReplace, "after_replace_ok")
	require.Contains(t, rawAfterReplace, "selfmon_logfile_reopened")
	require.Contains(t, rawAfterReplace, "logfile_replaced")

	warnsAfterReplace, err := m.QueryEvents(Query{Status: StatusWarn})
	require.NoError(t, err)
	require.Len(t, warnsAfterReplace, 2)
	var reasons []any
	for _, w := range warnsAfterReplace {
		require.Equal(t, "selfmon_logfile_reopened", w.Action)
		reasons = append(reasons, w.Detail["reason"])
	}
	require.ElementsMatch(t, []any{"logfile_missing", "logfile_replaced"}, reasons)
}

func TestHotWindowFullEvictsOKBeforeWarnAndError(t *testing.T) {
	dir := t.TempDir()
	m, err := newMonitor(dir, DefaultWriteQueueSize, false)
	require.NoError(t, err)

	m.mu.Lock()
	m.queryFlushTimeout = 5 * time.Millisecond
	maxHot := m.maxHot
	m.mu.Unlock()
	require.Equal(t, 4096, maxHot)

	// Place warn and error events at the very head of hotEvents (indices 0 and 1).
	earlyWarn := m.RecordWarn(StageProbe, "early_head_warn", "head warn must survive hot window eviction", map[string]any{"pos": 0})
	earlyErr := m.RecordError(StageParser, "early_head_error", errors.New("head error must survive hot window eviction"), map[string]any{"pos": 1})

	// Flood 5000 StatusOK events (> maxHot=4096 and > normalCap=3584) so hotEvents overflows 906 times
	// while earlyWarn and earlyErr sit at the front of hotEvents.
	const okBatch1 = 5000
	for i := 0; i < okBatch1; i++ {
		m.RecordOK(StageStream, "flood_ok_batch1", map[string]any{"seq": i})
	}

	// Record additional warn and error when writeCh is full (routed to prioCh), then 100 more OK events.
	lateWarn := m.RecordWarn(StageTracker, "late_warn", "late warn in hot window", nil)
	lateErr := m.RecordError(StageStore, "late_error", errors.New("late error in hot window"), nil)
	const okBatch2 = 100
	for i := 0; i < okBatch2; i++ {
		m.RecordOK(StageStream, "flood_ok_batch2", map[string]any{"seq": okBatch1 + i})
	}

	// Verify DroppedByStatus counters: writeCh (3584) took earlyWarn + earlyErr + 3582 OKs;
	// remaining (5100 - 3582 = 1518) OKs were dropped, while lateWarn + lateErr entered prioCh (0 dropped).
	normalCap := DefaultWriteQueueSize - DefaultPriorityQueueQuota
	expectedDroppedOK := int64(okBatch1 + okBatch2 - (normalCap - 2))
	met := m.Metrics()
	require.Equal(t, expectedDroppedOK, met.DroppedByStatus[StatusOK])
	require.Equal(t, int64(0), met.DroppedByStatus[StatusWarn])
	require.Equal(t, int64(0), met.DroppedByStatus[StatusError])
	require.Equal(t, expectedDroppedOK, met.DroppedEvents)
	require.Equal(t, met.DroppedByStatus, m.Stats().DroppedByStatus)

	// Verify hotEvents (len == 4096) kept earlyWarn and earlyErr at the head and evicted StatusOK events instead.
	m.mu.RLock()
	hotSnapshot := append([]Event(nil), m.hotEvents...)
	m.mu.RUnlock()
	require.Len(t, hotSnapshot, maxHot)
	require.Equal(t, earlyWarn.ID, hotSnapshot[0].ID, "head StatusWarn must not be evicted when StatusOK events exist")
	require.Equal(t, earlyErr.ID, hotSnapshot[1].ID, "head StatusError must not be evicted when StatusOK events exist")

	// Verify QueryEvents (before writer starts, so disk is empty and only hotEvents is available) returns both warns and errors.
	warns, err := m.QueryEvents(Query{Status: StatusWarn, Limit: 10})
	require.NoError(t, err)
	require.Len(t, warns, 2)
	require.ElementsMatch(t, []string{earlyWarn.ID, lateWarn.ID}, []string{warns[0].ID, warns[1].ID})

	errs, err := m.QueryEvents(Query{Status: StatusError, Limit: 10})
	require.NoError(t, err)
	require.Len(t, errs, 2)
	require.ElementsMatch(t, []string{earlyErr.ID, lateErr.ID}, []string{errs[0].ID, errs[1].ID})

	go m.writeLoop()
	require.NoError(t, m.Flush())
	require.NoError(t, m.Close())
}
