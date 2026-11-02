package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
)

func TestStore10MinuteWindowAndClean(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	st, err := NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	now := time.Now()
	oldTs := now.Add(-45 * time.Minute).UnixMilli()
	recentTs := now.Add(-2 * time.Minute).UnixMilli()

	// Save an old session (45 minutes ago)
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:        "ev_old",
		SessionID: "sess_old",
		Timestamp: oldTs,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
		Process:   model.ProcessInfo{PID: 111, Comm: "old-proc"},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "old message 45m ago"}},
			ResponseText: "old reply",
		},
	})
	require.NoError(t, err)

	// Save a recent session (2 minutes ago)
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:        "ev_recent",
		SessionID: "sess_recent",
		Timestamp: recentTs,
		Status:    "ok",
		Protocol:  model.ProtocolSystemOne,
		Process:   model.ProcessInfo{PID: 222, Comm: "jev"},
		SystemOne: &model.SystemOneStepSummary{
			Model:      "jev-latest",
			Goal:       "recent goal",
			SelectedOp: "CLICK",
		},
	})
	require.NoError(t, err)

	// Re-open store to verify cold startup only pre-loads the 10-minute hot window
	st2, err := NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st2.Close() })

	// 1. Default query (no from/to) MUST only return sessions within the 10-minute window
	defaultSessions, err := st2.QuerySessions(SessionQuery{})
	require.NoError(t, err)
	require.Len(t, defaultSessions, 1)
	require.Equal(t, "sess_recent", defaultSessions[0].ID)

	// 2. Sliding the timeline to [now - 60m, now] dynamically loads the older session & events from disk
	slidSessions, err := st2.QuerySessions(SessionQuery{
		From: now.Add(-60 * time.Minute).UnixMilli(),
		To:   now.UnixMilli(),
	})
	require.NoError(t, err)
	require.Len(t, slidSessions, 2)

	oldEvents, err := st2.QuerySessionEvents(EventQuery{
		SessionID: "sess_old",
		From:      now.Add(-60 * time.Minute).UnixMilli(),
		To:        now.UnixMilli(),
	})
	require.NoError(t, err)
	require.Len(t, oldEvents, 1)
	require.Equal(t, "old reply", oldEvents[0].Chat.ResponseText)

	// 3. Test Dry-Run and Clean older than 20 minutes
	dryRep, err := st2.Clean(CleanOptions{
		OlderThan: 20 * time.Minute,
		DryRun:    true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, dryRep.DeletedSessions)
	require.Greater(t, dryRep.FreedBytes, int64(0))

	cleanRep, err := st2.Clean(CleanOptions{
		OlderThan: 20 * time.Minute,
		DryRun:    false,
	})
	require.NoError(t, err)
	require.Equal(t, 1, cleanRep.DeletedSessions)

	allAfterClean, err := st2.QuerySessions(SessionQuery{
		From: now.Add(-60 * time.Minute).UnixMilli(),
		To:   now.UnixMilli(),
	})
	require.NoError(t, err)
	require.Len(t, allAfterClean, 1)
	require.Equal(t, "sess_recent", allAfterClean[0].ID)
}

func TestEvictExpiredHotEvents(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)

	st, err := NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer st.Close()

	baseNow := time.Now()
	expiredTs := baseNow.Add(-15 * time.Minute).UnixMilli()
	recentTs := baseNow.Add(-2 * time.Minute).UnixMilli()

	// Session 1: only expired event -> map key must be deleted after EvictExpiredHot
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:        "ev_s1_old",
		SessionID: "sess_expired",
		Timestamp: expiredTs,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
		Chat:      &model.ChatSummary{Model: "gpt-4o", ResponseText: "persisted on disk"},
	})
	require.NoError(t, err)

	// Session 2: one expired event + one recent event -> only expired event removed
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:        "ev_s2_old",
		SessionID: "sess_mixed",
		Timestamp: expiredTs,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
	})
	require.NoError(t, err)
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:        "ev_s2_new",
		SessionID: "sess_mixed",
		Timestamp: recentTs,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
	})
	require.NoError(t, err)

	evicted := st.EvictExpiredHot(baseNow)
	require.Equal(t, 2, evicted)

	st.mu.RLock()
	_, hasExpiredKey := st.hotEvents["sess_expired"]
	mixedHot := st.hotEvents["sess_mixed"]
	_, hasExpiredSummary := st.sessions["sess_expired"]
	st.mu.RUnlock()

	require.False(t, hasExpiredKey, "session with empty hot events must be removed from hotEvents map")
	require.True(t, hasExpiredSummary, "session summary must remain in sessions index")
	require.Len(t, mixedHot, 1)
	require.Equal(t, "ev_s2_new", mixedHot[0].ID)

	// Disk lazy-loading still works for the evicted session
	diskEvs, err := st.QuerySessionEvents(EventQuery{
		SessionID: "sess_expired",
		From:      baseNow.Add(-30 * time.Minute).UnixMilli(),
		To:        baseNow.UnixMilli(),
	})
	require.NoError(t, err)
	require.Len(t, diskEvs, 1)
	require.Equal(t, "persisted on disk", diskEvs[0].Chat.ResponseText)

	// Close/Stop idempotency via sync.Once
	require.NoError(t, st.Close())
	st.Stop()
}

func TestIncrementalTotalsStreamingToFinal(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	nowMs := time.Now().UnixMilli()

	// Event 1: completed normal event
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_1",
		SessionID:  "sess_inc",
		Timestamp:  nowMs,
		DurationMs: 100,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 20},
		},
	})
	require.NoError(t, err)

	// Event 2: streaming chunk 1
	ev2 := &model.TraceEvent{
		ID:         "ev_2",
		SessionID:  "sess_inc",
		Timestamp:  nowMs + 10,
		DurationMs: 40,
		Status:     "streaming",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 5},
		},
	}
	sum, err := st.SaveEvent(ev2)
	require.NoError(t, err)
	require.Equal(t, 2, sum.EventCount)
	require.Equal(t, 25, sum.TotalTokens)
	require.Equal(t, int64(140), sum.TotalDurationMs)
	require.Equal(t, 0, sum.ErrorCount)

	// Event 2: streaming chunk 2 (in-place update on same pointer to also test defensive snapshot)
	ev2.DurationMs = 90
	ev2.Chat.Usage.TotalTokens = 15
	sum, err = st.SaveEvent(ev2)
	require.NoError(t, err)
	require.Equal(t, 2, sum.EventCount)
	require.Equal(t, 35, sum.TotalTokens)
	require.Equal(t, int64(190), sum.TotalDurationMs)
	require.Equal(t, 0, sum.ErrorCount)

	// Event 2: final update (transitions to error with final token & duration totals)
	ev2.Status = "error"
	ev2.Error = "upstream reset"
	ev2.DurationMs = 250
	ev2.Chat.Usage.TotalTokens = 50
	sum, err = st.SaveEvent(ev2)
	require.NoError(t, err)
	require.Equal(t, 2, sum.EventCount)
	require.Equal(t, 70, sum.TotalTokens)
	require.Equal(t, int64(350), sum.TotalDurationMs)
	require.Equal(t, 1, sum.ErrorCount)
}

func TestIndexJSONLCompactionAndRecovery(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	nowMs := time.Now().UnixMilli()
	for i := 0; i < 100; i++ {
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("ev_%03d", i),
			SessionID:  "sess_bulk",
			Timestamp:  nowMs + int64(i),
			DurationMs: 10,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o-mini",
				Usage: model.TokenUsage{TotalTokens: 3},
			},
		})
		require.NoError(t, err)
	}

	// Redundant index.jsonl must no longer be created; recovery works directly from session.json without requiring Close().
	_, statErr := os.Stat(filepath.Join(dir, "index.jsonl"))
	require.True(t, os.IsNotExist(statErr), "redundant index.jsonl should not be generated")

	// Re-open store on the same directory and verify recovery via QuerySessions
	st2, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st2.Close()

	sessions, err := st2.QuerySessions(SessionQuery{})
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "sess_bulk", sessions[0].ID)
	require.Equal(t, 100, sessions[0].EventCount)
	require.Equal(t, 300, sessions[0].TotalTokens)
}

func TestSubscribeUnsubscribeConcurrentRace(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	const (
		subscriberWorkers = 16
		subIterations     = 80
		writerWorkers     = 8
		writeIterations   = 80
	)

	var wg sync.WaitGroup
	stopSubscribers := make(chan struct{})

	// N subscriber goroutines repeatedly subscribing, reading a few updates, and unsubscribing
	for i := 0; i < subscriberWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < subIterations; j++ {
				ch, unsub := st.Subscribe()
				select {
				case <-ch:
				case <-stopSubscribers:
				default:
				}
				unsub()
				// Calling unsub multiple times must also be safe
				unsub()
			}
		}(i)
	}

	// M writer goroutines concurrently broadcasting events via SaveEvent
	var writerWg sync.WaitGroup
	baseTs := time.Now().UnixMilli()
	for w := 0; w < writerWorkers; w++ {
		writerWg.Add(1)
		go func(writerID int) {
			defer writerWg.Done()
			sessID := fmt.Sprintf("sess_race_%d", writerID%3)
			for k := 0; k < writeIterations; k++ {
				status := "streaming"
				if k%2 == 1 {
					status = "ok"
				}
				_, saveErr := st.SaveEvent(&model.TraceEvent{
					ID:         fmt.Sprintf("ev_%d_%d", writerID, k/2),
					SessionID:  sessID,
					Timestamp:  baseTs + int64(k),
					DurationMs: 15,
					Status:     status,
					Protocol:   model.ProtocolOpenAIChat,
					Chat: &model.ChatSummary{
						Model: "gpt-4o",
						Usage: model.TokenUsage{TotalTokens: 10},
					},
				})
				require.NoError(t, saveErr)
			}
		}(w)
	}

	writerWg.Wait()
	close(stopSubscribers)
	wg.Wait()
}

func TestIncrementalTotalsEvictReplayRestartAndClean(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	baseNow := time.Now()
	oldTs := baseNow.Add(-20 * time.Minute).UnixMilli()

	// 1. Update after hot-window eviction:
	// First write an event with initial tokens=10, then evict it from hotEvents, then write final tokens=100.
	sum, err := st.SaveEvent(&model.TraceEvent{
		ID:         "ev_evicted_1",
		SessionID:  "sess_evict_update",
		TurnIndex:  1,
		Timestamp:  oldTs,
		DurationMs: 30,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 10},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, sum.EventCount)
	require.Equal(t, 10, sum.TotalTokens)
	require.Equal(t, 1, sum.TurnCount)

	evicted := st.EvictExpiredHot(baseNow)
	require.Equal(t, 1, evicted)
	st.mu.RLock()
	_, stillHot := st.hotEvents["sess_evict_update"]
	st.mu.RUnlock()
	require.False(t, stillHot, "event must be evicted from hotEvents before final update")

	// Final update for the same ID after eviction must NOT double-count EventCount, TurnCount, or TotalTokens.
	sum, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_evicted_1",
		SessionID:  "sess_evict_update",
		TurnIndex:  1,
		Timestamp:  oldTs,
		DurationMs: 120,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 100},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, sum.EventCount)
	require.Equal(t, 100, sum.TotalTokens)
	require.Equal(t, 1, sum.TurnCount)
	require.Equal(t, int64(120), sum.TotalDurationMs)

	// 2. Same-ID replay (both in-hot and after eviction) must be idempotent.
	sum, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_evicted_1",
		SessionID:  "sess_evict_update",
		TurnIndex:  1,
		Timestamp:  oldTs,
		DurationMs: 120,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 100},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, sum.EventCount)
	require.Equal(t, 100, sum.TotalTokens)
	require.Equal(t, 1, sum.TurnCount)
	require.Equal(t, int64(120), sum.TotalDurationMs)

	// 3. Restart (new Store on same directory) and update cold/evicted event:
	// Since oldTs is 20m ago (> 10m hotWindow), st2 cold startup will NOT preload hotEvents for sess_evict_update.
	st2, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st2.Close()

	st2.mu.RLock()
	_, preloadedInSt2 := st2.hotEvents["sess_evict_update"]
	st2.mu.RUnlock()
	require.False(t, preloadedInSt2, "cold session outside hotWindow should not have preloaded hotEvents")

	// Updating the existing event on st2 must lazy-load contributions from events.jsonl and avoid double-counting.
	sumAfterRestart, err := st2.SaveEvent(&model.TraceEvent{
		ID:         "ev_evicted_1",
		SessionID:  "sess_evict_update",
		TurnIndex:  1,
		Timestamp:  oldTs,
		DurationMs: 150,
		Status:     "error",
		Error:      "timeout",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 130},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, sumAfterRestart.EventCount)
	require.Equal(t, 130, sumAfterRestart.TotalTokens)
	require.Equal(t, 1, sumAfterRestart.TurnCount)
	require.Equal(t, int64(150), sumAfterRestart.TotalDurationMs)
	require.Equal(t, 1, sumAfterRestart.ErrorCount)

	// 4. Clean and re-write with the same session & event ID must start fresh from 1.
	cleanRep, err := st2.Clean(CleanOptions{All: true})
	require.NoError(t, err)
	require.Equal(t, 1, cleanRep.DeletedSessions)

	sumFresh, err := st2.SaveEvent(&model.TraceEvent{
		ID:         "ev_evicted_1",
		SessionID:  "sess_evict_update",
		TurnIndex:  1,
		Timestamp:  baseNow.UnixMilli(),
		DurationMs: 45,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-5",
			Usage: model.TokenUsage{TotalTokens: 60},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 1, sumFresh.EventCount)
	require.Equal(t, 60, sumFresh.TotalTokens)
	require.Equal(t, 1, sumFresh.TurnCount)
	require.Equal(t, int64(45), sumFresh.TotalDurationMs)
	require.Equal(t, 0, sumFresh.ErrorCount)
}

func TestSessionContribTrackerCapFallback(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	baseNow := time.Now()
	oldTs := baseNow.Add(-30 * time.Minute).UnixMilli()

	// Write maxSessionTrackedEvents + 10 events so tracker overflows its in-memory cap
	totalEvents := maxSessionTrackedEvents + 10
	for i := 0; i < totalEvents; i++ {
		status := "streaming"
		if i < 5 || i >= totalEvents-5 {
			status = "ok"
		}
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("ev_cap_%d", i),
			SessionID:  "sess_cap",
			Timestamp:  oldTs + int64(i),
			DurationMs: 5,
			Status:     status,
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o-mini",
				Usage: model.TokenUsage{TotalTokens: 2},
			},
		})
		require.NoError(t, err)
	}

	st.EvictExpiredHot(baseNow)

	st.mu.RLock()
	tracker := st.sessionContribs["sess_cap"]
	require.NotNil(t, tracker)
	require.True(t, tracker.overflowed, "tracker must mark overflowed when exceeding cap")
	require.LessOrEqual(t, len(tracker.byID), maxSessionTrackedEvents, "in-memory contrib map must be bounded by maxSessionTrackedEvents")
	// Force-evict ev_cap_0 from tracker.byID to deterministically test disk fallback
	delete(tracker.byID, "ev_cap_0")
	st.mu.RUnlock()

	// Updating ev_cap_0 (from 2 tokens to 12 tokens) must fall back to events.jsonl and NOT increment EventCount
	sum, err := st.SaveEvent(&model.TraceEvent{
		ID:         "ev_cap_0",
		SessionID:  "sess_cap",
		Timestamp:  oldTs,
		DurationMs: 15,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o-mini",
			Usage: model.TokenUsage{TotalTokens: 12},
		},
	})
	require.NoError(t, err)
	require.Equal(t, totalEvents, sum.EventCount)
	require.Equal(t, totalEvents*2+10, sum.TotalTokens)
	require.Equal(t, int64(totalEvents*5+10), sum.TotalDurationMs)
}

func TestStreamingEventNotEvictedAndPersistedOnTerminal(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	baseNow := time.Now()
	expiredTs := baseNow.Add(-25 * time.Minute).UnixMilli()

	// Save two streaming events whose timestamps are older than hotWindow
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_stream_incomplete",
		SessionID:  "sess_stream_persist",
		TurnIndex:  1,
		Timestamp:  expiredTs,
		DurationMs: 50,
		Status:     "streaming",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model:        "gpt-5",
			ResponseText: "partial chunk",
			Usage:        model.TokenUsage{TotalTokens: 12},
		},
	})
	require.NoError(t, err)

	_, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_stream_err",
		SessionID:  "sess_stream_persist",
		TurnIndex:  2,
		Timestamp:  expiredTs + 100,
		DurationMs: 60,
		Status:     "streaming",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model:        "gpt-5",
			ResponseText: "partial before error",
			Usage:        model.TokenUsage{TotalTokens: 8},
		},
	})
	require.NoError(t, err)

	// EvictExpiredHot MUST NOT evict status=="streaming" events even if Timestamp < cutoff
	evicted := st.EvictExpiredHot(baseNow)
	require.Equal(t, 0, evicted, "streaming events must never be evicted from hotEvents")

	st.mu.RLock()
	hotList := st.hotEvents["sess_stream_persist"]
	st.mu.RUnlock()
	require.Len(t, hotList, 2)

	// Transition first streaming event to "incomplete" terminal status -> must persist to disk and update totals in-place
	sum, err := st.SaveEvent(&model.TraceEvent{
		ID:         "ev_stream_incomplete",
		SessionID:  "sess_stream_persist",
		TurnIndex:  1,
		Timestamp:  expiredTs,
		DurationMs: 300,
		Status:     "incomplete",
		Error:      "EOF before stream completion",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model:        "gpt-5",
			ResponseText: "partial chunk preserved",
			Usage:        model.TokenUsage{TotalTokens: 40},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 2, sum.EventCount)
	require.Equal(t, 48, sum.TotalTokens)
	require.Equal(t, int64(360), sum.TotalDurationMs)
	require.Equal(t, 1, sum.ErrorCount)

	// Transition second streaming event to "error" terminal status -> must also persist to disk
	sum, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_stream_err",
		SessionID:  "sess_stream_persist",
		TurnIndex:  2,
		Timestamp:  expiredTs + 100,
		DurationMs: 400,
		Status:     "error",
		Error:      "connection reset",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model:        "gpt-5",
			ResponseText: "partial before error",
			Usage:        model.TokenUsage{TotalTokens: 20},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 2, sum.EventCount)
	require.Equal(t, 60, sum.TotalTokens)
	require.Equal(t, int64(700), sum.TotalDurationMs)
	require.Equal(t, 2, sum.ErrorCount)

	// Now that both events are in terminal states and older than hotWindow, EvictExpiredHot can evict them from memory
	evictedAfterTerminal := st.EvictExpiredHot(baseNow)
	require.Equal(t, 2, evictedAfterTerminal)

	// Verify both terminal events were persisted to disk and can be queried back
	persistedEvs, err := st.QuerySessionEvents(EventQuery{
		SessionID: "sess_stream_persist",
		From:      expiredTs - 1000,
		To:        baseNow.UnixMilli(),
	})
	require.NoError(t, err)
	require.Len(t, persistedEvs, 2)
	require.Equal(t, "incomplete", persistedEvs[0].Status)
	require.Equal(t, "partial chunk preserved", persistedEvs[0].Chat.ResponseText)
	require.Equal(t, "error", persistedEvs[1].Status)
}

func TestCloneEventForHotDeepCopy(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	nowMs := time.Now().UnixMilli()
	orig := &model.TraceEvent{
		ID:              "ev_deep",
		SessionID:       "sess_deep",
		Timestamp:       nowMs,
		Status:          "streaming",
		Protocol:        model.ProtocolSystemOne,
		HeadersRecorded: true,
		RequestHeaders:  map[string]string{"X-Trace": "orig-req"},
		ResponseHeaders: map[string]string{"X-Resp": "orig-resp"},
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Messages: []model.ChatMessage{
				{
					Role:      "assistant",
					Content:   "hello",
					ToolCalls: []model.ToolCallItem{{ID: "tc_1", Name: "read_file"}},
				},
			},
			NewMessages: []model.ChatMessage{
				{Role: "user", Content: "question"},
			},
			ToolCalls: []model.ToolCallItem{{ID: "tc_top", Name: "exec"}},
		},
		SystemOne: &model.SystemOneStepSummary{
			Model:         "s1-v1",
			Goal:          "orig-goal",
			RecentActions: []map[string]any{{"op": "CLICK", "nested": []string{"a", "b"}}},
			Questions: []model.SystemOneQuestion{
				{
					ID:          "q1",
					Guides:      []string{"g1"},
					Options:     map[string]string{"A": "optA"},
					OptionOrder: []string{"A"},
					Probs:       map[string]float64{"A": 0.9},
				},
			},
			QuestionsUsed: []string{"q1"},
		},
	}

	_, err = st.SaveEvent(orig)
	require.NoError(t, err)

	// Mutate caller's nested slices and maps in place after SaveEvent
	orig.RequestHeaders["X-Trace"] = "mutated-req"
	orig.ResponseHeaders["X-Resp"] = "mutated-resp"
	orig.Chat.Messages[0].Content = "mutated-content"
	orig.Chat.Messages[0].ToolCalls[0].Name = "mutated_tool"
	orig.Chat.NewMessages[0].Content = "mutated-new"
	orig.Chat.ToolCalls[0].Name = "mutated_top"
	orig.SystemOne.RecentActions[0]["op"] = "MUTATED"
	orig.SystemOne.RecentActions[0]["nested"].([]string)[0] = "z"
	orig.SystemOne.Questions[0].Guides[0] = "mutated-guide"
	orig.SystemOne.Questions[0].Options["A"] = "mutated-opt"
	orig.SystemOne.Questions[0].OptionOrder[0] = "B"
	orig.SystemOne.Questions[0].Probs["A"] = 0.1
	orig.SystemOne.QuestionsUsed[0] = "mutated-q"

	evs, err := st.QuerySessionEvents(EventQuery{SessionID: "sess_deep"})
	require.NoError(t, err)
	require.Len(t, evs, 1)
	got := evs[0]

	require.Equal(t, "orig-req", got.RequestHeaders["X-Trace"])
	require.Equal(t, "orig-resp", got.ResponseHeaders["X-Resp"])
	require.Equal(t, "hello", got.Chat.Messages[0].Content)
	require.Equal(t, "read_file", got.Chat.Messages[0].ToolCalls[0].Name)
	require.Equal(t, "question", got.Chat.NewMessages[0].Content)
	require.Equal(t, "exec", got.Chat.ToolCalls[0].Name)
	require.Equal(t, "CLICK", got.SystemOne.RecentActions[0]["op"])
	require.Equal(t, "a", got.SystemOne.RecentActions[0]["nested"].([]string)[0])
	require.Equal(t, "g1", got.SystemOne.Questions[0].Guides[0])
	require.Equal(t, "optA", got.SystemOne.Questions[0].Options["A"])
	require.Equal(t, "A", got.SystemOne.Questions[0].OptionOrder[0])
	require.InDelta(t, 0.9, got.SystemOne.Questions[0].Probs["A"], 1e-6)
	require.Equal(t, "q1", got.SystemOne.QuestionsUsed[0])
}

func TestOverflowSaveEventLatency(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	baseTs := time.Now().UnixMilli()
	const (
		preOverflowEvents  = maxSessionTrackedEvents // 4096
		postOverflowEvents = 300
	)

	preStart := time.Now()
	for i := 0; i < preOverflowEvents; i++ {
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("ev_perf_%d", i),
			SessionID:  "sess_overflow_perf",
			TurnIndex:  i + 1,
			Timestamp:  baseTs + int64(i),
			DurationMs: 5,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o-mini",
				Usage: model.TokenUsage{TotalTokens: 3},
			},
		})
		require.NoError(t, err)
	}
	preElapsed := time.Since(preStart)
	preAvg := preElapsed / preOverflowEvents

	postStart := time.Now()
	for i := preOverflowEvents; i < preOverflowEvents+postOverflowEvents; i++ {
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("ev_perf_%d", i),
			SessionID:  "sess_overflow_perf",
			TurnIndex:  i + 1,
			Timestamp:  baseTs + int64(i),
			DurationMs: 5,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o-mini",
				Usage: model.TokenUsage{TotalTokens: 3},
			},
		})
		require.NoError(t, err)
	}
	postElapsed := time.Since(postStart)
	postAvg := postElapsed / postOverflowEvents

	ratio := float64(postAvg) / float64(maxDuration(preAvg, time.Microsecond))
	t.Logf("SaveEvent latency: pre-overflow avg=%v (%d events in %v), post-overflow avg=%v (%d events in %v), ratio=%.2fx",
		preAvg, preOverflowEvents, preElapsed, postAvg, postOverflowEvents, postElapsed, ratio)

	baseline := maxDuration(preAvg, 250*time.Microsecond)
	require.LessOrEqual(t, postAvg, baseline*4, "post-overflow SaveEvent latency must not degrade relative to pre-overflow")
	require.Less(t, postAvg, 5*time.Millisecond, "post-overflow SaveEvent average latency must stay well below disk-scan levels")

	sess, ok := st.GetSession("sess_overflow_perf")
	require.True(t, ok)
	require.Equal(t, preOverflowEvents+postOverflowEvents, sess.EventCount)
	require.Equal(t, (preOverflowEvents+postOverflowEvents)*3, sess.TotalTokens)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func TestDuplicateEventIDDedupeAndLRU(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	baseNow := time.Now()
	oldTs := baseNow.Add(-25 * time.Minute).UnixMilli()

	// 1. Verify configurable LRU capacity and LRU eviction order on a dedicated session
	st.SetMaxTrackedEvents(4)
	st.SetMaxSeenEventIDs(8)
	require.Equal(t, 4, st.MaxTrackedEvents())
	require.Equal(t, 8, st.MaxSeenEventIDs())

	for i := 0; i < 4; i++ {
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("lru_ev_%d", i),
			SessionID:  "sess_lru_order",
			TurnIndex:  i + 1,
			Timestamp:  oldTs + int64(i),
			DurationMs: 10,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o",
				Usage: model.TokenUsage{TotalTokens: 10},
			},
		})
		require.NoError(t, err)
	}

	// Touch lru_ev_0 and lru_ev_1 so lru_ev_2 becomes the least-recently-used entry
	for _, touchID := range []string{"lru_ev_0", "lru_ev_1"} {
		sum, err := st.SaveEvent(&model.TraceEvent{
			ID:         touchID,
			SessionID:  "sess_lru_order",
			TurnIndex:  1,
			Timestamp:  oldTs + 10,
			DurationMs: 10,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o",
				Usage: model.TokenUsage{TotalTokens: 10},
			},
		})
		require.NoError(t, err)
		require.Equal(t, 4, sum.EventCount, "duplicate ID before overflow must not increment EventCount")
		require.Equal(t, 40, sum.TotalTokens, "duplicate ID with identical tokens must not increment TotalTokens")
		require.Equal(t, 4, sum.TurnCount, "duplicate ID before overflow must not increment TurnCount")
	}

	// Insert lru_ev_4 (5th unique event, exceeding maxTrackedEvents=4) -> must evict lru_ev_2 (LRU), keeping lru_ev_0 & lru_ev_1
	sum, err := st.SaveEvent(&model.TraceEvent{
		ID:         "lru_ev_4",
		SessionID:  "sess_lru_order",
		TurnIndex:  5,
		Timestamp:  oldTs + 20,
		DurationMs: 10,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Usage: model.TokenUsage{TotalTokens: 10},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 5, sum.EventCount)
	require.Equal(t, 50, sum.TotalTokens)
	require.Equal(t, 5, sum.TurnCount)

	st.mu.RLock()
	lruTracker := st.sessionContribs["sess_lru_order"]
	_, has0 := lruTracker.byID["lru_ev_0"]
	_, has1 := lruTracker.byID["lru_ev_1"]
	_, has2 := lruTracker.byID["lru_ev_2"]
	seenHas2 := lruTracker.seenIDs.contains("lru_ev_2")
	st.mu.RUnlock()
	require.True(t, has0, "recently touched lru_ev_0 must remain in byID")
	require.True(t, has1, "recently touched lru_ev_1 must remain in byID")
	require.False(t, has2, "least recently used lru_ev_2 must be evicted from byID")
	require.True(t, seenHas2, "evicted lru_ev_2 must still be retained in bounded seenIDs set")

	// Evict hot events and replay lru_ev_2 (post-overflow duplicate that was evicted from byID)
	st.EvictExpiredHot(baseNow)
	sum, err = st.SaveEvent(&model.TraceEvent{
		ID:         "lru_ev_2",
		SessionID:  "sess_lru_order",
		TurnIndex:  3,
		Timestamp:  oldTs + 2,
		DurationMs: 10,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Usage: model.TokenUsage{TotalTokens: 10},
		},
	})
	require.NoError(t, err)
	require.Equal(t, 5, sum.EventCount, "post-overflow duplicate ID must not increment EventCount")
	require.Equal(t, 50, sum.TotalTokens, "post-overflow duplicate ID with same tokens must not increment TotalTokens")
	require.Equal(t, 5, sum.TurnCount, "post-overflow duplicate ID must not increment TurnCount")

	// 2. Restore default capacities and verify >4096 overflow deduplication
	st.SetMaxTrackedEvents(DefaultMaxTrackedEvents)
	st.SetMaxSeenEventIDs(DefaultMaxSeenEventIDs)

	total := maxSessionTrackedEvents + 50
	for i := 0; i < total; i++ {
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("ev_full_%d", i),
			SessionID:  "sess_dedupe_full",
			TurnIndex:  i + 1,
			Timestamp:  oldTs + int64(i),
			DurationMs: 5,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o-mini",
				Usage: model.TokenUsage{TotalTokens: 4},
			},
		})
		require.NoError(t, err)
	}
	st.EvictExpiredHot(baseNow)

	// Replay oldest event (ev_full_0, evicted from byID) and newest event (ev_full_{total-1}, still in byID)
	for _, dupIdx := range []int{0, 10, total - 1} {
		sum, err := st.SaveEvent(&model.TraceEvent{
			ID:         fmt.Sprintf("ev_full_%d", dupIdx),
			SessionID:  "sess_dedupe_full",
			TurnIndex:  dupIdx + 1,
			Timestamp:  oldTs + int64(dupIdx),
			DurationMs: 5,
			Status:     "ok",
			Protocol:   model.ProtocolOpenAIChat,
			Chat: &model.ChatSummary{
				Model: "gpt-4o-mini",
				Usage: model.TokenUsage{TotalTokens: 4},
			},
		})
		require.NoError(t, err)
		require.Equal(t, total, sum.EventCount)
		require.Equal(t, total*4, sum.TotalTokens)
		require.Equal(t, total, sum.TurnCount)
	}

	// Update tokens on post-overflow duplicate ID (ev_full_10: 4 -> 14 tokens, +10 delta)
	sumUpdated, err := st.SaveEvent(&model.TraceEvent{
		ID:         "ev_full_10",
		SessionID:  "sess_dedupe_full",
		TurnIndex:  11,
		Timestamp:  oldTs + 10,
		DurationMs: 15,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o-mini",
			Usage: model.TokenUsage{TotalTokens: 14},
		},
	})
	require.NoError(t, err)
	require.Equal(t, total, sumUpdated.EventCount)
	require.Equal(t, total*4+10, sumUpdated.TotalTokens)
	require.Equal(t, total, sumUpdated.TurnCount)
}

func TestSessionPermissionsAndMigration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX file permission assertions on Windows")
	}

	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)

	nowMs := time.Now().UnixMilli()
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:        "ev_perm_1",
		SessionID: "sess_perm",
		Timestamp: nowMs,
		Status:    "ok",
		Protocol:  model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			ResponseText: "sensitive response payload",
		},
	})
	require.NoError(t, err)
	require.NoError(t, st.Close())

	sessRoot := filepath.Join(dir, "sessions")
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	dayDir := filepath.Join(sessRoot, day)
	sessDir := filepath.Join(dayDir, "sess_perm")
	sessionJSON := filepath.Join(sessDir, "session.json")
	eventsJSONL := filepath.Join(sessDir, "events.jsonl")

	assertPerm := func(path string, expected os.FileMode) {
		t.Helper()
		info, statErr := os.Stat(path)
		require.NoError(t, statErr)
		require.Equal(t, expected, info.Mode().Perm(), "unexpected permission for %s", path)
	}

	// 1. Newly created directories must be 0700 and files must be 0600
	assertPerm(sessRoot, 0o700)
	assertPerm(dayDir, 0o700)
	assertPerm(sessDir, 0o700)
	assertPerm(sessionJSON, 0o600)
	assertPerm(eventsJSONL, 0o600)

	// 2. Simulate legacy permissive permissions (0755 on dirs, 0644 on files) and verify startup migration
	require.NoError(t, os.Chmod(sessRoot, 0o755))
	require.NoError(t, os.Chmod(dayDir, 0o755))
	require.NoError(t, os.Chmod(sessDir, 0o755))
	require.NoError(t, os.Chmod(sessionJSON, 0o644))
	require.NoError(t, os.Chmod(eventsJSONL, 0o644))

	st2, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st2.Close()

	assertPerm(sessRoot, 0o700)
	assertPerm(dayDir, 0o700)
	assertPerm(sessDir, 0o700)
	assertPerm(sessionJSON, 0o600)
	assertPerm(eventsJSONL, 0o600)
}

func TestAtomicWriteSessionJSON(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	nowMs := time.Now().UnixMilli()
	_, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_atomic_1",
		SessionID:  "sess_atomic",
		TurnIndex:  1,
		Timestamp:  nowMs,
		DurationMs: 25,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Usage: model.TokenUsage{TotalTokens: 15},
		},
	})
	require.NoError(t, err)

	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessDir := filepath.Join(dir, "sessions", day, "sess_atomic")
	sessionJSON := filepath.Join(sessDir, "session.json")
	tmpJSON := sessionJSON + ".tmp"

	// 1. Verify .tmp does not remain after normal atomic write and session.json is complete
	_, err = os.Stat(tmpJSON)
	require.True(t, os.IsNotExist(err), "session.json.tmp must not remain after successful atomic write")

	rawBytes, err := os.ReadFile(sessionJSON)
	require.NoError(t, err)
	var persisted model.SessionSummary
	require.NoError(t, json.Unmarshal(rawBytes, &persisted))
	require.Equal(t, "sess_atomic", persisted.ID)
	require.Equal(t, 1, persisted.EventCount)
	require.Equal(t, 15, persisted.TotalTokens)

	// 2. Simulate interrupted write before rename -> .tmp must be cleaned up and previous session.json must stay intact
	st.mu.Lock()
	st.atomicBeforeRenameHook = func(tmpPath string) error {
		_, statErr := os.Stat(tmpPath)
		require.NoError(t, statErr, ".tmp file must exist before rename")
		return errors.New("simulated crash before rename")
	}
	st.mu.Unlock()

	_, err = st.SaveEvent(&model.TraceEvent{
		ID:         "ev_atomic_2",
		SessionID:  "sess_atomic",
		TurnIndex:  2,
		Timestamp:  nowMs + 10,
		DurationMs: 30,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Usage: model.TokenUsage{TotalTokens: 50},
		},
	})
	require.ErrorContains(t, err, "simulated crash before rename")

	_, err = os.Stat(tmpJSON)
	require.True(t, os.IsNotExist(err), ".tmp file must be cleaned up when atomic write fails before rename")

	rawAfterAbort, err := os.ReadFile(sessionJSON)
	require.NoError(t, err)
	var afterAbort model.SessionSummary
	require.NoError(t, json.Unmarshal(rawAfterAbort, &afterAbort))
	require.Equal(t, 1, afterAbort.EventCount, "previous session.json on disk must remain intact on interrupted write")
	require.Equal(t, 15, afterAbort.TotalTokens)

	// 3. Clear hook, leave a truncated .tmp from a simulated hard kill, and verify recovery + subsequent write
	st.mu.Lock()
	st.atomicBeforeRenameHook = nil
	st.mu.Unlock()

	require.NoError(t, os.WriteFile(tmpJSON, []byte(`{"id":"sess_atomic","truncated`), 0o600))

	stRecovered, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer stRecovered.Close()

	_, err = os.Stat(tmpJSON)
	require.True(t, os.IsNotExist(err), "stale .tmp file must be removed on store startup recovery")

	recSess, ok := stRecovered.GetSession("sess_atomic")
	require.True(t, ok)
	require.Equal(t, 1, recSess.EventCount)

	_, err = stRecovered.SaveEvent(&model.TraceEvent{
		ID:         "ev_atomic_2",
		SessionID:  "sess_atomic",
		TurnIndex:  2,
		Timestamp:  nowMs + 20,
		DurationMs: 30,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Usage: model.TokenUsage{TotalTokens: 50},
		},
	})
	require.NoError(t, err)

	_, err = os.Stat(tmpJSON)
	require.True(t, os.IsNotExist(err))

	finalBytes, err := os.ReadFile(sessionJSON)
	require.NoError(t, err)
	var finalSummary model.SessionSummary
	require.NoError(t, json.Unmarshal(finalBytes, &finalSummary))
	require.Equal(t, 2, finalSummary.EventCount)
	require.Equal(t, 65, finalSummary.TotalTokens)
}

func TestCleanRemovesEmptyDateDirsAndPreservesNonEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	fixedNow := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	st.nowFunc = func() time.Time { return fixedNow }

	dayOld := "2026-11-01"
	dayCur := "2026-11-02"
	oldDayTs1 := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC).UnixMilli()
	oldDayTs2 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC).UnixMilli()
	curDayOldTs := fixedNow.Add(-2 * time.Hour).UnixMilli()   // 2026-11-02T10:00:00Z
	curDayNewTs := fixedNow.Add(-5 * time.Minute).UnixMilli() // 2026-11-02T11:55:00Z

	// Two old sessions under 2026-11-01, one old + one new under 2026-11-02
	for _, tc := range []struct {
		evID   string
		sessID string
		ts     int64
	}{
		{"ev_old_1", "s_old_1", oldDayTs1},
		{"ev_old_2", "s_old_2", oldDayTs2},
		{"ev_cur_old", "s_cur_old", curDayOldTs},
		{"ev_cur_new", "s_cur_new", curDayNewTs},
	} {
		_, err := st.SaveEvent(&model.TraceEvent{
			ID:        tc.evID,
			SessionID: tc.sessID,
			Timestamp: tc.ts,
			Status:    "ok",
			Protocol:  model.ProtocolOpenAIChat,
			Chat:      &model.ChatSummary{Model: "gpt-4o", ResponseText: "hello"},
		})
		require.NoError(t, err)
	}

	sessRoot := filepath.Join(dir, "sessions")
	oldDayDir := filepath.Join(sessRoot, dayOld)
	curDayDir := filepath.Join(sessRoot, dayCur)

	// 1. Dry-run with --older-than 1h must NOT remove any session or date directory
	dryRep, err := st.Clean(CleanOptions{
		OlderThan: 1 * time.Hour,
		DryRun:    true,
	})
	require.NoError(t, err)
	require.True(t, dryRep.DryRun)
	require.Equal(t, 3, dryRep.DeletedSessions)
	require.Equal(t, 6, dryRep.DeletedFiles) // 3 sessions * (session.json + events.jsonl)
	_, err = os.Stat(oldDayDir)
	require.NoError(t, err, "dry-run must not remove old date directory")
	_, err = os.Stat(filepath.Join(oldDayDir, "s_old_1", "session.json"))
	require.NoError(t, err, "dry-run must not remove session files")

	// 2. Clean with --older-than 1h:
	// - 2026-11-01 becomes empty after s_old_1 and s_old_2 are deleted -> date directory must be removed
	// - 2026-11-02 still has s_cur_new after s_cur_old is deleted -> non-empty date directory must be preserved
	repOlder, err := st.Clean(CleanOptions{
		OlderThan: 1 * time.Hour,
		DryRun:    false,
	})
	require.NoError(t, err)
	require.Equal(t, 3, repOlder.DeletedSessions)
	require.Equal(t, 6, repOlder.DeletedFiles)

	_, err = os.Stat(oldDayDir)
	require.True(t, os.IsNotExist(err), "empty date dir %s must be removed after clean --older-than", oldDayDir)

	_, err = os.Stat(curDayDir)
	require.NoError(t, err, "non-empty date dir %s must be preserved", curDayDir)
	_, err = os.Stat(filepath.Join(curDayDir, "s_cur_old"))
	require.True(t, os.IsNotExist(err), "expired session s_cur_old must be removed")
	_, err = os.Stat(filepath.Join(curDayDir, "s_cur_new", "session.json"))
	require.NoError(t, err, "active session s_cur_new must be preserved")

	// 3. Also test pre-populated disk session (reproduction scenario) + Clean --all:
	reproDayDir := filepath.Join(sessRoot, "2026-11-03")
	reproSessDir := filepath.Join(reproDayDir, "s1")
	require.NoError(t, os.MkdirAll(reproSessDir, 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(reproSessDir, "session.json"),
		[]byte(`{"id":"s1","first_seen":"2026-11-02T00:00:00Z","last_seen":"2026-11-02T00:01:00Z"}`),
		0o600,
	))

	stReloaded, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer stReloaded.Close()

	dryAllRep, err := stReloaded.Clean(CleanOptions{
		All:    true,
		DryRun: true,
	})
	require.NoError(t, err)
	require.Equal(t, 2, dryAllRep.DeletedSessions)
	_, err = os.Stat(curDayDir)
	require.NoError(t, err)
	_, err = os.Stat(reproDayDir)
	require.NoError(t, err)

	repAll, err := stReloaded.Clean(CleanOptions{
		All:    true,
		DryRun: false,
	})
	require.NoError(t, err)
	require.Equal(t, 2, repAll.DeletedSessions)
	require.Equal(t, 3, repAll.DeletedFiles) // s_cur_new (2 files) + s1 (1 file)

	entries, err := os.ReadDir(sessRoot)
	require.NoError(t, err, "sessions root dir itself must remain")
	require.Empty(t, entries, "all empty date directories under sessions/ must be removed after clean --all")
}

func TestOpenReadOnlyAndSymlinkPermissionSafety(t *testing.T) {
	// 1. OpenReadOnly on a non-existent directory must fail and NOT create any directory
	parentDir := t.TempDir()
	nonExist := filepath.Join(parentDir, "nonexist")
	_, err := OpenReadOnly(nonExist, 10*time.Minute)
	require.Error(t, err)
	_, statErr := os.Stat(nonExist)
	require.True(t, os.IsNotExist(statErr), "OpenReadOnly must not create non-existent cacheDir or sessions subdir")

	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX symlink & chmod permission assertions on Windows")
	}

	// 2. Session directory containing session.json.tmp and link -> victim(0644)
	r4Dir := t.TempDir()
	victimFile := filepath.Join(r4Dir, "victim")
	require.NoError(t, os.WriteFile(victimFile, []byte("important-victim-data"), 0o644))
	require.NoError(t, os.Chmod(victimFile, 0o644))

	cacheDir := filepath.Join(r4Dir, "cache")
	nowMs := time.Now().Add(-1 * time.Minute).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessDir := filepath.Join(cacheDir, "sessions", day, "s_sym_1")
	require.NoError(t, os.MkdirAll(sessDir, 0o755))
	require.NoError(t, os.Chmod(filepath.Join(cacheDir, "sessions"), 0o755))
	require.NoError(t, os.Chmod(filepath.Join(cacheDir, "sessions", day), 0o755))
	require.NoError(t, os.Chmod(sessDir, 0o755))

	summary := model.SessionSummary{
		ID:         "s_sym_1",
		Title:      "symlink test session",
		CreatedAt:  nowMs,
		UpdatedAt:  nowMs,
		EventCount: 1,
	}
	sumBytes, err := json.Marshal(summary)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "session.json"), sumBytes, 0o644))
	require.NoError(t, os.Chmod(filepath.Join(sessDir, "session.json"), 0o644))

	tmpFile := filepath.Join(sessDir, "session.json.tmp")
	require.NoError(t, os.WriteFile(tmpFile, []byte(`{"in_flight":true}`), 0o644))
	require.NoError(t, os.Chmod(tmpFile, 0o644))

	linkPath := filepath.Join(sessDir, "link")
	require.NoError(t, os.Symlink(victimFile, linkPath))

	// 2a. OpenReadOnly must NOT delete .tmp, must NOT chmod session dirs/files, and must NOT chmod victim
	roStore, err := OpenReadOnly(cacheDir, 10*time.Minute)
	require.NoError(t, err)
	require.True(t, roStore.ReadOnly())

	roSessions, err := roStore.QuerySessions(SessionQuery{})
	require.NoError(t, err)
	require.Len(t, roSessions, 1)
	require.Equal(t, "s_sym_1", roSessions[0].ID)
	require.NoError(t, roStore.Close())

	_, tmpStatErr := os.Stat(tmpFile)
	require.NoError(t, tmpStatErr, "OpenReadOnly must not delete session.json.tmp")
	victimInfo, err := os.Stat(victimFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), victimInfo.Mode().Perm(), "OpenReadOnly must not alter symlink target permissions")
	sessDirInfo, err := os.Stat(sessDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), sessDirInfo.Mode().Perm(), "OpenReadOnly must not chmod session directory")

	// 2b. NewStore (write mode with migrateSessionDirPermissions) must ALSO skip symlinks and keep victim at 0644
	rwStore, err := NewStore(cacheDir, 10*time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, rwStore.Close())

	victimInfoAfterRW, err := os.Stat(victimFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), victimInfoAfterRW.Mode().Perm(), "NewStore permission migration must skip symlinks and preserve victim 0644")

	// 3. c5/sessions is a symlink pointing to tgt(0755) with tgt/2026-11-01(0755)
	c5Root := t.TempDir()
	tgtDir := filepath.Join(c5Root, "tgt")
	tgtDayDir := filepath.Join(tgtDir, "2026-11-01")
	require.NoError(t, os.MkdirAll(tgtDayDir, 0o755))
	require.NoError(t, os.Chmod(tgtDir, 0o755))
	require.NoError(t, os.Chmod(tgtDayDir, 0o755))

	c5Dir := filepath.Join(c5Root, "c5")
	require.NoError(t, os.MkdirAll(c5Dir, 0o755))
	require.NoError(t, os.Symlink(tgtDir, filepath.Join(c5Dir, "sessions")))

	roC5, err := OpenReadOnly(c5Dir, 10*time.Minute)
	require.NoError(t, err)
	require.NoError(t, roC5.Close())

	rwC5, err := NewStore(c5Dir, 10*time.Minute, nil)
	require.NoError(t, err)
	require.NoError(t, rwC5.Close())

	tgtInfo, err := os.Stat(tgtDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), tgtInfo.Mode().Perm(), "symlinked sessions target tgt must remain 0755")
	tgtDayInfo, err := os.Stat(tgtDayDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), tgtDayInfo.Mode().Perm(), "tgt/2026-11-01 under symlinked sessions must remain 0755")
}

func TestRebuildSummaryFromEventsAndCleanHooksTLSBin(t *testing.T) {
	dir := t.TempDir()
	nowMs := time.Now().Add(-1 * time.Minute).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessDir := filepath.Join(dir, "sessions", day, "sess_orphan_events")
	require.NoError(t, os.MkdirAll(sessDir, 0o700))

	// Write 2 events into events.jsonl WITHOUT creating session.json
	ev1 := model.TraceEvent{
		ID:         "ev_orphan_1",
		SessionID:  "sess_orphan_events",
		TurnIndex:  1,
		Timestamp:  nowMs,
		DurationMs: 120,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Process:    model.ProcessInfo{PID: 4321, Comm: "python3", Cmdline: "python3 agent.py", Cwd: "/work"},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "rebuild my missing session.json"}},
			ResponseText: "rebuilt response 1",
			Usage:        model.TokenUsage{TotalTokens: 42},
		},
	}
	ev2 := model.TraceEvent{
		ID:         "ev_orphan_2",
		SessionID:  "sess_orphan_events",
		TurnIndex:  2,
		Timestamp:  nowMs + 500,
		DurationMs: 80,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Process:    model.ProcessInfo{PID: 4321, Comm: "python3", Cmdline: "python3 agent.py", Cwd: "/work"},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "second turn"}},
			ResponseText: "rebuilt response 2",
			Usage:        model.TokenUsage{TotalTokens: 58},
		},
	}
	b1, err := json.Marshal(ev1)
	require.NoError(t, err)
	b2, err := json.Marshal(ev2)
	require.NoError(t, err)
	eventsPayload := append(append(b1, '\n'), append(b2, '\n')...)
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "events.jsonl"), eventsPayload, 0o600))

	// 1. OpenReadOnly must rebuild summary in memory without creating session.json on disk
	roSt, err := OpenReadOnly(dir, 10*time.Minute)
	require.NoError(t, err)
	sessions, err := roSt.QuerySessions(SessionQuery{})
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	require.Equal(t, "sess_orphan_events", sessions[0].ID)
	require.Equal(t, "rebuild my missing session.json", sessions[0].Title)
	require.Equal(t, 2, sessions[0].EventCount)
	require.Equal(t, 2, sessions[0].TurnCount)
	require.Equal(t, 100, sessions[0].TotalTokens)
	require.Equal(t, int64(200), sessions[0].TotalDurationMs)
	require.Equal(t, 4321, sessions[0].RootPID)
	require.NoError(t, roSt.Close())

	_, statErr := os.Stat(filepath.Join(sessDir, "session.json"))
	require.True(t, os.IsNotExist(statErr), "OpenReadOnly must not write rebuilt session.json to disk")

	// 2. NewStore must also rebuild summary and make events queryable
	rwSt, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer rwSt.Close()

	rwSessions, err := rwSt.QuerySessions(SessionQuery{})
	require.NoError(t, err)
	require.Len(t, rwSessions, 1)
	require.Equal(t, "sess_orphan_events", rwSessions[0].ID)

	evs, err := rwSt.QuerySessionEvents(EventQuery{SessionID: "sess_orphan_events"})
	require.NoError(t, err)
	require.Len(t, evs, 2)

	// 3. Clean --all must remove <cacheDir>/hooks/tls.bin while preserving non-llm-tracer files
	hooksDir := filepath.Join(dir, "hooks")
	require.NoError(t, os.MkdirAll(hooksDir, 0o700))
	tlsBinPath := filepath.Join(hooksDir, "tls.bin")
	require.NoError(t, os.WriteFile(tlsBinPath, []byte("LLMT-plaintext-pipe-frames"), 0o600))
	userKeepPath := filepath.Join(hooksDir, "custom_keep.txt")
	require.NoError(t, os.WriteFile(userKeepPath, []byte("keep-me"), 0o600))

	rep, err := rwSt.Clean(CleanOptions{All: true})
	require.NoError(t, err)
	require.Equal(t, 1, rep.DeletedSessions)
	require.Contains(t, rep.Paths, tlsBinPath)

	_, err = os.Stat(tlsBinPath)
	require.True(t, os.IsNotExist(err), "clean --all must delete hooks/tls.bin")
	_, err = os.Stat(userKeepPath)
	require.NoError(t, err, "clean --all must not delete unrelated user files in hooks/")
}
