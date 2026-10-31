package store

import (
	"testing"
	"time"

	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
)

func TestStore10MinuteWindowAndClean(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)

	st, err := NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)

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
