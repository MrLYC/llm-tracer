package store

import (
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/stretchr/testify/require"
)

func TestHotCloneDeepCopiesCorrelationHints(t *testing.T) {
	st, err := NewStore(t.TempDir(), 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	ev := &model.TraceEvent{
		ID: "ev_hint_clone", SessionID: "sess_hint_clone", Timestamp: time.Now().UnixMilli(),
		Protocol: model.ProtocolOpenAIChat, Status: "ok",
		ConnKey:          "conn:clone",
		CorrelationHints: []string{"hdr:x-session-id:7435bd6e93a2c6cf", "w3c_trace:59d5ba3ad8e13a4e"},
	}
	_, err = st.SaveEvent(ev)
	require.NoError(t, err)

	evs, err := st.QuerySessionEvents(EventQuery{SessionID: ev.SessionID, From: ev.Timestamp - 1, To: ev.Timestamp + 1})
	require.NoError(t, err)
	require.Len(t, evs, 1)
	require.Equal(t, "conn:clone", evs[0].ConnKey)
	require.Equal(t, ev.CorrelationHints, evs[0].CorrelationHints)
	require.NotSame(t, &ev.CorrelationHints[0], &evs[0].CorrelationHints[0])

	evs[0].CorrelationHints[0] = "mutated"
	again, err := st.QuerySessionEvents(EventQuery{SessionID: ev.SessionID, From: ev.Timestamp - 1, To: ev.Timestamp + 1})
	require.NoError(t, err)
	require.Equal(t, "hdr:x-session-id:7435bd6e93a2c6cf", again[0].CorrelationHints[0])
}
