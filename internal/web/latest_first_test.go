package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/collector"
	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func TestWebUIEventsRenderLatestFirst(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	col, err := collector.NewCollector(dir, model.ScopeFilter{RecordHeaders: false}, correlator.NewCorrelator(mon), st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })
	srv := NewServer(st, col, mon, nil)

	for _, ev := range []*model.TraceEvent{
		{ID: "ev_latest_1", SessionID: "sess_latest_first", Timestamp: 1000, Status: "ok", Protocol: model.ProtocolOpenAIChat},
		{ID: "ev_latest_2", SessionID: "sess_latest_first", Timestamp: 3000, Status: "ok", Protocol: model.ProtocolOpenAIChat},
		{ID: "ev_latest_3", SessionID: "sess_latest_first", Timestamp: 2000, Status: "ok", Protocol: model.ProtocolOpenAIChat},
	} {
		_, err := st.SaveEvent(ev)
		require.NoError(t, err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/sessions/sess_latest_first", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var payload struct {
		Events []model.TraceEvent `json:"events"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &payload))
	require.Len(t, payload.Events, 3)
	require.Less(t, payload.Events[0].Timestamp, payload.Events[len(payload.Events)-1].Timestamp)

	index := readStaticIndex(t, srv)
	require.Contains(t, index, "const orderedEvents = [...state.activeEvents].sort")
	require.Contains(t, index, "return b.timestamp - a.timestamp")
	require.Contains(t, index, "inspectEvent(state.activeEvents[0].id)")
	require.Contains(t, index, "const evs = [...(data.events || [])].sort((a, b) => {")
	require.Contains(t, index, "if (b.ts !== a.ts) return b.ts - a.ts")
}

func readStaticIndex(t *testing.T, srv *Server) string {
	t.Helper()
	require.NotNil(t, srv)
	// The page is embedded; this path intentionally keeps the test independent from disk cwd.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/index.html", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}
