package correlator

import (
	"testing"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
)

func newTestCorrelator(t *testing.T) *Correlator {
	t.Helper()
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	return NewCorrelator(mon)
}

func TestCorrelationHintsL1ExplicitWhenHeadersNotRecorded(t *testing.T) {
	corr := newTestCorrelator(t)
	first := &model.TraceEvent{
		ID: "ev_hint_1", Timestamp: 1000, Protocol: model.ProtocolOpenAIChat,
		HeadersRecorded: false, CorrelationHints: []string{"w3c_trace:59d5ba3ad8e13a4e"},
	}
	corr.Correlate(first)

	second := &model.TraceEvent{
		ID: "ev_hint_2", Timestamp: 2000, Protocol: model.ProtocolOpenAIChat,
		HeadersRecorded: false,
		CorrelationHints: []string{
			"hdr:x-session-id:7435bd6e93a2c6cf",
			"w3c_trace:59d5ba3ad8e13a4e",
		},
	}
	corr.Correlate(second)
	require.Equal(t, first.SessionID, second.SessionID)
	require.Equal(t, "L1_explicit", second.CorrelationLevel)
	require.Equal(t, "w3c_trace:59d5ba3ad8e13a4e", second.CorrelationReason)

	third := &model.TraceEvent{
		ID: "ev_hint_3", Timestamp: 3000, Protocol: model.ProtocolOpenAIChat,
		HeadersRecorded:  false,
		CorrelationHints: []string{"hdr:x-session-id:7435bd6e93a2c6cf"},
	}
	corr.Correlate(third)
	require.Equal(t, first.SessionID, third.SessionID)
	require.Equal(t, "L1_explicit", third.CorrelationLevel)
	require.Equal(t, "hdr:x-session-id:7435bd6e93a2c6cf", third.CorrelationReason)
}

func TestChatPrefixSlidingWindowAfterSummarization(t *testing.T) {
	corr := newTestCorrelator(t)
	first := &model.TraceEvent{
		ID: "ev_sliding_1", Timestamp: 1000, Status: "ok", Protocol: model.ProtocolAnthropic,
		Chat: &model.ChatSummary{
			Messages: []model.ChatMessage{
				{Role: "system", Content: "old detailed system prompt"},
				{Role: "user", Content: "first user message"},
				{Role: "assistant", Content: "first assistant answer"},
				{Role: "user", Content: "second user message"},
			},
			ResponseText: "second assistant answer",
		},
	}
	corr.Correlate(first)

	second := &model.TraceEvent{
		ID: "ev_sliding_2", Timestamp: 2000, Status: "ok", Protocol: model.ProtocolAnthropic,
		Chat: &model.ChatSummary{
			Messages: []model.ChatMessage{
				{Role: "system", Content: "new summarized system prompt"},
				{Role: "user", Content: "second user message"},
				{Role: "assistant", Content: "second assistant answer"},
				{Role: "user", Content: "third user message"},
			},
			ResponseText: "third assistant answer",
		},
	}
	corr.Correlate(second)
	require.Equal(t, first.SessionID, second.SessionID)
	require.Equal(t, "L2_context", second.CorrelationLevel)
	require.Equal(t, 3, second.Chat.PrefixCount)
	require.Equal(t, "messages_sliding_window(matched=3/4)", second.CorrelationReason)
	require.Len(t, second.Chat.NewMessages, 1)
	require.Equal(t, "third user message", second.Chat.NewMessages[0].Content)
}

func TestProcessTreePrefersConnAndTIDOverPID(t *testing.T) {
	corr := newTestCorrelator(t)
	pid := 700
	connA := &model.TraceEvent{
		ID:               "ev_conn_a",
		Timestamp:        1000,
		Protocol:         model.ProtocolOpenAIChat,
		Process:          model.ProcessInfo{PID: pid, TID: 701, Cwd: "/work"},
		ConnKey:          "conn:a",
		CorrelationHints: []string{"hdr:x-session-id:sess_a"},
	}
	corr.Correlate(connA)

	connB := &model.TraceEvent{
		ID:               "ev_conn_b",
		Timestamp:        2000,
		Protocol:         model.ProtocolOpenAIChat,
		Process:          model.ProcessInfo{PID: pid, TID: 702, Cwd: "/work"},
		ConnKey:          "conn:b",
		CorrelationHints: []string{"hdr:x-session-id:sess_b"},
	}
	corr.Correlate(connB)
	require.NotEqual(t, connA.SessionID, connB.SessionID)

	// Both sessions share PID. The newer same-TID session must win over PID affinity.
	tidEvent := &model.TraceEvent{
		ID: "ev_tid", Timestamp: 3000, Protocol: model.ProtocolOpenAIChat,
		Process: model.ProcessInfo{PID: pid, TID: 702}, ConnKey: "conn:other",
	}
	corr.Correlate(tidEvent)
	require.Equal(t, connB.SessionID, tidEvent.SessionID)
	require.Equal(t, "L3_proctree", tidEvent.CorrelationLevel)
	require.Contains(t, tidEvent.CorrelationReason, "same_tid")

	// A later Keep-Alive request on conn:a must win despite conn:b being newer.
	keepAlive := &model.TraceEvent{
		ID: "ev_keepalive", Timestamp: 4000, Protocol: model.ProtocolOpenAIChat,
		Process: model.ProcessInfo{PID: pid, TID: 703}, ConnKey: "conn:a",
	}
	corr.Correlate(keepAlive)
	require.Equal(t, connA.SessionID, keepAlive.SessionID)
	require.Equal(t, "L3_proctree", keepAlive.CorrelationLevel)
	require.Equal(t, "same_conn(conn:a)", keepAlive.CorrelationReason)
}
