package correlator

import (
	"testing"

	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
)

func TestCorrelatorThreeLevels(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	corr := NewCorrelator(mon)

	// 1. SystemOne Step 1 (root) -> Step 2 (L2_context via Goal) -> Helper OpenAI Chat for TYPE_TEXT (L3_proctree)
	step1 := &model.TraceEvent{
		ID:        "ev_s1_1",
		Timestamp: 1000,
		Protocol:  model.ProtocolSystemOne,
		Process:   model.ProcessInfo{PID: 500, Comm: "jev-release", Cwd: "/home/user/jev"},
		SystemOne: &model.SystemOneStepSummary{
			Model:        "jev-latest",
			Goal:         "Download ripgrep release",
			SelectedOp:   "TYPE_TEXT",
			SelectedText: "ripgrep",
		},
	}
	corr.Correlate(step1)
	require.Equal(t, "root", step1.CorrelationLevel)
	require.Equal(t, 1, step1.StepIndex)
	sessID := step1.SessionID
	require.NotEmpty(t, sessID)

	// Helper LLM call from the same process (PID 500) right after Step 1
	helperChat := &model.TraceEvent{
		ID:        "ev_helper_1",
		Timestamp: 1200,
		Protocol:  model.ProtocolOpenAIChat,
		Process:   model.ProcessInfo{PID: 500, Comm: "jev-release", Cwd: "/home/user/jev"},
		Chat: &model.ChatSummary{
			Model: "deepseek-chat",
			Messages: []model.ChatMessage{
				{Role: "system", Content: "Write field value"},
				{Role: "user", Content: `{"goal":"Download ripgrep release"}`},
			},
			ResponseText: `{"text":"ripgrep"}`,
		},
	}
	corr.Correlate(helperChat)
	require.Equal(t, sessID, helperChat.SessionID)
	require.Equal(t, "L3_proctree", helperChat.CorrelationLevel)
	require.Equal(t, "ev_s1_1", helperChat.ParentEventID)
	require.Equal(t, 1, helperChat.StepIndex)

	// SystemOne Step 2 (L2_context matching Goal)
	step2 := &model.TraceEvent{
		ID:        "ev_s1_2",
		Timestamp: 2000,
		Protocol:  model.ProtocolSystemOne,
		Process:   model.ProcessInfo{PID: 500, Comm: "jev-release", Cwd: "/home/user/jev"},
		SystemOne: &model.SystemOneStepSummary{
			Model:             "jev-latest",
			Goal:              "Download ripgrep release",
			RecentActionCount: 1,
			SelectedOp:        "DONE",
		},
	}
	corr.Correlate(step2)
	require.Equal(t, sessID, step2.SessionID)
	require.Equal(t, "L2_context", step2.CorrelationLevel)
	require.Equal(t, 2, step2.StepIndex)
	require.Equal(t, "ev_s1_1", step2.ParentEventID)

	// 2. Multi-turn Chat L2 Prefix Hash correlation
	turn1 := &model.TraceEvent{
		ID:        "ev_chat_1",
		Timestamp: 3000,
		Status:    "ok",
		Protocol:  model.ProtocolAnthropic,
		Process:   model.ProcessInfo{PID: 601, Comm: "claude"},
		Chat: &model.ChatSummary{
			Model: "claude-sonnet-4",
			Messages: []model.ChatMessage{
				{Role: "user", Content: "Read main.go"},
			},
			ResponseText: "I will read main.go now.",
		},
	}
	corr.Correlate(turn1)
	chatSessID := turn1.SessionID
	require.NotEqual(t, sessID, chatSessID)
	require.Equal(t, 1, turn1.TurnIndex)

	turn2 := &model.TraceEvent{
		ID:        "ev_chat_2",
		Timestamp: 4000,
		Status:    "ok",
		Protocol:  model.ProtocolAnthropic,
		Process:   model.ProcessInfo{PID: 602, Comm: "claude-worker"}, // even across different PID!
		Chat: &model.ChatSummary{
			Model: "claude-sonnet-4",
			Messages: []model.ChatMessage{
				{Role: "user", Content: "Read main.go"},
				{Role: "assistant", Content: "I will read main.go now."},
				{Role: "user", Content: "Now run go test"},
			},
			ResponseText: "Tests passed.",
		},
	}
	corr.Correlate(turn2)
	require.Equal(t, chatSessID, turn2.SessionID)
	require.Equal(t, "L2_context", turn2.CorrelationLevel)
	require.Equal(t, "ev_chat_1", turn2.ParentEventID)
	require.Equal(t, 2, turn2.Chat.PrefixCount)
	require.Len(t, turn2.Chat.NewMessages, 1)
	require.Equal(t, "Now run go test", turn2.Chat.NewMessages[0].Content)
}
