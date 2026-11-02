package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/stretchr/testify/require"
)

func snapshotDirSHA256(t *testing.T, root string) []string {
	t.Helper()
	var entries []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		require.NoError(t, walkErr)
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		info, err := os.Lstat(path)
		require.NoError(t, err)
		if info.IsDir() {
			entries = append(entries, fmt.Sprintf("DIR|%s|mode=%o", rel, info.Mode().Perm()))
			return nil
		}
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		sum := sha256.Sum256(raw)
		entries = append(entries, fmt.Sprintf("FILE|%s|mode=%o|size=%d|sha256=%s",
			rel, info.Mode().Perm(), info.Size(), hex.EncodeToString(sum[:])))
		return nil
	})
	require.NoError(t, err)
	sort.Strings(entries)
	return entries
}

func readDiskEventsJSONL(t *testing.T, eventsPath string) ([]model.TraceEvent, int) {
	t.Helper()
	raw, err := os.ReadFile(eventsPath)
	require.NoError(t, err)
	var valid []model.TraceEvent
	corruptLines := 0
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev model.TraceEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			corruptLines++
			continue
		}
		valid = append(valid, ev)
	}
	require.NoError(t, sc.Err())
	return valid, corruptLines
}

func TestTornTailSaveEventSurvivesRestartAndSummaryMatchesDisk(t *testing.T) {
	dir := t.TempDir()
	nowMs := time.Now().Add(-1 * time.Minute).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessID := "sess_torn_tail_1"
	sessDir := filepath.Join(dir, "sessions", day, sessID)
	eventsPath := filepath.Join(sessDir, "events.jsonl")
	sessionPath := filepath.Join(sessDir, "session.json")

	st1, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)

	ev1 := &model.TraceEvent{
		ID:         "ev_1",
		SessionID:  sessID,
		TurnIndex:  1,
		Timestamp:  nowMs,
		DurationMs: 100,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Process:    model.ProcessInfo{PID: 1001, Comm: "curl", Cmdline: "curl -u user:PASS_IN_EVENT_CMD https://u:URL_PASS_IN_EVENT@x.example/v1/chat"},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "first event"}},
			ResponseText: "resp 1",
			Usage:        model.TokenUsage{TotalTokens: 30},
		},
	}
	_, err = st1.SaveEvent(ev1)
	require.NoError(t, err)

	// Simulate a crash leaving a half-written JSON line without a trailing newline at the end of events.jsonl
	f, err := os.OpenFile(eventsPath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = f.Write([]byte(`{"id":"ev_torn_half","session_id":"sess_torn_tail_1","status":"ok","chat":{"model":`))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Save a new event after the torn tail
	ev2 := &model.TraceEvent{
		ID:         "ev_2_new",
		SessionID:  sessID,
		TurnIndex:  2,
		Timestamp:  nowMs + 500,
		DurationMs: 150,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Process:    model.ProcessInfo{PID: 1001, Comm: "curl", Cmdline: "curl https://x.example/v1/chat"},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "second event after torn tail"}},
			ResponseText: "resp 2",
			Usage:        model.TokenUsage{TotalTokens: 45},
		},
	}
	_, err = st1.SaveEvent(ev2)
	require.NoError(t, err)
	require.NoError(t, st1.Close())

	// Before restart: verify on-disk events.jsonl already has ev_2_new on its own valid line (not swallowed by torn tail)
	preRestartEvs, _ := readDiskEventsJSONL(t, eventsPath)
	require.Len(t, preRestartEvs, 2, "new event must not be concatenated onto the torn half-line on disk")
	require.Equal(t, "ev_2_new", preRestartEvs[1].ID)

	// Restart Store
	st2, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st2.Close()

	// 1. Assert on-disk artifacts after restart
	rawEventsBytes, err := os.ReadFile(eventsPath)
	require.NoError(t, err)
	require.NotEmpty(t, rawEventsBytes)
	require.Equal(t, byte('\n'), rawEventsBytes[len(rawEventsBytes)-1], "healed events.jsonl must end with newline")
	require.NotContains(t, string(rawEventsBytes), "PASS_IN_EVENT_CMD")
	require.NotContains(t, string(rawEventsBytes), "URL_PASS_IN_EVENT")

	diskEvs, corruptLines := readDiskEventsJSONL(t, eventsPath)
	require.Equal(t, 0, corruptLines, "restart self-heal must clean up torn line in events.jsonl")
	require.Len(t, diskEvs, 2, "both ev_1 and ev_2_new must exist on disk after restart")

	foundNew := false
	for _, dev := range diskEvs {
		if dev.ID == "ev_2_new" {
			foundNew = true
		}
	}
	require.True(t, foundNew, "new event ev_2_new must survive on disk after restart")

	rawSessionBytes, err := os.ReadFile(sessionPath)
	require.NoError(t, err)
	require.NotContains(t, string(rawSessionBytes), "PASS_IN_EVENT_CMD")
	require.NotContains(t, string(rawSessionBytes), "URL_PASS_IN_EVENT")

	var diskSummary model.SessionSummary
	require.NoError(t, json.Unmarshal(rawSessionBytes, &diskSummary))
	require.Equal(t, len(diskEvs), diskSummary.EventCount, "on-disk session.json event_count must equal actual events on disk")
	require.Equal(t, 75, diskSummary.TotalTokens)
	require.Equal(t, int64(250), diskSummary.TotalDurationMs)

	// 2. Assert Store query results match on-disk state
	memSummary, ok := st2.GetSession(sessID)
	require.True(t, ok)
	require.Equal(t, len(diskEvs), memSummary.EventCount, "in-memory summary.event_count must match on-disk event count")

	queriedEvs, err := st2.QuerySessionEvents(EventQuery{SessionID: sessID})
	require.NoError(t, err)
	require.Len(t, queriedEvs, 2)
	require.Equal(t, "ev_1", queriedEvs[0].ID)
	require.Equal(t, "ev_2_new", queriedEvs[1].ID)
}

func TestTornTailCrashAfterSessionJSONHealOnRestart(t *testing.T) {
	dir := t.TempDir()
	nowMs := time.Now().Add(-1 * time.Minute).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessID := "sess_crash_mismatch"
	sessDir := filepath.Join(dir, "sessions", day, sessID)
	require.NoError(t, os.MkdirAll(sessDir, 0o700))

	// Write 1 complete valid event + 1 torn half-line into events.jsonl
	ev1 := model.TraceEvent{
		ID:         "ev_valid_1",
		SessionID:  sessID,
		TurnIndex:  1,
		Timestamp:  nowMs,
		DurationMs: 80,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Process:    model.ProcessInfo{PID: 2002, Comm: "python3", Cmdline: "python3 app.py"},
		Chat: &model.ChatSummary{
			Model: "gpt-4o",
			Usage: model.TokenUsage{TotalTokens: 25},
		},
	}
	ev1Bytes, err := json.Marshal(ev1)
	require.NoError(t, err)
	eventsContent := append(ev1Bytes, '\n')
	eventsContent = append(eventsContent, []byte(`{"id":"ev_crashed_2","session_id":"sess_crash_mismatch","turn_index":2`)...)
	eventsPath := filepath.Join(sessDir, "events.jsonl")
	require.NoError(t, os.WriteFile(eventsPath, eventsContent, 0o600))

	// Write session.json that already incremented EventCount to 2 before the crash during events.jsonl append
	staleSummary := model.SessionSummary{
		ID:              sessID,
		Title:           "stale count before crash",
		PrimaryProtocol: model.ProtocolOpenAIChat,
		Protocols:       []string{string(model.ProtocolOpenAIChat)},
		CreatedAt:       nowMs,
		UpdatedAt:       nowMs + 100,
		EventCount:      2,
		TurnCount:       2,
		TotalTokens:     999,
		TotalDurationMs: 888,
		LastStatus:      "ok",
	}
	staleBytes, err := json.MarshalIndent(staleSummary, "", "  ")
	require.NoError(t, err)
	sessionPath := filepath.Join(sessDir, "session.json")
	require.NoError(t, os.WriteFile(sessionPath, staleBytes, 0o600))

	// Restart Store: must heal events.jsonl and rebuild session.json via rebuildSummaryFromEvents
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	diskEvs, corruptLines := readDiskEventsJSONL(t, eventsPath)
	require.Equal(t, 0, corruptLines, "torn tail must be removed from events.jsonl on load")
	require.Len(t, diskEvs, 1)

	rawSessionBytes, err := os.ReadFile(sessionPath)
	require.NoError(t, err)
	var healedDiskSummary model.SessionSummary
	require.NoError(t, json.Unmarshal(rawSessionBytes, &healedDiskSummary))
	require.Equal(t, 1, healedDiskSummary.EventCount, "on-disk session.json event_count must be rebuilt to match 1 valid event")
	require.Equal(t, 25, healedDiskSummary.TotalTokens, "on-disk session.json total_tokens must be rebuilt from valid events")

	memSummary, ok := st.GetSession(sessID)
	require.True(t, ok)
	require.Equal(t, 1, memSummary.EventCount, "in-memory summary.event_count must be rebuilt to 1")
	require.Equal(t, 25, memSummary.TotalTokens)
}

func TestTornTailOpenReadOnlyNeverWritesDisk(t *testing.T) {
	dir := t.TempDir()
	nowMs := time.Now().Add(-1 * time.Minute).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessID := "sess_ro_torn"
	sessDir := filepath.Join(dir, "sessions", day, sessID)
	require.NoError(t, os.MkdirAll(sessDir, 0o755))

	ev1 := model.TraceEvent{
		ID:         "ev_ro_1",
		SessionID:  sessID,
		TurnIndex:  1,
		Timestamp:  nowMs,
		DurationMs: 40,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat:       &model.ChatSummary{Model: "gpt-4o", Usage: model.TokenUsage{TotalTokens: 10}},
	}
	ev2 := model.TraceEvent{
		ID:         "ev_ro_2",
		SessionID:  sessID,
		TurnIndex:  2,
		Timestamp:  nowMs + 200,
		DurationMs: 60,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Chat:       &model.ChatSummary{Model: "gpt-4o", Usage: model.TokenUsage{TotalTokens: 20}},
	}
	b1, err := json.Marshal(ev1)
	require.NoError(t, err)
	b2, err := json.Marshal(ev2)
	require.NoError(t, err)

	// 2 valid lines + 1 torn half-line without trailing newline
	var eventsBuf bytes.Buffer
	eventsBuf.Write(b1)
	eventsBuf.WriteByte('\n')
	eventsBuf.Write(b2)
	eventsBuf.WriteByte('\n')
	eventsBuf.WriteString(`{"id":"ev_ro_torn_3","session_id":"sess_ro_torn","status":`)
	eventsPath := filepath.Join(sessDir, "events.jsonl")
	require.NoError(t, os.WriteFile(eventsPath, eventsBuf.Bytes(), 0o644))

	// Write a mismatched session.json (claiming event_count=5) and a leftover .tmp file
	staleSummary := model.SessionSummary{
		ID:              sessID,
		Title:           "ro torn session",
		PrimaryProtocol: model.ProtocolOpenAIChat,
		CreatedAt:       nowMs,
		UpdatedAt:       nowMs + 300,
		EventCount:      5,
		TurnCount:       5,
		TotalTokens:     500,
	}
	sumBytes, err := json.MarshalIndent(staleSummary, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "session.json"), sumBytes, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sessDir, "session.json.tmp"), []byte(`{"partial":true}`), 0o644))

	// Take SHA-256 snapshot of the entire directory before OpenReadOnly
	beforeSnap := snapshotDirSHA256(t, dir)

	roStore, err := OpenReadOnly(dir, 10*time.Minute)
	require.NoError(t, err)

	// In-memory summary must skip the torn tail and reflect the 2 valid events
	memSum, ok := roStore.GetSession(sessID)
	require.True(t, ok)
	require.Equal(t, 2, memSum.EventCount, "OpenReadOnly must fix summary.event_count in memory from valid events")
	require.Equal(t, 30, memSum.TotalTokens, "OpenReadOnly must fix total_tokens in memory from valid events")

	evs, err := roStore.QuerySessionEvents(EventQuery{SessionID: sessID})
	require.NoError(t, err)
	require.Len(t, evs, 2)
	require.NoError(t, roStore.Close())

	// Take SHA-256 snapshot after OpenReadOnly and assert zero disk writes/mutations
	afterSnap := snapshotDirSHA256(t, dir)
	require.Equal(t, beforeSnap, afterSnap, "OpenReadOnly must not modify any file, permission, or .tmp artifact on disk")
}
