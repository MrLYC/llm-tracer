package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/stretchr/testify/require"
)

func readAllPersistedFiles(t *testing.T, rootDir string) (map[string]string, string) {
	t.Helper()
	files := make(map[string]string)
	var combined strings.Builder
	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(rootDir, path)
		if relErr != nil {
			rel = path
		}
		content := string(data)
		files[rel] = content
		combined.WriteString(content)
		combined.WriteByte('\n')
		return nil
	})
	require.NoError(t, err)
	return files, combined.String()
}

// TestStoreLayerHeaderGating_LastLineOfDefense simulates the worst-case failure where both
// upstream layers (parser and collector) failed to strip headers, handing SaveEvent an event
// with HeadersRecorded=false but RequestHeaders and ResponseHeaders filled with credentials.
func TestStoreLayerHeaderGating_LastLineOfDefense(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	subCh, unsub := st.Subscribe()
	defer unsub()

	nowMs := time.Now().UnixMilli()
	ev := &model.TraceEvent{
		ID:              "ev_store_defense_off",
		SessionID:       "sess_store_defense_off",
		Timestamp:       nowMs,
		DurationMs:      35,
		Status:          "ok",
		HTTPStatus:      200,
		HTTPVersion:     "HTTP/2.0",
		Method:          "POST",
		Host:            "api.openai.com",
		Path:            "/v1/chat/completions",
		URL:             "https://api.openai.com/v1/chat/completions",
		Protocol:        model.ProtocolOpenAIChat,
		Process:         model.ProcessInfo{PID: 4242, Comm: "python3", Cmdline: "python3 app.py"},
		HeadersRecorded: false,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer sk-live-xxx-topsecret-credential",
			"authorization": "Bearer sk-live-lower-credential",
			"X-VirtX-TOTP":  "JBSWY3DPEHPK3PXP",
			"X-Api-Key":     "rk-live-9876543210",
			"Cookie":        "session_id=topsecret_cookie_token",
		},
		ResponseHeaders: map[string]string{
			"Set-Cookie":        "auth_token=resp_secret_cookie_value; HttpOnly",
			"X-Internal-Secret": "internal-resp-secret-xyz",
		},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o-mini",
			ResponseText: "safe body response",
		},
	}

	_, err = st.SaveEvent(ev)
	require.NoError(t, err)
	require.NoError(t, st.Flush())

	// 1. In-memory event passed to SaveEvent must have its headers scrubbed to nil
	require.False(t, ev.HeadersRecorded)
	require.Nil(t, ev.RequestHeaders, "SaveEvent must nil out RequestHeaders when HeadersRecorded=false")
	require.Nil(t, ev.ResponseHeaders, "SaveEvent must nil out ResponseHeaders when HeadersRecorded=false")

	// 2. Subscriber stream update must also carry nil headers
	select {
	case upd := <-subCh:
		require.NotNil(t, upd.Event)
		require.False(t, upd.Event.HeadersRecorded)
		require.Nil(t, upd.Event.RequestHeaders)
		require.Nil(t, upd.Event.ResponseHeaders)
	default:
		t.Fatal("expected subscriber update from SaveEvent")
	}

	// 3. Reading back from hot in-memory store must return nil headers
	hotEvs, err := st.QuerySessionEvents(EventQuery{SessionID: "sess_store_defense_off"})
	require.NoError(t, err)
	require.Len(t, hotEvs, 1)
	require.False(t, hotEvs[0].HeadersRecorded)
	require.Nil(t, hotEvs[0].RequestHeaders, "hot store event RequestHeaders must be nil when HeadersRecorded=false")
	require.Nil(t, hotEvs[0].ResponseHeaders, "hot store event ResponseHeaders must be nil when HeadersRecorded=false")

	// 4. Cold reload from disk via a fresh Store instance must return nil headers
	coldSt, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer coldSt.Close()
	coldEvs, err := coldSt.QuerySessionEvents(EventQuery{SessionID: "sess_store_defense_off"})
	require.NoError(t, err)
	require.Len(t, coldEvs, 1)
	require.False(t, coldEvs[0].HeadersRecorded)
	require.Nil(t, coldEvs[0].RequestHeaders, "cold reloaded event RequestHeaders must be nil when HeadersRecorded=false")
	require.Nil(t, coldEvs[0].ResponseHeaders, "cold reloaded event ResponseHeaders must be nil when HeadersRecorded=false")

	// 5. Persisted JSON/JSONL files on disk must not contain any sensitive header keys or values
	files, allDiskContent := readAllPersistedFiles(t, dir)
	require.NotEmpty(t, files, "expected persisted session files on disk")
	lowerDisk := strings.ToLower(allDiskContent)
	forbiddenSubstrings := []string{
		"bearer sk-live-xxx",
		"sk-live-xxx-topsecret-credential",
		"sk-live-lower-credential",
		"authorization",
		"jbswy3dpehpk3pxp",
		"x-virtx-totp",
		"rk-live-9876543210",
		"topsecret_cookie_token",
		"resp_secret_cookie_value",
		"internal-resp-secret-xyz",
		"request_headers",
		"response_headers",
	}
	for _, secret := range forbiddenSubstrings {
		require.NotContains(t, lowerDisk, secret, "persisted store files leaked forbidden header material: %s", secret)
	}
}

func TestStoreLayerHeaderGating_PositiveRecordHeadersTrue(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(dir, 10*time.Minute, nil)
	require.NoError(t, err)
	defer st.Close()

	nowMs := time.Now().UnixMilli()
	evOn := &model.TraceEvent{
		ID:              "ev_store_defense_on",
		SessionID:       "sess_store_defense_on",
		Timestamp:       nowMs,
		DurationMs:      20,
		Status:          "ok",
		HTTPStatus:      200,
		HTTPVersion:     "HTTP/1.1",
		Method:          "POST",
		Host:            "api.openai.com",
		Path:            "/v1/chat/completions",
		URL:             "https://api.openai.com/v1/chat/completions",
		Protocol:        model.ProtocolOpenAIChat,
		Process:         model.ProcessInfo{PID: 5151, Comm: "python3"},
		HeadersRecorded: true,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer sk-live-explicitly-recorded",
			"X-VirtX-TOTP":  "JBSWY3DPEHPK3PXP",
		},
		ResponseHeaders: map[string]string{
			"Set-Cookie":   "session=explicitly-recorded-cookie",
			"X-Request-Id": "req_store_positive",
		},
	}

	_, err = st.SaveEvent(evOn)
	require.NoError(t, err)
	require.NoError(t, st.Flush())

	evs, err := st.QuerySessionEvents(EventQuery{SessionID: "sess_store_defense_on"})
	require.NoError(t, err)
	require.Len(t, evs, 1)
	require.True(t, evs[0].HeadersRecorded)
	require.NotNil(t, evs[0].RequestHeaders)
	require.NotNil(t, evs[0].ResponseHeaders)
	require.Equal(t, "Bearer sk-live-explicitly-recorded", evs[0].RequestHeaders["Authorization"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", evs[0].RequestHeaders["X-VirtX-TOTP"])
	require.Equal(t, "session=explicitly-recorded-cookie", evs[0].ResponseHeaders["Set-Cookie"])
	require.Equal(t, "req_store_positive", evs[0].ResponseHeaders["X-Request-Id"])

	_, allDiskContent := readAllPersistedFiles(t, dir)
	require.Contains(t, allDiskContent, "Bearer sk-live-explicitly-recorded")
	require.Contains(t, allDiskContent, "JBSWY3DPEHPK3PXP")
	require.Contains(t, allDiskContent, "session=explicitly-recorded-cookie")
}
