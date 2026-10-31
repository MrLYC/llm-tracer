package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/liuyicong/llm-tracer/internal/collector"
	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
	"github.com/liuyicong/llm-tracer/internal/totp"
	"github.com/stretchr/testify/require"
)

func TestWebServerTOTPAndIngestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{RecordHeaders: false}, corr, st, mon)
	require.NoError(t, err)

	secret, err := totp.GenerateSecret()
	require.NoError(t, err)
	guard, err := totp.NewGuard(secret)
	require.NoError(t, err)

	srv := NewServer(st, col, mon, guard)
	h := srv.Handler()

	// 1. Unauthenticated request to /api/sessions must return 401 when TOTP is enabled
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest("GET", "/api/sessions", nil))
	require.Equal(t, http.StatusUnauthorized, rec1.Code)

	// 2. Login with valid TOTP 6-digit code
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	loginBody, _ := json.Marshal(map[string]string{"code": code})
	recLogin := httptest.NewRecorder()
	h.ServeHTTP(recLogin, httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody)))
	require.Equal(t, http.StatusOK, recLogin.Code)
	var loginOut struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(recLogin.Body).Decode(&loginOut))
	require.NotEmpty(t, loginOut.Token)

	// 3. Ingest a SystemOne JEV exchange with sensitive headers and verify headers are stripped by default
	ingestPayload := collector.DirectExchangeInput{
		Method:          "POST",
		Host:            "api.bamboonode.dev",
		Path:            "/v1/systemone",
		HTTPStatus:      200,
		DurationMs:      145,
		PID:             4321,
		Comm:            "jev-release",
		RequestHeaders:  map[string]string{"Authorization": "Bearer secret-systemone-key"},
		ResponseHeaders: map[string]string{"X-Request-Id": "req-1"},
		RequestBody:     []byte(`{"model":"startlux-decision-27b-autothink","state":{"page":{"url":"https://github.com","title":"GitHub"}},"questions":{"operation":{"type":"choice","criteria":{"CLICK":"click","DONE":"done"},"instructions":{"goal":"Find ripgrep"}}}}`),
		ResponseBody:    []byte(`{"model":"startlux-decision-27b-autothink","answers":{"operation":{"type":"choice","choice":"CLICK","confidence":0.96,"probabilities":{"CLICK":0.96,"DONE":0.04}}}}`),
	}
	ib, _ := json.Marshal(ingestPayload)
	recIng := httptest.NewRecorder()
	h.ServeHTTP(recIng, httptest.NewRequest("POST", "/api/ingest/exchange", bytes.NewReader(ib)))
	require.Equal(t, http.StatusOK, recIng.Code)

	// 4. Query /api/sessions with TOTP session token
	req := httptest.NewRequest("GET", "/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+loginOut.Token)
	recSess := httptest.NewRecorder()
	h.ServeHTTP(recSess, req)
	require.Equal(t, http.StatusOK, recSess.Code)
	var sessOut struct {
		Sessions []model.SessionSummary `json:"sessions"`
	}
	require.NoError(t, json.NewDecoder(recSess.Body).Decode(&sessOut))
	require.Len(t, sessOut.Sessions, 1)
	require.Equal(t, model.ProtocolSystemOne, sessOut.Sessions[0].PrimaryProtocol)

	// 5. Query session details and verify headers were not recorded
	reqDetail := httptest.NewRequest("GET", "/api/sessions/"+sessOut.Sessions[0].ID, nil)
	reqDetail.Header.Set("X-LLM-Tracer-TOTP", loginOut.Token)
	recDet := httptest.NewRecorder()
	h.ServeHTTP(recDet, reqDetail)
	require.Equal(t, http.StatusOK, recDet.Code)
	var detOut struct {
		Events []model.TraceEvent `json:"events"`
	}
	require.NoError(t, json.NewDecoder(recDet.Body).Decode(&detOut))
	require.Len(t, detOut.Events, 1)
	require.False(t, detOut.Events[0].HeadersRecorded)
	require.Nil(t, detOut.Events[0].RequestHeaders)
	require.Equal(t, "CLICK", detOut.Events[0].SystemOne.SelectedOp)
}
