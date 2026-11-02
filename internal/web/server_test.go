package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/collector"
	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/mrlyc/llm-tracer/internal/totp"
	"github.com/stretchr/testify/require"
)

func TestWebServerTOTPAndIngestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{RecordHeaders: false}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	secret, err := totp.GenerateSecret()
	require.NoError(t, err)
	guard, err := totp.NewGuard(secret)
	require.NoError(t, err)

	srv := NewServer(st, col, mon, guard)
	require.Len(t, srv.IngestToken(), 64)
	require.Equal(t, srv.IngestToken(), col.IngestToken())
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
	reqLogin := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	reqLogin.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(recLogin, reqLogin)
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

	// 3a. Ingest without X-LLM-Tracer-Ingest header or with wrong token must return 401 by default
	recUnauthIng := httptest.NewRecorder()
	h.ServeHTTP(recUnauthIng, httptest.NewRequest("POST", "/api/ingest/exchange", bytes.NewReader(ib)))
	require.Equal(t, http.StatusUnauthorized, recUnauthIng.Code)

	reqWrongIng := httptest.NewRequest("POST", "/api/ingest/exchange", bytes.NewReader(ib))
	reqWrongIng.Header.Set(IngestHeaderName, "wrong-token")
	recWrongIng := httptest.NewRecorder()
	h.ServeHTTP(recWrongIng, reqWrongIng)
	require.Equal(t, http.StatusUnauthorized, recWrongIng.Code)

	recUnauthTLS := httptest.NewRecorder()
	h.ServeHTTP(recUnauthTLS, httptest.NewRequest("POST", "/api/ingest/tls", strings.NewReader(`{"pid":1,"payload":"GET / HTTP/1.1\r\n\r\n"}`)))
	require.Equal(t, http.StatusUnauthorized, recUnauthTLS.Code)

	// 3b. Ingest with valid X-LLM-Tracer-Ingest token succeeds
	recIng := httptest.NewRecorder()
	reqIng := httptest.NewRequest("POST", "/api/ingest/exchange", bytes.NewReader(ib))
	reqIng.Header.Set("Content-Type", "application/json")
	reqIng.Header.Set(IngestHeaderName, srv.IngestToken())
	h.ServeHTTP(recIng, reqIng)
	require.Equal(t, http.StatusOK, recIng.Code)

	recTLS := httptest.NewRecorder()
	reqTLS := httptest.NewRequest("POST", "/api/ingest/tls", strings.NewReader(`{"pid":4321,"conn_id":"c1","direction":0,"payload":"POST /v1/systemone HTTP/1.1\r\nHost: api.bamboonode.dev\r\n\r\n"}`))
	reqTLS.Header.Set("Content-Type", "application/json")
	reqTLS.Header.Set(IngestHeaderName, srv.IngestToken())
	h.ServeHTTP(recTLS, reqTLS)
	require.Equal(t, http.StatusOK, recTLS.Code)

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

func TestWebServerIngestCompatAndMaxBytesLimit(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	// 1. Backward compatibility opt-out via WithIngestAuth(false)
	compatSrv := NewServer(st, col, mon, nil, WithIngestAuth(false))
	recCompat := httptest.NewRecorder()
	reqCompat := httptest.NewRequest("POST", "/api/ingest/tls", strings.NewReader(`{"pid":1,"payload":"hi"}`))
	reqCompat.Header.Set("Content-Type", "application/json")
	compatSrv.Handler().ServeHTTP(recCompat, reqCompat)
	require.Equal(t, http.StatusOK, recCompat.Code)

	// 2. Custom token via WithIngestToken
	customSrv := NewServer(st, col, mon, nil, WithIngestToken("custom-shared-token"))
	require.Equal(t, "custom-shared-token", customSrv.IngestToken())
	recNoHdr := httptest.NewRecorder()
	reqNoHdr := httptest.NewRequest("POST", "/api/ingest/tls", strings.NewReader(`{"pid":1,"payload":"hi"}`))
	reqNoHdr.Header.Set("Content-Type", "application/json")
	customSrv.Handler().ServeHTTP(recNoHdr, reqNoHdr)
	require.Equal(t, http.StatusUnauthorized, recNoHdr.Code)

	reqCustom := httptest.NewRequest("POST", "/api/ingest/tls", strings.NewReader(`{"pid":1,"payload":"hi"}`))
	reqCustom.Header.Set("Content-Type", "application/json")
	reqCustom.Header.Set(IngestHeaderName, "custom-shared-token")
	recCustom := httptest.NewRecorder()
	customSrv.Handler().ServeHTTP(recCustom, reqCustom)
	require.Equal(t, http.StatusOK, recCustom.Code)

	// 3. MaxBytesReader (> 8 MiB) must reject oversized payloads on write endpoints
	oversized := `{"payload":"` + strings.Repeat("a", int(MaxRequestBodyBytes)+1024) + `"}`
	for _, tc := range []struct {
		method string
		path   string
	}{
		{"POST", "/api/ingest/exchange"},
		{"POST", "/api/ingest/tls"},
		{"PUT", "/api/scope"},
		{"POST", "/api/pid/inject"},
		{"POST", "/api/cache/clean"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(oversized))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(IngestHeaderName, customSrv.IngestToken())
		rec := httptest.NewRecorder()
		customSrv.Handler().ServeHTTP(rec, req)
		require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "endpoint %s %s must enforce MaxRequestBodyBytes", tc.method, tc.path)
	}
}

func TestWriteEndpointsRequireAuthAndSucceedWithLocalToken(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	srv := NewServer(st, col, mon, nil)
	h := srv.Handler()

	// 1. Unauthenticated write calls to scope, inject, clean must return 401 even when TOTP is disabled
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{"PUT", "/api/scope", `{"hosts":["api.openai.com"]}`},
		{"POST", "/api/pid/inject", `{"all":true}`},
		{"POST", "/api/cache/clean", `{"all":true,"dry_run":true}`},
		{"POST", "/api/ingest/exchange", `{"method":"POST","host":"api.openai.com","path":"/v1/chat/completions"}`},
		{"POST", "/api/ingest/tls", `{"pid":1,"payload":"hi"}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code, "unauthenticated %s %s must return 401", tc.method, tc.path)
	}

	// 2. Write calls with valid local token succeed
	reqScope := httptest.NewRequest("PUT", "/api/scope", strings.NewReader(`{"hosts":["api.anthropic.com"]}`))
	reqScope.Header.Set("Content-Type", "application/json")
	reqScope.Header.Set(LocalTokenHeaderName, srv.LocalToken())
	recScope := httptest.NewRecorder()
	h.ServeHTTP(recScope, reqScope)
	require.Equal(t, http.StatusOK, recScope.Code)
	require.Equal(t, []string{"api.anthropic.com"}, col.Scope().Hosts)

	reqInject := httptest.NewRequest("POST", "/api/pid/inject", strings.NewReader(`{"all":true}`))
	reqInject.Header.Set("Content-Type", "application/json")
	reqInject.Header.Set(LocalTokenHeaderName, srv.LocalToken())
	recInject := httptest.NewRecorder()
	h.ServeHTTP(recInject, reqInject)
	require.Equal(t, http.StatusOK, recInject.Code)
	var injectResp map[string]any
	require.NoError(t, json.NewDecoder(recInject.Body).Decode(&injectResp))
	require.Equal(t, "local_token_header", injectResp["auth_mode"])
	require.Equal(t, "header_token_only_no_origin", injectResp["protection"])

	reqClean := httptest.NewRequest("POST", "/api/cache/clean", strings.NewReader(`{"all":true,"dry_run":true}`))
	reqClean.Header.Set("Content-Type", "application/json")
	reqClean.Header.Set("Authorization", "Bearer "+srv.LocalToken())
	recClean := httptest.NewRecorder()
	h.ServeHTTP(recClean, reqClean)
	require.Equal(t, http.StatusOK, recClean.Code)
}

func TestPIDInjectExtraProtectionAndBrowserBootstrap(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	srv := NewServer(st, col, mon, nil)
	h := srv.Handler()

	// 1. Browser loads GET / and GET /api/auth/status on 127.0.0.1:8787 -> receives HttpOnly cookie & injected meta token
	reqIndex := httptest.NewRequest("GET", "http://127.0.0.1:8787/", nil)
	reqIndex.Host = "127.0.0.1:8787"
	recIndex := httptest.NewRecorder()
	h.ServeHTTP(recIndex, reqIndex)
	require.Equal(t, http.StatusOK, recIndex.Code)
	require.Contains(t, recIndex.Body.String(), `<meta name="llm-tracer-token" content="`+srv.LocalToken()+`" />`)
	cookies := recIndex.Result().Cookies()
	var authCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == AuthCookieName {
			authCookie = c
			break
		}
	}
	require.NotNil(t, authCookie)
	require.True(t, authCookie.HttpOnly)
	require.Equal(t, srv.LocalToken(), authCookie.Value)

	// 2. Browser uses HttpOnly cookie on same-origin PUT /api/scope and POST /api/cache/clean -> succeeds
	reqBrowserScope := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["localhost"]}`))
	reqBrowserScope.Host = "127.0.0.1:8787"
	reqBrowserScope.Header.Set("Origin", "http://127.0.0.1:8787")
	reqBrowserScope.Header.Set("Content-Type", "application/json")
	reqBrowserScope.AddCookie(authCookie)
	recBrowserScope := httptest.NewRecorder()
	h.ServeHTTP(recBrowserScope, reqBrowserScope)
	require.Equal(t, http.StatusOK, recBrowserScope.Code)

	// 3. /api/pid/inject rejects cookie-only request (requires header token when TOTP is disabled)
	reqCookieOnlyInject := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/pid/inject", strings.NewReader(`{"all":true}`))
	reqCookieOnlyInject.Host = "127.0.0.1:8787"
	reqCookieOnlyInject.Header.Set("Content-Type", "application/json")
	reqCookieOnlyInject.AddCookie(authCookie)
	recCookieOnlyInject := httptest.NewRecorder()
	h.ServeHTTP(recCookieOnlyInject, reqCookieOnlyInject)
	require.Equal(t, http.StatusUnauthorized, recCookieOnlyInject.Code)

	// 4. /api/pid/inject rejects browser request carrying Origin header even with valid header token when TOTP is disabled
	reqBrowserInject := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/pid/inject", strings.NewReader(`{"all":true}`))
	reqBrowserInject.Host = "127.0.0.1:8787"
	reqBrowserInject.Header.Set("Origin", "http://127.0.0.1:8787")
	reqBrowserInject.Header.Set("Content-Type", "application/json")
	reqBrowserInject.Header.Set(LocalTokenHeaderName, srv.LocalToken())
	recBrowserInject := httptest.NewRecorder()
	h.ServeHTTP(recBrowserInject, reqBrowserInject)
	require.Equal(t, http.StatusForbidden, recBrowserInject.Code)
}

func TestContentTypeAndOriginHostCSRFProtection(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	srv := NewServer(st, col, mon, nil, WithListenAddr("127.0.0.1:8787"))
	h := srv.Handler()

	// 1. Non-JSON Content-Type (empty, text/plain, form-urlencoded) must be rejected with 415
	for _, ct := range []string{"", "text/plain", "text/plain; charset=utf-8", "application/x-www-form-urlencoded"} {
		req := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["a.com"]}`))
		req.Host = "127.0.0.1:8787"
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		req.Header.Set(LocalTokenHeaderName, srv.LocalToken())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnsupportedMediaType, rec.Code, "Content-Type %q must be rejected", ct)
	}

	// 2. Cross-origin Origin header must be rejected with 403
	for _, badOrigin := range []string{
		"https://evil.example.com",
		"http://evil.example.com:8787",
		"http://localhost:8787", // mismatches Host: 127.0.0.1:8787
		"null",
	} {
		req := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["a.com"]}`))
		req.Host = "127.0.0.1:8787"
		req.Header.Set("Origin", badOrigin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(LocalTokenHeaderName, srv.LocalToken())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, "Origin %q must be rejected", badOrigin)
	}

	// 3. DNS rebinding (Host header not loopback and not matching listen address) must be rejected with 403
	for _, badHost := range []string{
		"rebind.attacker.com",
		"rebind.attacker.com:8787",
		"192.168.99.99:8787",
	} {
		req := httptest.NewRequest("PUT", "http://"+badHost+"/api/scope", strings.NewReader(`{"hosts":["a.com"]}`))
		req.Host = badHost
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(LocalTokenHeaderName, srv.LocalToken())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, "Host %q must be rejected", badHost)
	}
}

func TestScopeEnvSanitizationAndRejectEmptyToken(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	// 1. WithIngestToken("") must be rejected and must NOT disable authentication
	srv := NewServer(st, col, mon, nil, WithIngestToken(""), WithIngestToken("   "))
	require.NotEmpty(t, srv.IngestToken())
	require.Len(t, srv.IngestToken(), 64)
	h := srv.Handler()

	recUnauth := httptest.NewRecorder()
	reqUnauth := httptest.NewRequest("POST", "/api/ingest/tls", strings.NewReader(`{"pid":1,"payload":"hi"}`))
	reqUnauth.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(recUnauth, reqUnauth)
	require.Equal(t, http.StatusUnauthorized, recUnauth.Code)

	// 2. Plan a launch command so collector populates LastLaunchPlan with InjectedEnv
	t.Setenv("OPENAI_API_KEY", "sk-live-super-secret")
	plan, _, err := col.PlanLaunchCommand([]string{"sh", "-c", "true"})
	require.NoError(t, err)
	require.NotNil(t, plan)
	if plan.InjectedEnv == nil {
		plan.InjectedEnv = make(map[string]string)
	}

	// Also verify sanitizeEnvMap directly and via GET /api/scope
	sanitized := srv.sanitizeLaunchPlan(&collector.LaunchAttachPlan{
		OriginalCmd: []string{"python3", "agent.py"},
		InjectedEnv: map[string]string{
			"LLM_TRACER_INGEST_TOKEN": srv.IngestToken(),
			"OPENAI_API_KEY":          "sk-secret-123",
			"CLIENT_SECRET":           "top-secret",
			"DB_PASSWORD":             "pw123",
			"LLM_TRACER_SOCK":         "/tmp/tls.sock",
		},
		InjectedArgs: []string{"--token=" + srv.IngestToken(), "--normal=1"},
	})
	require.Equal(t, "***", sanitized.InjectedEnv["LLM_TRACER_INGEST_TOKEN"])
	require.Equal(t, "***", sanitized.InjectedEnv["OPENAI_API_KEY"])
	require.Equal(t, "***", sanitized.InjectedEnv["CLIENT_SECRET"])
	require.Equal(t, "***", sanitized.InjectedEnv["DB_PASSWORD"])
	require.Equal(t, "/tmp/tls.sock", sanitized.InjectedEnv["LLM_TRACER_SOCK"])
	require.Equal(t, "--token=***", sanitized.InjectedArgs[0])
	require.Equal(t, "--normal=1", sanitized.InjectedArgs[1])

	// Query GET /api/scope and verify LLM_TRACER_INGEST_TOKEN is never leaked in the response body
	recScope := httptest.NewRecorder()
	h.ServeHTTP(recScope, httptest.NewRequest("GET", "/api/scope", nil))
	require.Equal(t, http.StatusOK, recScope.Code)
	bodyStr := recScope.Body.String()
	require.NotContains(t, bodyStr, srv.IngestToken(), "GET /api/scope must never leak raw ingest token")
	var scopeOut struct {
		LaunchPlan *collector.LaunchAttachPlan `json:"launch_plan"`
	}
	require.NoError(t, json.NewDecoder(strings.NewReader(bodyStr)).Decode(&scopeOut))
	require.NotNil(t, scopeOut.LaunchPlan)
	if val, ok := scopeOut.LaunchPlan.InjectedEnv["LLM_TRACER_INGEST_TOKEN"]; ok {
		require.Equal(t, "***", val)
	}
}

func TestPrometheusMetricsEndpoint(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	mon.RecordOK(selfmon.StageParser, "parse_http", nil)
	mon.RecordWarn(selfmon.StageAuth, "auth_warn", "sample warning", nil)

	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	srv := NewServer(st, nil, mon, nil)
	h := srv.Handler()

	// 1. Loopback GET /metrics succeeds and returns Prometheus text format
	reqLoop := httptest.NewRequest("GET", "http://127.0.0.1:8787/metrics", nil)
	reqLoop.Host = "127.0.0.1:8787"
	reqLoop.RemoteAddr = "127.0.0.1:54321"
	recLoop := httptest.NewRecorder()
	h.ServeHTTP(recLoop, reqLoop)
	require.Equal(t, http.StatusOK, recLoop.Code)
	require.Contains(t, recLoop.Header().Get("Content-Type"), "text/plain")
	metricsBody := recLoop.Body.String()
	require.Contains(t, metricsBody, "llm_tracer_selfmon_total_ok ")
	require.Contains(t, metricsBody, "llm_tracer_selfmon_total_warn ")
	require.Contains(t, metricsBody, `llm_tracer_selfmon_stage_events_total{stage="parser",status="ok"} 1`)
	require.Contains(t, metricsBody, `llm_tracer_selfmon_stage_events_total{stage="auth",status="warn"} 1`)

	// 2. Non-loopback remote without token is rejected with 401
	reqRemote := httptest.NewRequest("GET", "http://127.0.0.1:8787/metrics", nil)
	reqRemote.Host = "127.0.0.1:8787"
	reqRemote.RemoteAddr = "10.0.0.42:54321"
	recRemote := httptest.NewRecorder()
	h.ServeHTTP(recRemote, reqRemote)
	require.Equal(t, http.StatusUnauthorized, recRemote.Code)

	// 3. Non-loopback remote with valid local token succeeds
	reqRemoteAuth := httptest.NewRequest("GET", "http://127.0.0.1:8787/metrics", nil)
	reqRemoteAuth.Host = "127.0.0.1:8787"
	reqRemoteAuth.RemoteAddr = "10.0.0.42:54321"
	reqRemoteAuth.Header.Set(LocalTokenHeaderName, srv.LocalToken())
	recRemoteAuth := httptest.NewRecorder()
	h.ServeHTTP(recRemoteAuth, reqRemoteAuth)
	require.Equal(t, http.StatusOK, recRemoteAuth.Code)
}

var hex64Regex = regexp.MustCompile(`[0-9a-fA-F]{64}`)

func TestNonLoopbackNoTokenLeakAndWriteBlockedWithoutTOTP(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{RecordHeaders: false}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	srv := NewServer(st, col, mon, nil)
	h := srv.Handler()

	// 1. Non-loopback RemoteAddr=10.11.40.99:1234 requesting GET / must NOT receive 64-hex token or Set-Cookie
	reqIndex := httptest.NewRequest("GET", "/", nil)
	reqIndex.RemoteAddr = "10.11.40.99:1234"
	recIndex := httptest.NewRecorder()
	h.ServeHTTP(recIndex, reqIndex)
	require.Equal(t, http.StatusOK, recIndex.Code)
	bodyStr := recIndex.Body.String()
	require.NotContains(t, bodyStr, srv.LocalToken())
	require.False(t, hex64Regex.MatchString(bodyStr), "non-loopback GET / must not contain any 64-char hex token")
	require.Empty(t, recIndex.Result().Cookies(), "non-loopback GET / must not issue Set-Cookie")

	// GET /api/auth/status from non-loopback must also not issue Set-Cookie
	reqStatus := httptest.NewRequest("GET", "/api/auth/status", nil)
	reqStatus.RemoteAddr = "10.11.40.99:1234"
	recStatus := httptest.NewRecorder()
	h.ServeHTTP(recStatus, reqStatus)
	require.Equal(t, http.StatusOK, recStatus.Code)
	require.Empty(t, recStatus.Result().Cookies(), "non-loopback GET /api/auth/status must not issue Set-Cookie")

	// 2. Same non-loopback source requesting PUT /api/scope, POST /api/pid/inject, POST /api/cache/clean, and ingest must get 403
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{"PUT", "/api/scope", `{"record_headers":true}`},
		{"POST", "/api/pid/inject", `{"all":true}`},
		{"POST", "/api/cache/clean", `{"all":true,"dry_run":true}`},
		{"POST", "/api/ingest/exchange", `{"method":"POST","host":"api.openai.com","path":"/v1/chat/completions"}`},
		{"POST", "/api/ingest/tls", `{"pid":1,"payload":"hi"}`},
	} {
		// Without token
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.RemoteAddr = "10.11.40.99:1234"
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, "non-loopback %s %s without TOTP must return 403", tc.method, tc.path)
		require.Contains(t, rec.Body.String(), "非回环地址访问需启用 --totp-secret")

		// Even if attacker supplies localToken header from non-loopback
		reqWithTok := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		reqWithTok.RemoteAddr = "10.11.40.99:1234"
		reqWithTok.Header.Set("Content-Type", "application/json")
		reqWithTok.Header.Set(LocalTokenHeaderName, srv.LocalToken())
		reqWithTok.Header.Set(IngestHeaderName, srv.IngestToken())
		recWithTok := httptest.NewRecorder()
		h.ServeHTTP(recWithTok, reqWithTok)
		require.Equal(t, http.StatusForbidden, recWithTok.Code, "non-loopback %s %s with token but without TOTP must still return 403", tc.method, tc.path)
		require.Contains(t, recWithTok.Body.String(), "非回环地址访问需启用 --totp-secret")
	}
	require.False(t, col.Scope().RecordHeaders, "record_headers must remain false after blocked non-loopback writes")

	// 3. Loopback source (127.0.0.1:x) full lifecycle regression check
	reqLoopIndex := httptest.NewRequest("GET", "http://127.0.0.1:18788/", nil)
	reqLoopIndex.Host = "127.0.0.1:18788"
	reqLoopIndex.RemoteAddr = "127.0.0.1:54321"
	recLoopIndex := httptest.NewRecorder()
	h.ServeHTTP(recLoopIndex, reqLoopIndex)
	require.Equal(t, http.StatusOK, recLoopIndex.Code)
	require.Contains(t, recLoopIndex.Body.String(), `<meta name="llm-tracer-token" content="`+srv.LocalToken()+`" />`)
	loopCookies := recLoopIndex.Result().Cookies()
	require.NotEmpty(t, loopCookies)

	reqLoopScope := httptest.NewRequest("PUT", "http://127.0.0.1:18788/api/scope", strings.NewReader(`{"hosts":["api.openai.com"]}`))
	reqLoopScope.Host = "127.0.0.1:18788"
	reqLoopScope.RemoteAddr = "127.0.0.1:54321"
	reqLoopScope.Header.Set("Content-Type", "application/json")
	reqLoopScope.AddCookie(loopCookies[0])
	recLoopScope := httptest.NewRecorder()
	h.ServeHTTP(recLoopScope, reqLoopScope)
	require.Equal(t, http.StatusOK, recLoopScope.Code)

	reqLoopInject := httptest.NewRequest("POST", "http://127.0.0.1:18788/api/pid/inject", strings.NewReader(`{"all":true}`))
	reqLoopInject.Host = "127.0.0.1:18788"
	reqLoopInject.RemoteAddr = "127.0.0.1:54321"
	reqLoopInject.Header.Set("Content-Type", "application/json")
	reqLoopInject.Header.Set(LocalTokenHeaderName, srv.LocalToken())
	recLoopInject := httptest.NewRecorder()
	h.ServeHTTP(recLoopInject, reqLoopInject)
	require.Equal(t, http.StatusOK, recLoopInject.Code)
}

func TestTOTPLockoutPerIPNoCookieLockoutAndNoQueryTokenAuth(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	secret, err := totp.GenerateSecret()
	require.NoError(t, err)
	guard, err := totp.NewGuard(secret)
	require.NoError(t, err)

	srv := NewServer(st, col, mon, guard)
	h := srv.Handler()

	validCode, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	badCode := "000000"
	if validCode == badCode {
		badCode = "999999"
	}

	// 1. Repeatedly sending expired/invalid cookies or 64-hex tokens must NOT trigger TOTP lockout
	for i := 0; i < 12; i++ {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.RemoteAddr = "127.0.0.1:40001"
		req.AddCookie(&http.Cookie{Name: AuthCookieName, Value: "lt_expired_or_invalid_session_cookie"})
		req.Header.Set(LocalTokenHeaderName, strings.Repeat("a", 64))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
		require.NotContains(t, rec.Body.String(), "已锁定")
	}
	// Even sending 6-digit string inside a cookie must not count as TOTP code failure
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.RemoteAddr = "127.0.0.1:40001"
		req.AddCookie(&http.Cookie{Name: AuthCookieName, Value: badCode})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusUnauthorized, rec.Code)
	}

	// Same IP (127.0.0.1) can still authenticate with valid TOTP code
	reqAfterCookies := httptest.NewRequest("GET", "/api/sessions", nil)
	reqAfterCookies.RemoteAddr = "127.0.0.1:40001"
	reqAfterCookies.Header.Set("X-LLM-Tracer-TOTP", validCode)
	recAfterCookies := httptest.NewRecorder()
	h.ServeHTTP(recAfterCookies, reqAfterCookies)
	require.Equal(t, http.StatusOK, recAfterCookies.Code)

	// 2. IP A (10.11.40.99) sends 5 bad TOTP codes -> IP A is locked, IP B (127.0.0.1 and 10.11.40.100) still gets 200
	for i := 0; i < 5; i++ {
		reqBad := httptest.NewRequest("GET", "/api/sessions", nil)
		reqBad.RemoteAddr = "10.11.40.99:1234"
		reqBad.Header.Set("X-LLM-Tracer-TOTP", badCode)
		recBad := httptest.NewRecorder()
		h.ServeHTTP(recBad, reqBad)
		require.Equal(t, http.StatusUnauthorized, recBad.Code)
	}
	// IP A with valid code is now locked (401)
	reqLockedA := httptest.NewRequest("GET", "/api/sessions", nil)
	reqLockedA.RemoteAddr = "10.11.40.99:5678"
	reqLockedA.Header.Set("X-LLM-Tracer-TOTP", validCode)
	recLockedA := httptest.NewRecorder()
	h.ServeHTTP(recLockedA, reqLockedA)
	require.Equal(t, http.StatusUnauthorized, recLockedA.Code)
	require.Contains(t, recLockedA.Body.String(), "已锁定")

	// IP B (127.0.0.1:54321) with valid code returns 200
	reqValidB := httptest.NewRequest("GET", "/api/sessions", nil)
	reqValidB.RemoteAddr = "127.0.0.1:54321"
	reqValidB.Header.Set("X-LLM-Tracer-TOTP", validCode)
	recValidB := httptest.NewRecorder()
	h.ServeHTTP(recValidB, reqValidB)
	require.Equal(t, http.StatusOK, recValidB.Code)

	// IP B can also login via POST /api/auth/login and receive 200 + session cookie
	loginBody, _ := json.Marshal(map[string]string{"code": validCode})
	reqLoginB := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(loginBody))
	reqLoginB.RemoteAddr = "10.11.40.100:2222"
	reqLoginB.Header.Set("Content-Type", "application/json")
	recLoginB := httptest.NewRecorder()
	h.ServeHTTP(recLoginB, reqLoginB)
	require.Equal(t, http.StatusOK, recLoginB.Code)
	var loginResp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(recLoginB.Body).Decode(&loginResp))
	require.NotEmpty(t, loginResp.Token)

	// 3. ?token=<valid> query parameter must NO LONGER authenticate any endpoint
	for _, path := range []string{
		"/api/sessions?token=" + loginResp.Token,
		"/api/sessions?token=" + srv.LocalToken(),
		"/api/stream?token=" + loginResp.Token,
		"/api/timeline?token=" + loginResp.Token,
		"/metrics?token=" + srv.LocalToken(),
	} {
		reqQ := httptest.NewRequest("GET", path, nil)
		reqQ.RemoteAddr = "10.11.40.100:2222"
		recQ := httptest.NewRecorder()
		h.ServeHTTP(recQ, reqQ)
		require.Equal(t, http.StatusUnauthorized, recQ.Code, "query token on %s must be rejected", path)
	}

	// 4. /api/pid/inject rejects non-loopback even when TOTP is enabled and valid session/token is provided
	reqRemoteInject := httptest.NewRequest("POST", "/api/pid/inject", strings.NewReader(`{"all":true}`))
	reqRemoteInject.RemoteAddr = "10.11.40.100:2222"
	reqRemoteInject.Header.Set("Content-Type", "application/json")
	reqRemoteInject.Header.Set("X-LLM-Tracer-TOTP", loginResp.Token)
	reqRemoteInject.Header.Set(LocalTokenHeaderName, srv.LocalToken())
	recRemoteInject := httptest.NewRecorder()
	h.ServeHTTP(recRemoteInject, reqRemoteInject)
	require.Equal(t, http.StatusForbidden, recRemoteInject.Code)
}

func TestBrowserTOTPLoginEndToEndFlowAndLoopbackGuards(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })

	corr := correlator.NewCorrelator(mon)
	col, err := collector.NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	t.Run("totp_enabled_browser_e2e_login_cookie_and_per_ip_lockout", func(t *testing.T) {
		secret, err := totp.GenerateSecret()
		require.NoError(t, err)
		guard, err := totp.NewGuard(secret)
		require.NoError(t, err)

		srv := NewServer(st, col, mon, guard, WithListenAddr("0.0.0.0:8787"))
		h := srv.Handler()

		validCode, err := totp.GenerateCode(secret, time.Now())
		require.NoError(t, err)
		badCode := "000000"
		if validCode == badCode {
			badCode = "999999"
		}

		// 1. Unauthenticated access to protected read & write endpoints returns 401/403
		for _, tc := range []struct {
			method   string
			path     string
			body     string
			wantCode int
		}{
			{"GET", "/api/sessions", "", http.StatusUnauthorized},
			{"GET", "/api/timeline", "", http.StatusUnauthorized},
			{"GET", "/api/scope", "", http.StatusUnauthorized},
			{"GET", "/api/selfmon/stats", "", http.StatusUnauthorized},
			{"GET", "/api/selfmon/events", "", http.StatusUnauthorized},
			{"PUT", "/api/scope", `{"hosts":["api.openai.com"]}`, http.StatusUnauthorized},
			{"POST", "/api/cache/clean", `{"all":true,"dry_run":true}`, http.StatusUnauthorized},
			{"POST", "/api/pid/inject", `{"all":true}`, http.StatusForbidden},
		} {
			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			req.RemoteAddr = "10.88.0.20:50000"
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, tc.wantCode, rec.Code, "unauthenticated %s %s", tc.method, tc.path)
		}

		// 2. CheckSession path (expired/invalid cookies) does not count towards failure threshold
		for i := 0; i < 15; i++ {
			req := httptest.NewRequest("GET", "/api/sessions", nil)
			req.RemoteAddr = "10.88.0.20:50000"
			req.AddCookie(&http.Cookie{Name: AuthCookieName, Value: "lt_invalid_session_cookie"})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			require.NotContains(t, rec.Body.String(), "已锁定")
		}

		// 3. Client IP A (10.88.0.10) submits wrong TOTP codes to POST /api/auth/login -> fails and locks out IP A
		for i := 0; i < totp.MaxFailedAttempts; i++ {
			rawBody, _ := json.Marshal(map[string]string{"code": badCode})
			reqLoginA := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(rawBody))
			reqLoginA.RemoteAddr = fmt.Sprintf("10.88.0.10:%d", 40000+i)
			reqLoginA.Header.Set("Content-Type", "application/json")
			recLoginA := httptest.NewRecorder()
			h.ServeHTTP(recLoginA, reqLoginA)
			require.Equal(t, http.StatusUnauthorized, recLoginA.Code)
			require.Empty(t, recLoginA.Result().Cookies(), "failed login must not set auth cookie")
		}

		// IP A is now locked even with the valid current-window TOTP code
		validBody, _ := json.Marshal(map[string]string{"code": validCode})
		reqLockedA := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(validBody))
		reqLockedA.RemoteAddr = "10.88.0.10:49999"
		reqLockedA.Header.Set("Content-Type", "application/json")
		recLockedA := httptest.NewRecorder()
		h.ServeHTTP(recLockedA, reqLockedA)
		require.Equal(t, http.StatusUnauthorized, recLockedA.Code)
		require.Contains(t, recLockedA.Body.String(), "已锁定")
		require.Empty(t, recLockedA.Result().Cookies())

		// 4. Another client IP B (10.88.0.20) is unaffected: POST /api/auth/login with valid code issues llm_tracer_token cookie (SameSite=Strict)
		reqLoginB := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(validBody))
		reqLoginB.RemoteAddr = "10.88.0.20:50000"
		reqLoginB.Header.Set("Content-Type", "application/json")
		recLoginB := httptest.NewRecorder()
		h.ServeHTTP(recLoginB, reqLoginB)
		require.Equal(t, http.StatusOK, recLoginB.Code)

		var loginResp struct {
			Authenticated bool   `json:"authenticated"`
			Token         string `json:"token"`
			ExpiresAt     int64  `json:"expires_at"`
		}
		require.NoError(t, json.NewDecoder(recLoginB.Body).Decode(&loginResp))
		require.True(t, loginResp.Authenticated)
		require.NotEmpty(t, loginResp.Token)

		var totpCookie *http.Cookie
		for _, c := range recLoginB.Result().Cookies() {
			if c.Name == AuthCookieName {
				totpCookie = c
				break
			}
		}
		require.NotNil(t, totpCookie, "POST /api/auth/login must issue llm_tracer_token cookie")
		require.Equal(t, "llm_tracer_token", totpCookie.Name)
		require.Equal(t, loginResp.Token, totpCookie.Value)
		require.Equal(t, http.SameSiteStrictMode, totpCookie.SameSite)
		require.True(t, totpCookie.HttpOnly)
		require.Equal(t, "/", totpCookie.Path)

		// 5. Subsequent browser requests from IP B carrying only the llm_tracer_token cookie return 200
		for _, tc := range []struct {
			method string
			path   string
			body   string
		}{
			{"GET", "/api/auth/status", ""},
			{"GET", "/api/sessions", ""},
			{"GET", "/api/timeline", ""},
			{"GET", "/api/scope", ""},
			{"GET", "/api/selfmon/stats", ""},
			{"PUT", "/api/scope", `{"hosts":["api.openai.com"]}`},
			{"POST", "/api/cache/clean", `{"all":true,"dry_run":true}`},
		} {
			var bodyReader *strings.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			} else {
				bodyReader = strings.NewReader("")
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			req.RemoteAddr = "10.88.0.20:50001"
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			req.AddCookie(totpCookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, "authenticated browser request %s %s with cookie must return 200", tc.method, tc.path)
		}
	})

	t.Run("totp_disabled_loopback_only_token_and_non_loopback_write_403", func(t *testing.T) {
		srv := NewServer(st, col, mon, nil, WithListenAddr("0.0.0.0:8787"))
		h := srv.Handler()

		// 1. Non-loopback source (forged RemoteAddr) must NEVER receive token/cookie on any auth or index endpoint
		for _, tc := range []struct {
			method   string
			path     string
			wantCode int
		}{
			{"GET", "/", http.StatusOK},
			{"GET", "/index.html", http.StatusOK},
			{"GET", "/api/auth/status", http.StatusOK},
			{"POST", "/api/auth/bootstrap", http.StatusForbidden},
			{"POST", "/api/auth/login", http.StatusForbidden},
		} {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = "172.16.88.99:54321"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, tc.wantCode, rec.Code, "non-loopback %s %s", tc.method, tc.path)
			require.Empty(t, rec.Result().Cookies(), "non-loopback %s %s must not issue any cookie", tc.method, tc.path)
			require.NotContains(t, rec.Body.String(), srv.LocalToken(), "non-loopback %s %s must not leak local token", tc.method, tc.path)
		}

		// 2. Loopback source receives llm_tracer_token cookie with SameSite=Strict
		reqLoopBoot := httptest.NewRequest("POST", "/api/auth/bootstrap", nil)
		reqLoopBoot.RemoteAddr = "127.0.0.1:54321"
		recLoopBoot := httptest.NewRecorder()
		h.ServeHTTP(recLoopBoot, reqLoopBoot)
		require.Equal(t, http.StatusOK, recLoopBoot.Code)
		loopCookies := recLoopBoot.Result().Cookies()
		require.Len(t, loopCookies, 1)
		require.Equal(t, AuthCookieName, loopCookies[0].Name)
		require.Equal(t, srv.LocalToken(), loopCookies[0].Value)
		require.Equal(t, http.SameSiteStrictMode, loopCookies[0].SameSite)
		require.True(t, loopCookies[0].HttpOnly)

		// 3. Non-loopback source accessing write endpoints when TOTP is disabled -> 403 Forbidden
		for _, tc := range []struct {
			method string
			path   string
			body   string
		}{
			{"PUT", "/api/scope", `{"hosts":["api.openai.com"]}`},
			{"POST", "/api/cache/clean", `{"all":true,"dry_run":true}`},
			{"POST", "/api/pid/inject", `{"all":true}`},
			{"POST", "/api/ingest/exchange", `{"method":"POST","host":"api.openai.com","path":"/v1/chat/completions"}`},
			{"POST", "/api/ingest/tls", `{"pid":1,"payload":"hi"}`},
		} {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = "172.16.88.99:54321"
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(LocalTokenHeaderName, srv.LocalToken())
			req.AddCookie(loopCookies[0])
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, http.StatusForbidden, rec.Code, "non-loopback write %s %s without TOTP must return 403", tc.method, tc.path)
		}
	})
}

func TestSSECloseAndMissingSessionJSONRebuildVisibleInAPI(t *testing.T) {
	dir := t.TempDir()
	nowMs := time.Now().Add(-30 * time.Second).UnixMilli()
	day := time.UnixMilli(nowMs).UTC().Format("2006-01-02")
	sessDir := dir + "/sessions/" + day + "/sess_only_events"
	require.NoError(t, os.MkdirAll(sessDir, 0o700))

	ev := model.TraceEvent{
		ID:         "ev_only_1",
		SessionID:  "sess_only_events",
		TurnIndex:  1,
		Timestamp:  nowMs,
		DurationMs: 45,
		Status:     "ok",
		Protocol:   model.ProtocolOpenAIChat,
		Process:    model.ProcessInfo{PID: 9001, Comm: "codex"},
		Chat: &model.ChatSummary{
			Model:        "gpt-4o",
			Messages:     []model.ChatMessage{{Role: "user", Content: "recover session without session.json"}},
			ResponseText: "recovered in web api",
			Usage:        model.TokenUsage{TotalTokens: 25},
		},
	}
	evBytes, err := json.Marshal(ev)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sessDir+"/events.jsonl", append(evBytes, '\n'), 0o600))

	st, err := store.OpenReadOnly(dir, time.Hour)
	require.NoError(t, err)
	defer st.Close()

	guard, err := totp.NewGuard("")
	require.NoError(t, err)
	srv := NewServer(st, nil, nil, guard, WithListenAddr("127.0.0.1:8787"))
	h := srv.Handler()

	// 1. /api/auth/status must return window_ms == 3600000
	reqAuth := httptest.NewRequest("GET", "/api/auth/status", nil)
	reqAuth.RemoteAddr = "127.0.0.1:50000"
	recAuth := httptest.NewRecorder()
	h.ServeHTTP(recAuth, reqAuth)
	require.Equal(t, http.StatusOK, recAuth.Code)
	var authOut struct {
		WindowMs int64 `json:"window_ms"`
	}
	require.NoError(t, json.Unmarshal(recAuth.Body.Bytes(), &authOut))
	require.Equal(t, int64(3600000), authOut.WindowMs)

	// 2. Session with only events.jsonl (no session.json) must be visible in /api/sessions and /api/sessions/{id}/events
	reqSess := httptest.NewRequest("GET", "/api/sessions", nil)
	reqSess.RemoteAddr = "127.0.0.1:50000"
	recSess := httptest.NewRecorder()
	h.ServeHTTP(recSess, reqSess)
	require.Equal(t, http.StatusOK, recSess.Code)
	var sessOut struct {
		Sessions []model.SessionSummary `json:"sessions"`
		WindowMs int64                  `json:"window_ms"`
	}
	require.NoError(t, json.Unmarshal(recSess.Body.Bytes(), &sessOut))
	require.Equal(t, int64(3600000), sessOut.WindowMs)
	require.Len(t, sessOut.Sessions, 1)
	require.Equal(t, "sess_only_events", sessOut.Sessions[0].ID)
	require.Equal(t, "recover session without session.json", sessOut.Sessions[0].Title)

	reqEv := httptest.NewRequest("GET", "/api/sessions/sess_only_events/events", nil)
	reqEv.RemoteAddr = "127.0.0.1:50000"
	recEv := httptest.NewRecorder()
	h.ServeHTTP(recEv, reqEv)
	require.Equal(t, http.StatusOK, recEv.Code)
	var evOut struct {
		SessionID string             `json:"session_id"`
		Events    []model.TraceEvent `json:"events"`
	}
	require.NoError(t, json.Unmarshal(recEv.Body.Bytes(), &evOut))
	require.Len(t, evOut.Events, 1)
	require.Equal(t, "ev_only_1", evOut.Events[0].ID)

	// 3. SSE handler must exit immediately (<500ms) when srv.Close() is called even while r.Context() is still active
	reqSSE := httptest.NewRequest("GET", "/api/stream", nil)
	reqSSE.RemoteAddr = "127.0.0.1:50000"
	recSSE := httptest.NewRecorder()
	sseDone := make(chan struct{})
	go func() {
		h.ServeHTTP(recSSE, reqSSE)
		close(sseDone)
	}()
	time.Sleep(30 * time.Millisecond)
	t0 := time.Now()
	require.NoError(t, srv.Close())
	select {
	case <-sseDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handleSSEStream did not return within 500ms after Server.Close()")
	}
	require.Less(t, time.Since(t0), 500*time.Millisecond)
}

func harvestLoopbackMetaToken(t *testing.T, h http.Handler) string {
	t.Helper()
	req := httptest.NewRequest("GET", "http://127.0.0.1:8787/", nil)
	req.Host = "127.0.0.1:8787"
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	m := regexp.MustCompile(`<meta name="llm-tracer-token" content="([0-9a-fA-F]{64})" />`).FindStringSubmatch(rec.Body.String())
	require.Len(t, m, 2, "expected 64-hex local token in loopback index meta tag")
	return m[1]
}

func TestPIDInjectScopeEnforcementOverHTTP(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)

	shBin, err := exec.LookPath("sh")
	require.NoError(t, err)

	inScopeCmd := exec.Command(shBin, "-c", "sleep 30")
	require.NoError(t, inScopeCmd.Start())
	inScopePID := inScopeCmd.Process.Pid
	t.Cleanup(func() {
		_ = inScopeCmd.Process.Kill()
		_ = inScopeCmd.Wait()
	})

	outOfScopeCmd := exec.Command(shBin, "-c", "sleep 30")
	require.NoError(t, outOfScopeCmd.Start())
	outOfScopePID := outOfScopeCmd.Process.Pid
	t.Cleanup(func() {
		_ = outOfScopeCmd.Process.Kill()
		_ = outOfScopeCmd.Wait()
	})

	col, err := collector.NewCollector(dir, model.ScopeFilter{
		PIDs:    []int{inScopePID},
		PIDOnly: true,
	}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	srv := NewServer(st, col, mon, nil, WithListenAddr("127.0.0.1:8787"))
	h := srv.Handler()
	harvestedToken := harvestLoopbackMetaToken(t, h)

	// 1. Out-of-scope pid=1 with nil runtimeHooks: must be rejected with 403 by IsInScope BEFORE reaching ptrace
	reqPID1NoHooks := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/pid/inject", strings.NewReader(`{"pid":1}`))
	reqPID1NoHooks.Host = "127.0.0.1:8787"
	reqPID1NoHooks.RemoteAddr = "127.0.0.1:54321"
	reqPID1NoHooks.Header.Set("Content-Type", "application/json")
	reqPID1NoHooks.Header.Set(LocalTokenHeaderName, harvestedToken)
	recPID1NoHooks := httptest.NewRecorder()
	h.ServeHTTP(recPID1NoHooks, reqPID1NoHooks)
	require.Equal(t, http.StatusForbidden, recPID1NoHooks.Code, "out-of-scope pid=1 must be rejected with 403 Forbidden, not 500")
	require.Contains(t, recPID1NoHooks.Body.String(), "outside the configured capture scope")
	require.NotContains(t, strings.ToLower(recPID1NoHooks.Body.String()), "ptrace helper binary not available")

	// 2. Configure a spy PtraceBin script to prove out-of-scope PIDs never reach ptrace execution,
	// while in-scope PIDs succeed end-to-end over HTTP.
	ptraceLogPath := filepath.Join(dir, "ptrace_invocations.log")
	spyPtraceBin := filepath.Join(dir, "spy_ptrace.sh")
	spyScript := fmt.Sprintf("#!/bin/sh\necho \"$@\" >> %q\nexit 0\n", ptraceLogPath)
	require.NoError(t, os.WriteFile(spyPtraceBin, []byte(spyScript), 0o755))
	col.SetRuntimeHooks(&collector.RuntimeHookPaths{
		PtraceBin: spyPtraceBin,
	})

	for _, blockedPID := range []int{1, outOfScopePID} {
		body := fmt.Sprintf(`{"pid":%d}`, blockedPID)
		req := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/pid/inject", strings.NewReader(body))
		req.Host = "127.0.0.1:8787"
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(LocalTokenHeaderName, harvestedToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusForbidden, rec.Code, "out-of-scope pid=%d must return 403 Forbidden", blockedPID)
		require.Contains(t, rec.Body.String(), "outside the configured capture scope")
	}

	// Spy ptrace binary must NOT have been invoked for any out-of-scope PID
	_, statErr := os.Stat(ptraceLogPath)
	require.True(t, os.IsNotExist(statErr), "out-of-scope PID injection must never invoke ptrace helper binary")

	require.NoError(t, mon.Flush())
	evs, err := mon.QueryEvents(selfmon.Query{Limit: 100})
	require.NoError(t, err)
	var blockedPID1, blockedOther, anyInjectAttempt bool
	for _, ev := range evs {
		if ev.Action == "pid_inject_out_of_scope_blocked" && ev.Status == selfmon.StatusWarn {
			if ev.Detail["pid"] == float64(1) || ev.Detail["pid"] == 1 {
				blockedPID1 = true
			}
			if ev.Detail["pid"] == float64(outOfScopePID) || ev.Detail["pid"] == outOfScopePID {
				blockedOther = true
			}
		}
		if ev.Action == "inject_running_pid" {
			anyInjectAttempt = true
		}
	}
	require.True(t, blockedPID1, "selfmon must record pid_inject_out_of_scope_blocked warn event for pid=1")
	require.True(t, blockedOther, "selfmon must record pid_inject_out_of_scope_blocked warn event for outOfScopePID")
	require.False(t, anyInjectAttempt, "out-of-scope PID must never reach inject_running_pid")

	// 3. Positive case: in-scope PID succeeds over HTTP POST /api/pid/inject
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		reqInScope := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/pid/inject", strings.NewReader(fmt.Sprintf(`{"pid":%d}`, inScopePID)))
		reqInScope.Host = "127.0.0.1:8787"
		reqInScope.RemoteAddr = "127.0.0.1:54321"
		reqInScope.Header.Set("Content-Type", "application/json")
		reqInScope.Header.Set(LocalTokenHeaderName, harvestedToken)
		recInScope := httptest.NewRecorder()
		h.ServeHTTP(recInScope, reqInScope)
		require.Equal(t, http.StatusOK, recInScope.Code, "in-scope pid=%d must succeed on POST /api/pid/inject: %s", inScopePID, recInScope.Body.String())

		var resp struct {
			Plan collector.PIDAttachPlan `json:"plan"`
		}
		require.NoError(t, json.NewDecoder(recInScope.Body).Decode(&resp))
		require.Equal(t, inScopePID, resp.Plan.PID)
		require.True(t, resp.Plan.Injected, "in-scope PID plan must be marked injected=true")
		require.Equal(t, "ptrace_seize", resp.Plan.ActiveMode)

		logBytes, err := os.ReadFile(ptraceLogPath)
		require.NoError(t, err, "in-scope PID injection must invoke spy ptrace binary")
		require.Equal(t, "-p "+strconv.Itoa(inScopePID)+"\n", string(logBytes))
	}
}

func TestScopeRecordHeadersWebToggleGatingOverHTTP(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)

	initialScope := model.ScopeFilter{
		Hosts:         []string{"api.openai.com"},
		RecordHeaders: false,
	}
	col, err := collector.NewCollector(dir, initialScope, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col.Stop() })

	// 1. Default Server has AllowWebHeaderToggle == false (safe by default)
	srv := NewServer(st, col, mon, nil, WithListenAddr("127.0.0.1:8787"))
	require.False(t, srv.AllowWebHeaderToggle, "Server.AllowWebHeaderToggle must default to false")
	h := srv.Handler()
	harvestedToken := harvestLoopbackMetaToken(t, h)

	// 2. Attempt to flip record_headers from false -> true via PUT /api/scope when AllowWebHeaderToggle=false
	reqFlipOn := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["hijacked.example.com"],"record_headers":true}`))
	reqFlipOn.Host = "127.0.0.1:8787"
	reqFlipOn.RemoteAddr = "127.0.0.1:54321"
	reqFlipOn.Header.Set("Content-Type", "application/json")
	reqFlipOn.Header.Set(LocalTokenHeaderName, harvestedToken)
	recFlipOn := httptest.NewRecorder()
	h.ServeHTTP(recFlipOn, reqFlipOn)
	require.Equal(t, http.StatusForbidden, recFlipOn.Code, "PUT /api/scope flipping record_headers false->true must be rejected with 403 when AllowWebHeaderToggle=false")

	// Assert collector's actual runtime scope was NOT altered at all
	require.False(t, col.Scope().RecordHeaders, "collector actual Scope().RecordHeaders must remain false after rejected PUT /api/scope")
	require.Equal(t, []string{"api.openai.com"}, col.Scope().Hosts, "collector actual Scope().Hosts must remain unchanged after rejected PUT /api/scope")

	// Verify data-plane header gating on collector is still active (headers are stripped on ingested exchange)
	ingBodyOff, _ := json.Marshal(collector.DirectExchangeInput{
		ID:             "ev_hdr_blocked_1",
		Method:         "POST",
		Host:           "api.openai.com",
		Path:           "/v1/chat/completions",
		HTTPStatus:     200,
		PID:            os.Getpid(),
		Comm:           "python3",
		RequestHeaders: map[string]string{"Authorization": "Bearer sk-must-not-be-recorded"},
		RequestBody:    []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"ping"}]}`),
		ResponseBody:   []byte(`{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}]}`),
	})
	reqIngOff := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/ingest/exchange", bytes.NewReader(ingBodyOff))
	reqIngOff.Host = "127.0.0.1:8787"
	reqIngOff.RemoteAddr = "127.0.0.1:54321"
	reqIngOff.Header.Set("Content-Type", "application/json")
	reqIngOff.Header.Set(IngestHeaderName, srv.IngestToken())
	recIngOff := httptest.NewRecorder()
	h.ServeHTTP(recIngOff, reqIngOff)
	require.Equal(t, http.StatusOK, recIngOff.Code)
	var ingRespOff struct {
		Matched bool              `json:"matched"`
		Event   *model.TraceEvent `json:"event"`
	}
	require.NoError(t, json.NewDecoder(recIngOff.Body).Decode(&ingRespOff))
	require.True(t, ingRespOff.Matched)
	require.NotNil(t, ingRespOff.Event)
	require.False(t, ingRespOff.Event.HeadersRecorded, "ingested event must still have HeadersRecorded=false")
	require.Nil(t, ingRespOff.Event.RequestHeaders, "ingested event must still strip RequestHeaders")

	// Verify selfmon warning event was recorded
	require.NoError(t, mon.Flush())
	evs, err := mon.QueryEvents(selfmon.Query{Stage: selfmon.StageAuth, Status: selfmon.StatusWarn, Limit: 50})
	require.NoError(t, err)
	foundToggleBlocked := false
	for _, ev := range evs {
		if ev.Action == "scope_header_toggle_blocked" {
			foundToggleBlocked = true
			break
		}
	}
	require.True(t, foundToggleBlocked, "selfmon must record scope_header_toggle_blocked warning")

	// 3. Positive case: when AllowWebHeaderToggle=true, flipping false -> true via PUT /api/scope succeeds
	srvAllowed := NewServer(st, col, mon, nil, WithListenAddr("127.0.0.1:8787"), WithAllowWebHeaderToggle(true))
	require.True(t, srvAllowed.AllowWebHeaderToggle)
	hAllowed := srvAllowed.Handler()

	reqAllowOn := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["api.openai.com"],"record_headers":true}`))
	reqAllowOn.Host = "127.0.0.1:8787"
	reqAllowOn.RemoteAddr = "127.0.0.1:54321"
	reqAllowOn.Header.Set("Content-Type", "application/json")
	reqAllowOn.Header.Set(LocalTokenHeaderName, srvAllowed.LocalToken())
	recAllowOn := httptest.NewRecorder()
	hAllowed.ServeHTTP(recAllowOn, reqAllowOn)
	require.Equal(t, http.StatusOK, recAllowOn.Code, "PUT /api/scope flipping false->true must succeed when AllowWebHeaderToggle=true")
	require.True(t, col.Scope().RecordHeaders, "collector actual Scope().RecordHeaders must be true after authorized toggle")

	ingBodyOn, _ := json.Marshal(collector.DirectExchangeInput{
		ID:             "ev_hdr_allowed_2",
		Method:         "POST",
		Host:           "api.openai.com",
		Path:           "/v1/chat/completions",
		HTTPStatus:     200,
		PID:            os.Getpid(),
		Comm:           "python3",
		RequestHeaders: map[string]string{"Authorization": "Bearer sk-recorded-when-authorized"},
		RequestBody:    []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"ping2"}]}`),
		ResponseBody:   []byte(`{"id":"chatcmpl-2","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"pong2"},"finish_reason":"stop"}]}`),
	})
	reqIngOn := httptest.NewRequest("POST", "http://127.0.0.1:8787/api/ingest/exchange", bytes.NewReader(ingBodyOn))
	reqIngOn.Host = "127.0.0.1:8787"
	reqIngOn.RemoteAddr = "127.0.0.1:54321"
	reqIngOn.Header.Set("Content-Type", "application/json")
	reqIngOn.Header.Set(IngestHeaderName, srvAllowed.IngestToken())
	recIngOn := httptest.NewRecorder()
	hAllowed.ServeHTTP(recIngOn, reqIngOn)
	require.Equal(t, http.StatusOK, recIngOn.Code)
	var ingRespOn struct {
		Matched bool              `json:"matched"`
		Event   *model.TraceEvent `json:"event"`
	}
	require.NoError(t, json.NewDecoder(recIngOn.Body).Decode(&ingRespOn))
	require.True(t, ingRespOn.Matched)
	require.NotNil(t, ingRespOn.Event)
	require.True(t, ingRespOn.Event.HeadersRecorded)
	require.Equal(t, "Bearer sk-recorded-when-authorized", ingRespOn.Event.RequestHeaders["Authorization"])

	// 4. Closing direction (true -> false) is ALWAYS allowed even when AllowWebHeaderToggle=false
	srvClose := NewServer(st, col, mon, nil, WithListenAddr("127.0.0.1:8787"))
	require.False(t, srvClose.AllowWebHeaderToggle)
	require.True(t, col.Scope().RecordHeaders, "precondition: collector Scope().RecordHeaders is true before closing test")

	reqFlipOff := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["api.openai.com"],"record_headers":false}`))
	reqFlipOff.Host = "127.0.0.1:8787"
	reqFlipOff.RemoteAddr = "127.0.0.1:54321"
	reqFlipOff.Header.Set("Content-Type", "application/json")
	reqFlipOff.Header.Set(LocalTokenHeaderName, srvClose.LocalToken())
	recFlipOff := httptest.NewRecorder()
	srvClose.Handler().ServeHTTP(recFlipOff, reqFlipOff)
	require.Equal(t, http.StatusOK, recFlipOff.Code, "closing record_headers (true -> false) must always be permitted even when AllowWebHeaderToggle=false")
	require.False(t, col.Scope().RecordHeaders, "collector actual Scope().RecordHeaders must become false after closing")

	// Once closed (false), re-enabling (false -> true) on srvClose (AllowWebHeaderToggle=false) is rejected again
	reqReopen := httptest.NewRequest("PUT", "http://127.0.0.1:8787/api/scope", strings.NewReader(`{"hosts":["api.openai.com"],"record_headers":true}`))
	reqReopen.Host = "127.0.0.1:8787"
	reqReopen.RemoteAddr = "127.0.0.1:54321"
	reqReopen.Header.Set("Content-Type", "application/json")
	reqReopen.Header.Set(LocalTokenHeaderName, srvClose.LocalToken())
	recReopen := httptest.NewRecorder()
	srvClose.Handler().ServeHTTP(recReopen, reqReopen)
	require.Equal(t, http.StatusForbidden, recReopen.Code)
	require.False(t, col.Scope().RecordHeaders)
}

func TestInjectBackoffCleanedUpOnCollectorStopAndServerClose(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	corr := correlator.NewCorrelator(mon)

	// 1. Collector.Stop() automatically clears its entry from injectBackoffByCol
	col1, err := collector.NewCollector(dir, model.ScopeFilter{
		PIDs:    []int{os.Getpid()},
		PIDOnly: true,
	}, corr, st, mon)
	require.NoError(t, err)
	col1.SetRuntimeHooks(nil)

	_, injectErr := col1.InjectRunningPID(os.Getpid())
	require.Error(t, injectErr)
	require.Equal(t, 1, collector.InjectBackoffEntryCount(col1), "failed injection must record backoff entry for col1")

	col1.Stop()
	require.Eventually(t, func() bool {
		return collector.InjectBackoffEntryCount(col1) == 0
	}, time.Second, 5*time.Millisecond, "col1.Stop() must clear col1 from injectBackoffByCol")

	// 2. Server.Close() also clears its collector's entry from injectBackoffByCol
	col2, err := collector.NewCollector(dir, model.ScopeFilter{
		PIDs:    []int{os.Getpid()},
		PIDOnly: true,
	}, corr, st, mon)
	require.NoError(t, err)
	t.Cleanup(func() { col2.Stop() })
	col2.SetRuntimeHooks(nil)

	srv2 := NewServer(st, col2, mon, nil)
	_, injectErr2 := col2.InjectRunningPID(os.Getpid())
	require.Error(t, injectErr2)
	require.Equal(t, 1, collector.InjectBackoffEntryCount(col2))

	require.NoError(t, srv2.Close())
	require.Equal(t, 0, collector.InjectBackoffEntryCount(col2), "srv2.Close() must clear col2 from injectBackoffByCol")
}
