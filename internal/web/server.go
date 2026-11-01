package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/liuyicong/llm-tracer/internal/collector"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/parser"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
	"github.com/liuyicong/llm-tracer/internal/totp"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	store     *store.Store
	collector *collector.Collector
	mon       *selfmon.Monitor
	guard     *totp.Guard
	mux       *http.ServeMux
}

func NewServer(st *store.Store, col *collector.Collector, mon *selfmon.Monitor, guard *totp.Guard) *Server {
	s := &Server{
		store:     st,
		collector: col,
		mon:       mon,
		guard:     guard,
		mux:       http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	// Auth endpoints (unauthenticated)
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)

	// Local collector ingest endpoints
	s.mux.HandleFunc("POST /api/ingest/exchange", s.handleIngestExchange)
	s.mux.HandleFunc("POST /api/ingest/tls", s.handleIngestTLS)

	// Protected API endpoints
	s.mux.HandleFunc("GET /api/timeline", s.withAuth(s.handleTimeline))
	s.mux.HandleFunc("GET /api/sessions", s.withAuth(s.handleListSessions))
	s.mux.HandleFunc("GET /api/sessions/{id}", s.withAuth(s.handleGetSession))
	s.mux.HandleFunc("GET /api/sessions/{id}/events", s.withAuth(s.handleGetSessionEvents))
	s.mux.HandleFunc("GET /api/scope", s.withAuth(s.handleGetScope))
	s.mux.HandleFunc("PUT /api/scope", s.withAuth(s.handleUpdateScope))
	s.mux.HandleFunc("POST /api/pid/inject", s.withAuth(s.handleInjectPID))
	s.mux.HandleFunc("GET /api/selfmon/stats", s.withAuth(s.handleSelfmonStats))
	s.mux.HandleFunc("GET /api/selfmon/events", s.withAuth(s.handleSelfmonEvents))
	s.mux.HandleFunc("POST /api/cache/clean", s.withAuth(s.handleCacheClean))
	s.mux.HandleFunc("GET /api/stream", s.withAuth(s.handleSSEStream))

	// Embedded static SPA
	subFS, err := fs.Sub(staticFS, "static")
	if err == nil {
		fileServer := http.FileServer(http.FS(subFS))
		s.mux.Handle("/", fileServer)
	}
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.guard != nil && s.guard.Enabled() {
			token := extractRequestToken(r)
			if err := s.guard.CheckTokenOrCode(token); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error":        err.Error(),
					"totp_enabled": true,
				})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	enabled := s.guard != nil && s.guard.Enabled()
	authed := true
	if enabled {
		token := extractRequestToken(r)
		authed = s.guard.CheckTokenOrCode(token) == nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totp_enabled":  enabled,
		"authenticated": authed,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.guard == nil || !s.guard.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "无效的请求格式"})
		return
	}
	token, exp, err := s.guard.Login(body.Code, totp.DefaultSessionTTL)
	if err != nil {
		if s.mon != nil {
			s.mon.RecordError(selfmon.StageAuth, "totp_login", err, map[string]any{"remote": r.RemoteAddr})
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": err.Error()})
		return
	}
	if s.mon != nil {
		s.mon.RecordOK(selfmon.StageAuth, "totp_login", map[string]any{"remote": r.RemoteAddr})
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "llm_tracer_token",
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"token":         token,
		"expires_at":    exp.UnixMilli(),
	})
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	buckets, _ := strconv.Atoi(r.URL.Query().Get("buckets"))
	overview := s.store.TimelineOverview(buckets)
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	pid, _ := strconv.Atoi(q.Get("pid"))

	sessions, err := s.store.QuerySessions(store.SessionQuery{
		From:     from,
		To:       to,
		Before:   before,
		Limit:    limit,
		Protocol: q.Get("protocol"),
		Keyword:  q.Get("q"),
		PID:      pid,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions":  sessions,
		"window_ms": s.store.HotWindow().Milliseconds(),
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok := s.store.GetSession(id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}
	q := r.URL.Query()
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))

	// If user explicitly clicked a session whose timestamps are older than the default 10m window
	// and no explicit [from, to] was restricted, include that session's span.
	if from == 0 && before == 0 && sess.CreatedAt > 0 {
		from = sess.CreatedAt - 1000
		if sess.UpdatedAt+1000 > to {
			to = sess.UpdatedAt + 1000
		}
	}
	events, err := s.store.QuerySessionEvents(store.EventQuery{
		SessionID: id,
		From:      from,
		To:        to,
		Before:    before,
		Limit:     limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session": sess,
		"events":  events,
	})
}

func (s *Server) handleGetSessionEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	q := r.URL.Query()
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))

	events, err := s.store.QuerySessionEvents(store.EventQuery{
		SessionID: id,
		From:      from,
		To:        to,
		Before:    before,
		Limit:     limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": id,
		"events":     events,
	})
}

func (s *Server) handleGetScope(w http.ResponseWriter, r *http.Request) {
	var scope model.ScopeFilter
	var probes []collector.ProbeTarget
	var pidPlans []collector.PIDAttachPlan
	var launchPlan *collector.LaunchAttachPlan
	if s.collector != nil {
		scope = s.collector.Scope()
		probes = s.collector.Probes()
		pidPlans = s.collector.PIDPlans()
		launchPlan = s.collector.LastLaunchPlan()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":       scope,
		"probes":      probes,
		"pid_plans":   pidPlans,
		"launch_plan": launchPlan,
	})
}

func (s *Server) handleUpdateScope(w http.ResponseWriter, r *http.Request) {
	if s.collector == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "offline view mode"})
		return
	}
	var scope model.ScopeFilter
	if err := json.NewDecoder(r.Body).Decode(&scope); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.collector.UpdateScope(scope)
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":     s.collector.Scope(),
		"probes":    s.collector.Probes(),
		"pid_plans": s.collector.PIDPlans(),
	})
}

func (s *Server) handleInjectPID(w http.ResponseWriter, r *http.Request) {
	if s.collector == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "offline view mode"})
		return
	}
	var req struct {
		PID int  `json:"pid"`
		All bool `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body"})
		return
	}
	if req.All || req.PID == 0 {
		plans := s.collector.AutoInjectMatchingPIDs()
		writeJSON(w, http.StatusOK, map[string]any{"pid_plans": plans})
		return
	}
	if req.PID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid pid"})
		return
	}
	plan, err := s.collector.InjectRunningPID(req.PID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": err.Error(),
			"plan":  plan,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan":      plan,
		"pid_plans": s.collector.PIDPlans(),
	})
}

func (s *Server) handleSelfmonStats(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil {
		writeJSON(w, http.StatusOK, selfmon.Stats{})
		return
	}
	writeJSON(w, http.StatusOK, s.mon.Stats())
}

func (s *Server) handleSelfmonEvents(w http.ResponseWriter, r *http.Request) {
	if s.mon == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []selfmon.Event{}})
		return
	}
	q := r.URL.Query()
	from, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	to, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))

	evs, err := s.mon.QueryEvents(selfmon.Query{
		From:   from,
		To:     to,
		Before: before,
		Limit:  limit,
		Status: selfmon.Status(q.Get("status")),
		Stage:  selfmon.Stage(q.Get("stage")),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": evs,
		"stats":  s.mon.Stats(),
	})
}

func (s *Server) handleCacheClean(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OlderThan      string `json:"older_than"`
		All            bool   `json:"all"`
		DryRun         bool   `json:"dry_run"`
		IncludeSelfmon bool   `json:"include_selfmon"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	var dur time.Duration
	if req.OlderThan != "" {
		d, err := parseDurationEx(req.OlderThan)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		dur = d
	}
	rep, err := s.store.Clean(store.CleanOptions{
		OlderThan:      dur,
		All:            req.All,
		DryRun:         req.DryRun,
		IncludeSelfmon: req.IncludeSelfmon,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) handleIngestExchange(w http.ResponseWriter, r *http.Request) {
	if s.collector == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "collector disabled"})
		return
	}
	var input collector.DirectExchangeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ev, matched, err := s.collector.IngestDirectExchange(input)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matched": matched,
		"event":   ev,
	})
}

func (s *Server) handleIngestTLS(w http.ResponseWriter, r *http.Request) {
	if s.collector == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "collector disabled"})
		return
	}
	var body struct {
		PID       int    `json:"pid"`
		TID       int    `json:"tid"`
		ConnID    string `json:"conn_id"`
		Direction int    `json:"direction"`
		Payload   string `json:"payload"`
		TLSMode   string `json:"tls_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	dir := parser.DirWrite
	if body.Direction != 0 {
		dir = parser.DirRead
	}
	matched := s.collector.IngestRawChunk(body.PID, body.TID, body.ConnID, dir, []byte(body.Payload), body.TLSMode)
	writeJSON(w, http.StatusOK, map[string]any{"matched": matched})
}

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	storeCh, unsubStore := s.store.Subscribe()
	defer unsubStore()

	var monCh chan selfmon.Event
	var unsubMon func()
	if s.mon != nil {
		monCh, unsubMon = s.mon.Subscribe()
		defer unsubMon()
	}

	_, _ = fmt.Fprintf(w, "event: ready\ndata: {\"ok\":true}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case up, ok := <-storeCh:
			if !ok {
				return
			}
			b, _ := json.Marshal(up)
			_, _ = fmt.Fprintf(w, "event: trace\ndata: %s\n\n", string(b))
			flusher.Flush()
		case mev, ok := <-monCh:
			if !ok {
				return
			}
			b, _ := json.Marshal(mev)
			_, _ = fmt.Fprintf(w, "event: selfmon\ndata: %s\n\n", string(b))
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func extractRequestToken(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-LLM-Tracer-TOTP")); v != "" {
		return v
	}
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	if c, err := r.Cookie("llm_tracer_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" {
		return q
	}
	return ""
}

func parseDurationEx(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
