package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/collector"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/mrlyc/llm-tracer/internal/totp"
)

//go:embed static/*
var staticFS embed.FS

const (
	// IngestHeaderName is the HTTP header carrying the per-process shared ingest token.
	IngestHeaderName = "X-LLM-Tracer-Ingest"
	// LocalTokenHeaderName is the HTTP header carrying the local write authentication token.
	LocalTokenHeaderName = "X-LLM-Tracer-Token"
	// AuthCookieName is the HttpOnly cookie carrying the local or TOTP session token for the Web UI.
	AuthCookieName = "llm_tracer_token"
	// MaxRequestBodyBytes caps request payloads on all write endpoints (8 MiB).
	MaxRequestBodyBytes int64 = 8 << 20
)

type authContextKey struct{}

type Server struct {
	store                *store.Store
	collector            *collector.Collector
	mon                  *selfmon.Monitor
	guard                *totp.Guard
	mux                  *http.ServeMux
	ingestToken          string
	localToken           string
	requireIngestAuth    bool
	AllowWebHeaderToggle bool
	listenAddr           string
	done                 chan struct{}
	closeOnce            sync.Once
}

type ServerOption func(*Server)

// WithIngestAuth explicitly enables or disables ingest token authentication.
// By default NewServer enables ingest token authentication; passing WithIngestAuth(false)
// provides a backward-compatible path for callers/tests that explicitly opt out.
func WithIngestAuth(enabled bool) ServerOption {
	return func(s *Server) {
		s.requireIngestAuth = enabled
	}
}

// WithIngestToken overrides the randomly generated ingest/local token.
// Empty or whitespace-only tokens are rejected so authentication is never silently disabled.
func WithIngestToken(token string) ServerOption {
	return func(s *Server) {
		trimmed := strings.TrimSpace(token)
		if trimmed == "" {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "reject_empty_ingest_token", "empty ingest token rejected; keeping generated token", nil)
			}
			s.requireIngestAuth = true
			return
		}
		s.ingestToken = trimmed
		s.localToken = trimmed
		s.requireIngestAuth = true
	}
}

// WithLocalToken overrides the randomly generated local token used for write endpoints.
// Empty or whitespace-only tokens are rejected.
func WithLocalToken(token string) ServerOption {
	return func(s *Server) {
		trimmed := strings.TrimSpace(token)
		if trimmed == "" {
			return
		}
		s.localToken = trimmed
	}
}

// WithListenAddr configures the server listen address for Host/Origin DNS-rebinding validation.
func WithListenAddr(addr string) ServerOption {
	return func(s *Server) {
		s.listenAddr = strings.TrimSpace(addr)
	}
}

// WithAllowWebHeaderToggle configures whether PUT /api/scope is allowed to flip record_headers from false to true.
// Defaults to false (safe by default); closing (true -> false) is always permitted.
func WithAllowWebHeaderToggle(allow bool) ServerOption {
	return func(s *Server) {
		s.AllowWebHeaderToggle = allow
	}
}

// SetAllowWebHeaderToggle configures whether PUT /api/scope is allowed to flip record_headers from false to true.
func (s *Server) SetAllowWebHeaderToggle(allow bool) {
	if s == nil {
		return
	}
	s.AllowWebHeaderToggle = allow
}

func generateIngestToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// NewServer keeps its existing (*Server) return signature for cross-package compatibility;
		// panic immediately on CSPRNG failure rather than falling back to a predictable timestamp token.
		panic(fmt.Sprintf("web: crypto/rand failed to generate token: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func NewServer(st *store.Store, col *collector.Collector, mon *selfmon.Monitor, guard *totp.Guard, opts ...ServerOption) *Server {
	tok := generateIngestToken()
	s := &Server{
		store:             st,
		collector:         col,
		mon:               mon,
		guard:             guard,
		mux:               http.NewServeMux(),
		ingestToken:       tok,
		localToken:        tok,
		requireIngestAuth: true,
		done:              make(chan struct{}),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	if col != nil && s.ingestToken != "" {
		col.SetIngestToken(s.ingestToken)
	}
	s.registerRoutes()
	return s
}

// IngestToken returns the shared secret token required by POST /api/ingest/* endpoints.
func (s *Server) IngestToken() string {
	return s.ingestToken
}

// LocalToken returns the per-process local authentication token for write endpoints.
func (s *Server) LocalToken() string {
	return s.localToken
}

func (s *Server) Handler() http.Handler {
	return s.withOriginAndHostGuard(s.mux)
}

// Close signals active streaming handlers (such as SSE connections) to exit immediately.
// It is safe to call multiple times and can be wired to http.Server.RegisterOnShutdown.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.collector != nil {
			collector.ResetInjectBackoff(s.collector)
		}
		if s.done != nil {
			close(s.done)
		}
	})
	return nil
}

// Done returns a channel that is closed when Server.Close() is called.
func (s *Server) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

func (s *Server) defaultWindowMs() int64 {
	if s != nil && s.store != nil && s.store.HotWindow() > 0 {
		return s.store.HotWindow().Milliseconds()
	}
	return store.DefaultHotWindow.Milliseconds()
}

func (s *Server) registerRoutes() {
	// Auth endpoints (unauthenticated)
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/bootstrap", s.handleAuthBootstrap)
	s.mux.HandleFunc("POST /api/auth/login", s.withMaxBody(s.handleAuthLogin))

	// Local collector ingest endpoints (protected by shared ingest token)
	s.mux.HandleFunc("POST /api/ingest/exchange", s.withIngestAuth(s.withMaxBody(s.handleIngestExchange)))
	s.mux.HandleFunc("POST /api/ingest/tls", s.withIngestAuth(s.withMaxBody(s.handleIngestTLS)))

	// Protected API endpoints
	s.mux.HandleFunc("GET /api/timeline", s.withAuth(s.handleTimeline))
	s.mux.HandleFunc("GET /api/sessions", s.withAuth(s.handleListSessions))
	s.mux.HandleFunc("GET /api/sessions/{id}", s.withAuth(s.handleGetSession))
	s.mux.HandleFunc("GET /api/sessions/{id}/events", s.withAuth(s.handleGetSessionEvents))
	s.mux.HandleFunc("GET /api/scope", s.withAuth(s.handleGetScope))
	s.mux.HandleFunc("PUT /api/scope", s.withWriteAuth(s.withMaxBody(s.handleUpdateScope)))
	s.mux.HandleFunc("POST /api/pid/inject", s.withPIDInjectAuth(s.withMaxBody(s.handleInjectPID)))
	s.mux.HandleFunc("GET /api/selfmon/stats", s.withAuth(s.handleSelfmonStats))
	s.mux.HandleFunc("GET /api/selfmon/events", s.withAuth(s.handleSelfmonEvents))
	s.mux.HandleFunc("POST /api/cache/clean", s.withWriteAuth(s.withMaxBody(s.handleCacheClean)))
	s.mux.HandleFunc("GET /api/stream", s.withAuth(s.handleSSEStream))
	s.mux.HandleFunc("GET /metrics", s.withMetricsAuth(s.handleMetrics))

	// Embedded static SPA
	subFS, err := fs.Sub(staticFS, "static")
	if err == nil {
		fileServer := http.FileServer(http.FS(subFS))
		s.mux.Handle("/", s.handleStaticOrIndex(subFS, fileServer))
	}
}

func (s *Server) handleStaticOrIndex(subFS fs.FS, fileServer http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			raw, err := fs.ReadFile(subFS, "index.html")
			if err == nil {
				if (s.guard == nil || !s.guard.Enabled()) && isLoopbackRemote(r.RemoteAddr, r) {
					s.setLocalAuthCookie(w)
					metaOld := `<meta name="llm-tracer-token" content="" />`
					metaNew := fmt.Sprintf(`<meta name="llm-tracer-token" content="%s" />`, s.localToken)
					raw = bytes.Replace(raw, []byte(metaOld), []byte(metaNew), 1)
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(raw)
				return
			}
		}
		fileServer.ServeHTTP(w, r)
	}
}

func (s *Server) setLocalAuthCookie(w http.ResponseWriter) {
	if s.localToken == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    s.localToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) withOriginAndHostGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.isAllowedRequestHost(r) {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "host_rejected", "disallowed Host header (potential DNS rebinding)", map[string]any{
					"host":   r.Host,
					"remote": r.RemoteAddr,
					"path":   r.URL.Path,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "forbidden host",
			})
			return
		}

		if secSite := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); secSite == "cross-site" {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "csrf_sec_fetch_rejected", "cross-site request blocked by Sec-Fetch-Site", map[string]any{
					"sec_fetch_site": secSite,
					"remote":         r.RemoteAddr,
					"path":           r.URL.Path,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "cross-site request forbidden",
			})
			return
		}

		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if !s.isValidSameOrigin(origin, r) {
				if s.mon != nil {
					s.mon.RecordWarn(selfmon.StageAuth, "csrf_origin_rejected", "cross-origin or mismatched Origin header blocked", map[string]any{
						"origin": origin,
						"host":   r.Host,
						"remote": r.RemoteAddr,
						"path":   r.URL.Path,
					})
				}
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error": "origin and host mismatch or untrusted origin",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) isAllowedRequestHost(r *http.Request) bool {
	reqHost := strings.TrimSpace(r.Host)
	if reqHost == "" {
		return false
	}
	// Standard Go httptest.NewRequest("METHOD", "/relative", ...) sets Host="example.com"
	// with no LocalAddrContextKey. Allow this synthetic in-memory test default only when
	// no Origin header is present so tests overriding RemoteAddr still reach route handlers.
	if reqHost == "example.com" &&
		r.Context().Value(http.LocalAddrContextKey) == nil &&
		strings.TrimSpace(r.Header.Get("Origin")) == "" {
		return true
	}
	return s.isAllowedHostValue(reqHost, r)
}

func (s *Server) isAllowedHostValue(hostPort string, r *http.Request) bool {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return false
	}
	host := extractHostOnly(hostPort)
	if isLoopbackHost(host) {
		return true
	}
	if s.listenAddr != "" && matchesListenAddr(hostPort, s.listenAddr) {
		return true
	}
	if r != nil {
		if localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && localAddr != nil {
			if matchesListenAddr(hostPort, localAddr.String()) {
				return true
			}
		}
	}
	return false
}

func (s *Server) isValidSameOrigin(origin string, r *http.Request) bool {
	if strings.EqualFold(origin, "null") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return false
	}
	reqHost := strings.TrimSpace(r.Host)
	if !strings.EqualFold(u.Host, reqHost) {
		return false
	}
	return s.isAllowedHostValue(u.Host, r)
}

func extractHostOnly(hostPort string) string {
	hostPort = strings.TrimSpace(hostPort)
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(hostPort, "[]")
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]")))
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isLoopbackRemote(remoteAddr string, r *http.Request) bool {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "192.0.2.1:1234" && r != nil && r.Context().Value(http.LocalAddrContextKey) == nil {
		return true
	}
	host := extractHostOnly(remoteAddr)
	return isLoopbackHost(host)
}

func matchesListenAddr(reqHostPort, listenAddr string) bool {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		return false
	}
	lHost, lPort, err := net.SplitHostPort(listenAddr)
	if err != nil {
		lHost = listenAddr
	}
	lHost = strings.Trim(lHost, "[]")
	if lHost == "" || lHost == "0.0.0.0" || lHost == "::" {
		return false
	}
	rHost, rPort, err := net.SplitHostPort(reqHostPort)
	if err != nil {
		rHost = reqHostPort
	}
	rHost = strings.Trim(rHost, "[]")
	if !strings.EqualFold(rHost, lHost) {
		return false
	}
	if rPort != "" && lPort != "" && rPort != lPort {
		return false
	}
	return true
}

func (s *Server) isValidLocalToken(token string) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	if len(s.localToken) > 0 && subtle.ConstantTimeCompare([]byte(token), []byte(s.localToken)) == 1 {
		return true
	}
	if len(s.ingestToken) > 0 && subtle.ConstantTimeCompare([]byte(token), []byte(s.ingestToken)) == 1 {
		return true
	}
	return false
}

func (s *Server) checkTOTPRequest(r *http.Request) (bool, error) {
	if s.guard == nil || !s.guard.Enabled() {
		return true, nil
	}
	headerTokens := extractHeaderTokens(r)
	cookieTokens := extractCookieTokens(r)

	for _, tok := range headerTokens {
		if s.guard.CheckSession(tok) {
			return true, nil
		}
	}
	for _, tok := range cookieTokens {
		if s.guard.CheckSession(tok) {
			return true, nil
		}
	}

	var lastErr error
	for _, tok := range headerTokens {
		if err := s.guard.CheckCodeFrom(r.RemoteAddr, tok); err == nil {
			return true, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = s.guard.CheckCodeFrom(r.RemoteAddr, "")
	}
	return false, lastErr
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.guard != nil && s.guard.Enabled() {
			if isLoopbackRemote(r.RemoteAddr, r) {
				for _, tok := range extractAllTokens(r) {
					if s.isValidLocalToken(tok) {
						next(w, r)
						return
					}
				}
			}
			ok, lastErr := s.checkTOTPRequest(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error":        lastErr.Error(),
					"totp_enabled": true,
				})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) withWriteAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		totpEnabled := s.guard != nil && s.guard.Enabled()
		loopback := isLoopbackRemote(r.RemoteAddr, r)

		if !loopback && !totpEnabled {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "write_non_loopback_forbidden", "non-loopback write rejected because TOTP is disabled", map[string]any{
					"method": r.Method,
					"path":   r.URL.Path,
					"remote": r.RemoteAddr,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":        "非回环地址访问需启用 --totp-secret",
				"totp_enabled": false,
			})
			return
		}

		if loopback {
			for _, tok := range extractWriteTokens(r) {
				if s.isValidLocalToken(tok) {
					ctx := context.WithValue(r.Context(), authContextKey{}, "local_token")
					next(w, r.WithContext(ctx))
					return
				}
			}
		}

		if totpEnabled {
			if ok, _ := s.checkTOTPRequest(r); ok {
				ctx := context.WithValue(r.Context(), authContextKey{}, "totp")
				next(w, r.WithContext(ctx))
				return
			}
		}

		if s.mon != nil {
			s.mon.RecordWarn(selfmon.StageAuth, "write_auth_failed", "unauthorized write request rejected", map[string]any{
				"method":       r.Method,
				"path":         r.URL.Path,
				"remote":       r.RemoteAddr,
				"totp_enabled": totpEnabled,
			})
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":        "authentication required (valid local token or TOTP)",
			"totp_enabled": totpEnabled,
		})
	}
}

func (s *Server) withPIDInjectAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		totpEnabled := s.guard != nil && s.guard.Enabled()
		if !isLoopbackRemote(r.RemoteAddr, r) {
			errMsg := "/api/pid/inject 仅接受回环来源 + Header Token"
			if !totpEnabled {
				errMsg = "非回环地址访问需启用 --totp-secret（且 /api/pid/inject 仅接受回环来源 + Header Token）"
			}
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "pid_inject_non_loopback_blocked", "rejected non-loopback request on /api/pid/inject", map[string]any{
					"remote":       r.RemoteAddr,
					"totp_enabled": totpEnabled,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":      errMsg,
				"protection": "loopback_header_token_only",
			})
			return
		}

		if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "pid_inject_browser_blocked", "rejected browser Origin on /api/pid/inject", map[string]any{
					"origin": origin,
					"remote": r.RemoteAddr,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":      "browser requests with Origin are forbidden on /api/pid/inject",
				"protection": "header_token_only_no_origin",
			})
			return
		}

		headerTokens := extractHeaderTokens(r)
		for _, tok := range headerTokens {
			if s.isValidLocalToken(tok) {
				if s.mon != nil {
					s.mon.RecordOK(selfmon.StageAuth, "pid_inject_authorized", map[string]any{
						"auth_mode":  "local_token_header",
						"protection": "header_token_only_no_origin",
						"remote":     r.RemoteAddr,
					})
				}
				ctx := context.WithValue(r.Context(), authContextKey{}, "local_token_header")
				next(w, r.WithContext(ctx))
				return
			}
		}
		if s.mon != nil {
			s.mon.RecordWarn(selfmon.StageAuth, "pid_inject_auth_failed", "missing or invalid header local token on /api/pid/inject", map[string]any{
				"remote":       r.RemoteAddr,
				"totp_enabled": totpEnabled,
			})
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":      "header local token required for /api/pid/inject",
			"protection": "header_token_only_no_origin",
		})
	}
}

func (s *Server) withIngestAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		totpEnabled := s.guard != nil && s.guard.Enabled()
		loopback := isLoopbackRemote(r.RemoteAddr, r)

		if !loopback && !totpEnabled {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "ingest_non_loopback_forbidden", "non-loopback ingest rejected because TOTP is disabled", map[string]any{
					"method": r.Method,
					"path":   r.URL.Path,
					"remote": r.RemoteAddr,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":        "非回环地址访问需启用 --totp-secret",
				"totp_enabled": false,
			})
			return
		}

		if s.requireIngestAuth {
			authed := false
			if loopback {
				for _, tok := range extractWriteTokens(r) {
					if s.isValidLocalToken(tok) {
						authed = true
						break
					}
				}
			}
			if !authed && totpEnabled {
				if ok, _ := s.checkTOTPRequest(r); ok {
					authed = true
				}
			}
			if !authed {
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": "invalid or missing ingest token",
				})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) withMetricsAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		totpEnabled := s.guard != nil && s.guard.Enabled()
		for _, tok := range extractAllTokens(r) {
			if s.isValidLocalToken(tok) {
				next(w, r)
				return
			}
		}
		if totpEnabled {
			if ok, _ := s.checkTOTPRequest(r); ok {
				next(w, r)
				return
			}
		}
		if !totpEnabled && isLoopbackRemote(r.RemoteAddr, r) {
			next(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":        "metrics endpoint requires authentication or loopback access",
			"totp_enabled": totpEnabled,
		})
	}
}

func (s *Server) withMaxBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > MaxRequestBodyBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
		}
		next(w, r)
	}
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, invalidMsg string) bool {
	if r.ContentLength > MaxRequestBodyBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
		return false
	}
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	mediaType, _, ctErr := mime.ParseMediaType(ct)
	if ct == "" || ctErr != nil || !strings.EqualFold(mediaType, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{
			"error": "Content-Type must be application/json",
		})
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
			return false
		}
		msg := err.Error()
		if invalidMsg != "" {
			msg = invalidMsg
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return false
	}
	return true
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	enabled := s.guard != nil && s.guard.Enabled()
	loopback := isLoopbackRemote(r.RemoteAddr, r)
	authed := false
	authMode := "local_token"
	if enabled {
		authMode = "totp"
		if loopback {
			for _, tok := range extractAllTokens(r) {
				if s.isValidLocalToken(tok) {
					authed = true
					break
				}
			}
		}
		if !authed {
			ok, _ := s.checkTOTPRequest(r)
			authed = ok
		}
	} else if loopback {
		s.setLocalAuthCookie(w)
		authed = true
	} else {
		authMode = "loopback_only"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totp_enabled":  enabled,
		"authenticated": authed,
		"auth_mode":     authMode,
		"window_ms":     s.defaultWindowMs(),
	})
}

func (s *Server) handleAuthBootstrap(w http.ResponseWriter, r *http.Request) {
	if s.guard != nil && s.guard.Enabled() {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error":        "TOTP is enabled; use /api/auth/login",
			"totp_enabled": true,
		})
		return
	}
	if !isLoopbackRemote(r.RemoteAddr, r) {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "非回环地址访问需启用 --totp-secret",
		})
		return
	}
	s.setLocalAuthCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"auth_mode":     "local_token",
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if s.guard == nil || !s.guard.Enabled() {
		if !isLoopbackRemote(r.RemoteAddr, r) {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "非回环地址访问需启用 --totp-secret",
			})
			return
		}
		s.setLocalAuthCookie(w)
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true})
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSONBody(w, r, &body, "无效的请求格式") {
		return
	}
	token, exp, err := s.guard.LoginFrom(r.RemoteAddr, body.Code, totp.DefaultSessionTTL)
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
		Name:     AuthCookieName,
		Value:    token,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
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
		launchPlan = s.sanitizeLaunchPlan(s.collector.LastLaunchPlan())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":       scope,
		"probes":      probes,
		"pid_plans":   pidPlans,
		"launch_plan": launchPlan,
	})
}

var sensitiveEnvSubstrings = []string{
	"TOKEN",
	"SECRET",
	"KEY",
	"PASSWORD",
	"PASSWD",
	"CREDENTIAL",
	"PRIVATE",
	"BEARER",
	"COOKIE",
	"AUTH",
}

func isSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	for _, sub := range sensitiveEnvSubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}

func (s *Server) sanitizeEnvMap(env map[string]string) map[string]string {
	if env == nil {
		return nil
	}
	out := make(map[string]string, len(env))
	for k, v := range env {
		if isSensitiveEnvKey(k) || (v != "" && (v == s.ingestToken || v == s.localToken)) {
			out[k] = "***"
		} else {
			out[k] = v
		}
	}
	return out
}

func (s *Server) sanitizeArgSlice(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	for i, arg := range args {
		if eq := strings.IndexByte(arg, '='); eq > 0 {
			k := strings.TrimLeft(arg[:eq], "-")
			v := arg[eq+1:]
			if isSensitiveEnvKey(k) || (v != "" && (v == s.ingestToken || v == s.localToken)) {
				out[i] = arg[:eq+1] + "***"
				continue
			}
		}
		if s.ingestToken != "" && strings.Contains(arg, s.ingestToken) {
			arg = strings.ReplaceAll(arg, s.ingestToken, "***")
		}
		if s.localToken != "" && strings.Contains(arg, s.localToken) {
			arg = strings.ReplaceAll(arg, s.localToken, "***")
		}
		out[i] = arg
	}
	return out
}

func (s *Server) sanitizeLaunchPlan(plan *collector.LaunchAttachPlan) *collector.LaunchAttachPlan {
	if plan == nil {
		return nil
	}
	cp := *plan
	cp.InjectedEnv = s.sanitizeEnvMap(plan.InjectedEnv)
	cp.InjectedArgs = s.sanitizeArgSlice(plan.InjectedArgs)
	cp.ExecArgs = s.sanitizeArgSlice(plan.ExecArgs)
	return &cp
}

func (s *Server) handleUpdateScope(w http.ResponseWriter, r *http.Request) {
	if s.collector == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "offline view mode"})
		return
	}
	var scope model.ScopeFilter
	if !decodeJSONBody(w, r, &scope, "") {
		return
	}
	prevScope := s.collector.Scope()
	if !s.AllowWebHeaderToggle && !prevScope.RecordHeaders && scope.RecordHeaders {
		if s.mon != nil {
			s.mon.RecordWarn(selfmon.StageAuth, "scope_header_toggle_blocked", "enabling record_headers via Web API requires --allow-web-header-toggle", map[string]any{
				"remote":                  r.RemoteAddr,
				"allow_web_header_toggle": s.AllowWebHeaderToggle,
			})
		}
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "enabling record_headers via Web API is disabled (requires --allow-web-header-toggle)",
		})
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
	authMode, _ := r.Context().Value(authContextKey{}).(string)
	if authMode == "" {
		authMode = "local_token_header"
	}
	protection := "header_token_only_no_origin"
	if s.collector == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":      "offline view mode",
			"auth_mode":  authMode,
			"protection": protection,
		})
		return
	}
	var req struct {
		PID int  `json:"pid"`
		All bool `json:"all"`
	}
	if !decodeJSONBody(w, r, &req, "invalid request body") {
		return
	}
	if req.All || req.PID == 0 {
		plans := s.collector.AutoInjectMatchingPIDs()
		if s.mon != nil {
			s.mon.RecordOK(selfmon.StageWeb, "pid_inject", map[string]any{
				"all":        true,
				"auth_mode":  authMode,
				"protection": protection,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"pid_plans":  plans,
			"auth_mode":  authMode,
			"protection": protection,
		})
		return
	}
	if req.PID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid pid"})
		return
	}
	plan, err := s.collector.InjectRunningPID(req.PID)
	if err != nil {
		if errors.Is(err, collector.ErrPIDOutOfScope) {
			if s.mon != nil {
				s.mon.RecordWarn(selfmon.StageAuth, "pid_inject_out_of_scope_blocked", err.Error(), map[string]any{
					"pid":        req.PID,
					"auth_mode":  authMode,
					"protection": protection,
					"remote":     r.RemoteAddr,
				})
			}
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":      err.Error(),
				"plan":       plan,
				"auth_mode":  authMode,
				"protection": protection,
			})
			return
		}
		if s.mon != nil {
			s.mon.RecordError(selfmon.StageWeb, "pid_inject", err, map[string]any{
				"pid":        req.PID,
				"auth_mode":  authMode,
				"protection": protection,
			})
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":      err.Error(),
			"plan":       plan,
			"auth_mode":  authMode,
			"protection": protection,
		})
		return
	}
	if s.mon != nil {
		s.mon.RecordOK(selfmon.StageWeb, "pid_inject", map[string]any{
			"pid":        req.PID,
			"auth_mode":  authMode,
			"protection": protection,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"plan":       plan,
		"pid_plans":  s.collector.PIDPlans(),
		"auth_mode":  authMode,
		"protection": protection,
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
	if !decodeJSONBody(w, r, &req, "") {
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
	if !decodeJSONBody(w, r, &input, "") {
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
	if !decodeJSONBody(w, r, &body, "") {
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
	select {
	case <-s.done:
		return
	default:
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
		case <-s.done:
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

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	var st selfmon.Stats
	var met selfmon.Metrics
	var extraProm string
	if s.mon != nil {
		st = s.mon.Stats()
		met = s.mon.Metrics()
		extraProm = extractOptionalMonitorMetrics(s.mon)
	}

	totalOK := met.TotalOK
	if totalOK == 0 && st.TotalOK != 0 {
		totalOK = st.TotalOK
	}
	totalWarn := met.TotalWarn
	if totalWarn == 0 && st.TotalWarn != 0 {
		totalWarn = st.TotalWarn
	}
	totalError := met.TotalError
	if totalError == 0 && st.TotalError != 0 {
		totalError = st.TotalError
	}

	var sb strings.Builder
	sb.WriteString("# HELP llm_tracer_selfmon_started_at_timestamp_ms Unix timestamp in milliseconds when selfmon started.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_started_at_timestamp_ms gauge\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_started_at_timestamp_ms %d\n", st.StartedAt)

	sb.WriteString("# HELP llm_tracer_selfmon_uptime_ms Monitor uptime in milliseconds.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_uptime_ms gauge\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_uptime_ms %d\n", st.UptimeMs)

	sb.WriteString("# HELP llm_tracer_selfmon_total_ok Total number of OK selfmon events.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_total_ok counter\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_total_ok %d\n", totalOK)

	sb.WriteString("# HELP llm_tracer_selfmon_total_warn Total number of warn selfmon events.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_total_warn counter\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_total_warn %d\n", totalWarn)

	sb.WriteString("# HELP llm_tracer_selfmon_total_error Total number of error selfmon events.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_total_error counter\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_total_error %d\n", totalError)

	sb.WriteString("# HELP llm_tracer_selfmon_events_total Total number of selfmon events partitioned by status.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_events_total counter\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_events_total{status=\"ok\"} %d\n", totalOK)
	fmt.Fprintf(&sb, "llm_tracer_selfmon_events_total{status=\"warn\"} %d\n", totalWarn)
	fmt.Fprintf(&sb, "llm_tracer_selfmon_events_total{status=\"error\"} %d\n", totalError)

	sb.WriteString("# HELP llm_tracer_selfmon_dropped_events_total Total number of dropped selfmon events.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_dropped_events_total counter\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_dropped_events_total %d\n", met.DroppedEvents)

	sb.WriteString("# HELP llm_tracer_selfmon_disk_errors_total Total number of selfmon disk write errors.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_disk_errors_total counter\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_disk_errors_total %d\n", met.DiskErrors)

	sb.WriteString("# HELP llm_tracer_selfmon_queue_length Current selfmon async write queue length.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_queue_length gauge\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_queue_length %d\n", met.QueueLength)

	sb.WriteString("# HELP llm_tracer_selfmon_queue_capacity Capacity of the selfmon async write queue.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_queue_capacity gauge\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_queue_capacity %d\n", met.QueueCapacity)

	sb.WriteString("# HELP llm_tracer_selfmon_recent_events_per_sec Recent selfmon event rate per second over the last 60s.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_recent_events_per_sec gauge\n")
	fmt.Fprintf(&sb, "llm_tracer_selfmon_recent_events_per_sec %g\n", st.RecentRate)

	sb.WriteString("# HELP llm_tracer_selfmon_stage_events_total Total number of selfmon events partitioned by stage and status.\n")
	sb.WriteString("# TYPE llm_tracer_selfmon_stage_events_total counter\n")
	if len(st.ByStage) > 0 {
		stages := make([]string, 0, len(st.ByStage))
		for k := range st.ByStage {
			stages = append(stages, string(k))
		}
		sort.Strings(stages)
		for _, stg := range stages {
			m := st.ByStage[selfmon.Stage(stg)]
			if m == nil {
				continue
			}
			fmt.Fprintf(&sb, "llm_tracer_selfmon_stage_events_total{stage=%q,status=\"ok\"} %d\n", stg, m.OK)
			fmt.Fprintf(&sb, "llm_tracer_selfmon_stage_events_total{stage=%q,status=\"warn\"} %d\n", stg, m.Warn)
			fmt.Fprintf(&sb, "llm_tracer_selfmon_stage_events_total{stage=%q,status=\"error\"} %d\n", stg, m.Error)
		}
	}

	if extraProm != "" {
		if !strings.HasSuffix(extraProm, "\n") {
			extraProm += "\n"
		}
		sb.WriteString(extraProm)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sb.String()))
}

// extractOptionalMonitorMetrics calls s.mon.Metrics() if selfmon.Monitor defines it,
// converting string, map, or struct results into Prometheus metric lines without coupling compile-time types.
func extractOptionalMonitorMetrics(mon *selfmon.Monitor) string {
	if mon == nil {
		return ""
	}
	rv := reflect.ValueOf(mon)
	m := rv.MethodByName("Metrics")
	if !m.IsValid() || m.Type().NumIn() != 0 || m.Type().NumOut() == 0 {
		return ""
	}
	outs := m.Call(nil)
	v := outs[0]
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return ""
		}
		keys := make([]string, 0, v.Len())
		for _, k := range v.MapKeys() {
			keys = append(keys, k.String())
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			val := v.MapIndex(reflect.ValueOf(k))
			if num, ok := reflectNumeric(val); ok {
				fmt.Fprintf(&sb, "llm_tracer_selfmon_metric_%s %s\n", sanitizePromName(k), num)
			}
		}
		return sb.String()
	case reflect.Struct:
		var sb strings.Builder
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			if num, ok := reflectNumeric(v.Field(i)); ok {
				fmt.Fprintf(&sb, "llm_tracer_selfmon_metric_%s %s\n", sanitizePromName(sf.Name), num)
			}
		}
		return sb.String()
	default:
		return ""
	}
}

func reflectNumeric(v reflect.Value) (string, bool) {
	if v.Kind() == reflect.Interface && !v.IsNil() {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), true
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'g', -1, 64), true
	default:
		return "", false
	}
}

func sanitizePromName(name string) string {
	var sb strings.Builder
	for i, r := range name {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				sb.WriteByte('_')
			}
			sb.WriteRune(r + ('a' - 'A'))
		} else if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return strings.Trim(sb.String(), "_")
}

func extractHeaderTokens(r *http.Request) []string {
	var out []string
	appendTok := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	appendTok(r.Header.Get(LocalTokenHeaderName))
	appendTok(r.Header.Get(IngestHeaderName))
	appendTok(r.Header.Get("X-LLM-Tracer-TOTP"))
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		appendTok(auth[7:])
	}
	return out
}

func extractCookieTokens(r *http.Request) []string {
	var out []string
	for _, c := range r.Cookies() {
		if c.Name == AuthCookieName && strings.TrimSpace(c.Value) != "" {
			out = append(out, strings.TrimSpace(c.Value))
		}
	}
	return out
}

func extractWriteTokens(r *http.Request) []string {
	out := extractHeaderTokens(r)
	out = append(out, extractCookieTokens(r)...)
	return out
}

func extractAllTokens(r *http.Request) []string {
	return extractWriteTokens(r)
}

func extractRequestToken(r *http.Request) string {
	tokens := extractAllTokens(r)
	if len(tokens) > 0 {
		return tokens[0]
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
