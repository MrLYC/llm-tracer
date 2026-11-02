package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	DefaultStepSeconds = 30
	DefaultDigits      = 6
	DefaultWindow      = 1
	DefaultSessionTTL  = 12 * time.Hour
	MaxFailedAttempts  = 5
	LockoutDuration    = 15 * time.Second
	MaxClientBuckets   = 4096
	ClientBucketTTL    = 10 * time.Minute
	MaxActiveSessions  = 4096
)

var sixDigitsRegex = regexp.MustCompile(`^[0-9]{6}$`)

func GenerateSecret() (string, error) {
	var b [20]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]), nil
}

func NormalizeSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.TrimSpace(secret))
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.TrimRight(cleaned, "=")
	if cleaned == "" {
		return nil, fmt.Errorf("totp secret cannot be empty")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 totp secret: %w", err)
	}
	return key, nil
}

func GenerateCode(secret string, at time.Time) (string, error) {
	key, err := NormalizeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix() / DefaultStepSeconds)
	return hotp(key, counter), nil
}

func Verify(secret, code string, at time.Time, window int) bool {
	code = strings.TrimSpace(code)
	if !sixDigitsRegex.MatchString(code) {
		return false
	}
	key, err := NormalizeSecret(secret)
	if err != nil {
		return false
	}
	if window < 0 {
		window = 0
	}
	if window > 5 {
		window = 5
	}
	baseCounter := int64(at.Unix() / DefaultStepSeconds)
	for offset := -window; offset <= window; offset++ {
		c := baseCounter + int64(offset)
		if c < 0 {
			continue
		}
		expected := hotp(key, uint64(c))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

func ProvisioningURI(issuer, account, secret string) string {
	if issuer == "" {
		issuer = "llm-tracer"
	}
	if account == "" {
		account = "admin@llm-tracer"
	}
	cleaned := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	cleaned = strings.TrimRight(cleaned, "=")
	label := url.PathEscape(issuer + ":" + account)
	vals := url.Values{}
	vals.Set("secret", cleaned)
	vals.Set("issuer", issuer)
	vals.Set("algorithm", "SHA1")
	vals.Set("digits", "6")
	vals.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, vals.Encode())
}

func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	otp := binCode % 1000000
	return fmt.Sprintf("%06d", otp)
}

type clientFailureState struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

type Guard struct {
	mu         sync.Mutex
	enabled    bool
	secret     string
	window     int
	maxBuckets int
	clients    map[string]*clientFailureState
	sessions   map[string]time.Time
	nowFunc    func() time.Time
}

func NewGuard(secret string) (*Guard, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return &Guard{
			enabled:    false,
			window:     DefaultWindow,
			maxBuckets: MaxClientBuckets,
			clients:    make(map[string]*clientFailureState),
			sessions:   make(map[string]time.Time),
			nowFunc:    time.Now,
		}, nil
	}
	if _, err := NormalizeSecret(secret); err != nil {
		return nil, err
	}
	return &Guard{
		enabled:    true,
		secret:     secret,
		window:     DefaultWindow,
		maxBuckets: MaxClientBuckets,
		clients:    make(map[string]*clientFailureState),
		sessions:   make(map[string]time.Time),
		nowFunc:    time.Now,
	}, nil
}

func (g *Guard) Enabled() bool {
	return g != nil && g.enabled
}

func normalizeClientKey(client string) string {
	client = strings.TrimSpace(client)
	if client == "" {
		return "_default_"
	}
	if h, _, err := net.SplitHostPort(client); err == nil && h != "" {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(client, "[]")
}

func (g *Guard) getOrCreateClientLocked(key string, now time.Time) *clientFailureState {
	if st, ok := g.clients[key]; ok {
		return st
	}
	limit := g.maxBuckets
	if limit <= 0 {
		limit = MaxClientBuckets
	}
	if len(g.clients) >= limit {
		for k, v := range g.clients {
			lockExpired := !v.lockedUntil.IsZero() && !now.Before(v.lockedUntil)
			idleExpired := v.lockedUntil.IsZero() && now.Sub(v.lastSeen) > ClientBucketTTL
			if lockExpired || idleExpired {
				delete(g.clients, k)
			}
		}
	}
	if len(g.clients) >= limit {
		var evictKey string
		var evictTime time.Time
		foundUnlocked := false
		for k, v := range g.clients {
			isUnlocked := v.lockedUntil.IsZero() || !now.Before(v.lockedUntil)
			if isUnlocked {
				if !foundUnlocked || v.lastSeen.Before(evictTime) {
					foundUnlocked = true
					evictKey = k
					evictTime = v.lastSeen
				}
			} else if !foundUnlocked {
				if evictKey == "" || v.lastSeen.Before(evictTime) {
					evictKey = k
					evictTime = v.lastSeen
				}
			}
		}
		if evictKey != "" {
			delete(g.clients, evictKey)
		}
	}
	st := &clientFailureState{lastSeen: now}
	g.clients[key] = st
	return st
}

// CheckSession validates whether tok is an active, non-expired session token.
// Expired or unknown session tokens never increment TOTP failure counters.
func (g *Guard) CheckSession(tok string) bool {
	if !g.Enabled() {
		return false
	}
	val := strings.TrimSpace(tok)
	if val == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFunc()
	exp, ok := g.sessions[val]
	if !ok {
		return false
	}
	if now.Before(exp) {
		return true
	}
	delete(g.sessions, val)
	return false
}

// CheckCodeFrom verifies a 6-digit TOTP code for a specific client IP/bucket.
// Only 6-digit numeric code verification failures increment the per-client failure counter.
func (g *Guard) CheckCodeFrom(client, code string) error {
	if !g.Enabled() {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFunc()
	key := normalizeClientKey(client)
	if st, ok := g.clients[key]; ok {
		if now.Before(st.lockedUntil) {
			waitSec := int(st.lockedUntil.Sub(now).Seconds()) + 1
			return fmt.Errorf("TOTP 验证失败次数过多，已锁定 %d 秒", waitSec)
		}
		if !st.lockedUntil.IsZero() {
			st.lockedUntil = time.Time{}
			st.failures = 0
		}
	}

	val := strings.TrimSpace(code)
	if val == "" {
		return fmt.Errorf("需要 TOTP 认证")
	}
	if !sixDigitsRegex.MatchString(val) {
		return fmt.Errorf("TOTP 动态码无效")
	}

	if Verify(g.secret, val, now, g.window) {
		delete(g.clients, key)
		return nil
	}

	st := g.getOrCreateClientLocked(key, now)
	st.failures++
	st.lastSeen = now
	if st.failures >= MaxFailedAttempts {
		st.lockedUntil = now.Add(LockoutDuration)
		st.failures = 0
		return fmt.Errorf("TOTP 动态码错误（连续失败 5 次，锁定 15 秒）")
	}
	return fmt.Errorf("TOTP 动态码无效")
}

// CheckTokenOrCode is retained as a backward-compatible wrapper around CheckSession and CheckCodeFrom.
func (g *Guard) CheckTokenOrCode(tokenOrCode string) error {
	if !g.Enabled() {
		return nil
	}
	if g.CheckSession(tokenOrCode) {
		return nil
	}
	return g.CheckCodeFrom("", tokenOrCode)
}

func (g *Guard) Login(code string, ttl time.Duration) (string, time.Time, error) {
	return g.LoginFrom("", code, ttl)
}

func (g *Guard) LoginFrom(client, code string, ttl time.Duration) (string, time.Time, error) {
	if !g.Enabled() {
		return "", time.Time{}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFunc()
	key := normalizeClientKey(client)
	if st, ok := g.clients[key]; ok {
		if now.Before(st.lockedUntil) {
			waitSec := int(st.lockedUntil.Sub(now).Seconds()) + 1
			return "", time.Time{}, fmt.Errorf("TOTP 验证失败次数过多，已锁定 %d 秒", waitSec)
		}
		if !st.lockedUntil.IsZero() {
			st.lockedUntil = time.Time{}
			st.failures = 0
		}
	}
	if !Verify(g.secret, code, now, g.window) {
		st := g.getOrCreateClientLocked(key, now)
		st.failures++
		st.lastSeen = now
		if st.failures >= MaxFailedAttempts {
			st.lockedUntil = now.Add(LockoutDuration)
			st.failures = 0
			return "", time.Time{}, fmt.Errorf("TOTP 动态码错误（连续失败 5 次，锁定 15 秒）")
		}
		return "", time.Time{}, fmt.Errorf("TOTP 动态码无效")
	}
	delete(g.clients, key)
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	var randBytes [18]byte
	_, _ = rand.Read(randBytes[:])
	sessToken := "lt_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randBytes[:])
	exp := now.Add(ttl)
	for k, v := range g.sessions {
		if now.After(v) {
			delete(g.sessions, k)
		}
	}
	if len(g.sessions) >= MaxActiveSessions {
		var oldestKey string
		var oldestExp time.Time
		for k, v := range g.sessions {
			if oldestKey == "" || v.Before(oldestExp) {
				oldestKey = k
				oldestExp = v
			}
		}
		if oldestKey != "" {
			delete(g.sessions, oldestKey)
		}
	}
	g.sessions[sessToken] = exp
	return sessToken, exp, nil
}
