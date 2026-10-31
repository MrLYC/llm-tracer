package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
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

type Guard struct {
	mu          sync.Mutex
	enabled     bool
	secret      string
	window      int
	failures    int
	lockedUntil time.Time
	sessions    map[string]time.Time
	nowFunc     func() time.Time
}

func NewGuard(secret string) (*Guard, error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return &Guard{
			enabled:  false,
			window:   DefaultWindow,
			sessions: make(map[string]time.Time),
			nowFunc:  time.Now,
		}, nil
	}
	if _, err := NormalizeSecret(secret); err != nil {
		return nil, err
	}
	return &Guard{
		enabled:  true,
		secret:   secret,
		window:   DefaultWindow,
		sessions: make(map[string]time.Time),
		nowFunc:  time.Now,
	}, nil
}

func (g *Guard) Enabled() bool {
	return g != nil && g.enabled
}

func (g *Guard) CheckTokenOrCode(tokenOrCode string) error {
	if !g.Enabled() {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFunc()
	if now.Before(g.lockedUntil) {
		waitSec := int(g.lockedUntil.Sub(now).Seconds()) + 1
		return fmt.Errorf("TOTP 验证失败次数过多，已锁定 %d 秒", waitSec)
	}

	val := strings.TrimSpace(tokenOrCode)
	if val == "" {
		return fmt.Errorf("需要 TOTP 认证")
	}

	if exp, ok := g.sessions[val]; ok {
		if now.Before(exp) {
			return nil
		}
		delete(g.sessions, val)
	}

	if Verify(g.secret, val, now, g.window) {
		g.failures = 0
		return nil
	}

	g.failures++
	if g.failures >= 5 {
		g.lockedUntil = now.Add(15 * time.Second)
		g.failures = 0
		return fmt.Errorf("TOTP 动态码错误（连续失败 5 次，锁定 15 秒）")
	}
	return fmt.Errorf("TOTP 动态码无效")
}

func (g *Guard) Login(code string, ttl time.Duration) (string, time.Time, error) {
	if !g.Enabled() {
		return "", time.Time{}, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.nowFunc()
	if now.Before(g.lockedUntil) {
		waitSec := int(g.lockedUntil.Sub(now).Seconds()) + 1
		return "", time.Time{}, fmt.Errorf("TOTP 验证已暂时锁定，请 %d 秒后重试", waitSec)
	}
	if !Verify(g.secret, code, now, g.window) {
		g.failures++
		if g.failures >= 5 {
			g.lockedUntil = now.Add(15 * time.Second)
			g.failures = 0
		}
		return "", time.Time{}, fmt.Errorf("TOTP 动态码无效")
	}
	g.failures = 0
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
	g.sessions[sessToken] = exp
	return sessToken, exp, nil
}
