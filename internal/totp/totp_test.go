package totp

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTOTPGenerateVerifyAndLockout(t *testing.T) {
	sec, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateCode(sec, now)
	require.NoError(t, err)
	require.True(t, Verify(sec, code, now, 1))
	require.False(t, Verify(sec, "000000", now, 0) && code != "000000")

	g, err := NewGuard(sec)
	require.NoError(t, err)
	require.True(t, g.Enabled())

	tok, _, err := g.Login(code, 5*time.Minute)
	require.NoError(t, err)
	require.NoError(t, g.CheckTokenOrCode(tok))

	// 5 bad attempts trigger lockout
	for i := 0; i < 5; i++ {
		_, _, err = g.Login("invalid", 5*time.Minute)
		require.Error(t, err)
	}
	_, _, err = g.Login(code, 5*time.Minute)
	require.Error(t, err, "must be temporarily locked after 5 failed attempts")
}

func TestTOTPPerClientLockoutAndSessionCheckNoFailureCount(t *testing.T) {
	sec, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateCode(sec, now)
	require.NoError(t, err)
	badCode := "000000"
	if code == badCode {
		badCode = "999999"
	}

	g, err := NewGuard(sec)
	require.NoError(t, err)
	g.nowFunc = func() time.Time { return now }

	// 1. Repeated expired/invalid session checks or non-6-digit tokens must NOT trigger lockout
	sessTok, _, err := g.LoginFrom("10.0.0.10:1234", code, 1*time.Minute)
	require.NoError(t, err)
	require.True(t, g.CheckSession(sessTok))

	// Advance time past session expiration
	now = now.Add(2 * time.Minute)
	code, err = GenerateCode(sec, now)
	require.NoError(t, err)
	if code == badCode {
		badCode = "888888"
	}
	for i := 0; i < 20; i++ {
		require.False(t, g.CheckSession(sessTok))
		require.False(t, g.CheckSession("lt_nonexistent_cookie_value"))
		require.Error(t, g.CheckCodeFrom("10.0.0.10:1234", sessTok))
		require.Error(t, g.CheckCodeFrom("10.0.0.10:1234", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	}
	// Client 10.0.0.10 must still be able to authenticate with a valid 6-digit code
	require.NoError(t, g.CheckCodeFrom("10.0.0.10:9999", code))

	// 2. IP A (10.0.0.1) fails 5 times with wrong 6-digit codes -> IP A is locked, IP B (10.0.0.2) still succeeds
	for i := 0; i < MaxFailedAttempts; i++ {
		err = g.CheckCodeFrom(fmt.Sprintf("10.0.0.1:%d", 1000+i), badCode)
		require.Error(t, err)
	}
	err = g.CheckCodeFrom("10.0.0.1:2000", code)
	require.Error(t, err)
	require.Contains(t, err.Error(), "已锁定")

	// IP B with valid code succeeds immediately
	require.NoError(t, g.CheckCodeFrom("10.0.0.2:2000", code))
	tokB, _, err := g.LoginFrom("10.0.0.2:2001", code, 5*time.Minute)
	require.NoError(t, err)
	require.True(t, g.CheckSession(tokB))

	// After lockout window expires (16s), IP A can authenticate again
	now = now.Add(16 * time.Second)
	code, err = GenerateCode(sec, now)
	require.NoError(t, err)
	require.NoError(t, g.CheckCodeFrom("10.0.0.1:3000", code))
}

func TestTOTPClientBucketsCap(t *testing.T) {
	sec, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateCode(sec, now)
	require.NoError(t, err)
	badCode := "000000"
	if code == badCode {
		badCode = "999999"
	}

	g, err := NewGuard(sec)
	require.NoError(t, err)
	g.maxBuckets = 64
	g.nowFunc = func() time.Time { return now }

	for i := 0; i < 300; i++ {
		now = now.Add(time.Millisecond)
		ip := fmt.Sprintf("192.168.%d.%d:1234", i/256, i%256)
		_ = g.CheckCodeFrom(ip, badCode)
		g.mu.Lock()
		n := len(g.clients)
		g.mu.Unlock()
		require.LessOrEqual(t, n, 64, "client buckets must never exceed configured cap")
	}
}

func TestTOTPLoginFromPerClientIsolationAndLockedBucketProtection(t *testing.T) {
	require.Equal(t, 4096, MaxClientBuckets)
	require.Equal(t, 5, MaxFailedAttempts)

	sec, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	validCode, err := GenerateCode(sec, now)
	require.NoError(t, err)
	badCode := "000000"
	if validCode == badCode {
		badCode = "999999"
	}

	g, err := NewGuard(sec)
	require.NoError(t, err)
	g.nowFunc = func() time.Time { return now }

	// 1. CheckSession path never increments client failure buckets
	for i := 0; i < 30; i++ {
		require.False(t, g.CheckSession(""))
		require.False(t, g.CheckSession("lt_unknown_session_token"))
		require.False(t, g.CheckSession(badCode))
	}
	g.mu.Lock()
	require.Empty(t, g.clients, "CheckSession must never create or increment client failure buckets")
	g.mu.Unlock()

	// 2. Client IP A (198.51.100.10) fails LoginFrom 5 times -> locked out
	for i := 0; i < MaxFailedAttempts; i++ {
		tok, _, loginErr := g.LoginFrom(fmt.Sprintf("198.51.100.10:%d", 40000+i), badCode, DefaultSessionTTL)
		require.Error(t, loginErr)
		require.Empty(t, tok)
		if i == MaxFailedAttempts-1 {
			require.Contains(t, loginErr.Error(), "锁定 15 秒")
		}
	}

	// IP A is now locked even when submitting the valid code
	_, _, err = g.LoginFrom("198.51.100.10:49999", validCode, DefaultSessionTTL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "已锁定")

	// 3. Another IP B (198.51.100.20) is completely unaffected and can log in immediately
	tokB, expB, err := g.LoginFrom("198.51.100.20:50000", validCode, DefaultSessionTTL)
	require.NoError(t, err)
	require.True(t, len(tokB) > 3)
	require.Equal(t, now.Add(DefaultSessionTTL), expB)
	require.True(t, g.CheckSession(tokB))
	require.NoError(t, g.CheckTokenOrCode(tokB))

	// 4. Flooding MaxClientBuckets (4096) with unlocked single-failure IPs must NOT evict locked IP A
	for i := 0; i < MaxClientBuckets+100; i++ {
		floodIP := fmt.Sprintf("10.200.%d.%d:1234", (i/256)%256, i%256)
		_, _, _ = g.LoginFrom(floodIP, badCode, DefaultSessionTTL)
	}
	g.mu.Lock()
	bucketCount := len(g.clients)
	g.mu.Unlock()
	require.LessOrEqual(t, bucketCount, MaxClientBuckets)

	// Locked IP A must still be locked during LockoutDuration despite bucket churn
	_, _, err = g.LoginFrom("198.51.100.10:49999", validCode, DefaultSessionTTL)
	require.Error(t, err)
	require.Contains(t, err.Error(), "已锁定")

	// 5. After LockoutDuration expires, IP A can log in with a valid code
	now = now.Add(LockoutDuration + time.Second)
	validCodeAfter, err := GenerateCode(sec, now)
	require.NoError(t, err)
	tokA, _, err := g.LoginFrom("198.51.100.10:49999", validCodeAfter, DefaultSessionTTL)
	require.NoError(t, err)
	require.True(t, g.CheckSession(tokA))
}
