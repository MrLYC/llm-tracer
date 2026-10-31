package totp

import (
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
