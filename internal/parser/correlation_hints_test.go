package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractCorrelationHintsHashesOnly(t *testing.T) {
	headers := map[string]string{
		"Traceparent":  "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"X-Session-Id": " plaintext-session ",
		"X-Request-Id": "not-a-correlation-header",
	}
	hints := extractCorrelationHintsFromHeader(func(key string) string {
		for k, v := range headers {
			if strings.EqualFold(k, key) {
				return v
			}
		}
		return ""
	})

	require.Len(t, hints, 2)
	require.Contains(t, hints, "w3c_trace:"+sha256Prefix("4bf92f3577b34da6a3ce929d0e0e4736"))
	require.Contains(t, hints, "hdr:x-session-id:"+sha256Prefix("plaintext-session"))
	for _, hint := range hints {
		require.NotContains(t, hint, "plaintext-session")
		require.NotContains(t, hint, "4bf92f3577b34da6")
	}
}

func TestExtractCorrelationHintsRejectsInvalidTraceparent(t *testing.T) {
	for _, value := range []string{
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
		"00-4bf92f3577b34da6a3ce929d0e0g4736-00f067aa0ba902b7-01",
		"",
	} {
		hints := extractCorrelationHintsFromHeader(func(key string) string {
			if strings.EqualFold(key, "traceparent") {
				return value
			}
			return ""
		})
		require.Empty(t, hints, value)
	}
}

func sha256Prefix(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}
