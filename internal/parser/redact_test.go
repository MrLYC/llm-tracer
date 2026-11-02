package parser

import (
	"testing"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
)

func TestParserSharesSensitiveQueryKeysAndRedactsNewForms(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		secret string
		expect string
	}{
		{
			name:   "X-Goog-Api-Key",
			path:   "/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse&X-Goog-Api-Key=AIzaSyGoogParserSecret",
			secret: "AIzaSyGoogParserSecret",
			expect: "/v1beta/models/gemini-1.5-pro:streamGenerateContent?alt=sse&X-Goog-Api-Key=[REDACTED]",
		},
		{
			name:   "api%5Fkey",
			path:   "/v1/chat/completions?api%5Fkey=encoded_underscore_secret&foo=bar",
			secret: "encoded_underscore_secret",
			expect: "/v1/chat/completions?api%5Fkey=[REDACTED]&foo=bar",
		},
		{
			name:   "jwt",
			path:   "/v1/chat/completions?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload.sig",
			secret: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.payload.sig",
			expect: "/v1/chat/completions?jwt=[REDACTED]",
		},
		{
			name:   "semicolon_in_query",
			path:   "/v1beta/models/gemini:generateContent?alt=sse;key=AIzaSemiQuerySecret",
			secret: "AIzaSemiQuerySecret",
			expect: "/v1beta/models/gemini:generateContent?alt=sse;key=[REDACTED]",
		},
		{
			name:   "semicolon_in_path_matrix",
			path:   "/v1beta/models/gemini:generateContent;key=AIzaSemiMatrixSecret",
			secret: "AIzaSemiMatrixSecret",
			expect: "/v1beta/models/gemini:generateContent;key=[REDACTED]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSensitivePath(tc.path)
			require.NotContains(t, got, tc.secret, "RedactSensitivePath leaked %s", tc.name)
			require.Equal(t, tc.expect, got)

			ev := &model.TraceEvent{
				Host:            "generativelanguage.googleapis.com",
				Path:            tc.path,
				HeadersRecorded: false,
			}
			require.NoError(t, ParseExchange(ev, []byte(`{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`), []byte(`{}`), false))
			require.NotContains(t, ev.Path, tc.secret)
			require.NotContains(t, ev.URL, tc.secret)
			require.Equal(t, tc.expect, ev.Path)
		})
	}

	// Verify parser and selfmon reference the exact same underlying map entries.
	require.True(t, selfmon.SensitiveQueryKeys["x-goog-api-key"], "shared table must include x-goog-api-key")
	require.True(t, sensitiveQueryKeys["x-goog-api-key"], "parser sensitiveQueryKeys must share x-goog-api-key")
	require.True(t, sensitiveQueryKeys["jwt"], "parser sensitiveQueryKeys must share jwt")
}
