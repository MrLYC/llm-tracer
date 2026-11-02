package selfmon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRedactCmdlineAndSanitizeDetailSecrets(t *testing.T) {
	rawCmd := `python3 emit.py c11 --api-key=sk-CMDLINESECRET --custom-token=tok_eq_secret --app-secret=sec_eq_123 --token next_arg_tok_secret "Authorization: Bearer sk-ARGSECRET" sk-RAWSTANDALONEKEY123`
	redacted := RedactCmdline(rawCmd)

	for _, leaked := range []string{
		"sk-CMDLINESECRET",
		"tok_eq_secret",
		"sec_eq_123",
		"next_arg_tok_secret",
		"sk-ARGSECRET",
		"sk-RAWSTANDALONEKEY123",
	} {
		require.NotContains(t, redacted, leaked, "RedactCmdline must strip %q", leaked)
	}
	require.Contains(t, redacted, "--api-key=[REDACTED]")
	require.Contains(t, redacted, "--custom-token=[REDACTED]")
	require.Contains(t, redacted, "--app-secret=[REDACTED]")
	require.Contains(t, redacted, "--token [REDACTED]")
	require.Contains(t, redacted, "Bearer [REDACTED]")

	// Normal hyphenated words like task-1 or disk-util must not be falsely redacted as sk-*
	normalCmd := "python3 worker.py --task=task-12345678 /usr/bin/disk-utility"
	require.Equal(t, normalCmd, RedactCmdline(normalCmd))

	// Verify Monitor.Record + sanitizeDetailValue redacts string, []string, and []any details on disk
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	m.Record(Event{
		Status: StatusOK,
		Stage:  StageTracker,
		Action: "launch_command_started",
		PID:    1234,
		Comm:   "python3",
		Detail: map[string]any{
			"cmdline": `python3 emit.py c11 --api-key=sk-CMDLINESECRET "Authorization: Bearer sk-ARGSECRET"`,
			"args": []string{
				"python3",
				"emit.py",
				"c11",
				"--api-key=sk-CMDLINESECRET",
				"--token",
				"sk-SPLITTOKEN999",
				"Authorization: Bearer sk-ARGSECRET",
			},
			"any_args": []any{
				"--client-secret=sk-ANYEQSECRET",
				"--token",
				"sk-ANYSPLITSECRET",
			},
		},
	})
	require.NoError(t, m.Flush())

	day := time.Now().UTC().Format("2006-01-02")
	rawBytes, err := os.ReadFile(filepath.Join(dir, "selfmon", day+".jsonl"))
	require.NoError(t, err)
	diskStr := string(rawBytes)
	for _, secret := range []string{
		"sk-CMDLINESECRET",
		"sk-ARGSECRET",
		"sk-SPLITTOKEN999",
		"sk-ANYEQSECRET",
		"sk-ANYSPLITSECRET",
	} {
		require.False(t, strings.Contains(diskStr, secret), "selfmon jsonl leaked %q: %s", secret, diskStr)
	}
}

func TestSelfmonRedactSensitivePathSharedKeys(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		secret string
		expect string
	}{
		{
			name:   "x-goog-api-key",
			input:  "/v1beta/models/gemini-pro:generateContent?alt=sse&X-Goog-Api-Key=AIzaSyGoogSecret123",
			secret: "AIzaSyGoogSecret123",
			expect: "/v1beta/models/gemini-pro:generateContent?alt=sse&X-Goog-Api-Key=[REDACTED]",
		},
		{
			name:   "url-encoded-api_key",
			input:  "/v1/chat/completions?api%5Fkey=sk_encoded_secret_456&stream=true",
			secret: "sk_encoded_secret_456",
			expect: "/v1/chat/completions?api%5Fkey=[REDACTED]&stream=true",
		},
		{
			name:   "jwt-query-param",
			input:  "/v1/responses?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
			secret: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret",
			expect: "/v1/responses?jwt=[REDACTED]",
		},
		{
			name:   "semicolon-query-separator",
			input:  "/v1/chat?format=json;key=semi_query_secret_789",
			secret: "semi_query_secret_789",
			expect: "/v1/chat?format=json;key=[REDACTED]",
		},
		{
			name:   "semicolon-matrix-path-param",
			input:  "/v1/models;key=matrix_path_secret_000/chat?alt=sse",
			secret: "matrix_path_secret_000",
			expect: "/v1/models;key=[REDACTED]/chat?alt=sse",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSensitivePath(tc.input)
			require.NotContains(t, got, tc.secret)
			require.Equal(t, tc.expect, got)
		})
	}
}

func TestRedactCmdlineUnifiedPipelineAndDiskNoPlaintextSecrets(t *testing.T) {
	rawArgv := []string{
		"curl",
		"-u", "user:ARGSECRET5",
		"-p", "SHORT_P_SECRET_11",
		"--password", "LONG_PASS_SECRET_22",
		"--token", "LONG_TOK_SECRET_33",
		"-H", "Authorization: Bearer HDR_BEARER_SECRET_44",
		"-H", "x-api-key: HDR_APIKEY_SECRET_55",
		"--user=admin:EQ_USER_SECRET_66",
		"-uINLINE_U_SECRET_77:INLINE_U_PASS_88",
		"--proxy=http://puser:PROXY_URL_PASS_99@127.0.0.1:8080",
		"https://u:URL_USERINFO_PASS_00@x.example/?api_key=URL_QUERY_SECRET_AA",
	}
	rawCmdline := strings.Join(rawArgv, " ")

	allSecrets := []string{
		"ARGSECRET5",
		"SHORT_P_SECRET_11",
		"LONG_PASS_SECRET_22",
		"LONG_TOK_SECRET_33",
		"HDR_BEARER_SECRET_44",
		"HDR_APIKEY_SECRET_55",
		"EQ_USER_SECRET_66",
		"INLINE_U_PASS_88",
		"PROXY_URL_PASS_99",
		"URL_USERINFO_PASS_00",
		"URL_QUERY_SECRET_AA",
	}

	gotFromCmdline := RedactCmdline(rawCmdline)
	gotFromCmdArgs := RedactCmdArgs(rawArgv)
	gotFromArgSlice := strings.Join(RedactArgSlice(rawArgv), " ")

	for _, secret := range allSecrets {
		require.NotContains(t, gotFromCmdline, secret, "RedactCmdline leaked %q", secret)
		require.NotContains(t, gotFromCmdArgs, secret, "RedactCmdArgs leaked %q", secret)
		require.NotContains(t, gotFromArgSlice, secret, "RedactArgSlice leaked %q", secret)
	}
	require.NotContains(t, gotFromCmdline, "***", "must use [REDACTED] placeholder, never ***")
	require.Contains(t, gotFromCmdline, "-u user:[REDACTED]")
	require.Contains(t, gotFromCmdline, "-p [REDACTED]")
	require.Contains(t, gotFromCmdline, "--password [REDACTED]")
	require.Contains(t, gotFromCmdline, "--token [REDACTED]")
	require.Contains(t, gotFromCmdline, "https://u:[REDACTED]@x.example/?api_key=[REDACTED]")
	require.Equal(t, gotFromCmdArgs, gotFromCmdline, "RedactCmdline and RedactCmdArgs must produce identical output")

	// Persist events via Monitor and assert on the actual on-disk .jsonl file content
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)
	defer m.Stop()

	anyArgs := make([]any, len(rawArgv))
	for i, a := range rawArgv {
		anyArgs[i] = a
	}

	m.Record(Event{
		Status: StatusOK,
		Stage:  StageTracker,
		Action: "launch_command_started",
		PID:    4321,
		Comm:   "curl",
		Detail: map[string]any{
			"cmdline":  rawCmdline,
			"args":     rawArgv,
			"any_args": anyArgs,
		},
	})
	m.Record(Event{
		Status: StatusOK,
		Stage:  StageTracker,
		Action: "short_flag_single_cred",
		PID:    4322,
		Comm:   "curl",
		Detail: map[string]any{
			"cmdline": "curl -u SINGLE_U_NEXT_SECRET https://token_only_secret_bb@x.example/v1/models",
			"args":    []string{"curl", "-u", "SINGLE_U_NEXT_SECRET", "https://token_only_secret_bb@x.example/v1/models"},
		},
	})
	require.NoError(t, m.Flush())

	day := time.Now().UTC().Format("2006-01-02")
	logPath := filepath.Join(dir, "selfmon", day+".jsonl")
	rawDiskBytes, err := os.ReadFile(logPath)
	require.NoError(t, err)
	diskContent := string(rawDiskBytes)
	require.NotEmpty(t, diskContent)
	require.Contains(t, diskContent, "[REDACTED]")
	require.NotContains(t, diskContent, "***")

	for _, secret := range append(allSecrets, "SINGLE_U_NEXT_SECRET", "token_only_secret_bb") {
		require.False(t, strings.Contains(diskContent, secret),
			"on-disk selfmon jsonl file (%s) must not contain plaintext secret %q:\n%s", logPath, secret, diskContent)
	}

	// Verify on-disk JSON lines have consistent cmdline vs args redaction within the same record
	lines := strings.Split(strings.TrimSpace(diskContent), "\n")
	require.Len(t, lines, 2)
	for _, line := range lines {
		var ev Event
		require.NoError(t, json.Unmarshal([]byte(line), &ev))
		cmdStr, ok := ev.Detail["cmdline"].(string)
		require.True(t, ok)
		rawArgsSlice, ok := ev.Detail["args"].([]any)
		require.True(t, ok)
		joinedArgs := make([]string, 0, len(rawArgsSlice))
		for _, elem := range rawArgsSlice {
			s, ok := elem.(string)
			require.True(t, ok)
			joinedArgs = append(joinedArgs, s)
		}
		require.Equal(t, strings.Join(joinedArgs, " "), cmdStr,
			"cmdline and args in the same on-disk selfmon record must be redacted identically")
	}
}
