package collector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func TestChildProcessEnvStripsTOTPSecretAndTokens(t *testing.T) {
	// Helper subprocess entry: dumps its actual os.Environ() to LLM_TRACER_TEST_ENV_OUT
	if outFile := os.Getenv("LLM_TRACER_TEST_ENV_OUT"); outFile != "" {
		_ = os.WriteFile(outFile, []byte(strings.Join(os.Environ(), "\n")), 0o600)
		os.Exit(0)
	}

	// 1. llm-tracer's own credentials that MUST be stripped before spawning child processes
	tracerSecretKeys := []string{
		"LLM_TRACER_TOTP_SECRET",
		"LLM_TRACER_INGEST_TOKEN",
		"LLM_TRACER_LOCAL_TOKEN",
		"LLM_TRACER_AUTH_TOKEN",
		"LLM_TRACER_API_KEY",
		"LLM_TRACER_SESSION_COOKIE",
		"LLM_TRACER_PRIVATE_KEY",
		"LLM_TRACER_BEARER_TOKEN",
	}
	tracerSecrets := make(map[string]string, len(tracerSecretKeys))
	for _, k := range tracerSecretKeys {
		v := "tracer_internal_val_for_" + strings.ToLower(k)
		tracerSecrets[k] = v
		t.Setenv(k, v)
		require.True(t, IsSensitiveChildEnvKey(k), "tracer credential %s must be classified as sensitive", k)
	}

	// 2. User credentials that MUST be preserved intact for launched agent CLIs (claude, bedrock, gh, openai, etc.)
	userCredentialKeys := []string{
		"ANTHROPIC_AUTH_TOKEN",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"CLAUDE_CODE_OAUTH_TOKEN",
		"OPENAI_API_KEY",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"CUSTOM_SERVICE_TOKEN",
	}
	userCredentials := make(map[string]string, len(userCredentialKeys))
	for _, k := range userCredentialKeys {
		v := "user_passthrough_val_for_" + strings.ToLower(k)
		userCredentials[k] = v
		t.Setenv(k, v)
		require.False(t, IsSensitiveChildEnvKey(k), "user credential %s must NOT be stripped", k)
	}

	// 3. Safe internal hook transport keys must never be classified as sensitive
	for _, safeKey := range []string{"LLM_TRACER_SOCK", "LLM_TRACER_PIPE", "LLM_TRACER_PROXY_HOST", "LLM_TRACER_PROXY_PORT"} {
		require.False(t, IsSensitiveChildEnvKey(safeKey), "safe hook key %s must be preserved", safeKey)
	}

	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer st.Close()
	corr := correlator.NewCorrelator(mon)
	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	col.SetIngestToken(tracerSecrets["LLM_TRACER_INGEST_TOKEN"])

	selfExe, err := os.Executable()
	require.NoError(t, err)

	envDumpFile := filepath.Join(dir, "child_env.txt")
	t.Setenv("LLM_TRACER_TEST_ENV_OUT", envDumpFile)

	cmdArgs := []string{selfExe, "-test.run=^TestChildProcessEnvStripsTOTPSecretAndTokens$"}

	plan, plannedEnv, err := col.PlanLaunchCommand(cmdArgs)
	require.NoError(t, err)
	require.NotNil(t, plan)

	// 4. Assert on the actual environment inherited and printed by the spawned child process
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	exitCode, err := col.LaunchPlannedCommand(ctx, plan, plannedEnv)
	require.NoError(t, err)
	require.Equal(t, 0, exitCode)

	childEnvBytes, err := os.ReadFile(envDumpFile)
	require.NoError(t, err, "child process must write its actual environment")
	childEnvText := string(childEnvBytes)
	require.NotEmpty(t, childEnvText)

	childEnvMap := make(map[string]string)
	for _, line := range strings.Split(childEnvText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.ToUpper(line[:eq])
		v := line[eq+1:]
		childEnvMap[k] = v
	}

	for k, secretVal := range tracerSecrets {
		_, present := childEnvMap[k]
		require.False(t, present, "spawned child must NOT inherit llm-tracer credential %s", k)
		require.NotContains(t, childEnvText, secretVal, "spawned child environment leaked value of %s", k)
	}

	for k, wantVal := range userCredentials {
		gotVal, present := childEnvMap[k]
		require.True(t, present, "spawned child MUST inherit user credential %s", k)
		require.Equal(t, wantVal, gotVal, "spawned child user credential %s value mismatch", k)
	}

	// 5. Also assert on the returned env slice from PlanLaunchCommand
	plannedEnvMap := make(map[string]string)
	for _, kv := range plannedEnv {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 {
			plannedEnvMap[strings.ToUpper(kv[:eq])] = kv[eq+1:]
		}
	}
	for k := range tracerSecrets {
		_, present := plannedEnvMap[k]
		require.False(t, present, "planned env slice must not contain llm-tracer credential %s", k)
	}
	for k, wantVal := range userCredentials {
		gotVal, present := plannedEnvMap[k]
		require.True(t, present, "planned env slice must preserve user credential %s", k)
		require.Equal(t, wantVal, gotVal, "planned env slice user credential %s value mismatch", k)
	}
}

func TestCmdlineSecretsRedactedOnDiskInSessionsEventsAndSelfmon(t *testing.T) {
	// Subprocess helper that stays alive briefly while holding secret CLI arguments in /proc/<pid>/cmdline
	if sleepMarker := os.Getenv("LLM_TRACER_TEST_CMDLINE_CHILD"); sleepMarker == "1" {
		time.Sleep(150 * time.Millisecond)
		os.Exit(0)
	}

	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer st.Close()
	corr := correlator.NewCorrelator(mon)
	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)

	selfExe, err := os.Executable()
	require.NoError(t, err)
	t.Setenv("LLM_TRACER_TEST_CMDLINE_CHILD", "1")

	cmdArgs := []string{
		selfExe,
		"-test.run=^TestCmdlineSecretsRedactedOnDiskInSessionsEventsAndSelfmon$",
		"--",
		"c11",
		"--api-key=sk-CMDLINESECRET",
		"--token",
		"sk-SPLITARGSECRET",
		"Authorization: Bearer sk-ARGSECRET",
	}

	plan, env, err := col.PlanLaunchCommand(cmdArgs)
	require.NoError(t, err)

	// Start child via LaunchPlannedCommand in a goroutine and ingest an exchange while child is alive so InspectProcess reads its live /proc/<pid>/cmdline
	doneCh := make(chan error, 1)
	go func() {
		_, lErr := col.LaunchPlannedCommand(context.Background(), plan, env)
		doneCh <- lErr
	}()

	var rootPID int
	require.Eventually(t, func() bool {
		pids := col.Scope().PIDs
		if len(pids) > 0 && pids[0] > 0 {
			rootPID = pids[0]
			return true
		}
		return false
	}, 3*time.Second, 10*time.Millisecond)

	// InspectProcess directly must not return raw secrets
	inspected := InspectProcess(rootPID)

	// Emit a simulated HTTP exchange from rootPID so events.jsonl and session.json are written
	reqRaw := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: 55\r\n\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	respRaw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 74\r\n\r\n" +
		`{"model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"ok"}}]}`
	require.True(t, col.IngestRawChunk(rootPID, rootPID, "conn1", parser.DirWrite, []byte(reqRaw), "ebpf_uprobe"))
	require.True(t, col.IngestRawChunk(rootPID, rootPID, "conn1", parser.DirRead, []byte(respRaw), "ebpf_uprobe"))

	require.NoError(t, <-doneCh)
	col.Flush()
	require.NoError(t, st.Flush())
	require.NoError(t, mon.Flush())

	// Walk every file on disk under dir (sessions/*/events.jsonl, sessions/*/session.json, selfmon/*.jsonl)
	// and verify 0 occurrences of sk-CMDLINESECRET, sk-SPLITARGSECRET, and sk-ARGSECRET.
	var checkedFiles int
	err = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() {
			return walkErr
		}
		if !strings.HasSuffix(path, ".json") && !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		checkedFiles++
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		content := string(raw)
		require.NotContains(t, content, "sk-CMDLINESECRET", "file %s leaked sk-CMDLINESECRET", path)
		require.NotContains(t, content, "sk-SPLITARGSECRET", "file %s leaked sk-SPLITARGSECRET", path)
		require.NotContains(t, content, "sk-ARGSECRET", "file %s leaked sk-ARGSECRET", path)
		return nil
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, checkedFiles, 3, "must inspect session.json, events.jsonl, and selfmon/*.jsonl")

	require.NotContains(t, inspected.Cmdline, "sk-CMDLINESECRET")
	require.NotContains(t, inspected.Cmdline, "sk-SPLITARGSECRET")
	require.NotContains(t, inspected.Cmdline, "sk-ARGSECRET")
}
