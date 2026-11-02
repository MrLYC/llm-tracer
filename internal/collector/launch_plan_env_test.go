package collector

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func lookPathOrErr(bin string) (string, error) {
	return exec.LookPath(bin)
}

func envValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return kv[len(prefix):], true
		}
	}
	return "", false
}

// TestPlanLaunchCommandReturnsInjectedEnvVars guards against the applyLaunchPlan regression where
// the setAndTrackEnv closure mutated an outer slice while each apply*Env helper returned a stale
// snapshot, silently dropping every injected variable except LLM_TRACER_SOCK/LLM_TRACER_PIPE.
// Asserting only plan.InjectedEnv is not enough: the returned env slice is what actually reaches the child.
func TestPlanLaunchCommandReturnsInjectedEnvVars(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("preload/proxy env injection is POSIX-only")
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	cases := []struct {
		name     string
		lookup   func() (string, error)
		args     []string
		required []string
	}{
		{
			name:     "python",
			lookup:   findPythonExecutable,
			required: []string{"PYTHONPATH", "LLM_TRACER_PIPE"},
		},
		{
			name:     "node",
			lookup:   func() (string, error) { return lookPathOrErr("node") },
			required: []string{"NODE_OPTIONS", "LLM_TRACER_PIPE"},
		},
		{
			name:     "java",
			lookup:   func() (string, error) { return lookPathOrErr("java") },
			required: []string{"JAVA_TOOL_OPTIONS", "LLM_TRACER_PIPE"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin, err := tc.lookup()
			if err != nil || bin == "" {
				t.Skipf("%s not available", tc.name)
			}
			args := append([]string{bin}, tc.args...)
			plan, env, err := col.PlanLaunchCommand(args)
			require.NoError(t, err)
			require.NotNil(t, plan)
			require.True(t, plan.AutoIntrusiveTriggered, "auto-intrusive fallback must trigger for %s", tc.name)

			for _, key := range tc.required {
				want, ok := plan.InjectedEnv[key]
				require.True(t, ok, "plan.InjectedEnv must record %s for %s", key, tc.name)
				got, present := envValue(env, key)
				require.True(t, present, "returned env must actually carry %s for %s", key, tc.name)
				require.Equal(t, want, got, "%s value must match plan.InjectedEnv", key)
			}

			// Every tracked injected variable must be present in the env slice handed to the child.
			for k, v := range plan.InjectedEnv {
				got, present := envValue(env, k)
				require.True(t, present, "injected env %s missing from returned env slice", k)
				require.Equal(t, v, got, "injected env %s value mismatch", k)
			}
		})
	}

	t.Run("native_ld_preload", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("LD_PRELOAD path is linux-only")
		}
		selfExe, err := os.Executable()
		require.NoError(t, err)
		plan, env, err := col.PlanLaunchCommand([]string{selfExe, "-test.run=^$"})
		require.NoError(t, err)
		require.NotNil(t, plan)
		if preload, ok := plan.InjectedEnv["LD_PRELOAD"]; ok {
			got, present := envValue(env, "LD_PRELOAD")
			require.True(t, present, "returned env must carry LD_PRELOAD when planned")
			require.Equal(t, preload, got)
		}
		for k, v := range plan.InjectedEnv {
			got, present := envValue(env, k)
			require.True(t, present, "injected env %s missing from returned env slice", k)
			require.Equal(t, v, got)
		}
	})
}
