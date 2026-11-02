package collector

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

// LaunchAttachPlan describes the automatic pre-launch inspection of a directly launched child command (`-- <cmd>`),
// whether non-intrusive eBPF Uprobes can cover it directly, and what intrusive CLI arguments, wrapper parameters,
// and environment parameters were automatically completed when non-intrusive mode cannot be used.
type LaunchAttachPlan struct {
	OriginalCmd            []string          `json:"original_cmd"`
	BinaryPath             string            `json:"binary_path"`
	ResolvedELF            string            `json:"resolved_elf,omitempty"`
	DetectedStack          string            `json:"detected_stack"`              // dynamic-libssl | static-openssl | gotls | jvm-jsse | nodejs | bun-boringssl | python | stripped-embedded-tls | static-pie
	EBPFActive             bool              `json:"ebpf_active"`                 // true if kernel eBPF engine is active
	NonIntrusiveOK         bool              `json:"non_intrusive_ok"`            // true if non-intrusive eBPF Uprobes alone can capture TLS for this binary
	NonIntrusiveReason     string            `json:"non_intrusive_reason"`        // why non-intrusive eBPF succeeded or why it cannot cover this target
	AutoIntrusiveTriggered bool              `json:"auto_intrusive_triggered"`    // true when non-intrusive mode cannot be used and intrusive parameters were auto-completed
	IntrusiveMethods       []string          `json:"intrusive_methods,omitempty"` // e.g. cli_arg:-javaagent, cli_arg:--require, ptrace_wrapper, preload:libssl_hook, env:HTTPS_PROXY
	InjectedArgs           []string          `json:"injected_args,omitempty"`     // CLI arguments automatically prepended to the child command
	InjectedEnv            map[string]string `json:"injected_env,omitempty"`      // Key environment parameters automatically injected for the child
	PtraceWrapped          bool              `json:"ptrace_wrapped,omitempty"`    // true if wrapped via llm_tracer_ptrace <bin> <args...>
	DegradationNotices     []string          `json:"degradation_notices,omitempty"`
	ExecBin                string            `json:"exec_bin"`  // Final executable path invoked
	ExecArgs               []string          `json:"exec_args"` // Final argument vector passed to exec.CommandContext
}

type launchRuntimeKind string

const (
	runtimeKindJVM    launchRuntimeKind = "jvm"
	runtimeKindNode   launchRuntimeKind = "node"
	runtimeKindBun    launchRuntimeKind = "bun"
	runtimeKindPython launchRuntimeKind = "python"
	runtimeKindNative launchRuntimeKind = "native"
)

// launchPlanInput holds pure, side-effect-free inputs for planLaunch and applyLaunchPlan.
type launchPlanInput struct {
	CmdArgs          []string
	BinPath          string
	Profile          *BinaryProfile
	GoTarget         *ProbeTarget
	EBPFActive       bool
	AutoIntrusive    bool
	GOOS             string
	GOARCH           string
	ArchCapabilities *ebpfArchCapabilities
	CanUsePtrace     bool

	SockPath     string
	PipePath     string
	PreloadPath  string
	JavaAgentJar string
	NodeHookJS   string
	PyHookDir    string
	PtraceBin    string

	TapActive    bool
	ProxyURL     string
	ProxyHost    string
	ProxyPort    string
	CABundlePath string
}

func (c *Collector) inspectLaunchTarget(cmdArgs []string) (launchPlanInput, error) {
	if len(cmdArgs) == 0 {
		return launchPlanInput{}, fmt.Errorf("empty command")
	}
	binPath, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return launchPlanInput{}, err
	}

	prof, _ := InspectBinaryProfile(binPath)
	gt, _ := InspectGoTLSTarget(binPath)

	c.mu.RLock()
	ebpf := c.ebpfEngine
	ebpfActive := ebpf != nil && ebpf.Active()
	autoIntrusive := c.autoIntrusive
	sockPath := c.sockPath
	pipePath := c.pipePath
	preloadPath := c.preloadPath
	rtHooks := c.runtimeHooks
	tap := c.loopbackTap
	c.mu.RUnlock()

	in := launchPlanInput{
		CmdArgs:       append([]string(nil), cmdArgs...),
		BinPath:       binPath,
		Profile:       prof,
		GoTarget:      gt,
		EBPFActive:    ebpfActive,
		AutoIntrusive: autoIntrusive,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		CanUsePtrace:  CanUsePtrace(),
		SockPath:      sockPath,
		PipePath:      pipePath,
		PreloadPath:   preloadPath,
	}
	if rtHooks != nil {
		in.JavaAgentJar = rtHooks.JavaAgentJar
		in.NodeHookJS = rtHooks.NodeHookJS
		in.PyHookDir = rtHooks.PyHookDir
		in.PtraceBin = rtHooks.PtraceBin
	}
	if tap != nil {
		pHost, pPort := tap.HostPort()
		in.TapActive = true
		in.ProxyURL = tap.ProxyURL()
		in.ProxyHost = pHost
		in.ProxyPort = pPort
		in.CABundlePath = tap.CABundlePath()
	}
	return in, nil
}

func resolvePlanArchCapabilities(in launchPlanInput) ebpfArchCapabilities {
	if in.ArchCapabilities != nil {
		return *in.ArchCapabilities
	}
	if in.GOARCH != "" {
		return lookupArchCapabilities(in.GOARCH)
	}
	return currentArchCapabilities()
}

func classifyLaunchRuntime(binPath, resolvedELF string) launchRuntimeKind {
	baseBin := strings.ToLower(filepath.Base(binPath))
	baseResolved := strings.ToLower(filepath.Base(resolvedELF))
	switch {
	case isJVMLaunchTarget(binPath, resolvedELF):
		return runtimeKindJVM
	case isBunLaunchTarget(baseBin, baseResolved):
		return runtimeKindBun
	case isPythonLaunchTarget(baseBin, baseResolved):
		return runtimeKindPython
	case isNodeLaunchTarget(baseBin, baseResolved):
		return runtimeKindNode
	default:
		return runtimeKindNative
	}
}

// planLaunch performs pure, side-effect-free runtime detection and intrusive fallback planning.
func planLaunch(in launchPlanInput) *LaunchAttachPlan {
	if in.GOOS == "" {
		in.GOOS = runtime.GOOS
	}
	resolvedELF := in.BinPath
	if in.Profile != nil && in.Profile.ResolvedELF != "" {
		resolvedELF = in.Profile.ResolvedELF
	}

	plan := &LaunchAttachPlan{
		OriginalCmd: append([]string(nil), in.CmdArgs...),
		BinaryPath:  in.BinPath,
		ResolvedELF: resolvedELF,
		EBPFActive:  in.EBPFActive,
		InjectedEnv: make(map[string]string),
	}

	var userArgs []string
	if len(in.CmdArgs) > 1 {
		userArgs = in.CmdArgs[1:]
	}

	kind := classifyLaunchRuntime(in.BinPath, resolvedELF)
	switch kind {
	case runtimeKindJVM:
		planJVMLaunch(in, userArgs, plan)
	case runtimeKindBun:
		planBunLaunch(in, userArgs, plan)
	case runtimeKindPython:
		planPythonLaunch(in, userArgs, plan)
	case runtimeKindNode:
		planNodeLaunch(in, userArgs, plan)
	default:
		planNativeLaunch(in, userArgs, plan)
	}

	childArgs := append(append([]string(nil), plan.InjectedArgs...), userArgs...)
	archCap := resolvePlanArchCapabilities(in)
	planNativePtraceWrap(in, archCap, childArgs, plan)

	if in.AutoIntrusive {
		isJVM := kind == runtimeKindJVM
		isNode := kind == runtimeKindNode
		isBun := kind == runtimeKindBun
		isPython := kind == runtimeKindPython

		planNativePreloadMethods(in, isJVM, plan)
		planPythonEnvMethods(in, isPython, plan)
		planNodeBunEnvMethods(in, isNode, isBun, plan)
		planJVMEnvMethods(in, isJVM, plan)
		planNativeTapMethods(in, kind, resolvedELF, plan)
	}

	return plan
}

// applyLaunchPlan executes the side effects for a planned launch (attaching discovered eBPF uprobes,
// constructing the final child environment and ExecBin/ExecArgs, and recording selfmon/collector state).
func applyLaunchPlan(c *Collector, in launchPlanInput, plan *LaunchAttachPlan, baseEnv []string) []string {
	if in.GOOS == "" {
		in.GOOS = runtime.GOOS
	}
	if plan.InjectedEnv == nil {
		plan.InjectedEnv = make(map[string]string)
	}

	if c != nil {
		if c.mon != nil {
			lastCollectorMonitor.Store(c.mon)
		}
		if in.Profile != nil {
			extraProbes := ProbeAndRecordTargets(nil, []string{in.Profile.ResolvedELF}, c.mon)
			if len(extraProbes) > 0 {
				c.mu.RLock()
				ebpf := c.ebpfEngine
				c.mu.RUnlock()
				if ebpf != nil {
					ebpf.AttachTargets(extraProbes)
				}
				c.mu.Lock()
				c.probes = append(c.probes, extraProbes...)
				c.mu.Unlock()
			}
		}
		if in.GoTarget != nil {
			c.mu.RLock()
			ebpf := c.ebpfEngine
			c.mu.RUnlock()
			if ebpf != nil {
				ebpf.AttachTargets([]ProbeTarget{*in.GoTarget})
			}
			c.mu.Lock()
			c.probes = append(c.probes, *in.GoTarget)
			c.mu.Unlock()
			if c.mon != nil {
				c.mon.RecordOK(selfmon.StageProbe, "inspect_launched_go_binary", map[string]any{
					"binary": in.BinPath, "go_version": in.GoTarget.GoVersion, "symbols": in.GoTarget.Symbols,
				})
			}
		}
		if plan.PtraceWrapped && c.mon != nil && in.Profile != nil {
			c.mon.RecordOK(selfmon.StageProbe, "enable_ptrace_syscall_hook", map[string]any{
				"target":    in.Profile.ResolvedELF,
				"link_mode": in.Profile.LinkMode,
				"tls_stack": in.Profile.TLSStack,
			})
		}
		if len(plan.DegradationNotices) > 0 && c.mon != nil {
			archCap := resolvePlanArchCapabilities(in)
			for _, notice := range plan.DegradationNotices {
				c.mon.RecordWarn(selfmon.StageProbe, "ptrace_arch_unsupported", notice, map[string]any{
					"binary":            plan.BinaryPath,
					"arch":              archCap.Arch,
					"detected_stack":    plan.DetectedStack,
					"ptrace_supported":  archCap.PtraceUserspaceSupported,
					"degraded_features": archCap.DegradedFeatures,
				})
			}
		}
	}

	resolvedELF := plan.ResolvedELF
	if resolvedELF == "" {
		resolvedELF = in.BinPath
		if in.Profile != nil && in.Profile.ResolvedELF != "" {
			resolvedELF = in.Profile.ResolvedELF
		}
	}
	kind := classifyLaunchRuntime(in.BinPath, resolvedELF)
	isJVM := kind == runtimeKindJVM
	isNode := kind == runtimeKindNode
	isBun := kind == runtimeKindBun
	isPython := kind == runtimeKindPython

	env := stripSensitiveEnvKeys(baseEnv)
	// setAndTrackEnv must return the updated slice: setEnvVar may reallocate, and the
	// apply*Env helpers thread env through their return value.
	setAndTrackEnv := func(env []string, k, v string) []string {
		plan.InjectedEnv[k] = v
		return setEnvVar(env, k, v)
	}

	if in.SockPath != "" {
		env = setAndTrackEnv(env, "LLM_TRACER_SOCK", in.SockPath)
	}
	if in.PipePath != "" {
		env = setAndTrackEnv(env, "LLM_TRACER_PIPE", in.PipePath)
	}
	// TODO: if child processes ever require an ingest credential in the future,
	// pass it via a 0600 permission token file instead of environment variables.

	if in.AutoIntrusive {
		env = applyNativePreloadEnv(in, isJVM, plan, env, setAndTrackEnv)
		env = applyPythonLaunchEnv(in, isPython, plan, env, setAndTrackEnv)
		env = applyNodeBunLaunchEnv(in, isNode, isBun, plan, env, setAndTrackEnv)
		env = applyJVMLaunchEnv(in, isJVM, plan, env, setAndTrackEnv)
		env = applyNativeTapEnv(c, in, kind, resolvedELF, plan, baseEnv, env, setAndTrackEnv)
	}

	for k := range plan.InjectedEnv {
		if IsSensitiveChildEnvKey(k) {
			delete(plan.InjectedEnv, k)
		}
	}
	env = stripSensitiveEnvKeys(env)
	if len(baseEnv) > 0 && len(env) == 0 {
		env = []string{"PATH=" + lookupEnvVar(baseEnv, "PATH")}
	}

	if c != nil {
		c.mu.Lock()
		c.lastLaunchPlan = plan
		c.mu.Unlock()

		if c.mon != nil {
			detail := map[string]any{
				"binary":                   plan.BinaryPath,
				"detected_stack":           plan.DetectedStack,
				"non_intrusive_ok":         plan.NonIntrusiveOK,
				"auto_intrusive_triggered": plan.AutoIntrusiveTriggered,
				"intrusive_methods":        plan.IntrusiveMethods,
				"injected_args":            plan.InjectedArgs,
				"ptrace_wrapped":           plan.PtraceWrapped,
			}
			if len(plan.DegradationNotices) > 0 {
				detail["degradation_notices"] = plan.DegradationNotices
			}
			c.mon.RecordOK(selfmon.StageProbe, "plan_launch_command", detail)
		}
	}

	return env
}

var safeTracerChildEnvKeys = map[string]bool{
	"LLM_TRACER_SOCK":              true,
	"LLM_TRACER_PIPE":              true,
	"LLM_TRACER_PROXY_HOST":        true,
	"LLM_TRACER_PROXY_PORT":        true,
	"LLM_TRACER_PY_TLS_ACTIVE":     true,
	"LLM_TRACER_NODE_PLAIN_ACTIVE": true,
	"LLM_TRACER_TEST_RUN_MAIN":     true,
	"LLM_TRACER_TEST_MAIN_ARGS":    true,
	"LLM_TRACER_TEST_EXIT_CODE":    true,
	"LLM_TRACER_TEST_HELPER_SLEEP": true,
}

// IsSensitiveChildEnvKey reports whether an environment variable key is an internal llm-tracer
// credential (such as LLM_TRACER_TOTP_SECRET, LLM_TRACER_INGEST_TOKEN) that must be stripped
// before spawning a child process, while preserving user credentials.
func IsSensitiveChildEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" || safeTracerChildEnvKeys[upper] {
		return false
	}
	if upper == "LLM_TRACER_TOTP_SECRET" || strings.Contains(upper, "TOTP_SECRET") || strings.HasPrefix(upper, "LLM_TRACER_TOTP") {
		return true
	}
	if strings.HasPrefix(upper, "LLM_TRACER_") {
		for _, sub := range []string{"SECRET", "TOKEN", "KEY", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH", "TOTP", "COOKIE", "PRIVATE", "BEARER"} {
			if strings.Contains(upper, sub) {
				return true
			}
		}
	}
	return false
}

// StripSensitiveEnvKeys removes llm-tracer's own credentials (LLM_TRACER_TOTP_SECRET,
// LLM_TRACER_INGEST_TOKEN, etc.) from env while passing user environment variables through intact.
// Note: collector.go's LaunchPlannedCommand fallback branch (when env is empty) can also call
// StripSensitiveEnvKeys(env) instead of only unsetEnvVar(env, "LLM_TRACER_INGEST_TOKEN").
func StripSensitiveEnvKeys(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 {
			if IsSensitiveChildEnvKey(kv[:eq]) {
				continue
			}
		}
		out = append(out, kv)
	}
	return out
}

func stripSensitiveEnvKeys(env []string) []string {
	return StripSensitiveEnvKeys(env)
}

func lookupEnvVar(env []string, key string) string {
	prefix := key + "="
	var val string
	for _, kv := range env {
		if runtime.GOOS == "windows" {
			if len(kv) >= len(prefix) && strings.EqualFold(kv[:len(prefix)], prefix) {
				val = kv[len(prefix):]
			}
		} else if strings.HasPrefix(kv, prefix) {
			val = kv[len(prefix):]
		}
	}
	return val
}

func hasArgPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func hasArgExact(args []string, target string) bool {
	for _, a := range args {
		if a == target {
			return true
		}
	}
	return false
}

func isVersionOrHelpArgs(args []string) bool {
	if len(args) == 1 {
		switch args[0] {
		case "-v", "--version", "-version", "-h", "--help", "-help":
			return true
		}
	}
	return false
}

func appendUniqueStr(slice []string, items ...string) []string {
	for _, item := range items {
		exists := false
		for _, s := range slice {
			if s == item {
				exists = true
				break
			}
		}
		if !exists {
			slice = append(slice, item)
		}
	}
	return slice
}
