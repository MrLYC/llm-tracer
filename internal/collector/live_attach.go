package collector

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/liuyicong/llm-tracer/internal/selfmon"
)

// PIDAttachPlan describes the automatic runtime/TLS detection result for an already-running PID,
// whether non-intrusive eBPF succeeded, and what intrusive live-attach option is available if eBPF is insufficient.
type PIDAttachPlan struct {
	PID                  int               `json:"pid"`
	Comm                 string            `json:"comm"`
	Exe                  string            `json:"exe"`
	Cmdline              string            `json:"cmdline,omitempty"`
	DetectedStack        string            `json:"detected_stack"`                  // dynamic-libssl | static-openssl | gotls | gotls-pclntab | jvm-jsse | nodejs | python | stripped-native
	EBPFStatus           string            `json:"ebpf_status"`                     // attached | tracepoint_only | unavailable
	EBPFReason           string            `json:"ebpf_reason,omitempty"`           // human-readable explanation of eBPF status
	ActiveMode           string            `json:"active_mode"`                     // ebpf_uprobe | ebpf_tracepoint | jvm_dynamic_attach | node_inspector_sigusr1 | ptrace_seize | pending_confirmation
	IntrusiveNeeded      bool              `json:"intrusive_needed"`                // true if eBPF alone cannot capture encrypted TLS for this PID
	RecommendedIntrusive string            `json:"recommended_intrusive,omitempty"` // jvm_dynamic_attach | node_inspector_sigusr1 | ptrace_seize
	IntrusiveDescription string            `json:"intrusive_description,omitempty"`
	IntrusiveCommandHint string            `json:"intrusive_command_hint,omitempty"`
	Injected             bool              `json:"injected"`
	InjectError          string            `json:"inject_error,omitempty"`
	Symbols              map[string]uint64 `json:"symbols,omitempty"`
}

// LaunchAttachPlan describes the automatic pre-launch inspection of a directly launched child command (`-- <cmd>`),
// whether non-intrusive eBPF Uprobes can cover it directly, and what intrusive CLI arguments, wrapper parameters,
// and environment parameters were automatically completed when non-intrusive mode cannot be used.
type LaunchAttachPlan struct {
	OriginalCmd            []string          `json:"original_cmd"`
	BinaryPath             string            `json:"binary_path"`
	ResolvedELF            string            `json:"resolved_elf,omitempty"`
	DetectedStack          string            `json:"detected_stack"`                  // dynamic-libssl | static-openssl | gotls | jvm-jsse | nodejs | bun-boringssl | python | stripped-embedded-tls | static-pie
	EBPFActive             bool              `json:"ebpf_active"`                     // true if kernel eBPF engine is active
	NonIntrusiveOK         bool              `json:"non_intrusive_ok"`                // true if non-intrusive eBPF Uprobes alone can capture TLS for this binary
	NonIntrusiveReason     string            `json:"non_intrusive_reason"`            // why non-intrusive eBPF succeeded or why it cannot cover this target
	AutoIntrusiveTriggered bool              `json:"auto_intrusive_triggered"`        // true when non-intrusive mode cannot be used and intrusive parameters were auto-completed
	IntrusiveMethods       []string          `json:"intrusive_methods,omitempty"`     // e.g. cli_arg:-javaagent, cli_arg:--require, ptrace_wrapper, preload:libssl_hook, env:HTTPS_PROXY
	InjectedArgs           []string          `json:"injected_args,omitempty"`         // CLI arguments automatically prepended to the child command
	InjectedEnv            map[string]string `json:"injected_env,omitempty"`          // Key environment parameters automatically injected for the child
	PtraceWrapped          bool              `json:"ptrace_wrapped,omitempty"`        // true if wrapped via llm_tracer_ptrace <bin> <args...>
	ExecBin                string            `json:"exec_bin"`                        // Final executable path invoked
	ExecArgs               []string          `json:"exec_args"`                       // Final argument vector passed to exec.CommandContext
}

// SetAutoIntrusive configures whether LaunchCommand (`-- <cmd>`) automatically completes intrusive CLI/env parameters
// when non-intrusive eBPF cannot cover the target child program (enabled by default).
func (c *Collector) SetAutoIntrusive(enabled bool) {
	c.mu.Lock()
	c.autoIntrusive = enabled
	c.mu.Unlock()
}

// AutoIntrusive returns whether automatic intrusive parameter completion is enabled for launched child programs.
func (c *Collector) AutoIntrusive() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.autoIntrusive
}

// SetAutoInjectLive configures whether running processes matched by ScopeFilter (--pid, --exe, --cwd, --cmd)
// should automatically undergo live intrusive injection when non-intrusive eBPF cannot cover them.
func (c *Collector) SetAutoInjectLive(enabled bool) {
	c.mu.Lock()
	c.autoInjectLive = enabled
	c.mu.Unlock()
}

// AutoInjectLive returns whether automatic live intrusive injection is enabled for matched running processes.
func (c *Collector) AutoInjectLive() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.autoInjectLive
}

// LastLaunchPlan returns the most recent LaunchAttachPlan created by PlanLaunchCommand / LaunchCommand.
func (c *Collector) LastLaunchPlan() *LaunchAttachPlan {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastLaunchPlan == nil {
		return nil
	}
	cp := *c.lastLaunchPlan
	return &cp
}

// PlanLaunchCommand inspects a child command (`-- <cmd> [args...]`), checks whether non-intrusive eBPF Uprobes
// can cover it directly, and if non-intrusive mode cannot be used, automatically completes the intrusive scheme
// via CLI arguments (`InjectedArgs`), ptrace wrapper (`PtraceWrapped`), and environment parameters (`InjectedEnv`).
func (c *Collector) PlanLaunchCommand(cmdArgs []string) (*LaunchAttachPlan, []string, error) {
	if len(cmdArgs) == 0 {
		return nil, nil, fmt.Errorf("empty command")
	}
	binPath, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return nil, nil, err
	}

	prof, _ := InspectBinaryProfile(binPath)
	if prof != nil {
		extraProbes := ProbeAndRecordTargets(nil, []string{prof.ResolvedELF}, c.mon)
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

	gt, _ := InspectGoTLSTarget(binPath)
	if gt != nil {
		c.mu.RLock()
		ebpf := c.ebpfEngine
		c.mu.RUnlock()
		if ebpf != nil {
			ebpf.AttachTargets([]ProbeTarget{*gt})
		}
		c.mu.Lock()
		c.probes = append(c.probes, *gt)
		c.mu.Unlock()
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "inspect_launched_go_binary", map[string]any{
				"binary": binPath, "go_version": gt.GoVersion, "symbols": gt.Symbols,
			})
		}
	}

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

	resolvedELF := binPath
	if prof != nil && prof.ResolvedELF != "" {
		resolvedELF = prof.ResolvedELF
	}
	baseBin := strings.ToLower(filepath.Base(binPath))
	baseResolved := strings.ToLower(filepath.Base(resolvedELF))

	isJVM := isJavaBinary(binPath) || isJavaBinary(resolvedELF)
	isNode := baseBin == "node" || baseBin == "nodejs" || baseBin == "node.exe" ||
		baseResolved == "node" || baseResolved == "nodejs" || strings.HasPrefix(baseResolved, "node")
	isBun := baseBin == "bun" || baseBin == "bunx" || baseBin == "bun.exe" || baseResolved == "bun"
	isPython := strings.HasPrefix(baseBin, "python") || strings.HasPrefix(baseResolved, "python") || baseBin == "uv"
	isGo := gt != nil && len(gt.Symbols) > 0

	plan := &LaunchAttachPlan{
		OriginalCmd: append([]string(nil), cmdArgs...),
		BinaryPath:  binPath,
		ResolvedELF: resolvedELF,
		EBPFActive:  ebpfActive,
		InjectedEnv: make(map[string]string),
	}

	switch {
	case isJVM:
		plan.DetectedStack = "jvm-jsse"
		plan.NonIntrusiveOK = false
		plan.NonIntrusiveReason = "Java/JVM 使用 JSSE 纯字节码/JIT 执行 TLS 加解密，无固定 ELF 函数偏移，非侵入式 eBPF Uprobe 无法直接解密"
	case isBun:
		plan.DetectedStack = "bun-boringssl"
		plan.NonIntrusiveOK = false
		plan.NonIntrusiveReason = "Bun 静态内嵌并 strip 了 BoringSSL 符号表，非侵入式 eBPF Uprobe 无可挂载符号"
	case isPython:
		plan.DetectedStack = "python"
		plan.NonIntrusiveOK = false
		plan.NonIntrusiveReason = "Python LLM SDK (httpx/aiohttp/uv) 普遍使用 ssl.SSLObject (MemoryBIO/SSL_write_ex) 或静态 strip OpenSSL，仅靠非侵入式 SSL_write Uprobe 无法完整覆盖"
	case isNode:
		plan.DetectedStack = "nodejs"
		plan.NonIntrusiveOK = false
		if ebpfActive {
			plan.NonIntrusiveReason = "Node.js (undici/fetch/TLSSocket) 使用 BIO 流与内置根证书束，仅靠非侵入式 eBPF Uprobe 无法完整覆盖，自动通过参数完成 Runtime Hook 注入"
		} else {
			plan.NonIntrusiveReason = "当前未启用内核 eBPF Uprobe，自动通过 CLI 参数 (--require) 与环境变量完成 Node.js Runtime Hook 注入"
		}
	case isGo:
		plan.DetectedStack = "gotls"
		if ebpfActive {
			plan.NonIntrusiveOK = true
			plan.NonIntrusiveReason = fmt.Sprintf("已自动解析 GoTLS (%s) 函数偏移 (含 .gopclntab 恢复) 并挂载非侵入式内核 eBPF Uprobe", gt.GoVersion)
		} else {
			plan.NonIntrusiveOK = false
			plan.NonIntrusiveReason = fmt.Sprintf("已解析 GoTLS (%s) 符号偏移，但当前无内核 eBPF 权限，自动通过参数完成代理/证书与 ptrace 侵入式方案", gt.GoVersion)
		}
	case prof != nil && (prof.TLSStack == "dynamic-libssl" || prof.TLSStack == "static-openssl"):
		plan.DetectedStack = prof.TLSStack
		if ebpfActive {
			plan.NonIntrusiveOK = true
			plan.NonIntrusiveReason = fmt.Sprintf("已识别 %s 并挂载非侵入式内核 eBPF Uprobe (SSL_write/SSL_read)", prof.TLSStack)
		} else {
			plan.NonIntrusiveOK = false
			plan.NonIntrusiveReason = fmt.Sprintf("已识别 %s，但当前未启用内核 eBPF 引擎，自动通过参数完成 LD_PRELOAD/DYLD_INSERT_LIBRARIES 与代理注入", prof.TLSStack)
		}
	case prof != nil && prof.RequiresPtrace:
		plan.DetectedStack = "static-pie"
		plan.NonIntrusiveOK = false
		plan.NonIntrusiveReason = "目标程序为无 PT_INTERP 的静态链接二进制且无 OpenSSL/GoTLS 符号，非侵入式 eBPF Uprobe 无法解密，自动通过参数完成 ptrace + 代理注入"
	default:
		plan.DetectedStack = "stripped-embedded-tls"
		plan.NonIntrusiveOK = false
		plan.NonIntrusiveReason = "目标程序使用内嵌/strip TLS 栈 (如 rustls/BoringSSL)，无导出 TLS 符号可供非侵入式 eBPF Uprobe 挂载，自动通过参数完成代理证书与 Hook 注入"
	}

	userArgs := cmdArgs[1:]
	if autoIntrusive && !plan.NonIntrusiveOK {
		plan.AutoIntrusiveTriggered = true
		if isJVM && rtHooks != nil && rtHooks.JavaAgentJar != "" && !hasArgPrefix(userArgs, "-javaagent:") && !isVersionOrHelpArgs(userArgs) {
			if tap != nil {
				pHost, pPort := tap.HostPort()
				plan.InjectedArgs = []string{
					"-javaagent:" + rtHooks.JavaAgentJar + "=" + tap.ProxyURL(),
					"-Dhttp.proxyHost=" + pHost,
					"-Dhttp.proxyPort=" + pPort,
					"-Dhttps.proxyHost=" + pHost,
					"-Dhttps.proxyPort=" + pPort,
					"-Djdk.internal.httpclient.disableHostnameVerification=true",
				}
				plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:-javaagent", "cli_arg:-Dhttps.proxyHost")
			} else {
				plan.InjectedArgs = []string{"-javaagent:" + rtHooks.JavaAgentJar}
				plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:-javaagent")
			}
		} else if isNode && rtHooks != nil && rtHooks.NodeHookJS != "" && !hasArgPrefix(userArgs, "--require") && !hasArgExact(userArgs, "-r") && !isVersionOrHelpArgs(userArgs) {
			nodeHookSlash := filepath.ToSlash(rtHooks.NodeHookJS)
			plan.InjectedArgs = []string{"--require", nodeHookSlash}
			plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:--require")
		} else if isBun && rtHooks != nil && rtHooks.NodeHookJS != "" && !hasArgPrefix(userArgs, "--preload") && !isVersionOrHelpArgs(userArgs) {
			nodeHookSlash := filepath.ToSlash(rtHooks.NodeHookJS)
			plan.InjectedArgs = []string{"--preload", nodeHookSlash}
			plan.IntrusiveMethods = append(plan.IntrusiveMethods, "cli_arg:--preload")
		}
	}

	childArgs := append(append([]string(nil), plan.InjectedArgs...), userArgs...)
	execBin := binPath
	execArgs := childArgs

	if autoIntrusive && prof != nil && prof.RequiresPtrace && rtHooks != nil && rtHooks.PtraceBin != "" {
		execBin = rtHooks.PtraceBin
		execArgs = append([]string{binPath}, childArgs...)
		plan.PtraceWrapped = true
		plan.IntrusiveMethods = append(plan.IntrusiveMethods, "ptrace_wrapper")
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "enable_ptrace_syscall_hook", map[string]any{
				"target":    prof.ResolvedELF,
				"link_mode": prof.LinkMode,
				"tls_stack": prof.TLSStack,
			})
		}
	}
	plan.ExecBin = execBin
	plan.ExecArgs = execArgs

	env := os.Environ()
	setAndTrackEnv := func(k, v string) {
		env = setEnvVar(env, k, v)
		plan.InjectedEnv[k] = v
	}

	if sockPath != "" {
		setAndTrackEnv("LLM_TRACER_SOCK", sockPath)
	}
	if pipePath != "" {
		setAndTrackEnv("LLM_TRACER_PIPE", pipePath)
	}

	if autoIntrusive {
		if preloadPath != "" {
			if runtime.GOOS == "darwin" {
				if !isJVM {
					existingDyld := os.Getenv("DYLD_INSERT_LIBRARIES")
					if existingDyld != "" {
						setAndTrackEnv("DYLD_INSERT_LIBRARIES", preloadPath+":"+existingDyld)
					} else {
						setAndTrackEnv("DYLD_INSERT_LIBRARIES", preloadPath)
					}
					if prof != nil && prof.TLSStack == "dynamic-libssl" {
						setAndTrackEnv("DYLD_FORCE_FLAT_NAMESPACE", "1")
					}
					plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "preload:dyld_insert_libraries")
				}
			} else if runtime.GOOS == "linux" && !isJVM {
				existingPreload := os.Getenv("LD_PRELOAD")
				if existingPreload != "" {
					setAndTrackEnv("LD_PRELOAD", preloadPath+":"+existingPreload)
				} else {
					setAndTrackEnv("LD_PRELOAD", preloadPath)
				}
				plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "preload:ld_preload")
			}
		}
		if rtHooks != nil {
			if rtHooks.PyHookDir != "" {
				existingPyPath := os.Getenv("PYTHONPATH")
				sep := string(os.PathListSeparator)
				if existingPyPath != "" {
					setAndTrackEnv("PYTHONPATH", rtHooks.PyHookDir+sep+existingPyPath)
				} else {
					setAndTrackEnv("PYTHONPATH", rtHooks.PyHookDir)
				}
				if isPython {
					plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:PYTHONPATH(sitecustomize)")
				}
			}
			if rtHooks.NodeHookJS != "" {
				nodeHookSlash := filepath.ToSlash(rtHooks.NodeHookJS)
				reqOpt := "--require " + nodeHookSlash
				if existingNodeOpts := os.Getenv("NODE_OPTIONS"); existingNodeOpts != "" {
					setAndTrackEnv("NODE_OPTIONS", existingNodeOpts+" "+reqOpt)
				} else {
					setAndTrackEnv("NODE_OPTIONS", reqOpt)
				}
				preloadOpt := "--preload " + nodeHookSlash
				if existingBunOpts := os.Getenv("BUN_OPTIONS"); existingBunOpts != "" {
					setAndTrackEnv("BUN_OPTIONS", existingBunOpts+" "+preloadOpt)
				} else {
					setAndTrackEnv("BUN_OPTIONS", preloadOpt)
				}
				if isNode {
					plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:NODE_OPTIONS")
				}
				if isBun {
					plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:BUN_OPTIONS")
				}
			}
			if rtHooks.JavaAgentJar != "" {
				javaOpt := "-javaagent:" + rtHooks.JavaAgentJar
				if existingJavaOpts := os.Getenv("JAVA_TOOL_OPTIONS"); existingJavaOpts != "" {
					setAndTrackEnv("JAVA_TOOL_OPTIONS", existingJavaOpts+" "+javaOpt)
				} else {
					setAndTrackEnv("JAVA_TOOL_OPTIONS", javaOpt)
				}
				if isJVM {
					plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:JAVA_TOOL_OPTIONS")
				}
			}
		}
		if tap != nil {
			pHost, pPort := tap.HostPort()
			setAndTrackEnv("LLM_TRACER_PROXY_HOST", pHost)
			setAndTrackEnv("LLM_TRACER_PROXY_PORT", pPort)
			setAndTrackEnv("SSL_CERT_FILE", tap.CABundlePath())
			setAndTrackEnv("CURL_CA_BUNDLE", tap.CABundlePath())
			setAndTrackEnv("REQUESTS_CA_BUNDLE", tap.CABundlePath())
			setAndTrackEnv("NODE_EXTRA_CA_CERTS", tap.CABundlePath())
			setAndTrackEnv("CARGO_HTTP_CAINFO", tap.CABundlePath())

			isRuntime := isShellOrRuntimeBinary(binPath) || isShellOrRuntimeBinary(resolvedELF)
			needsProxyEnv := !isRuntime &&
				(runtime.GOOS != "linux" || (prof != nil && (prof.RequiresPtrace || prof.TLSStack == "stripped-embedded-tls")))
			env = unsetEnvVar(env, "ALL_PROXY")
			env = unsetEnvVar(env, "all_proxy")
			env = unsetEnvVar(env, "NO_PROXY")
			env = unsetEnvVar(env, "no_proxy")
			if needsProxyEnv {
				setAndTrackEnv("HTTPS_PROXY", tap.ProxyURL())
				setAndTrackEnv("https_proxy", tap.ProxyURL())
				plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "env:HTTPS_PROXY", "env:SSL_CERT_FILE", "loopback_tap")
				if !CanUsePtrace() || (prof != nil && prof.TLSStack == "stripped-embedded-tls") {
					setAndTrackEnv("HTTP_PROXY", tap.ProxyURL())
					setAndTrackEnv("http_proxy", tap.ProxyURL())
				}
			} else {
				env = unsetEnvVar(env, "HTTPS_PROXY")
				env = unsetEnvVar(env, "https_proxy")
				env = unsetEnvVar(env, "HTTP_PROXY")
				env = unsetEnvVar(env, "http_proxy")
			}
			if isJVM {
				plan.IntrusiveMethods = appendUniqueStr(plan.IntrusiveMethods, "loopback_tap")
			}
		}
	}

	c.mu.Lock()
	c.lastLaunchPlan = plan
	c.mu.Unlock()

	if c.mon != nil {
		c.mon.RecordOK(selfmon.StageProbe, "plan_launch_command", map[string]any{
			"binary":                  plan.BinaryPath,
			"detected_stack":          plan.DetectedStack,
			"non_intrusive_ok":        plan.NonIntrusiveOK,
			"auto_intrusive_triggered": plan.AutoIntrusiveTriggered,
			"intrusive_methods":       plan.IntrusiveMethods,
			"injected_args":           plan.InjectedArgs,
			"ptrace_wrapped":          plan.PtraceWrapped,
		})
	}
	return plan, env, nil
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

// AnalyzePIDPlans inspects all running processes matched by any active ScopeFilter selector
// (--pid with subtree, --exe/--binary, --cwd, --cmd), prioritizes non-intrusive eBPF Uprobes,
// and builds an actionable diagnosis & intrusive fallback plan for any matched PID where eBPF cannot cover TLS.
func (c *Collector) AnalyzePIDPlans() []PIDAttachPlan {
	targetPIDs := c.tracker.DiscoverMatchingPIDs()
	if len(targetPIDs) == 0 {
		c.mu.Lock()
		c.pidPlans = nil
		c.mu.Unlock()
		return nil
	}
	if len(targetPIDs) > 1 {
		var nonShell []int
		for _, pid := range targetPIDs {
			info := InspectProcess(pid)
			if !isPureShellComm(info.Comm, info.Exe) {
				nonShell = append(nonShell, pid)
			}
		}
		if len(nonShell) > 0 {
			targetPIDs = nonShell
		}
	}

	c.mu.RLock()
	ebpf := c.ebpfEngine
	ebpfActive := ebpf != nil && ebpf.Active()
	injectedMap := make(map[int]string, len(c.liveInjectedPIDs))
	for k, v := range c.liveInjectedPIDs {
		injectedMap[k] = v
	}
	prevPlans := make(map[int]PIDAttachPlan, len(c.pidPlans))
	for _, p := range c.pidPlans {
		prevPlans[p.PID] = p
	}
	c.mu.RUnlock()

	var plans []PIDAttachPlan
	for _, pid := range targetPIDs {
		if pid <= 0 {
			continue
		}
		var plan PIDAttachPlan
		prev, hadPrev := prevPlans[pid]
		prevEBPF := prev.EBPFStatus == "attached" || prev.EBPFStatus == "tracepoint_only"
		if hadPrev && prev.Exe != "" && prevEBPF == ebpfActive {
			plan = prev
		} else {
			plan = c.inspectSinglePIDPlan(pid, ebpfActive)
		}
		if mode, ok := injectedMap[pid]; ok && mode != "" {
			plan.Injected = true
			plan.ActiveMode = mode
			plan.IntrusiveNeeded = false
		}
		plans = append(plans, plan)
	}
	c.mu.Lock()
	c.pidPlans = plans
	c.mu.Unlock()
	return plans
}

// AutoInjectMatchingPIDs analyzes all currently running processes matching ScopeFilter (--pid, --exe, --cwd, --cmd)
// and automatically executes live intrusive attachment on any process where eBPF alone cannot cover TLS.
func (c *Collector) AutoInjectMatchingPIDs() []PIDAttachPlan {
	plans := c.AnalyzePIDPlans()
	for i := range plans {
		if plans[i].IntrusiveNeeded && !plans[i].Injected {
			if updated, err := c.InjectRunningPID(plans[i].PID); err == nil && updated != nil {
				plans[i] = *updated
			}
		}
	}
	return plans
}

func isPureShellComm(comm, exePath string) bool {
	c := strings.ToLower(strings.TrimSpace(comm))
	b := strings.ToLower(strings.TrimSuffix(filepath.Base(exePath), ".exe"))
	switch c {
	case "sh", "bash", "dash", "zsh", "fish":
		return true
	}
	switch b {
	case "sh", "bash", "dash", "zsh", "fish":
		return true
	}
	return false
}

// PIDPlans returns the most recent PIDAttachPlan list.
func (c *Collector) PIDPlans() []PIDAttachPlan {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.pidPlans) == 0 {
		return nil
	}
	out := make([]PIDAttachPlan, len(c.pidPlans))
	copy(out, c.pidPlans)
	return out
}

func (c *Collector) inspectSinglePIDPlan(pid int, ebpfActive bool) PIDAttachPlan {
	info := InspectProcess(pid)
	exePath := info.Exe
	if exePath == "" {
		if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			exePath = link
		}
	}
	comm := info.Comm
	if comm == "" && exePath != "" {
		comm = filepath.Base(exePath)
	}
	plan := PIDAttachPlan{
		PID:     pid,
		Comm:    comm,
		Exe:     exePath,
		Cmdline: info.Cmdline,
	}

	isJVM := isJavaBinary(exePath) || strings.EqualFold(comm, "java") || len(findMappedLibraries(pid, "libjvm.so")) > 0
	baseExe := strings.ToLower(filepath.Base(exePath))
	baseComm := strings.ToLower(comm)
	cmdLower := strings.ToLower(info.Cmdline)
	isNode := baseExe == "node" || baseExe == "nodejs" || strings.HasPrefix(baseExe, "node") ||
		baseComm == "node" || baseComm == "nodejs" || strings.Contains(cmdLower, "/node ") || strings.HasPrefix(cmdLower, "node ")
	isPython := strings.HasPrefix(baseExe, "python") || len(findMappedLibraries(pid, "libpython")) > 0

	// 1. Check if JVM (JSSE pure bytecode/JIT TLS)
	if isJVM {
		plan.DetectedStack = "jvm-jsse"
		if ebpfActive {
			plan.EBPFStatus = "tracepoint_only"
			plan.ActiveMode = "ebpf_tracepoint"
			plan.EBPFReason = "Java/JVM 默认使用 JSSE 纯字节码/JIT 执行 TLS 加解密，无固定 ELF 函数偏移；eBPF 仅能通过 Syscall Tracepoint 捕获明文 HTTP，无法直接解密 HTTPS"
		} else {
			plan.EBPFStatus = "unavailable"
			plan.ActiveMode = "pending_confirmation"
			plan.EBPFReason = "当前未启用内核 eBPF，且 JVM JSSE TLS 需通过 JVM Instrument Agent 拦截"
		}
		plan.IntrusiveNeeded = true
		plan.RecommendedIntrusive = "jvm_dynamic_attach"
		plan.IntrusiveDescription = "通过 JVM Dynamic Attach API (jcmd / AttachSocket) 向运行中 JVM 动态加载 LlmTracerAgent (agentmain)，免重启接管后续 HTTPS/HTTP 流量"
		plan.IntrusiveCommandHint = fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid)
		return plan
	}

	// 2. Check if Go binary (unstripped .symtab OR stripped -s -w via .gopclntab)
	if exePath != "" {
		if gt, err := InspectGoTLSTarget(exePath); err == nil && gt != nil && len(gt.Symbols) > 0 {
			plan.DetectedStack = "gotls"
			plan.Symbols = gt.Symbols
			if f, err := os.Open(exePath); err == nil {
				f.Close()
			}
			if ebpfActive {
				c.mu.RLock()
				eng := c.ebpfEngine
				c.mu.RUnlock()
				if eng != nil {
					eng.AttachTargets([]ProbeTarget{*gt})
				}
				plan.EBPFStatus = "attached"
				plan.ActiveMode = "ebpf_uprobe"
				plan.IntrusiveNeeded = false
				plan.EBPFReason = fmt.Sprintf("已自动识别 Go 运行时 (%s) 并挂载内核 eBPF Uprobe (crypto/tls.(*Conn).Write/Read，含 .gopclntab 恢复)，免重启、零侵入生效", gt.GoVersion)
				return plan
			}
			plan.EBPFStatus = "unavailable"
			plan.ActiveMode = "pending_confirmation"
			plan.IntrusiveNeeded = true
			plan.EBPFReason = fmt.Sprintf("已解析 GoTLS (%s) 函数偏移，但当前进程无 root/CAP_BPF 权限，无法加载内核 eBPF Uprobe", gt.GoVersion)
			plan.RecommendedIntrusive = "ptrace_seize"
			plan.IntrusiveDescription = "通过 PTRACE_SEIZE 热挂载运行中进程系统调用（仅能捕获明文 HTTP/Socket I/O），或以 sudo/CAP_BPF 重新运行 llm-tracer 启用零侵入 GoTLS eBPF Uprobe"
			plan.IntrusiveCommandHint = fmt.Sprintf("sudo llm-tracer capture --pid %d", pid)
			return plan
		}
	}

	// 3. Check OpenSSL (dynamic libssl.so in /proc/<pid>/maps OR static OpenSSL symbols in /proc/<pid>/exe)
	var pidSSLTargets []ProbeTarget
	for _, libPath := range append(findMappedLibraries(pid, "libssl"), findMappedLibraries(pid, "_ssl")...) {
		if syms, err := ResolveOpenSSLSymbols(libPath); err == nil && len(syms) > 0 {
			pidSSLTargets = append(pidSSLTargets, ProbeTarget{
				BinaryPath: libPath,
				Type:       "openssl",
				Symbols:    syms,
			})
		}
	}
	if exePath != "" {
		if syms, err := ResolveOpenSSLSymbols(exePath); err == nil && len(syms) > 0 {
			pidSSLTargets = append(pidSSLTargets, ProbeTarget{
				BinaryPath: exePath,
				Type:       "static_openssl",
				Symbols:    syms,
			})
		} else if prof, err := InspectBinaryProfile(exePath); err == nil && prof != nil && prof.TLSStack == "dynamic-libssl" && len(pidSSLTargets) == 0 {
			// Binary imports libssl.so dynamically (e.g. via DT_NEEDED or Mach-O LC_LOAD_DYLIB)
			sysTargets := DiscoverOpenSSLTargets(nil, exePath)
			if len(sysTargets) > 0 {
				pidSSLTargets = append(pidSSLTargets, sysTargets[0])
			}
		}
	}
	if len(pidSSLTargets) > 0 {
		t := pidSSLTargets[0]
		plan.DetectedStack = "dynamic-libssl"
		if t.Type == "static_openssl" {
			plan.DetectedStack = "static-openssl"
		}
		plan.Symbols = t.Symbols
		if ebpfActive {
			c.mu.RLock()
			eng := c.ebpfEngine
			c.mu.RUnlock()
			if eng != nil {
				eng.AttachTargets(pidSSLTargets)
			}
			plan.EBPFStatus = "attached"
			plan.ActiveMode = "ebpf_uprobe"
			plan.IntrusiveNeeded = false
			plan.EBPFReason = fmt.Sprintf("已自动识别 %s (%s) 并挂载内核 eBPF Uprobe (SSL_write/SSL_read)，免重启、零侵入直接捕获已有与新建连接", plan.DetectedStack, filepath.Base(t.BinaryPath))
			return plan
		}
		// eBPF is not available (unprivileged Linux / macOS / Windows)
		plan.EBPFStatus = "unavailable"
		plan.ActiveMode = "pending_confirmation"
		plan.IntrusiveNeeded = true
		plan.EBPFReason = fmt.Sprintf("已识别 %s (%s) 符号表，但当前未启用内核 eBPF 引擎（无 root/CAP_BPF 权限或非 Linux 环境）", plan.DetectedStack, filepath.Base(t.BinaryPath))
		if isNode {
			plan.RecommendedIntrusive = "node_inspector_sigusr1"
			plan.IntrusiveDescription = "向运行中 Node.js 进程发送 SIGUSR1 临时开启 V8 Inspector 端口，通过 Runtime.evaluate 动态注入 TLSSocket/Socket Hook 后立即关闭调试端口，免重启生效"
			plan.IntrusiveCommandHint = fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid)
		} else {
			plan.RecommendedIntrusive = "ptrace_seize"
			plan.IntrusiveDescription = "通过 PTRACE_SEIZE 热挂载运行中进程系统调用（退出时自动 PTRACE_DETACH），或使用 sudo 运行以启用 eBPF Uprobe"
			plan.IntrusiveCommandHint = fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid)
		}
		return plan
	}

	// 4. Node.js without exported OpenSSL symbols or on non-Linux
	if isNode {
		plan.DetectedStack = "nodejs"
		if ebpfActive {
			plan.EBPFStatus = "tracepoint_only"
			plan.ActiveMode = "ebpf_tracepoint"
			plan.EBPFReason = "目标 Node.js 二进制未导出 OpenSSL 符号，eBPF 仅能通过 Syscall Tracepoint 捕获明文 HTTP"
		} else {
			plan.EBPFStatus = "unavailable"
			plan.ActiveMode = "pending_confirmation"
			plan.EBPFReason = "当前未启用内核 eBPF 引擎"
		}
		plan.IntrusiveNeeded = true
		plan.RecommendedIntrusive = "node_inspector_sigusr1"
		plan.IntrusiveDescription = "向运行中 Node.js 进程发送 SIGUSR1 临时开启 V8 Inspector 端口，通过 Runtime.evaluate 动态注入 TLSSocket/Socket Hook 后立即关闭调试端口，免重启生效"
		plan.IntrusiveCommandHint = fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid)
		return plan
	}

	if isPython {
		plan.DetectedStack = "python"
	} else {
		plan.DetectedStack = "stripped-native"
	}
	if ebpfActive {
		plan.EBPFStatus = "tracepoint_only"
		plan.ActiveMode = "ebpf_tracepoint"
		plan.EBPFReason = "目标进程已 strip 符号表且未映射 libssl.so（如 rustls / 静态 strip 二进制）；eBPF Syscall Tracepoint 已挂载（可抓明文 HTTP/IPC），加密 TLS 需侵入式方案"
	} else {
		plan.EBPFStatus = "unavailable"
		plan.ActiveMode = "pending_confirmation"
		plan.EBPFReason = "当前未启用内核 eBPF 引擎，且目标进程已在运行中"
	}
	plan.IntrusiveNeeded = true
	plan.RecommendedIntrusive = "ptrace_seize"
	plan.IntrusiveDescription = "通过 PTRACE_SEIZE 热挂载运行中进程系统调用（退出时自动 PTRACE_DETACH 不中断目标进程）"
	plan.IntrusiveCommandHint = fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid)
	return plan
}

// InjectRunningPID executes the recommended live intrusive attachment for an already-running PID without restarting it.
func (c *Collector) InjectRunningPID(pid int) (*PIDAttachPlan, error) {
	c.mu.RLock()
	ebpf := c.ebpfEngine
	ebpfActive := ebpf != nil && ebpf.Active()
	c.mu.RUnlock()

	plan := c.inspectSinglePIDPlan(pid, ebpfActive)
	if !plan.IntrusiveNeeded && plan.EBPFStatus == "attached" {
		return &plan, nil
	}

	var err error
	switch plan.RecommendedIntrusive {
	case "jvm_dynamic_attach":
		err = c.injectRunningJVM(pid)
	case "node_inspector_sigusr1":
		err = c.injectRunningNodeJS(pid)
	case "ptrace_seize":
		err = c.injectRunningPtrace(pid)
	default:
		err = fmt.Errorf("no live injector available for stack %s", plan.DetectedStack)
	}

	if err != nil {
		plan.InjectError = err.Error()
		if c.mon != nil {
			c.mon.RecordError(selfmon.StageProbe, "inject_running_pid", err, map[string]any{
				"pid":    pid,
				"method": plan.RecommendedIntrusive,
				"stack":  plan.DetectedStack,
			})
		}
		return &plan, err
	}

	plan.Injected = true
	plan.IntrusiveNeeded = false
	plan.ActiveMode = plan.RecommendedIntrusive
	c.mu.Lock()
	if c.liveInjectedPIDs == nil {
		c.liveInjectedPIDs = make(map[int]string)
	}
	c.liveInjectedPIDs[pid] = plan.RecommendedIntrusive
	for i := range c.pidPlans {
		if c.pidPlans[i].PID == pid {
			c.pidPlans[i] = plan
		}
	}
	c.mu.Unlock()

	if c.mon != nil {
		c.mon.RecordOK(selfmon.StageProbe, "inject_running_pid", map[string]any{
			"pid":    pid,
			"method": plan.RecommendedIntrusive,
			"stack":  plan.DetectedStack,
		})
	}
	return &plan, nil
}

// injectRunningJVM uses JVM Dynamic Attach (jcmd JVMTI.agent_load or HotSpot .java_pid<pid> Unix socket)
// to load llm_tracer_java.jar (agentmain) into a running JVM process without restarting it.
func (c *Collector) injectRunningJVM(pid int) error {
	c.mu.RLock()
	rtHooks := c.runtimeHooks
	tap := c.loopbackTap
	c.mu.RUnlock()

	if rtHooks == nil || rtHooks.JavaAgentJar == "" {
		return fmt.Errorf("java agent jar not initialized")
	}
	if tap == nil {
		return fmt.Errorf("loopback tap not active")
	}

	// Copy the agent JAR to a world-readable path in /tmp so the target JVM process can always read it.
	sharedJar := filepath.Join(os.TempDir(), fmt.Sprintf("llm_tracer_agent_%d.jar", os.Getpid()))
	rawJar, err := os.ReadFile(rtHooks.JavaAgentJar)
	if err != nil {
		return fmt.Errorf("read java agent jar: %w", err)
	}
	if err := os.WriteFile(sharedJar, rawJar, 0o644); err != nil {
		return fmt.Errorf("stage shared java agent jar: %w", err)
	}
	_ = os.Chmod(sharedJar, 0o644)

	c.mu.Lock()
	c.activeTapPID = pid
	c.mu.Unlock()

	proxyURL := tap.ProxyURL()

	// Method 1: Try `jcmd <pid> JVMTI.agent_load <jarPath> <proxyURL>` if jcmd is available
	if jcmdPath, err := exec.LookPath("jcmd"); err == nil {
		out, err := exec.Command(jcmdPath, strconv.Itoa(pid), "JVMTI.agent_load", sharedJar, proxyURL).CombinedOutput()
		outStr := string(out)
		if err == nil && (strings.Contains(outStr, "return code: 0") || strings.Contains(outStr, "Command executed successfully")) {
			return nil
		}
	}

	// Method 2: Native HotSpot POSIX Dynamic Attach protocol over /proc/<pid>/root/tmp/.java_pid<pid>
	sockCandidates := []string{
		fmt.Sprintf("/proc/%d/root/tmp/.java_pid%d", pid, pid),
		filepath.Join(os.TempDir(), fmt.Sprintf(".java_pid%d", pid)),
	}
	var sockPath string
	for _, sc := range sockCandidates {
		if _, err := os.Stat(sc); err == nil {
			sockPath = sc
			break
		}
	}
	if sockPath == "" {
		// Trigger Attach Listener in target JVM by creating .attach_pid<pid> and sending SIGQUIT (3)
		attachFiles := []string{
			fmt.Sprintf("/proc/%d/cwd/.attach_pid%d", pid, pid),
			filepath.Join(os.TempDir(), fmt.Sprintf(".attach_pid%d", pid)),
		}
		for _, af := range attachFiles {
			if f, err := os.Create(af); err == nil {
				_ = f.Close()
				_ = os.Chmod(af, 0o666)
				defer os.Remove(af)
			}
		}
		_ = sendSignalByName(pid, "QUIT")
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			for _, sc := range sockCandidates {
				if _, err := os.Stat(sc); err == nil {
					sockPath = sc
					break
				}
			}
			if sockPath != "" {
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	if sockPath == "" {
		return fmt.Errorf("JVM attach socket .java_pid%d did not appear (check UID permissions)", pid)
	}

	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("dial jvm attach socket %s: %w", sockPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// HotSpot attach protocol: "1\0load\0instrument\0false\0<jarPath>=<args>\0"
	payload := fmt.Sprintf("1\x00load\x00instrument\x00false\x00%s=%s\x00", sharedJar, proxyURL)
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write jvm attach command: %w", err)
	}
	resp, _ := io.ReadAll(conn)
	respStr := strings.TrimSpace(string(resp))
	if !strings.HasPrefix(respStr, "0") {
		return fmt.Errorf("jvm attach returned error: %s", respStr)
	}
	return nil
}

// injectRunningNodeJS sends SIGUSR1 to a running Node.js process to activate the V8 Inspector on 127.0.0.1:9229,
// evaluates a runtime expression that sets LLM_TRACER_PIPE and requires node_hook.cjs, and immediately closes the inspector.
func (c *Collector) injectRunningNodeJS(pid int) error {
	c.mu.RLock()
	rtHooks := c.runtimeHooks
	pipePath := c.pipePath
	c.mu.RUnlock()

	if rtHooks == nil || rtHooks.NodeHookJS == "" {
		return fmt.Errorf("node runtime hook script not initialized")
	}
	if pipePath == "" {
		return fmt.Errorf("collector pipe path not initialized")
	}

	if err := sendSignalByName(pid, "USR1"); err != nil {
		return fmt.Errorf("send SIGUSR1 to node pid %d: %w", pid, err)
	}

	// Poll http://127.0.0.1:9229/json for V8 Inspector WebSocket URL
	var wsURL string
	client := &http.Client{Timeout: 300 * time.Millisecond}
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://127.0.0.1:9229/json")
		if err == nil {
			var targets []struct {
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&targets)
			_ = resp.Body.Close()
			if len(targets) > 0 && targets[0].WebSocketDebuggerURL != "" {
				wsURL = targets[0].WebSocketDebuggerURL
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	if wsURL == "" {
		return fmt.Errorf("V8 inspector did not open on 127.0.0.1:9229 after SIGUSR1 for pid %d", pid)
	}

	hookJSPath := filepath.ToSlash(rtHooks.NodeHookJS)
	pipePathSlash := filepath.ToSlash(pipePath)
	expr := fmt.Sprintf(
		`(() => { process.env.LLM_TRACER_PIPE = %q; if (!globalThis.__LLM_TRACER_LIVE_NODE__) { globalThis.__LLM_TRACER_LIVE_NODE__ = true; process.mainModule ? process.mainModule.require(%q) : require(%q); } try { const ins = process.mainModule ? process.mainModule.require("node:inspector") : require("node:inspector"); ins.close(); } catch (_) {} return "OK"; })()`,
		pipePathSlash, hookJSPath, hookJSPath,
	)
	if err := evalInV8InspectorWebSocket(wsURL, expr); err != nil {
		return err
	}

	c.mu.Lock()
	c.userHookPIDs[pid] = true
	c.mu.Unlock()
	return nil
}

// injectRunningPtrace spawns `llm_tracer_ptrace -p <pid>` in the background using PTRACE_SEIZE
// and detaches cleanly when the Collector stops.
func (c *Collector) injectRunningPtrace(pid int) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("ptrace live attach is only supported on Linux")
	}
	c.mu.RLock()
	rtHooks := c.runtimeHooks
	pipePath := c.pipePath
	c.mu.RUnlock()

	if rtHooks == nil || rtHooks.PtraceBin == "" {
		return fmt.Errorf("ptrace helper binary not available")
	}
	cmd := exec.Command(rtHooks.PtraceBin, "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LLM_TRACER_PIPE="+pipePath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ptrace -p %d: %w", pid, err)
	}
	// Check briefly that ptrace helper didn't immediately exit with error (e.g. Yama ptrace_scope EPERM)
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()
	select {
	case err := <-doneCh:
		if err != nil {
			return fmt.Errorf("ptrace attach to pid %d failed (check kernel.yama.ptrace_scope or root privileges): %w", pid, err)
		}
		return nil
	case <-time.After(120 * time.Millisecond):
		// Running and attached! Register cleanup when Collector stops.
		go func() {
			<-c.stopCh
			if cmd.Process != nil {
				_ = cmd.Process.Signal(os.Interrupt)
				select {
				case <-doneCh:
				case <-time.After(500 * time.Millisecond):
					_ = cmd.Process.Kill()
				}
			}
		}()
		return nil
	}
}

func sendSignalByName(pid int, sigName string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("signals not supported on windows")
	}
	cmd := exec.Command("kill", "-s", sigName, strconv.Itoa(pid))
	return cmd.Run()
}

// evalInV8InspectorWebSocket performs a minimal RFC 6455 WebSocket handshake with Node's V8 Inspector
// and sends a single Runtime.evaluate CDP command with includeCommandLineAPI: true.
func evalInV8InspectorWebSocket(wsURL, expression string) error {
	u, err := url.Parse(wsURL)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	var keyBytes [16]byte
	_, _ = rand.Read(keyBytes[:])
	wsKey := base64.StdEncoding.EncodeToString(keyBytes[:])

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		u.RequestURI(), u.Host, wsKey)
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		return fmt.Errorf("websocket handshake failed: %s", strings.TrimSpace(statusLine))
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}

	cdpMsg, err := json.Marshal(map[string]any{
		"id":     1,
		"method": "Runtime.evaluate",
		"params": map[string]any{
			"expression":            expression,
			"includeCommandLineAPI": true,
		},
	})
	if err != nil {
		return err
	}
	if err := writeMaskedWSFrame(conn, cdpMsg); err != nil {
		return err
	}
	// Read response frame (or EOF if inspector.close() already closed the socket after evaluating)
	_, _ = br.ReadByte()
	return nil
}

func writeMaskedWSFrame(w io.Writer, payload []byte) error {
	var hdr []byte
	hdr = append(hdr, 0x81) // FIN=1, opcode=1 (text)
	n := len(payload)
	switch {
	case n <= 125:
		hdr = append(hdr, byte(0x80|n))
	case n <= 65535:
		hdr = append(hdr, byte(0x80|126), byte(n>>8), byte(n))
	default:
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(n))
		hdr = append(hdr, byte(0x80|127))
		hdr = append(hdr, lenBuf[:]...)
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}
