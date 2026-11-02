package collector

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

const (
	injectBackoffInitial = 1 * time.Second
	injectBackoffMax     = 5 * time.Minute
)

// ErrPIDOutOfScope is returned when InjectRunningPID is called for a PID outside the active capture scope.
var ErrPIDOutOfScope = errors.New("pid is outside the configured capture scope")

type pidInjectBackoffState struct {
	failures    int
	lastBackoff time.Duration
	nextRetryAt time.Time
	lastError   string
	inFlight    bool
}

var (
	injectBackoffMu          sync.Mutex
	injectBackoffByCol       = make(map[*Collector]map[int]*pidInjectBackoffState)
	injectBackoffCancelByCol = make(map[*Collector]chan struct{})
)

func isCollectorStopped(c *Collector) bool {
	if c == nil || c.stopCh == nil {
		return false
	}
	select {
	case <-c.stopCh:
		return true
	default:
		return false
	}
}

func deleteInjectBackoffLocked(c *Collector) {
	if cancel, ok := injectBackoffCancelByCol[c]; ok {
		close(cancel)
		delete(injectBackoffCancelByCol, c)
	}
	delete(injectBackoffByCol, c)
}

func pruneStoppedCollectorsLocked() {
	for col := range injectBackoffByCol {
		if isCollectorStopped(col) {
			deleteInjectBackoffLocked(col)
		}
	}
}

func checkInjectBackoff(c *Collector, pid int, now time.Time) (pidInjectBackoffState, bool) {
	injectBackoffMu.Lock()
	defer injectBackoffMu.Unlock()
	pruneStoppedCollectorsLocked()
	if c != nil && isCollectorStopped(c) {
		deleteInjectBackoffLocked(c)
		return pidInjectBackoffState{}, false
	}
	byPID := injectBackoffByCol[c]
	if byPID != nil {
		if st, ok := byPID[pid]; ok && st != nil {
			if st.inFlight || now.Before(st.nextRetryAt) {
				cp := *st
				if cp.lastError == "" && cp.inFlight {
					cp.lastError = "injection already in progress"
				}
				return cp, true
			}
			st.inFlight = true
			return *st, false
		}
	}
	if byPID == nil {
		byPID = make(map[int]*pidInjectBackoffState)
		injectBackoffByCol[c] = byPID
		if c != nil && c.stopCh != nil {
			cancel := make(chan struct{})
			injectBackoffCancelByCol[c] = cancel
			go func(col *Collector, stopCh, cancelCh <-chan struct{}) {
				select {
				case <-stopCh:
					ResetInjectBackoff(col)
				case <-cancelCh:
				}
			}(c, c.stopCh, cancel)
		}
	}
	st := &pidInjectBackoffState{inFlight: true}
	byPID[pid] = st
	return *st, false
}

func recordInjectFailure(c *Collector, pid int, now time.Time, injectErr error) pidInjectBackoffState {
	injectBackoffMu.Lock()
	defer injectBackoffMu.Unlock()
	pruneStoppedCollectorsLocked()
	if c != nil && isCollectorStopped(c) {
		deleteInjectBackoffLocked(c)
		return pidInjectBackoffState{}
	}
	byPID := injectBackoffByCol[c]
	if byPID == nil {
		byPID = make(map[int]*pidInjectBackoffState)
		injectBackoffByCol[c] = byPID
		if c != nil && c.stopCh != nil {
			cancel := make(chan struct{})
			injectBackoffCancelByCol[c] = cancel
			go func(col *Collector, stopCh, cancelCh <-chan struct{}) {
				select {
				case <-stopCh:
					ResetInjectBackoff(col)
				case <-cancelCh:
				}
			}(c, c.stopCh, cancel)
		}
	}
	st := byPID[pid]
	if st == nil {
		st = &pidInjectBackoffState{}
		byPID[pid] = st
	}
	st.inFlight = false
	st.failures++
	shift := st.failures - 1
	if shift < 0 {
		shift = 0
	} else if shift > 9 {
		shift = 9
	}
	backoff := injectBackoffInitial << shift
	if backoff > injectBackoffMax {
		backoff = injectBackoffMax
	}
	st.lastBackoff = backoff
	st.nextRetryAt = now.Add(backoff)
	if injectErr != nil {
		st.lastError = injectErr.Error()
	}
	return *st
}

func clearInjectBackoff(c *Collector, pid int) {
	injectBackoffMu.Lock()
	defer injectBackoffMu.Unlock()
	if byPID := injectBackoffByCol[c]; byPID != nil {
		delete(byPID, pid)
		if len(byPID) == 0 {
			deleteInjectBackoffLocked(c)
		}
	}
}

// ResetInjectBackoff clears any recorded live-injection failure backoff state for c.
func ResetInjectBackoff(c *Collector) {
	injectBackoffMu.Lock()
	defer injectBackoffMu.Unlock()
	deleteInjectBackoffLocked(c)
}

// InjectBackoffEntryCount returns the number of active PID backoff entries tracked for c.
func InjectBackoffEntryCount(c *Collector) int {
	injectBackoffMu.Lock()
	defer injectBackoffMu.Unlock()
	pruneStoppedCollectorsLocked()
	return len(injectBackoffByCol[c])
}

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
	DegradationNotices   []string          `json:"degradation_notices,omitempty"`
	Symbols              map[string]uint64 `json:"symbols,omitempty"`
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

// SetRuntimeHooks overrides the runtime hook paths used for live attach (such as PtraceBin).
func (c *Collector) SetRuntimeHooks(rt *RuntimeHookPaths) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.runtimeHooks = rt
	c.mu.Unlock()
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
	in, err := c.inspectLaunchTarget(cmdArgs)
	if err != nil {
		return nil, nil, err
	}
	plan := planLaunch(in)
	env := applyLaunchPlan(c, in, plan, os.Environ())
	return plan, env, nil
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
	if c != nil && c.mon != nil {
		lastCollectorMonitor.Store(c.mon)
	}
	archCap := currentArchCapabilities()
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
			c.applyPtraceLiveFallback(
				pid,
				archCap,
				&plan,
				"通过 PTRACE_SEIZE 热挂载运行中进程系统调用（仅能捕获明文 HTTP/Socket I/O），或以 sudo/CAP_BPF 重新运行 llm-tracer 启用零侵入 GoTLS eBPF Uprobe",
				fmt.Sprintf("sudo llm-tracer capture --pid %d", pid),
			)
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
			c.applyPtraceLiveFallback(
				pid,
				archCap,
				&plan,
				"通过 PTRACE_SEIZE 热挂载运行中进程系统调用（退出时自动 PTRACE_DETACH），或使用 sudo 运行以启用 eBPF Uprobe",
				fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid),
			)
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
	c.applyPtraceLiveFallback(
		pid,
		archCap,
		&plan,
		"通过 PTRACE_SEIZE 热挂载运行中进程系统调用（退出时自动 PTRACE_DETACH 不中断目标进程）",
		fmt.Sprintf("llm-tracer capture --pid %d --inject-live", pid),
	)
	return plan
}

func (c *Collector) applyPtraceLiveFallback(
	pid int,
	archCap ebpfArchCapabilities,
	plan *PIDAttachPlan,
	defaultDesc string,
	defaultHint string,
) {
	if archCap.PtraceUserspaceSupported {
		plan.RecommendedIntrusive = "ptrace_seize"
		plan.IntrusiveDescription = defaultDesc
		plan.IntrusiveCommandHint = defaultHint
		return
	}
	notice := fmt.Sprintf("linux/%s 能力表 PtraceUserspaceSupported=false（内置用户态 ptrace 注入器仅支持 x86_64），已跳过 ptrace_seize 热注入方案", archCap.Arch)
	if archCap.DegradationNotice != "" {
		notice = fmt.Sprintf("%s [%s]", notice, archCap.DegradationNotice)
	}
	plan.RecommendedIntrusive = ""
	plan.DegradationNotices = appendUniqueStr(plan.DegradationNotices, notice)
	plan.IntrusiveDescription = notice
	plan.IntrusiveCommandHint = fmt.Sprintf("sudo llm-tracer capture --pid %d", pid)
	if c != nil && c.mon != nil {
		c.mon.RecordWarn(selfmon.StageProbe, "ptrace_arch_unsupported", notice, map[string]any{
			"pid":              pid,
			"arch":             archCap.Arch,
			"detected_stack":   plan.DetectedStack,
			"ptrace_supported": archCap.PtraceUserspaceSupported,
		})
	}
}

// InjectRunningPID executes the recommended live intrusive attachment for an already-running PID without restarting it.
func (c *Collector) InjectRunningPID(pid int) (*PIDAttachPlan, error) {
	if c == nil || c.tracker == nil || !c.tracker.IsInScope(pid) {
		err := fmt.Errorf("%w: pid %d", ErrPIDOutOfScope, pid)
		if c != nil && c.mon != nil {
			c.mon.RecordWarn(selfmon.StageProbe, "pid_inject_out_of_scope_blocked", err.Error(), map[string]any{
				"pid": pid,
			})
		}
		return &PIDAttachPlan{
			PID:         pid,
			InjectError: err.Error(),
		}, err
	}
	c.mu.RLock()
	ebpf := c.ebpfEngine
	ebpfActive := ebpf != nil && ebpf.Active()
	c.mu.RUnlock()

	c.ensureHookChannelPermissions([]int{pid})

	plan := c.inspectSinglePIDPlan(pid, ebpfActive)
	if !plan.IntrusiveNeeded && plan.EBPFStatus == "attached" {
		return &plan, nil
	}

	now := time.Now()
	if st, backedOff := checkInjectBackoff(c, pid, now); backedOff {
		plan.InjectError = st.lastError
		if c != nil && c.mon != nil {
			c.mon.RecordWarn(selfmon.StageProbe, "inject_backoff", st.lastError, map[string]any{
				"pid":         pid,
				"method":      plan.RecommendedIntrusive,
				"stack":       plan.DetectedStack,
				"failures":    st.failures,
				"backoff_ms":  st.lastBackoff.Milliseconds(),
				"retry_in_ms": st.nextRetryAt.Sub(now).Milliseconds(),
			})
		}
		return &plan, fmt.Errorf("inject pid %d backed off after %d failures: %s", pid, st.failures, st.lastError)
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
		if len(plan.DegradationNotices) > 0 {
			err = fmt.Errorf("no live injector available for stack %s: %s", plan.DetectedStack, strings.Join(plan.DegradationNotices, "; "))
		} else {
			err = fmt.Errorf("no live injector available for stack %s", plan.DetectedStack)
		}
	}

	if err != nil {
		st := recordInjectFailure(c, pid, time.Now(), err)
		plan.InjectError = err.Error()
		if c.mon != nil {
			c.mon.RecordError(selfmon.StageProbe, "inject_running_pid", err, map[string]any{
				"pid":        pid,
				"method":     plan.RecommendedIntrusive,
				"stack":      plan.DetectedStack,
				"failures":   st.failures,
				"backoff_ms": st.lastBackoff.Milliseconds(),
			})
			c.mon.RecordWarn(selfmon.StageProbe, "inject_backoff", err.Error(), map[string]any{
				"pid":         pid,
				"method":      plan.RecommendedIntrusive,
				"stack":       plan.DetectedStack,
				"failures":    st.failures,
				"backoff_ms":  st.lastBackoff.Milliseconds(),
				"retry_in_ms": st.lastBackoff.Milliseconds(),
			})
		}
		return &plan, err
	}

	clearInjectBackoff(c, pid)
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

	rawJar, err := os.ReadFile(rtHooks.JavaAgentJar)
	if err != nil {
		return fmt.Errorf("read java agent jar: %w", err)
	}
	// Stage the agent JAR via os.CreateTemp (O_EXCL) to prevent symlink hijacking in /tmp,
	// then chmod 0o644 so the target JVM process can read it during Dynamic Attach.
	tmpJar, err := os.CreateTemp(os.TempDir(), fmt.Sprintf("llm_tracer_agent_%d_*.jar", pid))
	if err != nil {
		return fmt.Errorf("create temp java agent jar: %w", err)
	}
	sharedJar := tmpJar.Name()
	if _, err := tmpJar.Write(rawJar); err != nil {
		_ = tmpJar.Close()
		_ = os.Remove(sharedJar)
		return fmt.Errorf("stage shared java agent jar: %w", err)
	}
	if err := tmpJar.Chmod(0o644); err != nil {
		_ = tmpJar.Close()
		_ = os.Remove(sharedJar)
		return fmt.Errorf("chmod shared java agent jar: %w", err)
	}
	if err := tmpJar.Close(); err != nil {
		_ = os.Remove(sharedJar)
		return fmt.Errorf("close shared java agent jar: %w", err)
	}

	c.mu.Lock()
	c.activeTapPID = pid
	c.stagedAgentJars = append(c.stagedAgentJars, sharedJar)
	c.mu.Unlock()
	if c.mon != nil {
		c.mon.RecordOK(selfmon.StageProbe, "stage_jvm_agent_jar", map[string]any{
			"pid":      pid,
			"jar_path": sharedJar,
		})
	}

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
		// HotSpot AttachListener::is_init_trigger only calls stat() on .attach_pid<pid> to check trigger
		// existence and owner UID (st_uid == geteuid() or root); the JVM never writes to this file.
		// Open with O_NOFOLLOW and apply f.Chmod() on the open file descriptor (fchmod semantics) via
		// initPipeFileNoFollow before Close to eliminate path-based chmod TOCTOU symlink races while
		// preserving the minimum permissions required by HotSpot (0o600 for same-UID, 0o644 across UIDs).
		attachPerm := os.FileMode(0o600)
		if isCrossUIDProcess(pid) {
			attachPerm = 0o644
		}
		for _, af := range attachFiles {
			if err := createJVMAttachTriggerFile(af, attachPerm); err == nil {
				defer func(p string) {
					_ = removeSocketNoFollow(p)
				}(af)
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

// createJVMAttachTriggerFile safely creates a HotSpot .attach_pid<pid> trigger file using O_NOFOLLOW
// and fchmod on the open file descriptor (via initPipeFileNoFollow) to prevent symlink TOCTOU attacks.
func createJVMAttachTriggerFile(path string, perm os.FileMode) error {
	_ = removeSocketNoFollow(path)
	return initPipeFileNoFollow(path, perm, -1)
}

// nodeInspectorTarget represents a single target entry returned by V8 Inspector GET /json.
type nodeInspectorTarget struct {
	ID                   string `json:"id"`
	Title                string `json:"title"`
	Type                 string `json:"type"`
	Description          string `json:"description"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	PID                  int    `json:"pid,omitempty"`
}

type procListeningSocket struct {
	Endpoint string
	Port     int
	Inode    string
}

var (
	nodeInspectorProcRoot    = "/proc"
	nodeInspectorPollTimeout = 2500 * time.Millisecond
	nodeInspectorLookupHook  func(pid int, cmdline string) (string, error)
)

func parseSocketInodeLink(linkTarget string) string {
	linkTarget = strings.TrimSpace(linkTarget)
	if strings.HasPrefix(linkTarget, "socket:[") && strings.HasSuffix(linkTarget, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(linkTarget, "socket:["), "]")
	}
	if strings.HasPrefix(linkTarget, "[0000]:") {
		return strings.TrimPrefix(linkTarget, "[0000]:")
	}
	return ""
}

func collectPIDSocketInodes(procRoot string, pid int) (map[string]bool, bool) {
	fdDir := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, false
	}
	inodes := make(map[string]bool)
	for _, ent := range entries {
		link, err := os.Readlink(filepath.Join(fdDir, ent.Name()))
		if err != nil {
			continue
		}
		if inode := parseSocketInodeLink(link); inode != "" && inode != "0" {
			inodes[inode] = true
		}
	}
	return inodes, true
}

func parseProcNetTCPAddr(localAddr string, isIPv6 bool) (endpoint string, port int, ok bool) {
	parts := strings.Split(strings.TrimSpace(localAddr), ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil || portVal == 0 {
		return "", 0, false
	}
	port = int(portVal)
	ipHex := strings.ToUpper(strings.TrimSpace(parts[0]))

	if !isIPv6 {
		if len(ipHex) != 8 {
			return "", 0, false
		}
		raw, err := hex.DecodeString(ipHex)
		if err != nil || len(raw) != 4 {
			return "", 0, false
		}
		// Linux /proc/net/tcp stores IPv4 in host (little-endian) byte order: 0100007F -> 127.0.0.1.
		// Also accept 7F000001 for hand-written test fixtures.
		ipLE := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		ipBE := net.IPv4(raw[0], raw[1], raw[2], raw[3])
		switch {
		case ipLE.IsUnspecified():
			return fmt.Sprintf("127.0.0.1:%d", port), port, true
		case ipLE.IsLoopback():
			return fmt.Sprintf("%s:%d", ipLE.String(), port), port, true
		case ipBE.IsLoopback():
			return fmt.Sprintf("%s:%d", ipBE.String(), port), port, true
		default:
			return "", 0, false
		}
	}

	if len(ipHex) != 32 {
		return "", 0, false
	}
	switch ipHex {
	case "00000000000000000000000000000000",
		"00000000000000000000000001000000",
		"00000000000000000000000000000001",
		"0000000000000000FFFF00000100007F",
		"00000000000000000000FFFF0100007F",
		"00000000000000000000FFFF7F000001":
		return fmt.Sprintf("127.0.0.1:%d", port), port, true
	default:
		return "", 0, false
	}
}

func parseProcNetTCPFile(path string, isIPv6 bool) ([]procListeningSocket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []procListeningSocket
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if lineNo == 1 && (strings.EqualFold(fields[0], "sl") || strings.Contains(strings.ToLower(line), "local_address")) {
			continue
		}
		if len(fields) < 10 {
			continue
		}
		// st == 0A is TCP_LISTEN
		if !strings.EqualFold(fields[3], "0A") {
			continue
		}
		ep, port, ok := parseProcNetTCPAddr(fields[1], isIPv6)
		if !ok {
			continue
		}
		out = append(out, procListeningSocket{
			Endpoint: ep,
			Port:     port,
			Inode:    fields[9],
		})
	}
	return out, sc.Err()
}

func sortInspectorSockets(sockets []procListeningSocket) []string {
	sort.SliceStable(sockets, func(i, j int) bool {
		pi, pj := sockets[i].Port, sockets[j].Port
		rankPort := func(p int) int {
			switch {
			case p == 9229:
				return 0
			case p >= 9230 && p <= 9299:
				return 1
			default:
				return 2
			}
		}
		ri, rj := rankPort(pi), rankPort(pj)
		if ri != rj {
			return ri < rj
		}
		return pi < pj
	})
	var endpoints []string
	seen := make(map[string]bool, len(sockets))
	for _, s := range sockets {
		if !seen[s.Endpoint] {
			seen[s.Endpoint] = true
			endpoints = append(endpoints, s.Endpoint)
		}
	}
	return endpoints
}

// discoverPIDInspectorEndpoints locates loopback TCP listening endpoints for pid using
// <procRoot>/<pid>/fd socket inodes and <procRoot>/<pid>/net/tcp{,6}.
func discoverPIDInspectorEndpoints(procRoot string, pid int) ([]string, bool, error) {
	if procRoot == "" {
		procRoot = nodeInspectorProcRoot
	}
	if pid <= 0 {
		return nil, false, fmt.Errorf("invalid pid %d", pid)
	}
	pidDir := filepath.Join(procRoot, strconv.Itoa(pid))
	tcpSockets, err4 := parseProcNetTCPFile(filepath.Join(pidDir, "net", "tcp"), false)
	tcp6Sockets, err6 := parseProcNetTCPFile(filepath.Join(pidDir, "net", "tcp6"), true)
	if err4 != nil && err6 != nil {
		return nil, false, fmt.Errorf("read %s/net/tcp: %w", pidDir, err4)
	}
	allListen := append(tcpSockets, tcp6Sockets...)

	pidInodes, hasFDDir := collectPIDSocketInodes(procRoot, pid)
	if hasFDDir {
		var owned []procListeningSocket
		for _, s := range allListen {
			if s.Inode != "" && s.Inode != "0" && pidInodes[s.Inode] {
				owned = append(owned, s)
			}
		}
		return sortInspectorSockets(owned), true, nil
	}

	// Fallback when <procRoot>/<pid>/fd is absent (e.g. minimal synthetic /proc/<pid>/net/tcp test fixture):
	// single listening endpoint is treated as authoritative for that per-PID table; multiple endpoints require /json disambiguation.
	var nonZero []procListeningSocket
	for _, s := range allListen {
		if s.Inode != "0" {
			nonZero = append(nonZero, s)
		}
	}
	endpoints := sortInspectorSockets(nonZero)
	return endpoints, len(endpoints) == 1, nil
}

func extractPIDFromInspectorText(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// 1. Match bracketed PID such as "node[12345]" or "process[12345]"
	for rest := s; ; {
		openIdx := strings.IndexByte(rest, '[')
		if openIdx < 0 {
			break
		}
		closeIdx := strings.IndexByte(rest[openIdx+1:], ']')
		if closeIdx < 0 {
			break
		}
		inside := strings.TrimSpace(rest[openIdx+1 : openIdx+1+closeIdx])
		if pid, err := strconv.Atoi(inside); err == nil && pid > 0 {
			return pid
		}
		rest = rest[openIdx+1+closeIdx+1:]
	}
	// 2. Match "pid:12345", "pid=12345", "pid 12345"
	lower := strings.ToLower(s)
	for idx := 0; idx < len(lower); {
		pos := strings.Index(lower[idx:], "pid")
		if pos < 0 {
			break
		}
		absPos := idx + pos
		if absPos > 0 {
			prev := lower[absPos-1]
			if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
				idx = absPos + 3
				continue
			}
		}
		after := lower[absPos+3:]
		after = strings.TrimLeft(after, " :=\t")
		var digits strings.Builder
		for i := 0; i < len(after); i++ {
			if after[i] >= '0' && after[i] <= '9' {
				digits.WriteByte(after[i])
			} else {
				break
			}
		}
		if digits.Len() > 0 {
			if pid, err := strconv.Atoi(digits.String()); err == nil && pid > 0 {
				return pid
			}
		}
		idx = absPos + 3
	}
	return 0
}

func extractTargetExplicitPID(t nodeInspectorTarget) int {
	if t.PID > 0 {
		return t.PID
	}
	if pid := extractPIDFromInspectorText(t.Title); pid > 0 {
		return pid
	}
	if pid := extractPIDFromInspectorText(t.Description); pid > 0 {
		return pid
	}
	return 0
}

func matchesNodeCmdline(cmdline string, t nodeInspectorTarget) bool {
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return false
	}
	fields := strings.Fields(cmdline)
	var scriptTokens []string
	for i, tok := range fields {
		if i == 0 {
			base := strings.ToLower(filepath.Base(tok))
			if base == "node" || base == "nodejs" || base == "node.exe" || strings.HasPrefix(base, "node") {
				continue
			}
		}
		if strings.HasPrefix(tok, "-") {
			continue
		}
		cleaned := filepath.ToSlash(strings.TrimSpace(tok))
		if cleaned == "" {
			continue
		}
		base := filepath.Base(cleaned)
		if len(base) >= 3 && base != "node" && base != "nodejs" {
			scriptTokens = append(scriptTokens, cleaned, base)
		}
	}
	if len(scriptTokens) == 0 {
		return false
	}
	haystack := strings.ToLower(filepath.ToSlash(t.URL + " " + t.Title + " " + t.Description))
	for _, st := range scriptTokens {
		if strings.Contains(haystack, strings.ToLower(st)) {
			return true
		}
	}
	return false
}

func validateInspectorWSURL(wsURL, expectedEndpoint string) error {
	u, err := url.Parse(strings.TrimSpace(wsURL))
	if err != nil {
		return fmt.Errorf("invalid webSocketDebuggerUrl %q: %w", wsURL, err)
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("unexpected scheme in webSocketDebuggerUrl %q", wsURL)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("non-loopback host in webSocketDebuggerUrl %q", wsURL)
	}
	if expectedEndpoint != "" {
		_, expPort, err := net.SplitHostPort(expectedEndpoint)
		if err == nil && expPort != "" && u.Port() != "" && u.Port() != expPort {
			return fmt.Errorf("webSocketDebuggerUrl port %s does not match queried inspector port %s", u.Port(), expPort)
		}
	}
	return nil
}

// selectNodeInspectorTarget chooses and validates a V8 Inspector target for pid from GET /json results.
// When socketOwnedByPID is false, it requires an explicit PID or cmdline script match and refuses blind selection.
func selectNodeInspectorTarget(
	pid int,
	cmdline string,
	endpoint string,
	targets []nodeInspectorTarget,
	socketOwnedByPID bool,
) (string, error) {
	var valid []nodeInspectorTarget
	for _, t := range targets {
		if strings.TrimSpace(t.WebSocketDebuggerURL) == "" {
			continue
		}
		if err := validateInspectorWSURL(t.WebSocketDebuggerURL, endpoint); err != nil {
			continue
		}
		valid = append(valid, t)
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("no valid V8 inspector targets with webSocketDebuggerUrl on %s", endpoint)
	}

	var (
		pidMatched     []nodeInspectorTarget
		cmdlineMatched []nodeInspectorTarget
		untagged       []nodeInspectorTarget
		mismatchedPID  int
	)
	for _, t := range valid {
		tPID := extractTargetExplicitPID(t)
		switch {
		case tPID == pid:
			pidMatched = append(pidMatched, t)
		case tPID > 0 && tPID != pid:
			mismatchedPID = tPID
		default:
			if matchesNodeCmdline(cmdline, t) {
				cmdlineMatched = append(cmdlineMatched, t)
			} else {
				untagged = append(untagged, t)
			}
		}
	}

	if len(pidMatched) == 1 {
		return pidMatched[0].WebSocketDebuggerURL, nil
	}
	if len(pidMatched) > 1 {
		for _, t := range pidMatched {
			if matchesNodeCmdline(cmdline, t) {
				return t.WebSocketDebuggerURL, nil
			}
		}
		return pidMatched[0].WebSocketDebuggerURL, nil
	}

	if mismatchedPID > 0 && len(cmdlineMatched) == 0 && len(untagged) == 0 {
		return "", fmt.Errorf("V8 inspector on %s belongs to pid %d, not target pid %d; refusing injection", endpoint, mismatchedPID, pid)
	}

	if len(cmdlineMatched) == 1 && mismatchedPID == 0 {
		return cmdlineMatched[0].WebSocketDebuggerURL, nil
	}
	if len(cmdlineMatched) > 1 {
		return "", fmt.Errorf("ambiguous V8 inspector targets (%d matched cmdline) on %s for pid %d; refusing blind injection", len(cmdlineMatched), endpoint, pid)
	}

	if socketOwnedByPID && mismatchedPID == 0 {
		if len(untagged) == 1 {
			return untagged[0].WebSocketDebuggerURL, nil
		}
		return "", fmt.Errorf("ambiguous V8 inspector targets (%d candidates) on %s for pid %d; refusing blind injection", len(untagged), endpoint, pid)
	}

	return "", fmt.Errorf("cannot verify that V8 inspector on %s belongs to pid %d (no /proc socket match and no PID/script match in /json); refusing blind injection", endpoint, pid)
}

func fetchInspectorTargets(client *http.Client, endpoint string) ([]nodeInspectorTarget, error) {
	if client == nil {
		client = &http.Client{Timeout: 300 * time.Millisecond}
	}
	resp, err := client.Get("http://" + endpoint + "/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET http://%s/json returned status %d", endpoint, resp.StatusCode)
	}
	var targets []nodeInspectorTarget
	if err := json.NewDecoder(resp.Body).Decode(&targets); err != nil {
		return nil, fmt.Errorf("decode http://%s/json: %w", endpoint, err)
	}
	return targets, nil
}

// resolveNodeInspectorWSURL resolves and validates the V8 Inspector WebSocket URL for pid.
// It prioritizes /proc/<pid>/fd + /proc/<pid>/net/tcp{,6} to find the exact port bound by pid,
// and validates /json targets against pid/cmdline before returning.
func resolveNodeInspectorWSURL(procRoot string, pid int, cmdline string, client *http.Client) (string, error) {
	if nodeInspectorLookupHook != nil {
		return nodeInspectorLookupHook(pid, cmdline)
	}
	endpoints, authoritative, procErr := discoverPIDInspectorEndpoints(procRoot, pid)
	if procErr == nil {
		if len(endpoints) == 0 {
			return "", fmt.Errorf("pid %d has no listening V8 inspector socket in %s/%d", pid, procRoot, pid)
		}
		var (
			matchedWS []string
			lastErr   error
		)
		for _, ep := range endpoints {
			targets, err := fetchInspectorTargets(client, ep)
			if err != nil {
				lastErr = err
				continue
			}
			wsURL, err := selectNodeInspectorTarget(pid, cmdline, ep, targets, authoritative)
			if err != nil {
				lastErr = err
				continue
			}
			matchedWS = append(matchedWS, wsURL)
		}
		if len(matchedWS) == 1 {
			return matchedWS[0], nil
		}
		if len(matchedWS) > 1 {
			return "", fmt.Errorf("ambiguous V8 inspector endpoints (%d matched) for pid %d; refusing blind injection", len(matchedWS), pid)
		}
		if lastErr != nil {
			return "", lastErr
		}
		return "", fmt.Errorf("no valid V8 inspector endpoint for pid %d among %v", pid, endpoints)
	}

	// When /proc is unavailable (e.g. non-Linux), probe 127.0.0.1:9229 ONLY with socketOwnedByPID=false,
	// which requires explicit PID or cmdline script verification in /json and refuses blind targets[0] selection.
	const fallbackEndpoint = "127.0.0.1:9229"
	targets, err := fetchInspectorTargets(client, fallbackEndpoint)
	if err != nil {
		return "", fmt.Errorf("procfs unavailable (%v) and %s unreachable: %w", procErr, fallbackEndpoint, err)
	}
	return selectNodeInspectorTarget(pid, cmdline, fallbackEndpoint, targets, false)
}

// injectRunningNodeJS sends SIGUSR1 to a running Node.js process to activate the V8 Inspector,
// locates the inspector endpoint belonging to pid, evaluates a runtime expression that sets
// LLM_TRACER_PIPE and requires node_hook.cjs, and immediately closes the inspector.
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

	cmdline := InspectProcess(pid).Cmdline
	if cmdline == "" && nodeInspectorProcRoot != "" {
		if raw, err := os.ReadFile(filepath.Join(nodeInspectorProcRoot, strconv.Itoa(pid), "cmdline")); err == nil {
			cmdline = strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		}
	}

	if err := sendSignalByName(pid, "USR1"); err != nil {
		return fmt.Errorf("send SIGUSR1 to node pid %d: %w", pid, err)
	}

	var (
		wsURL   string
		lastErr error
	)
	client := &http.Client{Timeout: 300 * time.Millisecond}
	deadline := time.Now().Add(nodeInspectorPollTimeout)
	for time.Now().Before(deadline) {
		resolved, err := resolveNodeInspectorWSURL(nodeInspectorProcRoot, pid, cmdline, client)
		if err == nil && resolved != "" {
			wsURL = resolved
			break
		}
		lastErr = err
		time.Sleep(30 * time.Millisecond)
	}
	if wsURL == "" {
		if lastErr == nil {
			lastErr = fmt.Errorf("V8 inspector did not open for pid %d after SIGUSR1", pid)
		} else {
			lastErr = fmt.Errorf("select V8 inspector target for pid %d: %w", pid, lastErr)
		}
		if c != nil && c.mon != nil {
			c.mon.RecordWarn(selfmon.StageProbe, "node_inspector_target_rejected", lastErr.Error(), map[string]any{
				"pid": pid,
			})
		}
		return lastErr
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
	archCap := currentArchCapabilities()
	if !archCap.PtraceUserspaceSupported {
		msg := fmt.Sprintf("ptrace live attach skipped for pid %d: architecture %s has PtraceUserspaceSupported=false", pid, archCap.Arch)
		if c != nil && c.mon != nil {
			c.mon.RecordWarn(selfmon.StageProbe, "ptrace_arch_unsupported", msg, map[string]any{
				"pid":              pid,
				"arch":             archCap.Arch,
				"ptrace_supported": archCap.PtraceUserspaceSupported,
			})
		}
		return fmt.Errorf("%s", msg)
	}
	c.mu.RLock()
	rtHooks := c.runtimeHooks
	pipePath := c.pipePath
	c.mu.RUnlock()

	if rtHooks == nil || rtHooks.PtraceBin == "" {
		return fmt.Errorf("ptrace helper binary not available")
	}
	cmd := exec.Command(rtHooks.PtraceBin, "-p", strconv.Itoa(pid))
	cmd.Env = append(StripSensitiveEnvKeys(os.Environ()), "LLM_TRACER_PIPE="+pipePath)
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
