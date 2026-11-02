package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
)

var sockSeq uint64

// Sink delivers a captured raw TLS/HTTP frame from a Source into the Collector pipeline.
type Sink func(pid, tid int, connID string, dir parser.Direction, payload []byte, tlsMode string)

// Source represents an independent capture channel managed by Collector.
type Source interface {
	Name() string
	Start(ctx context.Context, sink Sink) error
	Close() error
}

type flushableSource interface {
	Flush()
}

const outOfScopeDropRateWindow = 1 * time.Second

type pidDropRateState struct {
	lastEmit        time.Time
	suppressedCount int
	suppressedBytes int
	comm            string
	exe             string
	tlsMode         string
}

type Collector struct {
	cfgMu             sync.RWMutex
	sourcesMu         sync.RWMutex
	permMu            sync.Mutex
	dropRateMu        sync.Mutex
	mu                sync.RWMutex
	cacheDir          string
	hooksDir          string
	sockPath          string
	pipePath          string
	preloadPath       string
	runtimeHooks      *RuntimeHookPaths
	loopbackTap       *LoopbackTap
	ebpfEngine        *EBPFEngine
	sources           []Source
	tapSrc            *tapSource
	channelRelaxed    bool
	channelTargetUID  int
	userHookPIDs      map[int]bool
	liveInjectedPIDs  map[int]string
	dropRateByPID     map[int]*pidDropRateState
	stagedAgentJars   []string
	autoIntrusive     bool
	autoInjectLive    bool
	tapInsecure       bool
	captureUnknown    bool
	ingestToken       string
	secretIngestToken string
	lastLaunchPlan    *LaunchAttachPlan
	activeTapPID      int
	tracker           *ProcessTracker
	reassembler       *parser.StreamReassembler
	correlator        *correlator.Correlator
	store             *store.Store
	mon               *selfmon.Monitor
	probes            []ProbeTarget
	pidPlans          []PIDAttachPlan
	stopCh            chan struct{}
	periodicStarted   bool
	periodicDoneCh    chan struct{}
	stopOnce          sync.Once
}

type DirectExchangeInput struct {
	ID              string            `json:"id,omitempty"`
	Timestamp       int64             `json:"timestamp,omitempty"`
	DurationMs      int64             `json:"duration_ms,omitempty"`
	Method          string            `json:"method"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	HTTPStatus      int               `json:"http_status"`
	HTTPVersion     string            `json:"http_version,omitempty"`
	PID             int               `json:"pid,omitempty"`
	PPID            int               `json:"ppid,omitempty"`
	Comm            string            `json:"comm,omitempty"`
	Cmdline         string            `json:"cmdline,omitempty"`
	Exe             string            `json:"exe,omitempty"`
	Cwd             string            `json:"cwd,omitempty"`
	TLSMode         string            `json:"tls_mode,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	RequestBody     []byte            `json:"request_body"`
	ResponseBody    []byte            `json:"response_body"`
	IsSSE           bool              `json:"is_sse"`
}

func NewCollector(
	cacheDir string,
	scope model.ScopeFilter,
	corr *correlator.Correlator,
	st *store.Store,
	mon *selfmon.Monitor,
) (*Collector, error) {
	tracker := NewProcessTracker(scope, mon)
	c := &Collector{
		cacheDir:         cacheDir,
		channelTargetUID: -1,
		userHookPIDs:     make(map[int]bool),
		liveInjectedPIDs: make(map[int]string),
		dropRateByPID:    make(map[int]*pidDropRateState),
		autoIntrusive:    true,
		tracker:          tracker,
		correlator:       corr,
		store:            st,
		mon:              mon,
		stopCh:           make(chan struct{}),
		periodicDoneCh:   make(chan struct{}),
	}
	c.reassembler = parser.NewStreamReassembler(scope.RecordHeaders, scope.Hosts, mon, c.handleReassembledEvent)
	return c, nil
}

// RegisterSource adds a capture Source to the Collector registry before Start.
func (c *Collector) RegisterSource(src Source) {
	if src == nil {
		return
	}
	c.sourcesMu.Lock()
	c.sources = append(c.sources, src)
	c.sourcesMu.Unlock()
}

// Sources returns a snapshot of registered capture sources.
func (c *Collector) Sources() []Source {
	c.sourcesMu.RLock()
	defer c.sourcesMu.RUnlock()
	out := make([]Source, len(c.sources))
	copy(out, c.sources)
	return out
}

// SetTapInsecure configures whether LoopbackTap skips certificate verification for non-loopback upstreams.
func (c *Collector) SetTapInsecure(insecure bool) {
	c.cfgMu.Lock()
	c.tapInsecure = insecure
	c.cfgMu.Unlock()

	c.sourcesMu.RLock()
	tapSrc := c.tapSrc
	c.sourcesMu.RUnlock()
	if tapSrc != nil {
		tapSrc.SetInsecure(insecure)
		return
	}

	c.mu.RLock()
	tap := c.loopbackTap
	c.mu.RUnlock()
	if tap != nil {
		tap.SetInsecure(insecure)
	}
}

// TapInsecure reports whether LoopbackTap skips certificate verification for non-loopback upstreams.
func (c *Collector) TapInsecure() bool {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.tapInsecure
}

// SetCaptureUnknown configures whether unknown-protocol HTTP exchanges are retained when host filters are empty.
func (c *Collector) SetCaptureUnknown(v bool) {
	c.cfgMu.Lock()
	c.captureUnknown = v
	c.cfgMu.Unlock()
	if c.reassembler != nil {
		c.reassembler.SetDropUnknown(!v)
	}
}

// CaptureUnknown reports whether unknown-protocol HTTP exchanges are retained when host filters are empty.
func (c *Collector) CaptureUnknown() bool {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.captureUnknown
}

// SetIngestToken stores the local HTTP ingest shared secret token for child hooks.
func (c *Collector) SetIngestToken(token string) {
	c.cfgMu.Lock()
	c.secretIngestToken = token
	c.cfgMu.Unlock()
	c.mu.Lock()
	c.ingestToken = ""
	c.mu.Unlock()
}

// IngestToken returns the local HTTP ingest shared secret token.
func (c *Collector) IngestToken() string {
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.secretIngestToken
}

// StagedAgentJars returns temporary JVM agent JAR paths created via os.CreateTemp during live attach.
func (c *Collector) StagedAgentJars() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, len(c.stagedAgentJars))
	copy(out, c.stagedAgentJars)
	return out
}

func (c *Collector) Start(ctx context.Context) error {
	hooksDir := filepath.Join(c.cacheDir, "hooks")
	if err := ensureSafeHooksDir(hooksDir); err != nil {
		return err
	}

	// Use a short socket path in /tmp if cacheDir path is long (AF_UNIX 108-byte limit)
	sockPath := filepath.Join(hooksDir, "tls.sock")
	if len(sockPath) > 80 {
		sockPath = filepath.Join("/tmp", fmt.Sprintf("llmt-%d-%d.sock", os.Getpid(), atomic.AddUint64(&sockSeq, 1)))
	}
	pipePath := filepath.Join(hooksDir, "tls.bin")

	channelPerm, targetUID, hasCross := c.resolveCrossUIDState(c.tracker.GetScope().PIDs)
	c.permMu.Lock()
	c.hooksDir = hooksDir
	c.channelRelaxed = hasCross
	c.channelTargetUID = targetUID
	c.permMu.Unlock()
	if hasCross && targetUID >= 0 {
		_ = setHooksDirModeNoFollow(hooksDir, 0o711)
	}

	c.mu.Lock()
	c.pipePath = pipePath
	c.mu.Unlock()

	scope := c.tracker.GetScope()
	initialProbes := ProbeAndRecordTargets(scope.PIDs, scope.Exes, c.mon)

	pipeSrc := newPipeSource(pipePath, channelPerm, targetUID, c.markUserHookPID, c.mon)
	unixSrc := newUnixSockSource(sockPath, pipePath, channelPerm, targetUID, c.mon, func(readySock string, _ net.Listener) {
		c.mu.Lock()
		c.sockPath = readySock
		c.mu.Unlock()
	}, c.markUserHookPID)
	tapSrc := newTapSource(hooksDir, c.TapInsecure(), c.mon, func() int {
		c.mu.RLock()
		defer c.mu.RUnlock()
		return c.activeTapPID
	}, func(tap *LoopbackTap) {
		c.mu.Lock()
		c.loopbackTap = tap
		c.mu.Unlock()
	})
	ebpfSrc := newEBPFSource(initialProbes, c.mon, c.isUserHookPID, func(eng *EBPFEngine, updatedProbes []ProbeTarget) {
		c.mu.Lock()
		c.ebpfEngine = eng
		c.probes = deduplicateProbes(updatedProbes)
		c.mu.Unlock()
	})

	c.sourcesMu.Lock()
	customSources := append([]Source(nil), c.sources...)
	allSources := []Source{pipeSrc, unixSrc, tapSrc, ebpfSrc}
	allSources = append(allSources, customSources...)
	c.sources = allSources
	c.tapSrc = tapSrc
	c.sourcesMu.Unlock()

	for _, src := range allSources {
		if err := src.Start(ctx, c.ingestFromSource); err != nil {
			if src.Name() == "pipe" {
				return err
			}
		}
	}

	if soPath, err := EnsureSSLPreloadHook(hooksDir); err == nil {
		c.mu.Lock()
		c.preloadPath = soPath
		c.mu.Unlock()
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "build_ssl_hook", map[string]any{"so_path": soPath, "sock_path": sockPath})
		}
	} else if c.mon != nil {
		c.mon.RecordWarn(selfmon.StageProbe, "build_ssl_hook", err.Error(), nil)
	}

	if rtHooks, err := EnsureRuntimeHooks(hooksDir); err == nil && rtHooks != nil {
		c.mu.Lock()
		c.runtimeHooks = rtHooks
		c.mu.Unlock()
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "build_runtime_hooks", map[string]any{
				"py_hook":    rtHooks.PyHookDir,
				"node_hook":  rtHooks.NodeHookJS,
				"java_agent": rtHooks.JavaAgentJar,
				"ptrace":     rtHooks.PtraceBin,
			})
		}
	} else if err != nil && c.mon != nil {
		c.mon.RecordWarn(selfmon.StageProbe, "build_runtime_hooks", err.Error(), nil)
	}

	c.AnalyzePIDPlans()
	c.mu.Lock()
	select {
	case <-c.stopCh:
		c.mu.Unlock()
		return fmt.Errorf("collector is stopped")
	default:
		c.periodicStarted = true
		go func() {
			defer close(c.periodicDoneCh)
			c.periodicSubtreeRefresh(ctx)
		}()
	}
	c.mu.Unlock()
	return nil
}

func (c *Collector) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.Flush()
		c.sourcesMu.RLock()
		sources := append([]Source(nil), c.sources...)
		c.sourcesMu.RUnlock()
		for _, src := range sources {
			if src != nil {
				_ = src.Close()
			}
		}
		if c.tracker != nil {
			c.tracker.Close()
		}
		c.flushSuppressedDrops()

		c.mu.RLock()
		sock := c.sockPath
		pipe := c.pipePath
		tap := c.loopbackTap
		ebpf := c.ebpfEngine
		stagedJars := append([]string(nil), c.stagedAgentJars...)
		c.mu.RUnlock()
		if tap != nil {
			tap.Close()
		}
		if ebpf != nil {
			ebpf.Close()
		}
		if sock != "" {
			_ = removeSocketNoFollow(sock)
		}
		if pipe != "" {
			_ = truncateAndRemovePipeNoFollow(pipe)
		}
		for _, jar := range stagedJars {
			if jar != "" {
				_ = os.Remove(jar)
			}
		}
	})
	c.mu.RLock()
	started := c.periodicStarted
	c.mu.RUnlock()
	if started {
		<-c.periodicDoneCh
	}
}

func (c *Collector) Probes() []ProbeTarget {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return deduplicateProbes(c.probes)
}

func (c *Collector) Scope() model.ScopeFilter {
	return c.tracker.GetScope()
}

func (c *Collector) UpdateScope(scope model.ScopeFilter) {
	c.tracker.SetScope(scope)
	c.reassembler.SetScope(scope.RecordHeaders, scope.Hosts)
	c.ensureHookChannelPermissions(scope.PIDs)
	probes := ProbeAndRecordTargets(scope.PIDs, scope.Exes, c.mon)
	c.mu.RLock()
	ebpf := c.ebpfEngine
	c.mu.RUnlock()
	if ebpf != nil {
		ebpf.AttachTargets(probes)
	}
	c.mu.Lock()
	c.probes = deduplicateProbes(probes)
	c.mu.Unlock()
	if c.AutoInjectLive() {
		c.AutoInjectMatchingPIDs()
	} else {
		c.AnalyzePIDPlans()
	}
	if c.mon != nil {
		c.mon.RecordOK(selfmon.StageTracker, "update_scope", map[string]any{
			"pids":           scope.PIDs,
			"pid_only":       scope.PIDOnly,
			"exes":           scope.Exes,
			"cwds":           scope.Cwds,
			"cmds":           scope.Cmds,
			"hosts":          scope.Hosts,
			"record_headers": scope.RecordHeaders,
		})
	}
}

// AttachBinaryTargets resolves ELF symbols (OpenSSL, Static-OpenSSL, GoTLS) for the specified executables
// and dynamically attaches kernel eBPF uprobes/uretprobes when EBPFEngine is active.
func (c *Collector) AttachBinaryTargets(exes ...string) []ProbeTarget {
	extra := ProbeAndRecordTargets(nil, exes, c.mon)
	if len(extra) == 0 {
		return nil
	}
	c.mu.RLock()
	ebpf := c.ebpfEngine
	c.mu.RUnlock()
	if ebpf != nil {
		ebpf.AttachTargets(extra)
	}
	c.mu.Lock()
	c.probes = appendUniqueProbes(c.probes, extra...)
	c.mu.Unlock()
	return extra
}

// LaunchCommand starts a child command (`-- <cmd> [args...]`), immediately registers its PID in the ProcessTracker
// before traffic starts, automatically completes intrusive CLI/env parameters when non-intrusive eBPF cannot be used,
// and waits for completion.
func (c *Collector) LaunchCommand(ctx context.Context, cmdArgs []string) (int, error) {
	if len(cmdArgs) == 0 {
		return 1, fmt.Errorf("empty command")
	}
	plan, env, err := c.PlanLaunchCommand(cmdArgs)
	if err != nil {
		if c.mon != nil {
			c.mon.RecordError(selfmon.StageTracker, "launch_command", err, map[string]any{"cmd": cmdArgs})
		}
		return 127, err
	}
	return c.LaunchPlannedCommand(ctx, plan, env)
}

// LaunchPlannedCommand executes a pre-computed LaunchAttachPlan with the given environment,
// registers the spawned child PID in ProcessTracker, and waits for completion.
func (c *Collector) LaunchPlannedCommand(ctx context.Context, plan *LaunchAttachPlan, env []string) (int, error) {
	if plan == nil || strings.TrimSpace(plan.ExecBin) == "" {
		return 1, fmt.Errorf("empty launch plan")
	}
	cmdArgs := plan.OriginalCmd
	if len(cmdArgs) == 0 {
		cmdArgs = append([]string{plan.ExecBin}, plan.ExecArgs...)
	}
	if plan.InjectedEnv != nil {
		delete(plan.InjectedEnv, "LLM_TRACER_INGEST_TOKEN")
	}
	c.mu.Lock()
	c.probes = deduplicateProbes(c.probes)
	if c.lastLaunchPlan != nil && c.lastLaunchPlan.InjectedEnv != nil {
		delete(c.lastLaunchPlan.InjectedEnv, "LLM_TRACER_INGEST_TOKEN")
	}
	c.mu.Unlock()
	if len(env) == 0 {
		env = os.Environ()
	}
	// Strip every llm-tracer credential (TOTP secret, tokens) plus generic
	// *_TOKEN/*_SECRET style keys so an observed agent cannot read them back.
	env = StripSensitiveEnvKeys(env)

	cmd := exec.CommandContext(ctx, plan.ExecBin, plan.ExecArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		if c.mon != nil {
			c.mon.RecordError(selfmon.StageTracker, "launch_command_start", err, map[string]any{"cmd": cmdArgs})
		}
		return 1, err
	}

	childPID := cmd.Process.Pid
	c.mu.Lock()
	c.activeTapPID = childPID
	c.mu.Unlock()
	info := c.tracker.RegisterRootPID(childPID)
	if c.mon != nil {
		c.mon.Record(selfmon.Event{
			Status: selfmon.StatusOK,
			Stage:  selfmon.StageTracker,
			Action: "launch_command_started",
			PID:    childPID,
			Comm:   info.Comm,
			Detail: map[string]any{
				"args":                     cmdArgs,
				"exe":                      plan.BinaryPath,
				"detected_stack":           plan.DetectedStack,
				"non_intrusive_ok":         plan.NonIntrusiveOK,
				"auto_intrusive_triggered": plan.AutoIntrusiveTriggered,
				"injected_args":            plan.InjectedArgs,
				"intrusive_methods":        plan.IntrusiveMethods,
			},
		})
	}

	err := cmd.Wait()
	c.Flush()
	c.tracker.MarkRootExited(childPID)
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
		if c.mon != nil {
			c.mon.RecordWarn(selfmon.StageTracker, "launch_command_exited", err.Error(), map[string]any{
				"pid": childPID, "exit_code": exitCode,
			})
		}
	} else if c.mon != nil {
		c.mon.Record(selfmon.Event{
			Status: selfmon.StatusOK,
			Stage:  selfmon.StageTracker,
			Action: "launch_command_exited",
			PID:    childPID,
			Comm:   info.Comm,
			Detail: map[string]any{"exit_code": 0},
		})
	}
	return exitCode, err
}

func probeTargetKey(p ProbeTarget) string {
	bin := filepath.Clean(p.BinaryPath)
	if realBin, err := filepath.EvalSymlinks(bin); err == nil && realBin != "" {
		bin = realBin
	}
	return bin + "\x00" + p.Type
}

func appendUniqueProbes(dst []ProbeTarget, extra ...ProbeTarget) []ProbeTarget {
	out := make([]ProbeTarget, 0, len(dst)+len(extra))
	idxByKey := make(map[string]int, len(dst)+len(extra))
	add := func(p ProbeTarget) {
		key := probeTargetKey(p)
		if idx, exists := idxByKey[key]; exists {
			cur := &out[idx]
			if p.Attached {
				cur.Attached = true
			}
			if cur.Note == "" && p.Note != "" {
				cur.Note = p.Note
			}
			if cur.LinkMode == "" && p.LinkMode != "" {
				cur.LinkMode = p.LinkMode
			}
			if cur.GoVersion == "" && p.GoVersion != "" {
				cur.GoVersion = p.GoVersion
			}
			if len(cur.Symbols) == 0 && len(p.Symbols) > 0 {
				cur.Symbols = p.Symbols
			}
			if len(cur.GoTLSReadRetOffsets) == 0 && len(p.GoTLSReadRetOffsets) > 0 {
				cur.GoTLSReadRetOffsets = p.GoTLSReadRetOffsets
			}
			return
		}
		idxByKey[key] = len(out)
		out = append(out, p)
	}
	for _, p := range dst {
		add(p)
	}
	for _, p := range extra {
		add(p)
	}
	return out
}

func deduplicateProbes(probes []ProbeTarget) []ProbeTarget {
	return appendUniqueProbes(nil, probes...)
}

// IngestRawChunk feeds a raw TLS plaintext frame into scope filtering and stream reassembly.
func (c *Collector) IngestRawChunk(pid int, tid int, connID string, dir parser.Direction, payload []byte, tlsMode string) bool {
	hint := model.ProcessInfo{PID: pid, TID: tid, TLSMode: tlsMode}
	procInfo, matched := c.tracker.MatchAndEnrich(pid, hint)
	if !matched {
		c.recordOutOfScopeDrop(pid, procInfo, tlsMode, len(payload))
		return false
	}
	connKey := fmt.Sprintf("%d:%s", pid, connID)
	c.reassembler.IngestChunk(parser.RawTLSChunk{
		ConnKey:   connKey,
		Direction: dir,
		Timestamp: time.Now().UnixMilli(),
		Process:   procInfo,
		Data:      payload,
	})
	return true
}

// IngestDirectExchange processes a complete or streaming HTTP exchange through scope filtering, protocol parsing, session correlation, and storage.
func (c *Collector) IngestDirectExchange(in DirectExchangeInput) (*model.TraceEvent, bool, error) {
	hint := model.ProcessInfo{
		PID:     in.PID,
		PPID:    in.PPID,
		Comm:    in.Comm,
		Cmdline: in.Cmdline,
		Exe:     in.Exe,
		Cwd:     in.Cwd,
		TLSMode: in.TLSMode,
	}
	procInfo, matched := c.tracker.MatchAndEnrich(in.PID, hint)
	if !matched {
		c.recordOutOfScopeDrop(in.PID, procInfo, in.TLSMode, len(in.RequestBody)+len(in.ResponseBody))
		return nil, false, nil
	}

	scope := c.tracker.GetScope()
	if len(scope.Hosts) > 0 {
		hostMatched := false
		h := strings.ToLower(strings.Split(in.Host, ":")[0])
		for _, fh := range scope.Hosts {
			fh = strings.ToLower(strings.TrimSpace(fh))
			if fh != "" && (h == fh || strings.Contains(h, fh)) {
				hostMatched = true
				break
			}
		}
		if !hostMatched {
			return nil, false, nil
		}
	}

	reqDecoded, _ := parser.DecompressBody(in.RequestBody, headerValueCI(in.RequestHeaders, "content-encoding"))
	respDecoded, _ := parser.DecompressBody(in.ResponseBody, headerValueCI(in.ResponseHeaders, "content-encoding"))
	proto := parser.DetectProtocol(in.Path, reqDecoded, respDecoded)
	if proto == model.ProtocolUnknown && len(scope.Hosts) == 0 && !c.CaptureUnknown() {
		return nil, false, nil
	}

	evID := in.ID
	if evID == "" {
		evID = "ev_" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
	}
	ts := in.Timestamp
	if ts == 0 {
		ts = time.Now().UnixMilli()
	}
	status := "ok"
	if in.HTTPStatus >= 400 {
		status = "error"
	}
	httpVer := in.HTTPVersion
	if httpVer == "" {
		httpVer = "HTTP/1.1"
	}
	var reqHdr, respHdr map[string]string
	if scope.RecordHeaders {
		reqHdr = in.RequestHeaders
		respHdr = in.ResponseHeaders
	}

	ev := &model.TraceEvent{
		ID:              evID,
		Timestamp:       ts,
		DurationMs:      in.DurationMs,
		Status:          status,
		HTTPStatus:      in.HTTPStatus,
		HTTPVersion:     httpVer,
		Method:          in.Method,
		Host:            in.Host,
		Path:            in.Path,
		URL:             fmt.Sprintf("https://%s%s", in.Host, in.Path),
		Protocol:        proto,
		Process:         procInfo,
		HeadersRecorded: scope.RecordHeaders,
		RequestHeaders:  reqHdr,
		ResponseHeaders: respHdr,
		RequestBytes:    len(reqDecoded),
		ResponseBytes:   len(respDecoded),
	}
	if err := parser.ParseExchange(ev, reqDecoded, respDecoded, in.IsSSE); err != nil {
		if c.mon != nil {
			c.mon.RecordError(selfmon.StageParser, "parse_"+string(proto), err, map[string]any{
				"pid": procInfo.PID, "path": in.Path,
			})
		}
	} else if c.mon != nil {
		c.mon.Record(selfmon.Event{
			Status:     selfmon.StatusOK,
			Stage:      selfmon.StageParser,
			Action:     "parse_" + string(proto),
			PID:        procInfo.PID,
			Comm:       procInfo.Comm,
			DurationMs: in.DurationMs,
			Bytes:      len(reqDecoded) + len(respDecoded),
			Detail:     map[string]any{"host": in.Host, "path": in.Path, "http_status": in.HTTPStatus},
		})
	}

	c.handleReassembledEvent(ev)
	return ev, true, nil
}

func (c *Collector) handleReassembledEvent(ev *model.TraceEvent) {
	c.correlator.Correlate(ev)
	_, _ = c.store.SaveEvent(ev)
}

func (c *Collector) ingestFromSource(pid, tid int, connID string, dir parser.Direction, payload []byte, tlsMode string) {
	c.IngestRawChunk(pid, tid, connID, dir, payload, tlsMode)
}

func (c *Collector) recordOutOfScopeDrop(pid int, procInfo model.ProcessInfo, tlsMode string, nBytes int) {
	if c.mon == nil {
		return
	}
	now := time.Now()
	c.dropRateMu.Lock()
	if c.dropRateByPID == nil {
		c.dropRateByPID = make(map[int]*pidDropRateState)
	}
	st, ok := c.dropRateByPID[pid]
	if !ok {
		st = &pidDropRateState{}
		c.dropRateByPID[pid] = st
	}
	if procInfo.Comm != "" {
		st.comm = procInfo.Comm
	}
	if procInfo.Exe != "" {
		st.exe = procInfo.Exe
	}
	if tlsMode != "" {
		st.tlsMode = tlsMode
	}
	if !st.lastEmit.IsZero() && now.Sub(st.lastEmit) < outOfScopeDropRateWindow {
		st.suppressedCount++
		st.suppressedBytes += nBytes
		c.dropRateMu.Unlock()
		return
	}
	droppedCount := 1 + st.suppressedCount
	totalBytes := nBytes + st.suppressedBytes
	comm := st.comm
	exe := st.exe
	mode := st.tlsMode
	st.lastEmit = now
	st.suppressedCount = 0
	st.suppressedBytes = 0
	c.dropRateMu.Unlock()

	c.mon.Record(selfmon.Event{
		Status: selfmon.StatusWarn,
		Stage:  selfmon.StageTracker,
		Action: "ingest_out_of_scope_dropped",
		PID:    pid,
		Comm:   comm,
		Bytes:  totalBytes,
		Error:  "frame from out-of-scope process dropped",
		Detail: map[string]any{
			"pid":           pid,
			"comm":          comm,
			"exe":           exe,
			"tls_mode":      mode,
			"dropped_count": droppedCount,
		},
	})
}

func (c *Collector) flushSuppressedDrops() {
	if c.mon == nil {
		return
	}
	type pendingDrop struct {
		pid   int
		count int
		bytes int
		comm  string
		exe   string
		mode  string
	}
	var pending []pendingDrop
	c.dropRateMu.Lock()
	for pid, st := range c.dropRateByPID {
		if st != nil && st.suppressedCount > 0 {
			pending = append(pending, pendingDrop{
				pid:   pid,
				count: st.suppressedCount,
				bytes: st.suppressedBytes,
				comm:  st.comm,
				exe:   st.exe,
				mode:  st.tlsMode,
			})
			st.suppressedCount = 0
			st.suppressedBytes = 0
			st.lastEmit = time.Now()
		}
	}
	c.dropRateMu.Unlock()

	for _, p := range pending {
		c.mon.Record(selfmon.Event{
			Status: selfmon.StatusWarn,
			Stage:  selfmon.StageTracker,
			Action: "ingest_out_of_scope_dropped",
			PID:    p.pid,
			Comm:   p.comm,
			Bytes:  p.bytes,
			Error:  "frame from out-of-scope process dropped (aggregated)",
			Detail: map[string]any{
				"pid":           p.pid,
				"comm":          p.comm,
				"exe":           p.exe,
				"tls_mode":      p.mode,
				"dropped_count": p.count,
			},
		})
	}
}

func (c *Collector) markUserHookPID(pid int) {
	if pid <= 0 {
		return
	}
	c.mu.Lock()
	c.userHookPIDs[pid] = true
	c.mu.Unlock()
	if c.tracker != nil {
		c.tracker.RecordUserHookPID(pid)
	}
}

func (c *Collector) isUserHookPID(pid int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.userHookPIDs[pid]
}

// Flush synchronously drains any pending frames from registered capture sources.
func (c *Collector) Flush() {
	c.sourcesMu.RLock()
	sources := append([]Source(nil), c.sources...)
	c.sourcesMu.RUnlock()
	for _, src := range sources {
		if flusher, ok := src.(flushableSource); ok {
			flusher.Flush()
		}
	}
	c.flushSuppressedDrops()
}

func (c *Collector) periodicSubtreeRefresh(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.tracker.RefreshSubtree()
			c.ensureHookChannelPermissions(nil)
			if c.AutoInjectLive() {
				c.AutoInjectMatchingPIDs()
			} else {
				c.AnalyzePIDPlans()
			}
		}
	}
}

func (c *Collector) ensureHookChannelPermissions(pids []int) {
	perm, targetUID, hasCross := c.resolveCrossUIDState(pids)

	c.permMu.Lock()
	wasRelaxed := c.channelRelaxed
	prevUID := c.channelTargetUID
	hooksDir := c.hooksDir
	if !hasCross && !wasRelaxed {
		c.permMu.Unlock()
		return
	}
	c.channelRelaxed = hasCross
	c.channelTargetUID = targetUID
	c.permMu.Unlock()

	if hooksDir != "" {
		if hasCross {
			_ = setHooksDirModeNoFollow(hooksDir, 0o711)
		} else {
			_ = setHooksDirModeNoFollow(hooksDir, 0o700)
		}
	}

	if hasCross && wasRelaxed && prevUID == targetUID {
		return
	}

	c.mu.RLock()
	pipePath := c.pipePath
	sockPath := c.sockPath
	c.mu.RUnlock()
	permDenied := false
	if pipePath != "" {
		if err := applyPipePermissionsNoFollow(pipePath, perm, targetUID); errors.Is(err, errCrossUIDPermissionDenied) {
			permDenied = true
		}
	}
	if sockPath != "" {
		if err := applySocketPermissionsNoFollow(sockPath, perm, targetUID); errors.Is(err, errCrossUIDPermissionDenied) {
			permDenied = true
		}
	}
	if permDenied {
		if hooksDir != "" {
			_ = setHooksDirModeNoFollow(hooksDir, 0o700)
		}
		if c.mon != nil {
			c.mon.RecordWarn(
				selfmon.StageProbe,
				"cross_uid_channel_denied",
				"refusing world-readable 0666 mode for cross-UID target; keeping 0600 private channel",
				map[string]any{"target_uid": targetUID, "pipe": pipePath, "sock": sockPath},
			)
		}
	}
}

func (c *Collector) resolveCrossUIDState(extraPIDs []int) (os.FileMode, int, bool) {
	seenPIDs := make(map[int]bool)
	var candidates []int
	addPID := func(pid int) {
		if pid > 0 && !seenPIDs[pid] {
			seenPIDs[pid] = true
			candidates = append(candidates, pid)
		}
	}
	for _, pid := range extraPIDs {
		addPID(pid)
	}
	if c.tracker != nil {
		for _, pid := range c.tracker.GetScope().PIDs {
			addPID(pid)
		}
		for _, pid := range c.tracker.DiscoverMatchingPIDs() {
			addPID(pid)
		}
	}
	c.mu.RLock()
	for pid := range c.liveInjectedPIDs {
		addPID(pid)
	}
	c.mu.RUnlock()

	selfUID := getEffectiveUID()
	if selfUID < 0 {
		return 0o600, -1, false
	}
	crossUIDs := make(map[int]bool)
	var singleUID int
	for _, pid := range candidates {
		uid, ok := lookupProcessUID(pid)
		if !ok || uid < 0 || uid == selfUID {
			continue
		}
		crossUIDs[uid] = true
		singleUID = uid
	}
	switch len(crossUIDs) {
	case 0:
		return 0o600, -1, false
	case 1:
		return 0o600, singleUID, true
	default:
		return 0o600, -2, true
	}
}

func hasCrossUIDTarget(pids []int) bool {
	for _, pid := range pids {
		if isCrossUIDProcess(pid) {
			return true
		}
	}
	return false
}

func isCrossUIDProcess(pid int) bool {
	if pid <= 0 || runtime.GOOS == "windows" {
		return false
	}
	selfUID := getEffectiveUID()
	if selfUID < 0 {
		return false
	}
	uid, ok := lookupProcessUID(pid)
	return ok && uid >= 0 && uid != selfUID
}

func headerValueCI(hdrs map[string]string, key string) string {
	k := strings.ToLower(key)
	for hk, hv := range hdrs {
		if strings.ToLower(hk) == k {
			return hv
		}
	}
	return ""
}

func isShellOrRuntimeBinary(exePath string) bool {
	base := strings.ToLower(filepath.Base(exePath))
	base = strings.TrimSuffix(base, ".exe")
	if strings.HasPrefix(base, "python") ||
		strings.HasPrefix(base, "pypy") ||
		strings.HasPrefix(base, "node") ||
		strings.HasPrefix(base, "bun") ||
		strings.HasPrefix(base, "java") {
		return true
	}
	switch base {
	case "sh", "bash", "dash", "zsh", "fish", "env":
		return true
	default:
		return false
	}
}

func isJavaBinary(exePath string) bool {
	base := strings.ToLower(filepath.Base(exePath))
	base = strings.TrimSuffix(base, ".exe")
	return strings.HasPrefix(base, "java")
}

func setEnvVar(env []string, key, value string) []string {
	out := unsetEnvVar(env, key)
	return append(out, key+"="+value)
}

func unsetEnvVar(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if runtime.GOOS == "windows" {
			if len(kv) >= len(prefix) && strings.EqualFold(kv[:len(prefix)], prefix) {
				continue
			}
		} else if strings.HasPrefix(kv, prefix) {
			continue
		}
		out = append(out, kv)
	}
	return out
}
