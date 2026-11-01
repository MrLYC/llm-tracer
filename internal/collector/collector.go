package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/parser"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
)

type Collector struct {
	mu           sync.RWMutex
	cacheDir     string
	sockPath     string
	pipePath     string
	pipeMu       sync.Mutex
	pipeOffset   int64
	preloadPath  string
	runtimeHooks *RuntimeHookPaths
	loopbackTap  *LoopbackTap
	ebpfEngine   *EBPFEngine
	userHookPIDs map[int]bool
	activeTapPID int
	listener     net.Listener
	tracker      *ProcessTracker
	reassembler  *parser.StreamReassembler
	correlator   *correlator.Correlator
	store        *store.Store
	mon          *selfmon.Monitor
	probes       []ProbeTarget
	stopCh       chan struct{}
	stopOnce     sync.Once
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
		cacheDir:     cacheDir,
		userHookPIDs: make(map[int]bool),
		tracker:      tracker,
		correlator:   corr,
		store:        st,
		mon:          mon,
		stopCh:       make(chan struct{}),
	}
	c.reassembler = parser.NewStreamReassembler(scope.RecordHeaders, scope.Hosts, mon, c.handleReassembledEvent)
	return c, nil
}

func (c *Collector) Start(ctx context.Context) error {
	hooksDir := filepath.Join(c.cacheDir, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return err
	}

	// Use a short socket path in /tmp if cacheDir path is long (AF_UNIX 108-byte limit)
	sockPath := filepath.Join(hooksDir, "tls.sock")
	if len(sockPath) > 96 {
		sockPath = filepath.Join(os.TempDir(), fmt.Sprintf("llm-tracer-%d.sock", os.Getpid()))
	}
	pipePath := filepath.Join(hooksDir, "tls.bin")
	_ = os.WriteFile(pipePath, nil, 0o666)

	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err == nil {
		_ = os.Chmod(sockPath, 0o666)
		c.mu.Lock()
		c.sockPath = sockPath
		c.listener = ln
		c.mu.Unlock()
		go c.acceptLoop(ln)
	} else if c.mon != nil {
		c.mon.RecordWarn(selfmon.StageProbe, "listen_unix_sock_fallback_pipe", err.Error(), map[string]any{"pipe": pipePath})
	}
	c.mu.Lock()
	c.pipePath = pipePath
	c.mu.Unlock()

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
				"py_hook":   rtHooks.PyHookDir,
				"node_hook": rtHooks.NodeHookJS,
				"ptrace":    rtHooks.PtraceBin,
			})
		}
	} else if err != nil && c.mon != nil {
		c.mon.RecordWarn(selfmon.StageProbe, "build_runtime_hooks", err.Error(), nil)
	}

	if tap, err := NewLoopbackTap(hooksDir, func(connID string, dir parser.Direction, data []byte) {
		c.mu.RLock()
		pid := c.activeTapPID
		c.mu.RUnlock()
		if pid <= 0 {
			pid = os.Getpid()
		}
		c.IngestRawChunk(pid, pid, connID, dir, data, "loopback_tap")
	}); err == nil {
		c.mu.Lock()
		c.loopbackTap = tap
		c.mu.Unlock()
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "start_loopback_tap", map[string]any{
				"proxy_url": tap.ProxyURL(),
				"ca_bundle": tap.CABundlePath(),
			})
		}
	}

	scope := c.tracker.GetScope()
	probes := ProbeAndRecordTargets(scope.PIDs, scope.Exes, c.mon)
	if eng, err := StartEBPFEngine(probes, c.mon, func(pid, tid int, connID string, dir parser.Direction, payload []byte, mode string) {
		c.mu.RLock()
		alreadyHooked := c.userHookPIDs[pid]
		c.mu.RUnlock()
		if alreadyHooked {
			return
		}
		c.IngestRawChunk(pid, tid, connID, dir, payload, mode)
	}); err == nil && eng != nil {
		c.mu.Lock()
		c.ebpfEngine = eng
		c.mu.Unlock()
		for i := range probes {
			if len(probes[i].Symbols) > 0 {
				probes[i].Attached = eng.Active()
				probes[i].Note = fmt.Sprintf("eBPF kernel engine active (attached=%d)", eng.AttachedCount())
			}
		}
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "start_ebpf_engine", map[string]any{
				"attached_count": eng.AttachedCount(),
			})
		}
	}
	c.mu.Lock()
	c.probes = probes
	c.mu.Unlock()

	go c.tailPipeLoop(ctx, pipePath)
	go c.periodicSubtreeRefresh(ctx)
	return nil
}

func (c *Collector) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		c.mu.RLock()
		ln := c.listener
		sock := c.sockPath
		tap := c.loopbackTap
		ebpf := c.ebpfEngine
		c.mu.RUnlock()
		if ln != nil {
			_ = ln.Close()
		}
		if tap != nil {
			tap.Close()
		}
		if ebpf != nil {
			ebpf.Close()
		}
		if sock != "" {
			_ = os.Remove(sock)
		}
	})
}

func (c *Collector) Probes() []ProbeTarget {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ProbeTarget, len(c.probes))
	copy(out, c.probes)
	return out
}

func (c *Collector) Scope() model.ScopeFilter {
	return c.tracker.GetScope()
}

func (c *Collector) UpdateScope(scope model.ScopeFilter) {
	c.tracker.SetScope(scope)
	c.reassembler.SetScope(scope.RecordHeaders, scope.Hosts)
	probes := ProbeAndRecordTargets(scope.PIDs, scope.Exes, c.mon)
	c.mu.RLock()
	ebpf := c.ebpfEngine
	c.mu.RUnlock()
	if ebpf != nil {
		ebpf.AttachTargets(probes)
	}
	c.mu.Lock()
	c.probes = probes
	c.mu.Unlock()
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
	c.probes = append(c.probes, extra...)
	c.mu.Unlock()
	return extra
}

// LaunchCommand starts a child command (`-- <cmd> [args...]`), immediately registers its PID in the ProcessTracker
// before traffic starts, injects SSL hook env vars for zero-root OpenSSL capture, and waits for completion.
func (c *Collector) LaunchCommand(ctx context.Context, cmdArgs []string) (int, error) {
	if len(cmdArgs) == 0 {
		return 1, fmt.Errorf("empty command")
	}
	binPath, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		if c.mon != nil {
			c.mon.RecordError(selfmon.StageTracker, "launch_command", err, map[string]any{"cmd": cmdArgs})
		}
		return 127, err
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

	// Inspect if target binary is a Go binary for GoTLS uprobe resolution
	if gt, err := InspectGoTLSTarget(binPath); err == nil && gt != nil {
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
	sockPath := c.sockPath
	pipePath := c.pipePath
	preloadPath := c.preloadPath
	rtHooks := c.runtimeHooks
	tap := c.loopbackTap
	c.mu.RUnlock()

	execBin := binPath
	execArgs := cmdArgs[1:]
	if prof != nil && prof.RequiresPtrace && rtHooks != nil && rtHooks.PtraceBin != "" {
		execBin = rtHooks.PtraceBin
		execArgs = append([]string{binPath}, cmdArgs[1:]...)
		if c.mon != nil {
			c.mon.RecordOK(selfmon.StageProbe, "enable_ptrace_syscall_hook", map[string]any{
				"target":    prof.ResolvedELF,
				"link_mode": prof.LinkMode,
				"tls_stack": prof.TLSStack,
			})
		}
	}

	cmd := exec.CommandContext(ctx, execBin, execArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	env := os.Environ()
	if sockPath != "" {
		env = append(env, "LLM_TRACER_SOCK="+sockPath)
	}
	if pipePath != "" {
		env = append(env, "LLM_TRACER_PIPE="+pipePath)
	}
	if preloadPath != "" {
		existingPreload := os.Getenv("LD_PRELOAD")
		if existingPreload != "" {
			env = append(env, "LD_PRELOAD="+preloadPath+":"+existingPreload)
		} else {
			env = append(env, "LD_PRELOAD="+preloadPath)
		}
	}
	if rtHooks != nil {
		if rtHooks.PyHookDir != "" {
			existingPyPath := os.Getenv("PYTHONPATH")
			if existingPyPath != "" {
				env = append(env, "PYTHONPATH="+rtHooks.PyHookDir+":"+existingPyPath)
			} else {
				env = append(env, "PYTHONPATH="+rtHooks.PyHookDir)
			}
		}
		if rtHooks.NodeHookJS != "" {
			reqOpt := "--require " + rtHooks.NodeHookJS
			if existingNodeOpts := os.Getenv("NODE_OPTIONS"); existingNodeOpts != "" {
				env = append(env, "NODE_OPTIONS="+existingNodeOpts+" "+reqOpt)
			} else {
				env = append(env, "NODE_OPTIONS="+reqOpt)
			}
			preloadOpt := "--preload " + rtHooks.NodeHookJS
			if existingBunOpts := os.Getenv("BUN_OPTIONS"); existingBunOpts != "" {
				env = append(env, "BUN_OPTIONS="+existingBunOpts+" "+preloadOpt)
			} else {
				env = append(env, "BUN_OPTIONS="+preloadOpt)
			}
		}
	}
	if prof != nil && prof.RequiresPtrace && tap != nil {
		if os.Getenv("HTTP_PROXY") == "" && os.Getenv("HTTPS_PROXY") == "" {
			env = append(env,
				"HTTPS_PROXY="+tap.ProxyURL(),
				"https_proxy="+tap.ProxyURL(),
				"SSL_CERT_FILE="+tap.CABundlePath(),
				"NODE_EXTRA_CA_CERTS="+tap.CABundlePath(),
			)
			if !CanUsePtrace() {
				env = append(env,
					"HTTP_PROXY="+tap.ProxyURL(),
					"http_proxy="+tap.ProxyURL(),
				)
			}
		}
	}
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
			Detail: map[string]any{"args": cmdArgs, "exe": binPath},
		})
	}

	err = cmd.Wait()
	c.Flush()
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

// IngestRawChunk feeds a raw TLS plaintext frame into scope filtering and stream reassembly.
func (c *Collector) IngestRawChunk(pid int, tid int, connID string, dir parser.Direction, payload []byte, tlsMode string) bool {
	hint := model.ProcessInfo{PID: pid, TID: tid, TLSMode: tlsMode}
	procInfo, matched := c.tracker.MatchAndEnrich(pid, hint)
	if !matched {
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
	if proto == model.ProtocolUnknown && len(scope.Hosts) == 0 {
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

func (c *Collector) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-c.stopCh:
				return
			default:
				continue
			}
		}
		c.handleHookConn(conn)
	}
}

func (c *Collector) handleHookConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var hdr [24]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	magic := binary.NativeEndian.Uint32(hdr[0:4])
	if magic != 0x4c4c4d54 {
		return
	}
	pid := int(binary.NativeEndian.Uint32(hdr[4:8]))
	tid := int(binary.NativeEndian.Uint32(hdr[8:12]))
	sslLow := binary.NativeEndian.Uint32(hdr[12:16])
	dirVal := binary.NativeEndian.Uint32(hdr[16:20])
	payloadLen := binary.NativeEndian.Uint32(hdr[20:24])
	if payloadLen == 0 || payloadLen > 512*1024 {
		return
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	dir := parser.DirWrite
	if dirVal != 0 {
		dir = parser.DirRead
	}
	c.mu.Lock()
	c.userHookPIDs[pid] = true
	c.mu.Unlock()
	connID := fmt.Sprintf("ssl_%x", sslLow)
	c.IngestRawChunk(pid, tid, connID, dir, payload, "openssl_hook")
}

// Flush synchronously drains any pending TLS hook frames from the fallback pipe file.
func (c *Collector) Flush() {
	c.mu.RLock()
	pipePath := c.pipePath
	ebpf := c.ebpfEngine
	c.mu.RUnlock()
	if ebpf != nil {
		ebpf.Flush()
	}
	if pipePath == "" {
		return
	}
	c.drainPipeFile(pipePath)
}

func (c *Collector) drainPipeFile(pipePath string) {
	c.pipeMu.Lock()
	defer c.pipeMu.Unlock()
	f, err := os.Open(pipePath)
	if err != nil {
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() < c.pipeOffset+24 {
		return
	}
	_, _ = f.Seek(c.pipeOffset, io.SeekStart)
	for {
		var hdr [24]byte
		if _, err := io.ReadFull(f, hdr[:]); err != nil {
			break
		}
		magic := binary.NativeEndian.Uint32(hdr[0:4])
		if magic != 0x4c4c4d54 {
			break
		}
		pid := int(binary.NativeEndian.Uint32(hdr[4:8]))
		tid := int(binary.NativeEndian.Uint32(hdr[8:12]))
		sslLow := binary.NativeEndian.Uint32(hdr[12:16])
		dirVal := binary.NativeEndian.Uint32(hdr[16:20])
		payloadLen := binary.NativeEndian.Uint32(hdr[20:24])
		if payloadLen == 0 || payloadLen > 512*1024 {
			break
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			break
		}
		c.pipeOffset += 24 + int64(payloadLen)
		dir := parser.DirWrite
		if dirVal != 0 {
			dir = parser.DirRead
		}
		c.mu.Lock()
		c.userHookPIDs[pid] = true
		c.mu.Unlock()
		connID := fmt.Sprintf("ssl_%x", sslLow)
		c.IngestRawChunk(pid, tid, connID, dir, payload, "openssl_hook")
	}
}

func (c *Collector) tailPipeLoop(ctx context.Context, pipePath string) {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.drainPipeFile(pipePath)
		}
	}
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
		}
	}
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
