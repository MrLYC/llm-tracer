package collector

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
)

type ProcessTracker struct {
	mu          sync.RWMutex
	scope       model.ScopeFilter
	rootPIDs    map[int]bool
	trackedPIDs map[int]int // pid -> rootPID
	procCache   map[int]model.ProcessInfo
	mon         *selfmon.Monitor
}

func NewProcessTracker(scope model.ScopeFilter, mon *selfmon.Monitor) *ProcessTracker {
	pt := &ProcessTracker{
		scope:       scope,
		rootPIDs:    make(map[int]bool),
		trackedPIDs: make(map[int]int),
		procCache:   make(map[int]model.ProcessInfo),
		mon:         mon,
	}
	pt.SetScope(scope)
	return pt
}

func (pt *ProcessTracker) SetScope(scope model.ScopeFilter) {
	pt.mu.Lock()
	pt.scope = scope
	pt.rootPIDs = make(map[int]bool, len(scope.PIDs))
	pt.trackedPIDs = make(map[int]int)
	for _, pid := range scope.PIDs {
		if pid > 0 {
			pt.rootPIDs[pid] = true
			pt.trackedPIDs[pid] = pid
		}
	}
	pt.mu.Unlock()
	pt.RefreshSubtree()
}

func (pt *ProcessTracker) GetScope() model.ScopeFilter {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.scope
}

// RegisterRootPID adds a root PID (such as a child process spawned via `-- <cmd>`) and immediately tracks it.
func (pt *ProcessTracker) RegisterRootPID(pid int) model.ProcessInfo {
	info := InspectProcess(pid)
	pt.mu.Lock()
	if !containsInt(pt.scope.PIDs, pid) {
		pt.scope.PIDs = append(pt.scope.PIDs, pid)
	}
	pt.rootPIDs[pid] = true
	pt.trackedPIDs[pid] = pid
	if info.PID > 0 {
		pt.procCache[pid] = info
	}
	pt.mu.Unlock()

	pt.RefreshSubtree()
	if pt.mon != nil {
		pt.mon.Record(selfmon.Event{
			Status: selfmon.StatusOK,
			Stage:  selfmon.StageTracker,
			Action: "register_root_pid",
			PID:    pid,
			Comm:   info.Comm,
			Detail: map[string]any{
				"cmdline":  info.Cmdline,
				"exe":      info.Exe,
				"cwd":      info.Cwd,
				"pid_only": pt.scope.PIDOnly,
			},
		})
	}
	return info
}

// RefreshSubtree scans /proc to discover all child/descendant processes of rootPIDs when PIDOnly is false.
func (pt *ProcessTracker) RefreshSubtree() []int {
	pt.mu.RLock()
	roots := make([]int, 0, len(pt.rootPIDs))
	for pid := range pt.rootPIDs {
		roots = append(roots, pid)
	}
	pidOnly := pt.scope.PIDOnly
	pt.mu.RUnlock()

	if len(roots) == 0 {
		return nil
	}
	if pidOnly {
		return roots
	}

	ppidMap := scanAllPPIDs()
	childrenByPPID := make(map[int][]int)
	for pid, ppid := range ppidMap {
		childrenByPPID[ppid] = append(childrenByPPID[ppid], pid)
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()
	var all []int
	for _, root := range roots {
		queue := []int{root}
		visited := map[int]bool{root: true}
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			pt.trackedPIDs[curr] = root
			all = append(all, curr)
			for _, ch := range readTaskChildren(curr) {
				if !visited[ch] {
					visited[ch] = true
					queue = append(queue, ch)
				}
			}
			for _, ch := range childrenByPPID[curr] {
				if !visited[ch] {
					visited[ch] = true
					queue = append(queue, ch)
				}
			}
		}
	}
	return all
}

// MatchAndEnrich checks if a process matches the configured ScopeFilter and returns its enriched ProcessInfo.
func (pt *ProcessTracker) MatchAndEnrich(pid int, hint model.ProcessInfo) (model.ProcessInfo, bool) {
	info := pt.ResolveProcess(pid, hint)
	pt.mu.RLock()
	scope := pt.scope
	hasPIDFilter := len(pt.rootPIDs) > 0
	_, inTracked := pt.trackedPIDs[pid]
	pt.mu.RUnlock()

	if hasPIDFilter && !inTracked {
		if !scope.PIDOnly && pid > 0 {
			if pt.isDescendantOfRoot(pid) {
				inTracked = true
			}
		}
		if !inTracked {
			return info, false
		}
	}

	// Check Exe filter (--exe / --binary)
	if len(scope.Exes) > 0 {
		matchedExe := false
		procExe := strings.ToLower(info.Exe)
		procBase := strings.ToLower(filepath.Base(info.Exe))
		for _, targetExe := range scope.Exes {
			t := strings.ToLower(strings.TrimSpace(targetExe))
			if resolved, err := filepath.EvalSymlinks(targetExe); err == nil {
				t = strings.ToLower(resolved)
			}
			if t == "" {
				continue
			}
			if procExe == t || procBase == filepath.Base(t) || strings.Contains(procExe, t) {
				matchedExe = true
				break
			}
		}
		if !matchedExe {
			return info, false
		}
	}

	// Check Cwd filter (--cwd)
	if len(scope.Cwds) > 0 {
		matchedCwd := false
		procCwd := filepath.Clean(info.Cwd)
		for _, targetCwd := range scope.Cwds {
			tc := filepath.Clean(strings.TrimSpace(targetCwd))
			if tc == "" {
				continue
			}
			if procCwd == tc || strings.HasPrefix(procCwd, tc+string(filepath.Separator)) {
				matchedCwd = true
				break
			}
		}
		if !matchedCwd {
			return info, false
		}
	}

	// Check Cmd/Comm filter (--cmd)
	if len(scope.Cmds) > 0 {
		matchedCmd := false
		haystack := strings.ToLower(info.Comm + " " + info.Cmdline + " " + info.Exe)
		for _, pat := range scope.Cmds {
			pat = strings.ToLower(strings.TrimSpace(pat))
			if pat != "" && strings.Contains(haystack, pat) {
				matchedCmd = true
				break
			}
		}
		if !matchedCmd {
			return info, false
		}
	}

	return info, true
}

func (pt *ProcessTracker) ResolveProcess(pid int, hint model.ProcessInfo) model.ProcessInfo {
	if pid <= 0 {
		return hint
	}
	pt.mu.RLock()
	cached, ok := pt.procCache[pid]
	pt.mu.RUnlock()
	if ok && cached.Comm != "" && cached.Cwd != "" {
		if hint.TLSMode != "" {
			cached.TLSMode = hint.TLSMode
		}
		return cached
	}
	inspected := InspectProcess(pid)
	if inspected.Comm == "" {
		inspected.Comm = hint.Comm
	}
	if inspected.Cmdline == "" {
		inspected.Cmdline = hint.Cmdline
	}
	if inspected.Cwd == "" {
		inspected.Cwd = hint.Cwd
	}
	if inspected.Exe == "" {
		inspected.Exe = hint.Exe
	}
	if hint.TLSMode != "" {
		inspected.TLSMode = hint.TLSMode
	}
	if inspected.PID > 0 {
		pt.mu.Lock()
		pt.procCache[pid] = inspected
		pt.mu.Unlock()
	}
	return inspected
}

func (pt *ProcessTracker) isDescendantOfRoot(pid int) bool {
	curr := pid
	for depth := 0; depth < 16 && curr > 1; depth++ {
		pt.mu.RLock()
		root, tracked := pt.trackedPIDs[curr]
		isRoot := pt.rootPIDs[curr]
		pt.mu.RUnlock()
		if isRoot {
			pt.mu.Lock()
			pt.trackedPIDs[pid] = curr
			pt.mu.Unlock()
			return true
		}
		if tracked {
			pt.mu.Lock()
			pt.trackedPIDs[pid] = root
			pt.mu.Unlock()
			if pt.mon != nil {
				info := InspectProcess(pid)
				pt.mon.Record(selfmon.Event{
					Status: selfmon.StatusOK,
					Stage:  selfmon.StageTracker,
					Action: "track_child_process",
					PID:    pid,
					Comm:   info.Comm,
					Detail: map[string]any{"root_pid": root, "ppid": info.PPID, "cmdline": info.Cmdline},
				})
			}
			return true
		}
		ppid := readPPID(curr)
		if ppid <= 1 || ppid == curr {
			break
		}
		curr = ppid
	}
	return false
}

func InspectProcess(pid int) model.ProcessInfo {
	info := model.ProcessInfo{PID: pid}
	if pid <= 0 {
		return info
	}
	procDir := fmt.Sprintf("/proc/%d", pid)
	if commBytes, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		info.Comm = strings.TrimSpace(string(commBytes))
	}
	if cmdBytes, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil && len(cmdBytes) > 0 {
		parts := bytes.Split(bytes.TrimRight(cmdBytes, "\x00"), []byte{0})
		strs := make([]string, 0, len(parts))
		for _, p := range parts {
			if len(p) > 0 {
				strs = append(strs, string(p))
			}
		}
		info.Cmdline = strings.Join(strs, " ")
	}
	if exe, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		info.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if cwd, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		info.Cwd = cwd
	}
	info.PPID = readPPID(pid)
	return info
}

func readPPID(pid int) int {
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(statBytes)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

func readTaskChildren(pid int) []int {
	var out []int
	tasksDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(tasksDir)
	if err != nil {
		return nil
	}
	for _, ent := range entries {
		b, err := os.ReadFile(filepath.Join(tasksDir, ent.Name(), "children"))
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if ch, err := strconv.Atoi(f); err == nil && ch > 0 {
				out = append(out, ch)
			}
		}
	}
	return out
}

func scanAllPPIDs() map[int]int {
	out := make(map[int]int, 256)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if ppid := readPPID(pid); ppid > 0 {
			out[pid] = ppid
		}
	}
	return out
}

func containsInt(list []int, v int) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
