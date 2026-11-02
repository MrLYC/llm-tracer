package collector

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type rootLifecycle struct {
	pid       int
	startedAt time.Time
	exitedAt  time.Time
}

// procKey uniquely identifies a process instance by its OS PID and start timestamp.
// Keying caches by (pid, startTime) prevents stale cache hits after OS PID reuse.
type procKey struct {
	pid       int
	startTime uint64
}

type ProcessTracker struct {
	mu               sync.RWMutex
	scope            model.ScopeFilter
	rootPIDs         map[int]bool
	rootStartTimes   map[int]uint64    // rootPID -> startTime observed when registered
	trackedPIDs      map[procKey]int   // (pid, startTime) -> rootPID
	ancestryCache    map[procKey][]int // (pid, startTime) -> [ppid, pppid, ..., rootPID]
	procCache        map[procKey]model.ProcessInfo
	lastSeenStart    map[int]uint64 // pid -> most recent observed startTime
	activeRoots      map[int]rootLifecycle
	mon              *selfmon.Monitor
	watchOnce        sync.Once
	disappearedAt    map[int]time.Time
	disappearedGrace time.Duration
	stopCh           chan struct{}
	stopOnce         sync.Once
}

func NewProcessTracker(scope model.ScopeFilter, mon *selfmon.Monitor) *ProcessTracker {
	pt := &ProcessTracker{
		scope:          scope,
		rootPIDs:       make(map[int]bool),
		rootStartTimes: make(map[int]uint64),
		trackedPIDs:    make(map[procKey]int),
		ancestryCache:  make(map[procKey][]int),
		procCache:      make(map[procKey]model.ProcessInfo),
		lastSeenStart:  make(map[int]uint64),
		activeRoots:    make(map[int]rootLifecycle),
		disappearedAt:  make(map[int]time.Time),
		mon:            mon,
		stopCh:         make(chan struct{}),
	}
	pt.SetScope(scope)
	return pt
}

// inspectLiveIdentity returns the current OS startTime and whether pid is currently alive.
// When a platform cannot read startTime for a live process, startTime is 0 and alive is true
// (explicit conservative fallback: never retain stale cache entries across refreshes).
func inspectLiveIdentity(pid int) (startTime uint64, alive bool) {
	if pid <= 0 {
		return 0, false
	}
	st := readProcessStartTime(pid)
	if st > 0 {
		return st, true
	}
	if readPPID(pid) > 0 {
		return 0, true
	}
	return 0, false
}

func (pt *ProcessTracker) SetDisappearedGrace(d time.Duration) {
	if pt == nil {
		return
	}
	pt.mu.Lock()
	pt.disappearedGrace = d
	pt.mu.Unlock()
}

func (pt *ProcessTracker) evictPIDLocked(pid int) {
	if pt.disappearedAt != nil {
		delete(pt.disappearedAt, pid)
	}
	if prevStart, ok := pt.lastSeenStart[pid]; ok {
		k := procKey{pid: pid, startTime: prevStart}
		delete(pt.trackedPIDs, k)
		delete(pt.ancestryCache, k)
		delete(pt.procCache, k)
		delete(pt.lastSeenStart, pid)
	}
	zeroKey := procKey{pid: pid, startTime: 0}
	delete(pt.trackedPIDs, zeroKey)
	delete(pt.ancestryCache, zeroKey)
	delete(pt.procCache, zeroKey)
	for k := range pt.trackedPIDs {
		if k.pid == pid {
			delete(pt.trackedPIDs, k)
		}
	}
	for k := range pt.ancestryCache {
		if k.pid == pid {
			delete(pt.ancestryCache, k)
		}
	}
	for k := range pt.procCache {
		if k.pid == pid {
			delete(pt.procCache, k)
		}
	}
}

// syncLiveKeyLocked updates the observed startTime for a live PID and evicts any
// cached state from an earlier process generation if the PID was reused.
func (pt *ProcessTracker) syncLiveKeyLocked(pid int, liveStart uint64) procKey {
	if pt.disappearedAt != nil {
		delete(pt.disappearedAt, pid)
	}
	if prevStart, ok := pt.lastSeenStart[pid]; ok && prevStart != liveStart {
		pt.evictPIDLocked(pid)
	} else if liveStart == 0 {
		// Conservative fallback when platform cannot provide startTime:
		// do not trust previously cached ancestry/proc entries from an unknown generation.
		pt.evictPIDLocked(pid)
	}
	if liveStart > 0 {
		pt.lastSeenStart[pid] = liveStart
	}
	if rootStart, isRoot := pt.rootStartTimes[pid]; isRoot && rootStart > 0 && liveStart > 0 && rootStart != liveStart {
		delete(pt.rootPIDs, pid)
		delete(pt.rootStartTimes, pid)
		delete(pt.activeRoots, pid)
	}
	return procKey{pid: pid, startTime: liveStart}
}

// resolveKeyForPID resolves the active (pid, startTime) cache key for pid.
// If pid is alive with a different startTime than previously cached, stale entries are evicted immediately.
// If pid has already exited (not reused by any live process), it falls back to the last cached key
// so in-flight frames from short-lived subprocesses are still accepted before RefreshSubtree eviction.
func (pt *ProcessTracker) resolveKeyForPID(pid int) (procKey, bool, bool) {
	if pid <= 0 {
		return procKey{}, false, false
	}
	liveStart, alive := inspectLiveIdentity(pid)
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if alive {
		k := pt.syncLiveKeyLocked(pid, liveStart)
		return k, true, true
	}
	if lastStart, exists := pt.lastSeenStart[pid]; exists {
		return procKey{pid: pid, startTime: lastStart}, false, true
	}
	zeroKey := procKey{pid: pid, startTime: 0}
	if _, hasAnc := pt.ancestryCache[zeroKey]; hasAnc {
		return zeroKey, false, true
	}
	if _, hasProc := pt.procCache[zeroKey]; hasProc {
		return zeroKey, false, true
	}
	if _, hasTrk := pt.trackedPIDs[zeroKey]; hasTrk {
		return zeroKey, false, true
	}
	return procKey{}, false, false
}

func (pt *ProcessTracker) Close() {
	pt.stopOnce.Do(func() {
		close(pt.stopCh)
	})
}

func (pt *ProcessTracker) ensureSubtreeWatcher() {
	pt.watchOnce.Do(func() {
		go pt.subtreeWatchLoop()
	})
}

func (pt *ProcessTracker) subtreeWatchLoop() {
	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-pt.stopCh:
			return
		case <-ticker.C:
			pt.scanAndCacheSubtreeAncestry()
		}
	}
}

func (pt *ProcessTracker) scanAndCacheSubtreeAncestry() {
	pt.mu.RLock()
	if pt.scope.PIDOnly || len(pt.rootPIDs) == 0 {
		pt.mu.RUnlock()
		return
	}
	roots := make([]int, 0, len(pt.rootPIDs))
	for pid := range pt.rootPIDs {
		roots = append(roots, pid)
	}
	pt.mu.RUnlock()

	for _, root := range roots {
		rootStart, rootAlive := inspectLiveIdentity(root)
		if !rootAlive {
			continue
		}
		pt.mu.Lock()
		_ = pt.syncLiveKeyLocked(root, rootStart)
		stillRoot := pt.rootPIDs[root]
		pt.mu.Unlock()
		if !stillRoot {
			continue
		}

		queue := []int{root}
		visited := map[int]bool{root: true}
		chainByPID := map[int][]int{root: nil}
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			currChain := chainByPID[curr]
			for _, ch := range readTaskChildren(curr) {
				if ch <= 1 || visited[ch] {
					continue
				}
				visited[ch] = true
				chStart, chAlive := inspectLiveIdentity(ch)
				if !chAlive {
					continue
				}
				chChain := make([]int, 0, len(currChain)+1)
				chChain = append(chChain, curr)
				chChain = append(chChain, currChain...)
				chainByPID[ch] = chChain
				queue = append(queue, ch)

				pt.mu.Lock()
				chKey := pt.syncLiveKeyLocked(ch, chStart)
				_, hasAnc := pt.ancestryCache[chKey]
				_, hasProc := pt.procCache[chKey]
				if !hasAnc {
					pt.ancestryCache[chKey] = chChain
				}
				pt.mu.Unlock()
				if !hasProc {
					info := InspectProcess(ch)
					if info.Comm != "" || info.Exe != "" {
						pt.mu.Lock()
						pt.procCache[chKey] = info
						pt.mu.Unlock()
					}
				}
			}
		}
	}
}

func (pt *ProcessTracker) SetScope(scope model.ScopeFilter) {
	pt.mu.Lock()
	pt.scope = scope
	pt.rootPIDs = make(map[int]bool, len(scope.PIDs))
	pt.rootStartTimes = make(map[int]uint64, len(scope.PIDs))
	pt.trackedPIDs = make(map[procKey]int)
	pt.ancestryCache = make(map[procKey][]int)
	pt.procCache = make(map[procKey]model.ProcessInfo)
	pt.lastSeenStart = make(map[int]uint64)
	for _, pid := range scope.PIDs {
		if pid > 0 {
			pt.rootPIDs[pid] = true
			liveStart, _ := inspectLiveIdentity(pid)
			if liveStart > 0 {
				pt.rootStartTimes[pid] = liveStart
				pt.lastSeenStart[pid] = liveStart
			}
			pt.trackedPIDs[procKey{pid: pid, startTime: liveStart}] = pid
		}
	}
	hasRoots := len(pt.rootPIDs) > 0 && !scope.PIDOnly
	pt.mu.Unlock()
	if hasRoots {
		pt.ensureSubtreeWatcher()
	}
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
	liveStart, _ := inspectLiveIdentity(pid)
	now := time.Now()
	pt.mu.Lock()
	if !containsInt(pt.scope.PIDs, pid) {
		pt.scope.PIDs = append(pt.scope.PIDs, pid)
	}
	pt.rootPIDs[pid] = true
	if liveStart > 0 {
		pt.rootStartTimes[pid] = liveStart
	}
	rootKey := pt.syncLiveKeyLocked(pid, liveStart)
	pt.trackedPIDs[rootKey] = pid
	pt.activeRoots[pid] = rootLifecycle{
		pid:       pid,
		startedAt: now,
	}
	if info.PID > 0 {
		pt.procCache[rootKey] = info
	}
	hasRoots := !pt.scope.PIDOnly
	pt.mu.Unlock()
	if hasRoots {
		pt.ensureSubtreeWatcher()
	}

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

// MarkRootExited marks the end of a launched root process's execution after final source drain.
func (pt *ProcessTracker) MarkRootExited(pid int) {
	pt.mu.Lock()
	if lc, ok := pt.activeRoots[pid]; ok {
		lc.exitedAt = time.Now()
		pt.activeRoots[pid] = lc
	}
	pt.mu.Unlock()
}

// RecordUserHookPID caches the live ancestor chain of a PID observed on a user-space hook channel,
// or attributes an already-exited PID to an active launched root whose lifecycle overlaps the frame arrival.
func (pt *ProcessTracker) RecordUserHookPID(pid int) {
	if pid <= 0 {
		return
	}
	if chain := pt.cacheAncestry(pid); len(chain) > 0 {
		return
	}
	liveStart, alive := inspectLiveIdentity(pid)
	if alive {
		pt.mu.Lock()
		_ = pt.syncLiveKeyLocked(pid, liveStart)
		pt.mu.Unlock()
		return
	}
	now := time.Now()
	pt.mu.Lock()
	defer pt.mu.Unlock()
	if pt.scope.PIDOnly || pt.rootPIDs[pid] {
		return
	}
	if lastStart, ok := pt.lastSeenStart[pid]; ok {
		if existing := pt.ancestryCache[procKey{pid: pid, startTime: lastStart}]; len(existing) > 0 {
			return
		}
	}
	zeroKey := procKey{pid: pid, startTime: 0}
	if existing := pt.ancestryCache[zeroKey]; len(existing) > 0 {
		return
	}
	var matchedRoot int
	for rootPID, lc := range pt.activeRoots {
		if !pt.rootPIDs[rootPID] {
			continue
		}
		if now.Before(lc.startedAt) {
			continue
		}
		if !lc.exitedAt.IsZero() && now.After(lc.exitedAt.Add(500*time.Millisecond)) {
			continue
		}
		matchedRoot = rootPID
		break
	}
	if matchedRoot > 0 {
		pt.lastSeenStart[pid] = 0
		pt.ancestryCache[zeroKey] = []int{matchedRoot}
	}
}

func (pt *ProcessTracker) cacheAncestry(pid int) []int {
	if pid <= 1 {
		return nil
	}
	key, alive, ok := pt.resolveKeyForPID(pid)
	if ok {
		pt.mu.RLock()
		if existing, has := pt.ancestryCache[key]; has && len(existing) > 0 {
			out := make([]int, len(existing))
			copy(out, existing)
			pt.mu.RUnlock()
			return out
		}
		pt.mu.RUnlock()
	}
	if !alive {
		return nil
	}

	var chain []int
	curr := pid
	for depth := 0; depth < 16 && curr > 1; depth++ {
		ppid := readPPID(curr)
		if ppid <= 0 || ppid == curr {
			if curr != pid {
				if tailKey, _, tailOK := pt.resolveKeyForPID(curr); tailOK {
					pt.mu.RLock()
					tail := pt.ancestryCache[tailKey]
					pt.mu.RUnlock()
					if len(tail) > 0 {
						chain = append(chain, tail...)
					}
				}
			}
			break
		}
		chain = append(chain, ppid)
		curr = ppid
	}
	if len(chain) == 0 {
		return nil
	}
	pt.mu.Lock()
	if key.startTime > 0 {
		pt.lastSeenStart[pid] = key.startTime
	}
	pt.ancestryCache[key] = chain
	for i := 0; i < len(chain)-1; i++ {
		anc := chain[i]
		if anc <= 1 {
			continue
		}
		ancStart, ancAlive := inspectLiveIdentity(anc)
		if !ancAlive {
			continue
		}
		ancKey := pt.syncLiveKeyLocked(anc, ancStart)
		if len(pt.ancestryCache[ancKey]) == 0 {
			sub := make([]int, len(chain)-(i+1))
			copy(sub, chain[i+1:])
			pt.ancestryCache[ancKey] = sub
		}
	}
	pt.mu.Unlock()
	return chain
}

func (pt *ProcessTracker) lookupCachedAncestryRoot(key procKey) (int, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	chain, ok := pt.ancestryCache[key]
	if !ok || len(chain) == 0 {
		return 0, false
	}
	for _, anc := range chain {
		if pt.rootPIDs[anc] {
			return anc, true
		}
		if ancStart, has := pt.lastSeenStart[anc]; has {
			if root, tracked := pt.trackedPIDs[procKey{pid: anc, startTime: ancStart}]; tracked {
				return root, true
			}
		}
		if root, tracked := pt.trackedPIDs[procKey{pid: anc, startTime: 0}]; tracked {
			return root, true
		}
	}
	return 0, false
}

func (pt *ProcessTracker) pruneDisappearedLocked(ppidMap map[int]int) {
	seenPIDs := make(map[int]struct{})
	for k := range pt.trackedPIDs {
		seenPIDs[k.pid] = struct{}{}
	}
	for k := range pt.ancestryCache {
		seenPIDs[k.pid] = struct{}{}
	}
	for k := range pt.procCache {
		seenPIDs[k.pid] = struct{}{}
	}
	for pid := range pt.lastSeenStart {
		seenPIDs[pid] = struct{}{}
	}

	for pid := range seenPIDs {
		liveStart, alive := inspectLiveIdentity(pid)
		if !alive {
			if pt.disappearedGrace > 0 {
				if pt.disappearedAt == nil {
					pt.disappearedAt = make(map[int]time.Time)
				}
				disAt, seenBefore := pt.disappearedAt[pid]
				if !seenBefore {
					pt.disappearedAt[pid] = time.Now()
					continue
				}
				if time.Since(disAt) < pt.disappearedGrace {
					continue
				}
				delete(pt.disappearedAt, pid)
			}
			pt.evictPIDLocked(pid)
			continue
		}
		if liveStart == 0 {
			// Conservative fallback: evict when platform cannot provide startTime.
			pt.evictPIDLocked(pid)
			continue
		}
		if prevStart, ok := pt.lastSeenStart[pid]; ok && prevStart != liveStart {
			pt.evictPIDLocked(pid)
			pt.lastSeenStart[pid] = liveStart
			continue
		}
		for k := range pt.trackedPIDs {
			if k.pid == pid && k.startTime != liveStart {
				delete(pt.trackedPIDs, k)
			}
		}
		for k := range pt.ancestryCache {
			if k.pid == pid && k.startTime != liveStart {
				delete(pt.ancestryCache, k)
			}
		}
		for k := range pt.procCache {
			if k.pid == pid && k.startTime != liveStart {
				delete(pt.procCache, k)
			}
		}
	}
}

// RefreshSubtree scans /proc to discover all child/descendant processes of rootPIDs when PIDOnly is false.
func (pt *ProcessTracker) RefreshSubtree() []int {
	ppidMap := scanAllPPIDs()
	childrenByPPID := make(map[int][]int)
	for pid, ppid := range ppidMap {
		childrenByPPID[ppid] = append(childrenByPPID[ppid], pid)
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.pruneDisappearedLocked(ppidMap)

	roots := make([]int, 0, len(pt.rootPIDs))
	for pid := range pt.rootPIDs {
		roots = append(roots, pid)
	}
	if len(roots) == 0 {
		return nil
	}
	if pt.scope.PIDOnly {
		var aliveRoots []int
		for _, r := range roots {
			if st, alive := inspectLiveIdentity(r); alive {
				rk := pt.syncLiveKeyLocked(r, st)
				if pt.rootPIDs[r] {
					pt.trackedPIDs[rk] = r
					aliveRoots = append(aliveRoots, r)
				}
			}
		}
		return aliveRoots
	}

	var all []int
	for _, root := range roots {
		rootStart, rootAlive := inspectLiveIdentity(root)
		if !rootAlive {
			continue
		}
		rootKey := pt.syncLiveKeyLocked(root, rootStart)
		if !pt.rootPIDs[root] {
			continue
		}
		queue := []int{root}
		visited := map[int]bool{root: true}
		chainByPID := map[int][]int{root: nil}
		pt.trackedPIDs[rootKey] = root
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			currChain := chainByPID[curr]
			if curr != root {
				chStart, chAlive := inspectLiveIdentity(curr)
				if !chAlive {
					pt.evictPIDLocked(curr)
					continue
				}
				chKey := pt.syncLiveKeyLocked(curr, chStart)
				pt.trackedPIDs[chKey] = root
				if len(currChain) > 0 {
					pt.ancestryCache[chKey] = currChain
				}
			}
			all = append(all, curr)
			for _, ch := range readTaskChildren(curr) {
				if !visited[ch] {
					visited[ch] = true
					chChain := make([]int, 0, len(currChain)+1)
					chChain = append(chChain, curr)
					chChain = append(chChain, currChain...)
					chainByPID[ch] = chChain
					queue = append(queue, ch)
				}
			}
			for _, ch := range childrenByPPID[curr] {
				if !visited[ch] {
					visited[ch] = true
					chChain := make([]int, 0, len(currChain)+1)
					chChain = append(chChain, curr)
					chChain = append(chChain, currChain...)
					chainByPID[ch] = chChain
					queue = append(queue, ch)
				}
			}
		}
	}
	return all
}

// IsInScope reports whether pid is currently within the configured capture scope.
func (pt *ProcessTracker) IsInScope(pid int) bool {
	if pt == nil || pid <= 0 {
		return false
	}
	_, ok := pt.MatchAndEnrich(pid, model.ProcessInfo{PID: pid})
	return ok
}

// MatchAndEnrich checks if a process matches the configured ScopeFilter and returns its enriched ProcessInfo.
func (pt *ProcessTracker) MatchAndEnrich(pid int, hint model.ProcessInfo) (model.ProcessInfo, bool) {
	info := pt.ResolveProcess(pid, hint)
	key, alive, hasKey := pt.resolveKeyForPID(pid)

	pt.mu.RLock()
	scope := pt.scope
	hasPIDFilter := len(pt.rootPIDs) > 0
	inTracked := pt.rootPIDs[pid] && (alive || hasKey)
	if !inTracked && hasKey {
		_, inTracked = pt.trackedPIDs[key]
	}
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

	if matchesAttributes(info, scope) {
		return info, true
	}

	// When PIDOnly is false (default subtree mode), also allow descendant child processes
	// whose ancestor process matches --exe / --cwd / --cmd (stopping before llm-tracer's own PID).
	if !scope.PIDOnly && pid > 0 {
		selfPID := os.Getpid()
		ancestors := pt.cacheAncestry(pid)
		for _, anc := range ancestors {
			if anc <= 1 || anc == selfPID {
				break
			}
			ancInfo := pt.ResolveProcess(anc, model.ProcessInfo{PID: anc})
			if matchesAttributes(ancInfo, scope) {
				return info, true
			}
		}
	}

	return info, false
}

func matchesAttributes(info model.ProcessInfo, scope model.ScopeFilter) bool {
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
			if procExe != "" && (procExe == t || procBase == filepath.Base(t) || strings.Contains(procExe, t)) {
				matchedExe = true
				break
			}
		}
		if !matchedExe {
			return false
		}
	}

	// Check Cwd filter (--cwd)
	if len(scope.Cwds) > 0 {
		matchedCwd := false
		procCwd := filepath.Clean(info.Cwd)
		if resolvedProcCwd, err := filepath.EvalSymlinks(procCwd); err == nil {
			procCwd = filepath.Clean(resolvedProcCwd)
		}
		for _, targetCwd := range scope.Cwds {
			tc := filepath.Clean(strings.TrimSpace(targetCwd))
			if resolvedTargetCwd, err := filepath.EvalSymlinks(tc); err == nil {
				tc = filepath.Clean(resolvedTargetCwd)
			}
			if tc == "" {
				continue
			}
			if info.Cwd != "" && (procCwd == tc || strings.HasPrefix(procCwd, tc+string(filepath.Separator))) {
				matchedCwd = true
				break
			}
		}
		if !matchedCwd {
			return false
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
			return false
		}
	}

	return true
}

// DiscoverMatchingPIDs returns all currently running PIDs on the host that match the active ScopeFilter
// (--pid with optional subtree, --exe/--binary, --cwd, --cmd), excluding llm-tracer's own process.
func (pt *ProcessTracker) DiscoverMatchingPIDs() []int {
	scope := pt.GetScope()
	hasPID := len(scope.PIDs) > 0
	hasAttr := len(scope.Exes) > 0 || len(scope.Cwds) > 0 || len(scope.Cmds) > 0
	if !hasPID && !hasAttr {
		return nil
	}
	selfPID := os.Getpid()

	if hasPID {
		var candidates []int
		if scope.PIDOnly {
			candidates = append(candidates, scope.PIDs...)
		} else {
			candidates = pt.RefreshSubtree()
		}
		seen := make(map[int]bool, len(candidates))
		var out []int
		for _, pid := range candidates {
			if pid <= 0 || seen[pid] {
				continue
			}
			info := InspectProcess(pid)
			if info.Comm == "llm_tracer_ptra" || strings.Contains(info.Exe, "llm_tracer_ptrace") {
				continue
			}
			if _, ok := pt.MatchAndEnrich(pid, model.ProcessInfo{PID: pid}); ok {
				seen[pid] = true
				out = append(out, pid)
			}
		}
		return out
	}

	// Attribute-based process selectors (--exe / --binary, --cwd, --cmd) without explicit --pid
	ppidMap := scanAllPPIDs()
	pt.mu.Lock()
	pt.pruneDisappearedLocked(ppidMap)
	pt.mu.Unlock()

	childrenByPPID := make(map[int][]int)
	for pid, ppid := range ppidMap {
		if ppid == selfPID {
			// Still allow direct test subprocesses matched by attributes, but don't expand selfPID
		}
		childrenByPPID[ppid] = append(childrenByPPID[ppid], pid)
	}

	var matchedRoots []int
	seen := make(map[int]bool)
	for pid := range ppidMap {
		if pid <= 1 || pid == selfPID {
			continue
		}
		liveStart, alive := inspectLiveIdentity(pid)
		if !alive {
			continue
		}
		k := procKey{pid: pid, startTime: liveStart}
		pt.mu.RLock()
		info, cached := pt.procCache[k]
		pt.mu.RUnlock()
		if !cached || (info.Comm == "" && info.Exe == "") {
			info = InspectProcess(pid)
			pt.mu.Lock()
			pt.procCache[k] = info
			pt.mu.Unlock()
		}
		if info.Comm == "llm_tracer_ptra" || strings.Contains(info.Exe, "llm_tracer_ptrace") {
			continue
		}
		if matchesAttributes(info, scope) {
			pt.mu.Lock()
			key := pt.syncLiveKeyLocked(pid, liveStart)
			pt.procCache[key] = info
			pt.mu.Unlock()
			seen[pid] = true
			matchedRoots = append(matchedRoots, pid)
		}
	}

	out := append([]int(nil), matchedRoots...)
	if !scope.PIDOnly && len(matchedRoots) > 0 {
		queue := append([]int(nil), matchedRoots...)
		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]
			for _, ch := range childrenByPPID[curr] {
				if ch > 1 && ch != selfPID && !seen[ch] {
					seen[ch] = true
					out = append(out, ch)
					queue = append(queue, ch)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

func (pt *ProcessTracker) ResolveProcess(pid int, hint model.ProcessInfo) model.ProcessInfo {
	if pid <= 0 {
		return hint
	}
	_ = pt.cacheAncestry(pid)
	key, alive, hasKey := pt.resolveKeyForPID(pid)
	if hasKey {
		pt.mu.RLock()
		cached, ok := pt.procCache[key]
		pt.mu.RUnlock()
		if ok && cached.Comm != "" && (cached.Cwd != "" || !alive) {
			if hint.TLSMode != "" {
				cached.TLSMode = hint.TLSMode
			}
			return cached
		}
	}
	if !alive {
		if hasKey {
			pt.mu.RLock()
			cached, ok := pt.procCache[key]
			pt.mu.RUnlock()
			if ok && (cached.Comm != "" || cached.Exe != "" || cached.Cwd != "") {
				if hint.TLSMode != "" {
					cached.TLSMode = hint.TLSMode
				}
				return cached
			}
		}
		if hint.PID == 0 {
			hint.PID = pid
		}
		return hint
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
	if hasKey && inspected.PID > 0 && (inspected.Comm != "" || inspected.Exe != "" || inspected.Cwd != "") {
		pt.mu.Lock()
		pt.procCache[key] = inspected
		pt.mu.Unlock()
	}
	return inspected
}

func (pt *ProcessTracker) isDescendantOfRoot(pid int) bool {
	_ = pt.cacheAncestry(pid)
	key, alive, hasKey := pt.resolveKeyForPID(pid)
	if !hasKey {
		return false
	}
	if root, ok := pt.lookupCachedAncestryRoot(key); ok {
		pt.mu.Lock()
		_, alreadyTracked := pt.trackedPIDs[key]
		pt.trackedPIDs[key] = root
		info := pt.procCache[key]
		pt.mu.Unlock()
		if !alreadyTracked && pt.mon != nil {
			if info.Comm == "" && alive {
				info = InspectProcess(pid)
			}
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
	if !alive {
		return false
	}
	curr := pid
	for depth := 0; depth < 16 && curr > 1; depth++ {
		currKey, currAlive, currOK := pt.resolveKeyForPID(curr)
		pt.mu.RLock()
		var root int
		var tracked bool
		if currOK && currAlive {
			root, tracked = pt.trackedPIDs[currKey]
		}
		isRoot := currAlive && pt.rootPIDs[curr]
		pt.mu.RUnlock()
		if isRoot {
			pt.mu.Lock()
			pt.trackedPIDs[key] = curr
			pt.mu.Unlock()
			return true
		}
		if tracked {
			pt.mu.Lock()
			pt.trackedPIDs[key] = root
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

// parseProcStatPPIDAndStartTime extracts field 4 (ppid) and field 22 (starttime)
// from a Linux /proc/<pid>/stat line, splitting after the last ')' because field 2 (comm)
// may contain spaces and parentheses.
func parseProcStatPPIDAndStartTime(s string) (int, uint64) {
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0, 0
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 2 {
		return 0, 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	var startTime uint64
	// Field 22 in /proc/<pid>/stat is starttime (index 19 after field 2).
	if len(fields) >= 20 {
		startTime, _ = strconv.ParseUint(fields[19], 10, 64)
	}
	return ppid, startTime
}

func containsInt(list []int, v int) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
