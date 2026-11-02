package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

const (
	DefaultHotWindow        = 10 * time.Minute
	defaultEvictSweepOps    = 256
	maxSessionTrackedEvents = 4096
	DefaultMaxTrackedEvents = maxSessionTrackedEvents
	DefaultMaxSeenEventIDs  = 65536

	sessionDirPerm  os.FileMode = 0o700
	sessionFilePerm os.FileMode = 0o600
	minSyncInterval             = 50 * time.Millisecond
)

type SessionQuery struct {
	From     int64
	To       int64
	Before   int64
	Limit    int
	Protocol string
	Keyword  string
	PID      int
}

type EventQuery struct {
	SessionID string
	From      int64
	To        int64
	Before    int64
	Limit     int
}

type TimelineBucket struct {
	StartTs int64 `json:"start_ts"`
	EndTs   int64 `json:"end_ts"`
	Count   int   `json:"count"`
}

type TimelineOverview struct {
	MinTs       int64            `json:"min_ts"`
	MaxTs       int64            `json:"max_ts"`
	DefaultFrom int64            `json:"default_from"`
	DefaultTo   int64            `json:"default_to"`
	WindowMs    int64            `json:"window_ms"`
	TotalCount  int              `json:"total_sessions"`
	Buckets     []TimelineBucket `json:"buckets"`
}

type CleanOptions struct {
	OlderThan      time.Duration `json:"older_than"`
	All            bool          `json:"all"`
	DryRun         bool          `json:"dry_run"`
	IncludeSelfmon bool          `json:"include_selfmon"`
}

type CleanReport struct {
	DeletedSessions int      `json:"deleted_sessions"`
	DeletedFiles    int      `json:"deleted_files"`
	FreedBytes      int64    `json:"freed_bytes"`
	DryRun          bool     `json:"dry_run"`
	Paths           []string `json:"paths,omitempty"`
}

type StreamUpdate struct {
	Type    string                `json:"type"` // event | session
	Event   *model.TraceEvent     `json:"event,omitempty"`
	Session *model.SessionSummary `json:"session,omitempty"`
}

type diskSessionMeta struct {
	summary *model.SessionSummary
	dirPath string
}

type eventContribution struct {
	tokens int
	durMs  int64
	errCnt int
}

type lruNode struct {
	id   string
	prev *lruNode
	next *lruNode
}

type lruIDSet struct {
	cap   int
	nodes map[string]*lruNode
	head  *lruNode // most recently used (MRU)
	tail  *lruNode // least recently used (LRU)
}

func newLRUIDSet(capacity int) *lruIDSet {
	return &lruIDSet{
		cap:   capacity,
		nodes: make(map[string]*lruNode),
	}
}

func (l *lruIDSet) len() int {
	if l == nil {
		return 0
	}
	return len(l.nodes)
}

func (l *lruIDSet) contains(id string) bool {
	if l == nil || id == "" {
		return false
	}
	node, ok := l.nodes[id]
	if !ok {
		return false
	}
	l.moveToFront(node)
	return true
}

func (l *lruIDSet) touch(id string) {
	if l == nil || id == "" {
		return
	}
	if node, ok := l.nodes[id]; ok {
		l.moveToFront(node)
		return
	}
	node := &lruNode{id: id}
	l.nodes[id] = node
	l.pushFront(node)
}

func (l *lruIDSet) addWithCap(id string) (string, bool) {
	if l == nil || id == "" {
		return "", false
	}
	if node, ok := l.nodes[id]; ok {
		l.moveToFront(node)
		return "", false
	}
	var evictedID string
	var evicted bool
	if l.cap > 0 {
		for len(l.nodes) >= l.cap && l.tail != nil {
			victim := l.tail
			l.removeNode(victim)
			delete(l.nodes, victim.id)
			evictedID = victim.id
			evicted = true
		}
	}
	node := &lruNode{id: id}
	l.nodes[id] = node
	l.pushFront(node)
	return evictedID, evicted
}

func (l *lruIDSet) popLRU() (string, bool) {
	if l == nil || l.tail == nil {
		return "", false
	}
	victim := l.tail
	l.removeNode(victim)
	delete(l.nodes, victim.id)
	return victim.id, true
}

func (l *lruIDSet) setCap(newCap int) bool {
	if l == nil || newCap <= 0 {
		return false
	}
	l.cap = newCap
	evicted := false
	for len(l.nodes) > l.cap && l.tail != nil {
		victim := l.tail
		l.removeNode(victim)
		delete(l.nodes, victim.id)
		evicted = true
	}
	return evicted
}

func (l *lruIDSet) pushFront(node *lruNode) {
	node.prev = nil
	node.next = l.head
	if l.head != nil {
		l.head.prev = node
	} else {
		l.tail = node
	}
	l.head = node
}

func (l *lruIDSet) removeNode(node *lruNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		l.head = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	} else {
		l.tail = node.prev
	}
	node.prev = nil
	node.next = nil
}

func (l *lruIDSet) moveToFront(node *lruNode) {
	if l.head == node {
		return
	}
	l.removeNode(node)
	l.pushFront(node)
}

type sessionContribTracker struct {
	byID           map[string]eventContribution
	contribLRU     *lruIDSet
	seenIDs        *lruIDSet
	maxContribs    int
	maxSeenIDs     int
	diskLoaded     bool
	overflowed     bool
	seenOverflowed bool
}

func newSessionContribTracker(maxContribs, maxSeenIDs int, diskLoaded bool) *sessionContribTracker {
	if maxContribs <= 0 {
		maxContribs = DefaultMaxTrackedEvents
	}
	if maxSeenIDs <= 0 {
		maxSeenIDs = DefaultMaxSeenEventIDs
	}
	return &sessionContribTracker{
		byID:        make(map[string]eventContribution),
		contribLRU:  newLRUIDSet(maxContribs),
		seenIDs:     newLRUIDSet(maxSeenIDs),
		maxContribs: maxContribs,
		maxSeenIDs:  maxSeenIDs,
		diskLoaded:  diskLoaded,
	}
}

func (t *sessionContribTracker) ensureInit(maxContribs, maxSeenIDs int) {
	if t.maxContribs <= 0 {
		if maxContribs > 0 {
			t.maxContribs = maxContribs
		} else {
			t.maxContribs = DefaultMaxTrackedEvents
		}
	}
	if t.maxSeenIDs <= 0 {
		if maxSeenIDs > 0 {
			t.maxSeenIDs = maxSeenIDs
		} else {
			t.maxSeenIDs = DefaultMaxSeenEventIDs
		}
	}
	if t.byID == nil {
		t.byID = make(map[string]eventContribution)
	}
	if t.contribLRU == nil {
		t.contribLRU = newLRUIDSet(t.maxContribs)
		for id := range t.byID {
			t.contribLRU.touch(id)
		}
	}
	if t.seenIDs == nil {
		t.seenIDs = newLRUIDSet(t.maxSeenIDs)
		for id := range t.byID {
			t.seenIDs.addWithCap(id)
		}
	}
}

func (t *sessionContribTracker) setMaxContribs(max int) {
	if max <= 0 {
		max = DefaultMaxTrackedEvents
	}
	t.ensureInit(max, t.maxSeenIDs)
	t.maxContribs = max
	t.contribLRU.cap = max
	for len(t.byID) > t.maxContribs {
		victimID, ok := t.contribLRU.popLRU()
		if !ok {
			for k := range t.byID {
				delete(t.byID, k)
				break
			}
			break
		}
		delete(t.byID, victimID)
		t.overflowed = true
	}
}

func (t *sessionContribTracker) setMaxSeenIDs(max int) {
	if max <= 0 {
		max = DefaultMaxSeenEventIDs
	}
	t.ensureInit(t.maxContribs, max)
	t.maxSeenIDs = max
	if t.seenIDs.setCap(max) {
		t.seenOverflowed = true
		t.overflowed = true
	}
}

type Store struct {
	mu                     sync.RWMutex
	baseDir                string
	hotWindow              time.Duration
	readOnly               bool
	sessions               map[string]*model.SessionSummary
	sessionDirs            map[string]string
	hotEvents              map[string][]*model.TraceEvent // sessionID -> events in hot window
	sessionContribs        map[string]*sessionContribTracker
	maxTrackedEvents       int
	maxSeenEventIDs        int
	lastSyncNs             map[string]int64
	dirtySyncDirs          map[string]string
	atomicBeforeRenameHook func(tmpPath string) error
	subscribers            map[chan StreamUpdate]struct{}
	mon                    *selfmon.Monitor
	nowFunc                func() time.Time
	opsSinceEvict          int
	lastEvictMs            int64
	stopCh                 chan struct{}
	closeOnce              sync.Once
}

func NewStore(baseDir string, hotWindow time.Duration, mon *selfmon.Monitor) (*Store, error) {
	return newStore(baseDir, hotWindow, mon, false)
}

// OpenReadOnly opens an existing cache directory in strictly read-only mode:
// it never creates directories, never chmods paths, and never deletes .tmp or any other files.
func OpenReadOnly(baseDir string, hotWindow time.Duration, mons ...*selfmon.Monitor) (*Store, error) {
	var mon *selfmon.Monitor
	if len(mons) > 0 {
		mon = mons[0]
	}
	return newStore(baseDir, hotWindow, mon, true)
}

func newStore(baseDir string, hotWindow time.Duration, mon *selfmon.Monitor, readOnly bool) (*Store, error) {
	if hotWindow <= 0 {
		hotWindow = DefaultHotWindow
	}
	sessRoot := filepath.Join(baseDir, "sessions")
	if readOnly {
		fi, err := os.Stat(baseDir)
		if err != nil {
			return nil, fmt.Errorf("open cache dir %s: %w", baseDir, err)
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("cache dir %s is not a directory", baseDir)
		}
	} else {
		if fi, err := os.Lstat(sessRoot); err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				// sessRoot is a symlink; do not MkdirAll or chmod target
			} else if !fi.IsDir() {
				return nil, fmt.Errorf("sessions path %s is not a directory", sessRoot)
			} else {
				_ = chmodNoFollow(sessRoot, sessionDirPerm)
			}
		} else {
			if err := os.MkdirAll(sessRoot, sessionDirPerm); err != nil {
				return nil, fmt.Errorf("create sessions dir: %w", err)
			}
			_ = chmodNoFollow(sessRoot, sessionDirPerm)
		}
	}
	now := time.Now()
	s := &Store{
		baseDir:          baseDir,
		hotWindow:        hotWindow,
		readOnly:         readOnly,
		sessions:         make(map[string]*model.SessionSummary),
		sessionDirs:      make(map[string]string),
		hotEvents:        make(map[string][]*model.TraceEvent),
		sessionContribs:  make(map[string]*sessionContribTracker),
		maxTrackedEvents: DefaultMaxTrackedEvents,
		maxSeenEventIDs:  DefaultMaxSeenEventIDs,
		lastSyncNs:       make(map[string]int64),
		dirtySyncDirs:    make(map[string]string),
		subscribers:      make(map[chan StreamUpdate]struct{}),
		mon:              mon,
		nowFunc:          time.Now,
		lastEvictMs:      now.UnixMilli(),
		stopCh:           make(chan struct{}),
	}
	if err := s.loadIndexAndHotWindow(); err != nil && mon != nil {
		mon.RecordError(selfmon.StageStore, "load_index", err, nil)
	}
	evictTick := hotWindow / 2
	if evictTick < 100*time.Millisecond {
		evictTick = 100 * time.Millisecond
	}
	if evictTick > 30*time.Second {
		evictTick = 30 * time.Second
	}
	go s.evictLoop(evictTick)
	return s, nil
}

func (s *Store) evictLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.EvictExpiredHot(s.nowFunc())
		}
	}
}

// Close stops the background eviction goroutine.
// It is safe to call multiple times and optional (daemon-style goroutine won't block process exit).
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		if s.stopCh != nil {
			close(s.stopCh)
		}
	})
	if s.readOnly {
		return nil
	}
	return s.Flush()
}

// Stop is an alias for Close to match daemon component conventions.
func (s *Store) Stop() {
	_ = s.Close()
}

// Flush ensures any pending session.json writes are fsynced to stable storage.
func (s *Store) Flush() error {
	if s.readOnly {
		return nil
	}
	s.mu.Lock()
	dirs := make([]string, 0, len(s.dirtySyncDirs))
	nowNs := time.Now().UnixNano()
	for id, dir := range s.dirtySyncDirs {
		if dir != "" {
			dirs = append(dirs, dir)
			s.lastSyncNs[id] = nowNs
		}
		delete(s.dirtySyncDirs, id)
	}
	s.mu.Unlock()

	var firstErr error
	for _, dir := range dirs {
		if err := syncFilePath(filepath.Join(dir, "session.json")); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// EvictExpiredHot removes non-streaming events with Timestamp < now-hotWindow from hotEvents.
// If a session has no remaining hot events, its hotEvents map entry is deleted while keeping its summary in sessions.
func (s *Store) EvictExpiredHot(now time.Time) int {
	if now.IsZero() {
		now = s.nowFunc()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.evictExpiredHotLocked(now.UnixMilli())
}

func shouldKeepInHotWindow(ev *model.TraceEvent, cutoffMs int64) bool {
	return ev != nil && (ev.Status == "streaming" || ev.Timestamp >= cutoffMs)
}

func (s *Store) evictExpiredHotLocked(nowMs int64) int {
	cutoffMs := nowMs - s.hotWindow.Milliseconds()
	evicted := 0
	for sessID, evs := range s.hotEvents {
		keptCount := 0
		for _, ev := range evs {
			if shouldKeepInHotWindow(ev, cutoffMs) {
				keptCount++
			}
		}
		if keptCount == 0 {
			evicted += len(evs)
			delete(s.hotEvents, sessID)
			continue
		}
		if keptCount < len(evs) {
			evicted += len(evs) - keptCount
			kept := make([]*model.TraceEvent, 0, keptCount)
			for _, ev := range evs {
				if shouldKeepInHotWindow(ev, cutoffMs) {
					kept = append(kept, ev)
				}
			}
			s.hotEvents[sessID] = kept
		}
	}
	s.lastEvictMs = nowMs
	s.opsSinceEvict = 0
	return evicted
}

func (s *Store) BaseDir() string {
	return s.baseDir
}

func (s *Store) HotWindow() time.Duration {
	return s.hotWindow
}

func (s *Store) ReadOnly() bool {
	return s.readOnly
}

// SetMaxTrackedEvents configures the per-session in-memory eventContribution LRU capacity.
func (s *Store) SetMaxTrackedEvents(max int) {
	if max <= 0 {
		max = DefaultMaxTrackedEvents
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxTrackedEvents = max
	for _, tracker := range s.sessionContribs {
		tracker.setMaxContribs(max)
	}
}

// MaxTrackedEvents returns the per-session in-memory eventContribution LRU capacity.
func (s *Store) MaxTrackedEvents() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxTrackedEvents
}

// SetMaxSeenEventIDs configures the per-session bounded seen-event-ID LRU set capacity.
func (s *Store) SetMaxSeenEventIDs(max int) {
	if max <= 0 {
		max = DefaultMaxSeenEventIDs
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxSeenEventIDs = max
	for _, tracker := range s.sessionContribs {
		tracker.setMaxSeenIDs(max)
	}
}

// MaxSeenEventIDs returns the per-session bounded seen-event-ID LRU set capacity.
func (s *Store) MaxSeenEventIDs() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxSeenEventIDs
}

func (s *Store) SaveEvent(ev *model.TraceEvent) (*model.SessionSummary, error) {
	if s.readOnly {
		return nil, fmt.Errorf("store is read-only")
	}
	t0 := time.Now()
	if !ev.HeadersRecorded {
		ev.RequestHeaders = nil
		ev.ResponseHeaders = nil
	}
	if ev.Process.Cmdline != "" {
		ev.Process.Cmdline = selfmon.RedactCmdline(ev.Process.Cmdline)
	}

	s.mu.Lock()
	sess, exists := s.sessions[ev.SessionID]
	if !exists {
		sess = &model.SessionSummary{
			ID:              ev.SessionID,
			Title:           deriveSessionTitle(ev),
			PrimaryProtocol: ev.Protocol,
			Protocols:       []string{string(ev.Protocol)},
			RootPID:         ev.Process.PID,
			RootComm:        ev.Process.Comm,
			RootCmdline:     ev.Process.Cmdline,
			RootCwd:         ev.Process.Cwd,
			CreatedAt:       ev.Timestamp,
			UpdatedAt:       ev.Timestamp,
			LastStatus:      ev.Status,
		}
		if ev.SystemOne != nil && ev.SystemOne.Goal != "" {
			sess.Goal = ev.SystemOne.Goal
		}
		s.sessions[ev.SessionID] = sess
		s.sessionContribs[ev.SessionID] = newSessionContribTracker(s.maxTrackedEvents, s.maxSeenEventIDs, true)
	}
	tracker := s.ensureSessionContribsLocked(ev.SessionID)
	prevContrib, seenBefore := s.lookupEventContribLocked(ev.SessionID, tracker, ev.ID)

	// Update or append event in hotEvents
	evSnapshot := cloneEventForHot(ev)
	evs := s.hotEvents[ev.SessionID]
	replacedInHot := false
	if seenBefore {
		for i, existing := range evs {
			if existing.ID == ev.ID {
				evs[i] = evSnapshot
				replacedInHot = true
				break
			}
		}
	}
	if !replacedInHot {
		s.hotEvents[ev.SessionID] = append(evs, evSnapshot)
	}

	curContrib := eventContributionFromEvent(ev)
	if !seenBefore {
		sess.EventCount++
		if ev.Protocol == model.ProtocolSystemOne {
			if ev.StepIndex > sess.StepCount {
				sess.StepCount = ev.StepIndex
			} else {
				sess.StepCount++
			}
		} else {
			if ev.TurnIndex > sess.TurnCount {
				sess.TurnCount = ev.TurnIndex
			} else {
				sess.TurnCount++
			}
		}
		sess.TotalTokens += curContrib.tokens
		sess.TotalDurationMs += curContrib.durMs
		sess.ErrorCount += curContrib.errCnt
	} else {
		if ev.Protocol == model.ProtocolSystemOne {
			if ev.StepIndex > sess.StepCount {
				sess.StepCount = ev.StepIndex
			}
		} else {
			if ev.TurnIndex > sess.TurnCount {
				sess.TurnCount = ev.TurnIndex
			}
		}
		sess.TotalTokens += curContrib.tokens - prevContrib.tokens
		if sess.TotalTokens < 0 {
			sess.TotalTokens = 0
		}
		sess.TotalDurationMs += curContrib.durMs - prevContrib.durMs
		if sess.TotalDurationMs < 0 {
			sess.TotalDurationMs = 0
		}
		sess.ErrorCount += curContrib.errCnt - prevContrib.errCnt
		if sess.ErrorCount < 0 {
			sess.ErrorCount = 0
		}
	}
	recordEventContribLocked(tracker, ev.ID, curContrib)

	if ev.Timestamp > sess.UpdatedAt {
		sess.UpdatedAt = ev.Timestamp
	}
	if ev.Timestamp > 0 && (sess.CreatedAt == 0 || ev.Timestamp < sess.CreatedAt) {
		sess.CreatedAt = ev.Timestamp
	}
	sess.LastStatus = ev.Status
	if sess.Goal == "" && ev.SystemOne != nil && ev.SystemOne.Goal != "" {
		sess.Goal = ev.SystemOne.Goal
		sess.Title = deriveSessionTitle(ev)
	}
	if !containsString(sess.Protocols, string(ev.Protocol)) && ev.Protocol != "" {
		sess.Protocols = append(sess.Protocols, string(ev.Protocol))
	}
	modelName := extractEventModel(ev)
	if modelName != "" && !containsString(sess.Models, modelName) {
		sess.Models = append(sess.Models, modelName)
	}

	s.opsSinceEvict++
	nowMs := s.nowFunc().UnixMilli()
	if s.opsSinceEvict >= defaultEvictSweepOps || (s.lastEvictMs > 0 && nowMs-s.lastEvictMs >= s.hotWindow.Milliseconds()) {
		s.evictExpiredHotLocked(nowMs)
	}

	sessDir := s.ensureSessionDirLocked(sess)
	sessCopy := cloneSessionSummary(sess)
	evCopy := cloneEventForHot(evSnapshot)

	var err error
	if ev.Status != "streaming" {
		err = s.persistSessionEvent(sessDir, &sessCopy, evCopy)
	}

	subs := make([]chan StreamUpdate, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()
	if s.mon != nil {
		dur := time.Since(t0).Milliseconds()
		if err != nil {
			s.mon.RecordError(selfmon.StageStore, "save_event", err, map[string]any{
				"session_id": ev.SessionID, "event_id": ev.ID,
			})
		} else if ev.Status != "streaming" {
			s.mon.Record(selfmon.Event{
				Status:     selfmon.StatusOK,
				Stage:      selfmon.StageStore,
				Action:     "save_event",
				PID:        ev.Process.PID,
				Comm:       ev.Process.Comm,
				SessionID:  ev.SessionID,
				DurationMs: dur,
				Bytes:      ev.RequestBytes + ev.ResponseBytes,
				Detail:     map[string]any{"event_id": ev.ID, "protocol": ev.Protocol},
			})
		}
	}

	for _, ch := range subs {
		select {
		case ch <- StreamUpdate{Type: "event", Event: evCopy, Session: &sessCopy}:
		default:
		}
	}
	return &sessCopy, err
}

func (s *Store) Subscribe() (chan StreamUpdate, func()) {
	ch := make(chan StreamUpdate, 256)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()
	return ch, func() {
		s.mu.Lock()
		delete(s.subscribers, ch)
		s.mu.Unlock()
	}
}

// QuerySessions returns sessions active within [From, To].
// By default (when From==0 && To==0 && Before==0), only returns sessions within the last hotWindow (10m).
func (s *Store) QuerySessions(q SessionQuery) ([]model.SessionSummary, error) {
	nowMs := s.nowFunc().UnixMilli()
	if q.To <= 0 {
		q.To = nowMs + 1000
	}
	if q.Before > 0 && q.Before < q.To {
		q.To = q.Before
	}
	if q.From <= 0 {
		q.From = q.To - s.hotWindow.Milliseconds()
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}

	s.mu.RLock()
	out := make([]model.SessionSummary, 0, len(s.sessions))
	kw := strings.ToLower(strings.TrimSpace(q.Keyword))
	protoFilter := strings.ToLower(strings.TrimSpace(q.Protocol))

	for _, sess := range s.sessions {
		if sess.UpdatedAt < q.From || sess.CreatedAt > q.To {
			continue
		}
		if q.PID > 0 && sess.RootPID != q.PID {
			continue
		}
		if protoFilter != "" && protoFilter != "all" {
			matchedProto := strings.ToLower(string(sess.PrimaryProtocol)) == protoFilter
			for _, p := range sess.Protocols {
				if strings.ToLower(p) == protoFilter {
					matchedProto = true
					break
				}
			}
			if !matchedProto {
				continue
			}
		}
		if kw != "" {
			haystack := strings.ToLower(sess.Title + " " + sess.Goal + " " + sess.RootComm + " " + sess.RootCmdline + " " + sess.RootCwd + " " + sess.ID)
			if !strings.Contains(haystack, kw) {
				continue
			}
		}
		out = append(out, cloneSessionSummary(sess))
	}
	s.mu.RUnlock()

	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (s *Store) GetSession(sessionID string) (*model.SessionSummary, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	cp := cloneSessionSummary(sess)
	return &cp, true
}

// QuerySessionEvents returns events for a session within [From, To].
// By default (From==0 && To==0 && Before==0), only loads events within the 10-minute window unless the session itself is being inspected via timeline slider.
func (s *Store) QuerySessionEvents(q EventQuery) ([]model.TraceEvent, error) {
	t0 := time.Now()
	nowMs := s.nowFunc().UnixMilli()
	if q.To <= 0 {
		q.To = nowMs + 1000
	}
	if q.Before > 0 && q.Before < q.To {
		q.To = q.Before
	}
	if q.From <= 0 {
		q.From = q.To - s.hotWindow.Milliseconds()
	}
	if q.Limit <= 0 {
		q.Limit = 500
	}

	s.mu.RLock()
	hotCut := nowMs - s.hotWindow.Milliseconds()
	hotList, hasHot := s.hotEvents[q.SessionID]
	sessDir := s.sessionDirs[q.SessionID]
	canUseHotOnly := hasHot && q.From >= hotCut && len(hotList) > 0
	var eventsCopy []model.TraceEvent
	var hotMatched []model.TraceEvent
	for _, ev := range hotList {
		if ev.Timestamp >= q.From && ev.Timestamp <= q.To {
			cloned := cloneEventForHot(ev)
			if canUseHotOnly {
				eventsCopy = append(eventsCopy, *cloned)
			} else {
				hotMatched = append(hotMatched, *cloned)
			}
		}
	}
	s.mu.RUnlock()

	if !canUseHotOnly && sessDir != "" {
		diskEvs, err := readEventsFile(filepath.Join(sessDir, "events.jsonl"), q.From, q.To)
		if err == nil {
			eventsCopy = diskEvs
		}
		if len(hotMatched) > 0 {
			idxByID := make(map[string]int, len(eventsCopy))
			for i := range eventsCopy {
				idxByID[eventsCopy[i].ID] = i
			}
			for _, hev := range hotMatched {
				if idx, ok := idxByID[hev.ID]; ok {
					eventsCopy[idx] = hev
				} else {
					idxByID[hev.ID] = len(eventsCopy)
					eventsCopy = append(eventsCopy, hev)
				}
			}
		}
		if s.mon != nil {
			s.mon.Record(selfmon.Event{
				Status:     selfmon.StatusOK,
				Stage:      selfmon.StageStore,
				Action:     "lazy_load_events",
				SessionID:  q.SessionID,
				DurationMs: time.Since(t0).Milliseconds(),
				Detail: map[string]any{
					"from": q.From, "to": q.To, "loaded_count": len(eventsCopy),
				},
			})
		}
	}

	sort.Slice(eventsCopy, func(i, j int) bool {
		if eventsCopy[i].Timestamp == eventsCopy[j].Timestamp {
			if eventsCopy[i].StepIndex != eventsCopy[j].StepIndex {
				return eventsCopy[i].StepIndex < eventsCopy[j].StepIndex
			}
			return eventsCopy[i].TurnIndex < eventsCopy[j].TurnIndex
		}
		return eventsCopy[i].Timestamp < eventsCopy[j].Timestamp
	})
	if len(eventsCopy) > q.Limit {
		eventsCopy = eventsCopy[len(eventsCopy)-q.Limit:]
	}
	return eventsCopy, nil
}

func (s *Store) TimelineOverview(bucketCount int) TimelineOverview {
	if bucketCount <= 0 {
		bucketCount = 36
	}
	nowMs := s.nowFunc().UnixMilli()
	defaultFrom := nowMs - s.hotWindow.Milliseconds()

	s.mu.RLock()
	defer s.mu.RUnlock()

	minTs := defaultFrom
	maxTs := nowMs
	for _, sess := range s.sessions {
		if sess.CreatedAt > 0 && sess.CreatedAt < minTs {
			minTs = sess.CreatedAt
		}
		if sess.UpdatedAt > maxTs {
			maxTs = sess.UpdatedAt
		}
	}
	if maxTs <= minTs {
		minTs = maxTs - s.hotWindow.Milliseconds()
	}

	span := maxTs - minTs
	step := span / int64(bucketCount)
	if step <= 0 {
		step = 1000
	}
	buckets := make([]TimelineBucket, bucketCount)
	for i := 0; i < bucketCount; i++ {
		st := minTs + int64(i)*step
		et := st + step
		if i == bucketCount-1 {
			et = maxTs
		}
		buckets[i] = TimelineBucket{StartTs: st, EndTs: et}
	}
	for _, sess := range s.sessions {
		idx := int((sess.UpdatedAt - minTs) / step)
		if idx < 0 {
			idx = 0
		}
		if idx >= bucketCount {
			idx = bucketCount - 1
		}
		buckets[idx].Count += sess.EventCount
	}

	return TimelineOverview{
		MinTs:       minTs,
		MaxTs:       maxTs,
		DefaultFrom: defaultFrom,
		DefaultTo:   nowMs,
		WindowMs:    s.hotWindow.Milliseconds(),
		TotalCount:  len(s.sessions),
		Buckets:     buckets,
	}
}

var knownHookArtifacts = []string{
	"tls.bin",
	"tls.sock",
	"libllmtracer_ssl.c",
	"libllmtracer_ssl.so",
	"libllmtracer_ssl.dylib",
	"llm_tracer_ptrace.c",
	"llm_tracer_ptrace",
	"llm_tracer_java.jar",
	"llm_tracer_ca_bundle.pem",
	"node_hook.cjs",
	filepath.Join("pyhook", "sitecustomize.py"),
}

// Clean removes cached sessions older than opts.OlderThan (or all if opts.All is true).
func (s *Store) Clean(opts CleanOptions) (CleanReport, error) {
	var report CleanReport
	report.DryRun = opts.DryRun
	if !opts.All && opts.OlderThan <= 0 {
		return report, fmt.Errorf("请指定 --older-than <duration> 或 --all")
	}
	if s.readOnly && !opts.DryRun {
		return report, fmt.Errorf("store is read-only")
	}

	cutoffMs := s.nowFunc().Add(-opts.OlderThan).UnixMilli()
	s.mu.Lock()
	toDeleteIDs := make([]string, 0)
	for id, sess := range s.sessions {
		if opts.All || sess.UpdatedAt < cutoffMs {
			toDeleteIDs = append(toDeleteIDs, id)
		}
	}

	sessRoot := filepath.Clean(filepath.Join(s.baseDir, "sessions"))
	for _, id := range toDeleteIDs {
		dirPath := s.sessionDirs[id]
		if dirPath != "" {
			files, bytesCnt := dirUsage(dirPath)
			report.DeletedFiles += files
			report.FreedBytes += bytesCnt
			report.Paths = append(report.Paths, dirPath)
			if !opts.DryRun {
				_ = os.RemoveAll(dirPath)
				if dayDir := filepath.Clean(filepath.Dir(dirPath)); dayDir != sessRoot && dayDir != "." && dayDir != string(filepath.Separator) {
					_ = os.Remove(dayDir)
				}
			}
		}
		report.DeletedSessions++
		if !opts.DryRun {
			delete(s.sessions, id)
			delete(s.sessionDirs, id)
			delete(s.hotEvents, id)
			delete(s.sessionContribs, id)
			delete(s.lastSyncNs, id)
			delete(s.dirtySyncDirs, id)
		}
	}

	if opts.All {
		if !opts.DryRun {
			if dayEntries, err := os.ReadDir(sessRoot); err == nil {
				for _, ent := range dayEntries {
					if ent.IsDir() {
						_ = os.Remove(filepath.Join(sessRoot, ent.Name()))
					}
				}
			}
		}
		hooksDir := filepath.Join(s.baseDir, "hooks")
		if hfi, herr := os.Lstat(hooksDir); herr == nil && hfi.Mode()&os.ModeSymlink == 0 && hfi.IsDir() {
			for _, rel := range knownHookArtifacts {
				p := filepath.Join(hooksDir, rel)
				info, err := os.Lstat(p)
				if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
					continue
				}
				report.DeletedFiles++
				report.FreedBytes += info.Size()
				report.Paths = append(report.Paths, p)
				if !opts.DryRun {
					_ = os.Remove(p)
				}
			}
			if !opts.DryRun {
				_ = os.Remove(filepath.Join(hooksDir, "pyhook", "__pycache__"))
				_ = os.Remove(filepath.Join(hooksDir, "pyhook"))
				_ = os.Remove(hooksDir)
			}
		}
	}

	if opts.IncludeSelfmon {
		selfmonDir := filepath.Join(s.baseDir, "selfmon")
		entries, _ := os.ReadDir(selfmonDir)
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".jsonl") {
				continue
			}
			p := filepath.Join(selfmonDir, ent.Name())
			info, err := ent.Info()
			if err != nil {
				continue
			}
			if opts.All || info.ModTime().UnixMilli() < cutoffMs {
				report.DeletedFiles++
				report.FreedBytes += info.Size()
				report.Paths = append(report.Paths, p)
				if !opts.DryRun {
					_ = os.Remove(p)
				}
			}
		}
	}
	s.mu.Unlock()

	if s.mon != nil {
		s.mon.Record(selfmon.Event{
			Status: selfmon.StatusOK,
			Stage:  selfmon.StageStore,
			Action: "clean_cache",
			Bytes:  int(report.FreedBytes),
			Detail: map[string]any{
				"deleted_sessions": report.DeletedSessions,
				"deleted_files":    report.DeletedFiles,
				"freed_bytes":      report.FreedBytes,
				"dry_run":          report.DryRun,
			},
		})
	}
	return report, nil
}

func (s *Store) ensureSessionDirLocked(sess *model.SessionSummary) string {
	if dir, ok := s.sessionDirs[sess.ID]; ok && dir != "" {
		return dir
	}
	day := time.UnixMilli(sess.CreatedAt).UTC().Format("2006-01-02")
	dayDir := filepath.Join(s.baseDir, "sessions", day)
	dir := filepath.Join(dayDir, sess.ID)
	if !s.readOnly {
		_ = os.MkdirAll(dir, sessionDirPerm)
		_ = chmodNoFollow(dayDir, sessionDirPerm)
		_ = chmodNoFollow(dir, sessionDirPerm)
	}
	s.sessionDirs[sess.ID] = dir
	return dir
}

func (s *Store) persistSessionEvent(sessDir string, sess *model.SessionSummary, ev *model.TraceEvent) error {
	if err := os.MkdirAll(sessDir, sessionDirPerm); err != nil {
		return err
	}
	// Write session.json metadata snapshot atomically (.tmp -> Sync -> Rename) under s.mu lock
	metaBytes, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	nowNs := time.Now().UnixNano()
	lastSync := s.lastSyncNs[sess.ID]
	syncDisk := lastSync == 0 || nowNs-lastSync >= int64(minSyncInterval)
	sessionPath := filepath.Join(sessDir, "session.json")
	if err := writeFileAtomicWithHook(sessionPath, metaBytes, sessionFilePerm, syncDisk, s.atomicBeforeRenameHook); err != nil {
		return err
	}
	if syncDisk {
		s.lastSyncNs[sess.ID] = nowNs
		delete(s.dirtySyncDirs, sess.ID)
	} else {
		s.dirtySyncDirs[sess.ID] = sessDir
	}

	// Append or update events.jsonl
	eventsPath := filepath.Join(sessDir, "events.jsonl")
	f, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, sessionFilePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	evBytes, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	writeBuf := make([]byte, 0, len(evBytes)+2)
	if fi, statErr := f.Stat(); statErr == nil && fi.Size() > 0 {
		var last [1]byte
		if _, rerr := f.ReadAt(last[:], fi.Size()-1); rerr == nil && last[0] != '\n' {
			writeBuf = append(writeBuf, '\n')
		}
	}
	writeBuf = append(writeBuf, evBytes...)
	writeBuf = append(writeBuf, '\n')
	if _, err := f.Write(writeBuf); err != nil {
		return err
	}

	return nil
}

func writeFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	return writeFileAtomicWithHook(targetPath, data, perm, true, nil)
}

func writeFileAtomicWithHook(targetPath string, data []byte, perm os.FileMode, syncDisk bool, beforeRename func(tmpPath string) error) error {
	tmpPath := targetPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_ = f.Chmod(perm)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if syncDisk {
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if beforeRename != nil {
		if err := beforeRename(tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := renameReplace(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func renameReplace(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(dst)
		return os.Rename(src, dst)
	}
	return err
}

func syncFilePath(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, sessionFilePerm)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Store) ensureSessionContribsLocked(sessionID string) *sessionContribTracker {
	tracker, ok := s.sessionContribs[sessionID]
	if !ok {
		tracker = newSessionContribTracker(s.maxTrackedEvents, s.maxSeenEventIDs, false)
		s.sessionContribs[sessionID] = tracker
	} else {
		tracker.ensureInit(s.maxTrackedEvents, s.maxSeenEventIDs)
	}
	if !tracker.diskLoaded {
		if dirPath := s.sessionDirs[sessionID]; dirPath != "" {
			loadContribsFromEventsFile(filepath.Join(dirPath, "events.jsonl"), tracker)
		}
		for _, ev := range s.hotEvents[sessionID] {
			if ev != nil && ev.ID != "" {
				recordEventContribLocked(tracker, ev.ID, eventContributionFromEvent(ev))
			}
		}
		tracker.diskLoaded = true
	}
	return tracker
}

func (s *Store) lookupEventContribLocked(sessionID string, tracker *sessionContribTracker, eventID string) (eventContribution, bool) {
	if eventID == "" || tracker == nil {
		return eventContribution{}, false
	}
	tracker.ensureInit(s.maxTrackedEvents, s.maxSeenEventIDs)
	if c, ok := tracker.byID[eventID]; ok {
		tracker.contribLRU.touch(eventID)
		tracker.seenIDs.touch(eventID)
		return c, true
	}
	// Fast path: if eventID is not in the bounded seen-ID set, it has not been seen before.
	// Skip disk scanning completely for unseen IDs.
	if !tracker.seenIDs.contains(eventID) {
		return eventContribution{}, false
	}
	// Suspected duplicate (hit in seenIDs, but evicted/removed from byID):
	for _, existing := range s.hotEvents[sessionID] {
		if existing != nil && existing.ID == eventID {
			return eventContributionFromEvent(existing), true
		}
	}
	if dirPath := s.sessionDirs[sessionID]; dirPath != "" {
		if c, ok := findEventContribInFile(filepath.Join(dirPath, "events.jsonl"), eventID); ok {
			return c, true
		}
	}
	return eventContribution{}, true
}

func recordEventContribLocked(tracker *sessionContribTracker, eventID string, contrib eventContribution) {
	if eventID == "" || tracker == nil {
		return
	}
	tracker.ensureInit(DefaultMaxTrackedEvents, DefaultMaxSeenEventIDs)
	if _, exists := tracker.byID[eventID]; !exists && len(tracker.byID) >= tracker.maxContribs {
		for len(tracker.byID) >= tracker.maxContribs {
			victimID, ok := tracker.contribLRU.popLRU()
			if !ok {
				for k := range tracker.byID {
					delete(tracker.byID, k)
					break
				}
				break
			}
			delete(tracker.byID, victimID)
		}
		tracker.overflowed = true
	}
	tracker.byID[eventID] = contrib
	tracker.contribLRU.touch(eventID)
	if _, evicted := tracker.seenIDs.addWithCap(eventID); evicted {
		tracker.seenOverflowed = true
		tracker.overflowed = true
	}
}

func eventContributionFromEvent(ev *model.TraceEvent) eventContribution {
	return eventContribution{
		tokens: eventTokens(ev),
		durMs:  eventDuration(ev),
		errCnt: eventErrorCount(ev),
	}
}

// loadIndexAndHotWindow loads lightweight session summaries from disk, and ONLY loads event payloads for sessions active within hotWindow (default 10m).
func (s *Store) loadIndexAndHotWindow() error {
	sessRoot := filepath.Join(s.baseDir, "sessions")
	sessRootIsSymlink := false
	if fi, err := os.Lstat(sessRoot); err != nil {
		return nil
	} else if fi.Mode()&os.ModeSymlink != 0 {
		sessRootIsSymlink = true
	} else if !s.readOnly {
		_ = chmodNoFollow(sessRoot, sessionDirPerm)
	}
	dayEntries, err := os.ReadDir(sessRoot)
	if err != nil {
		return nil
	}
	nowMs := s.nowFunc().UnixMilli()
	hotCutoff := nowMs - s.hotWindow.Milliseconds()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, dayEnt := range dayEntries {
		if !dayEnt.IsDir() {
			continue
		}
		dayDir := filepath.Join(sessRoot, dayEnt.Name())
		if !s.readOnly && !sessRootIsSymlink {
			dayInfo, lerr := os.Lstat(dayDir)
			if lerr != nil || dayInfo.Mode()&os.ModeSymlink != 0 || !dayInfo.IsDir() {
				continue
			}
			_ = chmodNoFollow(dayDir, sessionDirPerm)
		}
		sessEntries, err := os.ReadDir(dayDir)
		if err != nil {
			continue
		}
		for _, sEnt := range sessEntries {
			if !sEnt.IsDir() {
				continue
			}
			dirPath := filepath.Join(dayDir, sEnt.Name())
			if !s.readOnly && !sessRootIsSymlink {
				sInfo, lerr := os.Lstat(dirPath)
				if lerr != nil || sInfo.Mode()&os.ModeSymlink != 0 || !sInfo.IsDir() {
					continue
				}
				migrateSessionDirPermissions(dirPath)
			}
			var summary model.SessionSummary
			metaBytes, err := os.ReadFile(filepath.Join(dirPath, "session.json"))
			needRebuild := err != nil
			if !needRebuild {
				if err := json.Unmarshal(metaBytes, &summary); err != nil || summary.ID == "" {
					needRebuild = true
				}
			}
			eventsPath := filepath.Join(dirPath, "events.jsonl")
			eventsDamaged, validEventCount, eventsExist := inspectAndHealEventsFile(eventsPath, s.readOnly || sessRootIsSymlink)
			if eventsExist && (eventsDamaged || (!needRebuild && summary.EventCount != validEventCount)) {
				needRebuild = true
			}
			if needRebuild {
				rebuilt, rebuildErr := rebuildSummaryFromEvents(eventsPath, sEnt.Name())
				if rebuildErr != nil || rebuilt == nil || rebuilt.ID == "" {
					continue
				}
				summary = *rebuilt
				if !s.readOnly && !sessRootIsSymlink {
					sessionPath := filepath.Join(dirPath, "session.json")
					if lfi, lerr := os.Lstat(sessionPath); os.IsNotExist(lerr) || (lerr == nil && lfi.Mode()&os.ModeSymlink == 0) {
						if b, merr := json.MarshalIndent(&summary, "", "  "); merr == nil {
							_ = writeFileAtomic(sessionPath, b, sessionFilePerm)
						}
					}
				}
			}
			s.sessions[summary.ID] = &summary
			s.sessionDirs[summary.ID] = dirPath
			tracker := newSessionContribTracker(s.maxTrackedEvents, s.maxSeenEventIDs, false)
			s.sessionContribs[summary.ID] = tracker

			// Only pre-load events into memory if updated within the 10-minute hot window
			if summary.UpdatedAt >= hotCutoff {
				evs, err := readEventsFileAndContribs(filepath.Join(dirPath, "events.jsonl"), hotCutoff, nowMs+1000, tracker)
				if err == nil {
					ptrs := make([]*model.TraceEvent, 0, len(evs))
					for i := range evs {
						ptrs = append(ptrs, cloneEventForHot(&evs[i]))
					}
					if len(ptrs) > 0 {
						s.hotEvents[summary.ID] = ptrs
					}
					tracker.diskLoaded = true
				}
			}
		}
	}
	return nil
}

// inspectAndHealEventsFile checks events.jsonl for a torn tail (missing trailing newline)
// or corrupted JSON lines. In read-write mode, it rewrites events.jsonl with only valid
// newline-terminated lines so subsequent loads and tools see a clean file.
func inspectAndHealEventsFile(eventsPath string, readOnly bool) (damaged bool, validUniqueCount int, exists bool) {
	lfi, err := os.Lstat(eventsPath)
	if err != nil || lfi.IsDir() {
		return false, 0, false
	}
	if lfi.Mode()&os.ModeSymlink != 0 {
		readOnly = true
	}
	f, err := os.Open(eventsPath)
	if err != nil {
		return false, 0, false
	}

	reader := bufio.NewReaderSize(f, 64*1024)
	var validLines [][]byte
	seenIDs := make(map[string]struct{})
	noIDCount := 0
	for {
		line, rerr := reader.ReadBytes('\n')
		if len(line) > 0 {
			if line[len(line)-1] != '\n' {
				damaged = true
			}
			trimmed := bytes.TrimRight(line, "\r\n")
			if len(trimmed) == 0 {
				damaged = true
			} else {
				var ev model.TraceEvent
				if uerr := json.Unmarshal(trimmed, &ev); uerr != nil {
					damaged = true
				} else {
					cp := make([]byte, len(trimmed))
					copy(cp, trimmed)
					validLines = append(validLines, cp)
					if ev.ID != "" {
						seenIDs[ev.ID] = struct{}{}
					} else {
						noIDCount++
					}
				}
			}
		}
		if rerr != nil {
			break
		}
	}
	_ = f.Close()

	validUniqueCount = len(seenIDs) + noIDCount
	if damaged && !readOnly {
		var healed bytes.Buffer
		for _, vl := range validLines {
			healed.Write(vl)
			healed.WriteByte('\n')
		}
		_ = writeFileAtomic(eventsPath, healed.Bytes(), sessionFilePerm)
	}
	return damaged, validUniqueCount, true
}

// rebuildSummaryFromEvents reconstructs a SessionSummary from events.jsonl when session.json is missing or corrupted.
func rebuildSummaryFromEvents(eventsPath string, fallbackSessionID string) (*model.SessionSummary, error) {
	f, err := os.Open(eventsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	byID := make(map[string]model.TraceEvent)
	var order []string
	var noIDEvents []model.TraceEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var ev model.TraceEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if ev.ID == "" {
			noIDEvents = append(noIDEvents, ev)
			continue
		}
		if _, exists := byID[ev.ID]; !exists {
			order = append(order, ev.ID)
		}
		byID[ev.ID] = ev
	}
	if len(order) == 0 && len(noIDEvents) == 0 {
		return nil, fmt.Errorf("no valid events in %s", eventsPath)
	}

	var sess *model.SessionSummary
	applyEvent := func(ev *model.TraceEvent) {
		sessID := strings.TrimSpace(ev.SessionID)
		if sessID == "" {
			sessID = strings.TrimSpace(fallbackSessionID)
		}
		if sess == nil {
			sess = &model.SessionSummary{
				ID:              sessID,
				Title:           deriveSessionTitle(ev),
				PrimaryProtocol: ev.Protocol,
				RootPID:         ev.Process.PID,
				RootComm:        ev.Process.Comm,
				RootCmdline:     selfmon.RedactCmdline(ev.Process.Cmdline),
				RootCwd:         ev.Process.Cwd,
				CreatedAt:       ev.Timestamp,
				UpdatedAt:       ev.Timestamp,
				LastStatus:      ev.Status,
			}
			if ev.Protocol != "" {
				sess.Protocols = []string{string(ev.Protocol)}
			}
			if ev.SystemOne != nil && ev.SystemOne.Goal != "" {
				sess.Goal = ev.SystemOne.Goal
			}
		}
		sess.EventCount++
		if ev.Protocol == model.ProtocolSystemOne {
			if ev.StepIndex > sess.StepCount {
				sess.StepCount = ev.StepIndex
			} else {
				sess.StepCount++
			}
		} else {
			if ev.TurnIndex > sess.TurnCount {
				sess.TurnCount = ev.TurnIndex
			} else {
				sess.TurnCount++
			}
		}
		contrib := eventContributionFromEvent(ev)
		sess.TotalTokens += contrib.tokens
		sess.TotalDurationMs += contrib.durMs
		sess.ErrorCount += contrib.errCnt
		if ev.Timestamp > sess.UpdatedAt {
			sess.UpdatedAt = ev.Timestamp
		}
		if ev.Timestamp > 0 && (sess.CreatedAt == 0 || ev.Timestamp < sess.CreatedAt) {
			sess.CreatedAt = ev.Timestamp
		}
		if ev.Status != "" {
			sess.LastStatus = ev.Status
		}
		if sess.RootPID == 0 && ev.Process.PID != 0 {
			sess.RootPID = ev.Process.PID
		}
		if sess.RootComm == "" && ev.Process.Comm != "" {
			sess.RootComm = ev.Process.Comm
		}
		if sess.RootCmdline == "" && ev.Process.Cmdline != "" {
			sess.RootCmdline = selfmon.RedactCmdline(ev.Process.Cmdline)
		}
		if sess.RootCwd == "" && ev.Process.Cwd != "" {
			sess.RootCwd = ev.Process.Cwd
		}
		if sess.Goal == "" && ev.SystemOne != nil && ev.SystemOne.Goal != "" {
			sess.Goal = ev.SystemOne.Goal
			sess.Title = deriveSessionTitle(ev)
		}
		if ev.Protocol != "" && !containsString(sess.Protocols, string(ev.Protocol)) {
			sess.Protocols = append(sess.Protocols, string(ev.Protocol))
		}
		if sess.PrimaryProtocol == "" && ev.Protocol != "" {
			sess.PrimaryProtocol = ev.Protocol
		}
		modelName := extractEventModel(ev)
		if modelName != "" && !containsString(sess.Models, modelName) {
			sess.Models = append(sess.Models, modelName)
		}
	}
	for _, id := range order {
		ev := byID[id]
		applyEvent(&ev)
	}
	for i := range noIDEvents {
		applyEvent(&noIDEvents[i])
	}
	return sess, nil
}

func openFlagNoFollow() int {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "arm64", "arm", "ppc64", "ppc64le":
			return 0x8000
		default:
			return 0x20000
		}
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		return 0x100
	default:
		return 0
	}
}

func chmodNoFollow(path string, perm os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to chmod symlink: %s", path)
	}
	if runtime.GOOS == "windows" {
		return os.Chmod(path, perm)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openFlagNoFollow(), 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(perm)
}

func migrateSessionDirPermissions(dirPath string) {
	fi, err := os.Lstat(dirPath)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return
	}
	_ = chmodNoFollow(dirPath, sessionDirPerm)
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return
	}
	for _, ent := range entries {
		p := filepath.Join(dirPath, ent.Name())
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() {
			continue
		}
		if strings.HasSuffix(ent.Name(), ".tmp") {
			_ = os.Remove(p)
			continue
		}
		_ = chmodNoFollow(p, sessionFilePerm)
	}
}

func readEventsFile(path string, fromMs, toMs int64) ([]model.TraceEvent, error) {
	return readEventsFileAndContribs(path, fromMs, toMs, nil)
}

func readEventsFileAndContribs(path string, fromMs, toMs int64, tracker *sessionContribTracker) ([]model.TraceEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	byID := make(map[string]model.TraceEvent)
	var order []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var ev model.TraceEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if tracker != nil && ev.ID != "" {
			recordEventContribLocked(tracker, ev.ID, eventContributionFromEvent(&ev))
		}
		if ev.Timestamp < fromMs || ev.Timestamp > toMs {
			continue
		}
		if _, exists := byID[ev.ID]; !exists {
			order = append(order, ev.ID)
		}
		byID[ev.ID] = ev
	}
	out := make([]model.TraceEvent, 0, len(order))
	for _, id := range order {
		out = append(out, byID[id])
	}
	return out, nil
}

func loadContribsFromEventsFile(path string, tracker *sessionContribTracker) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var ev model.TraceEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil || ev.ID == "" {
			continue
		}
		recordEventContribLocked(tracker, ev.ID, eventContributionFromEvent(&ev))
	}
}

func findEventContribInFile(path string, targetID string) (eventContribution, bool) {
	f, err := os.Open(path)
	if err != nil {
		return eventContribution{}, false
	}
	defer f.Close()

	var last eventContribution
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var ev model.TraceEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			continue
		}
		if ev.ID == targetID {
			last = eventContributionFromEvent(&ev)
			found = true
		}
	}
	return last, found
}

func dirUsage(path string) (int, int64) {
	var files int
	var bytesCnt int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files++
		if info, err := d.Info(); err == nil {
			bytesCnt += info.Size()
		}
		return nil
	})
	return files, bytesCnt
}

func deriveSessionTitle(ev *model.TraceEvent) string {
	if ev.SystemOne != nil && ev.SystemOne.Goal != "" {
		return truncateRunes(strings.TrimSpace(ev.SystemOne.Goal), 64)
	}
	if ev.Chat != nil {
		for i := len(ev.Chat.Messages) - 1; i >= 0; i-- {
			if ev.Chat.Messages[i].Role == "user" && strings.TrimSpace(ev.Chat.Messages[i].Content) != "" {
				return truncateRunes(strings.TrimSpace(ev.Chat.Messages[i].Content), 64)
			}
		}
	}
	if ev.Process.Comm != "" {
		return fmt.Sprintf("%s (%s)", ev.Process.Comm, ev.Path)
	}
	return fmt.Sprintf("%s %s", ev.Protocol, ev.Path)
}

func extractEventModel(ev *model.TraceEvent) string {
	if ev.SystemOne != nil && ev.SystemOne.Model != "" {
		return ev.SystemOne.Model
	}
	if ev.Chat != nil && ev.Chat.Model != "" {
		return ev.Chat.Model
	}
	return ""
}

func containsString(list []string, target string) bool {
	for _, item := range list {
		if item == target {
			return true
		}
	}
	return false
}

func cloneSessionSummary(sess *model.SessionSummary) model.SessionSummary {
	if sess == nil {
		return model.SessionSummary{}
	}
	cp := *sess
	if sess.Protocols != nil {
		cp.Protocols = append([]string(nil), sess.Protocols...)
	}
	if sess.Models != nil {
		cp.Models = append([]string(nil), sess.Models...)
	}
	return cp
}

// cloneEventForHot performs a full deep copy of TraceEvent (including nested slices and maps)
// so caller mutations on streaming or replayed events never race with hotEvents or subscribers.
func cloneEventForHot(ev *model.TraceEvent) *model.TraceEvent {
	if ev == nil {
		return nil
	}
	cp := *ev
	if ev.RequestHeaders != nil {
		cp.RequestHeaders = cloneStringMap(ev.RequestHeaders)
	}
	if ev.ResponseHeaders != nil {
		cp.ResponseHeaders = cloneStringMap(ev.ResponseHeaders)
	}
	if ev.Chat != nil {
		chatCopy := *ev.Chat
		if ev.Chat.Messages != nil {
			chatCopy.Messages = cloneChatMessages(ev.Chat.Messages)
		}
		if ev.Chat.NewMessages != nil {
			chatCopy.NewMessages = cloneChatMessages(ev.Chat.NewMessages)
		}
		if ev.Chat.ToolCalls != nil {
			chatCopy.ToolCalls = append([]model.ToolCallItem(nil), ev.Chat.ToolCalls...)
		}
		cp.Chat = &chatCopy
	}
	if ev.SystemOne != nil {
		s1Copy := *ev.SystemOne
		if ev.SystemOne.RecentActions != nil {
			s1Copy.RecentActions = make([]map[string]any, len(ev.SystemOne.RecentActions))
			for i, act := range ev.SystemOne.RecentActions {
				s1Copy.RecentActions[i] = cloneAnyMap(act)
			}
		}
		if ev.SystemOne.Questions != nil {
			s1Copy.Questions = make([]model.SystemOneQuestion, len(ev.SystemOne.Questions))
			for i, q := range ev.SystemOne.Questions {
				qCopy := q
				if q.Guides != nil {
					qCopy.Guides = append([]string(nil), q.Guides...)
				}
				if q.OptionOrder != nil {
					qCopy.OptionOrder = append([]string(nil), q.OptionOrder...)
				}
				if q.Options != nil {
					qCopy.Options = cloneStringMap(q.Options)
				}
				if q.Probs != nil {
					qCopy.Probs = make(map[string]float64, len(q.Probs))
					for k, v := range q.Probs {
						qCopy.Probs[k] = v
					}
				}
				s1Copy.Questions[i] = qCopy
			}
		}
		if ev.SystemOne.QuestionsUsed != nil {
			s1Copy.QuestionsUsed = append([]string(nil), ev.SystemOne.QuestionsUsed...)
		}
		cp.SystemOne = &s1Copy
	}
	return &cp
}

func cloneChatMessages(msgs []model.ChatMessage) []model.ChatMessage {
	out := make([]model.ChatMessage, len(msgs))
	for i, m := range msgs {
		mCopy := m
		if m.ToolCalls != nil {
			mCopy.ToolCalls = append([]model.ToolCallItem(nil), m.ToolCalls...)
		}
		out[i] = mCopy
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneAnyValue(v)
	}
	return out
}

func cloneAnyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		return cloneAnyMap(val)
	case []any:
		cp := make([]any, len(val))
		for i := range val {
			cp[i] = cloneAnyValue(val[i])
		}
		return cp
	case []string:
		return append([]string(nil), val...)
	default:
		return v
	}
}

func eventTokens(ev *model.TraceEvent) int {
	if ev != nil && ev.Chat != nil {
		return ev.Chat.Usage.TotalTokens
	}
	return 0
}

func eventDuration(ev *model.TraceEvent) int64 {
	if ev != nil {
		return ev.DurationMs
	}
	return 0
}

func eventErrorCount(ev *model.TraceEvent) int {
	if ev != nil && (ev.Status == "error" || ev.Error != "") {
		return 1
	}
	return 0
}

func truncateRunes(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}
