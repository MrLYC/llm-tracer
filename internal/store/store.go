package store

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
)

const DefaultHotWindow = 10 * time.Minute

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

type Store struct {
	mu          sync.RWMutex
	baseDir     string
	hotWindow   time.Duration
	sessions    map[string]*model.SessionSummary
	sessionDirs map[string]string
	hotEvents   map[string][]*model.TraceEvent // sessionID -> events in hot window
	subscribers map[chan StreamUpdate]struct{}
	mon         *selfmon.Monitor
	nowFunc     func() time.Time
}

func NewStore(baseDir string, hotWindow time.Duration, mon *selfmon.Monitor) (*Store, error) {
	if hotWindow <= 0 {
		hotWindow = DefaultHotWindow
	}
	sessRoot := filepath.Join(baseDir, "sessions")
	if err := os.MkdirAll(sessRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create sessions dir: %w", err)
	}
	s := &Store{
		baseDir:     baseDir,
		hotWindow:   hotWindow,
		sessions:    make(map[string]*model.SessionSummary),
		sessionDirs: make(map[string]string),
		hotEvents:   make(map[string][]*model.TraceEvent),
		subscribers: make(map[chan StreamUpdate]struct{}),
		mon:         mon,
		nowFunc:     time.Now,
	}
	if err := s.loadIndexAndHotWindow(); err != nil && mon != nil {
		mon.RecordError(selfmon.StageStore, "load_index", err, nil)
	}
	return s, nil
}

func (s *Store) BaseDir() string {
	return s.baseDir
}

func (s *Store) HotWindow() time.Duration {
	return s.hotWindow
}

func (s *Store) SaveEvent(ev *model.TraceEvent) (*model.SessionSummary, error) {
	t0 := time.Now()
	if !ev.HeadersRecorded {
		ev.RequestHeaders = nil
		ev.ResponseHeaders = nil
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
	}

	// Check if event with same ID already exists in hotEvents (streaming -> final update)
	evs := s.hotEvents[ev.SessionID]
	updatedInPlace := false
	for i, existing := range evs {
		if existing.ID == ev.ID {
			evs[i] = ev
			updatedInPlace = true
			break
		}
	}
	if !updatedInPlace {
		s.hotEvents[ev.SessionID] = append(evs, ev)
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
	}

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

	// Recalculate totals from hot events
	var totalTokens int
	var totalDur int64
	var errCount int
	for _, item := range s.hotEvents[ev.SessionID] {
		if item.Chat != nil {
			totalTokens += item.Chat.Usage.TotalTokens
		}
		totalDur += item.DurationMs
		if item.Status == "error" || item.Error != "" {
			errCount++
		}
	}
	if totalTokens > sess.TotalTokens {
		sess.TotalTokens = totalTokens
	}
	sess.TotalDurationMs = totalDur
	sess.ErrorCount = errCount

	sessDir := s.ensureSessionDirLocked(sess)
	sessCopy := *sess
	evCopy := *ev

	subs := make([]chan StreamUpdate, 0, len(s.subscribers))
	for ch := range s.subscribers {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	var err error
	if ev.Status != "streaming" {
		err = s.persistSessionEvent(sessDir, &sessCopy, &evCopy)
	}
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
		case ch <- StreamUpdate{Type: "event", Event: &evCopy, Session: &sessCopy}:
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
		close(ch)
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
		out = append(out, *sess)
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
	cp := *sess
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
	if canUseHotOnly {
		for _, ev := range hotList {
			if ev.Timestamp >= q.From && ev.Timestamp <= q.To {
				eventsCopy = append(eventsCopy, *ev)
			}
		}
	}
	s.mu.RUnlock()

	if !canUseHotOnly && sessDir != "" {
		diskEvs, err := readEventsFile(filepath.Join(sessDir, "events.jsonl"), q.From, q.To)
		if err == nil {
			eventsCopy = diskEvs
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
			return eventsCopy[i].StepIndex < eventsCopy[j].StepIndex
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

// Clean removes cached sessions older than opts.OlderThan (or all if opts.All is true).
func (s *Store) Clean(opts CleanOptions) (CleanReport, error) {
	var report CleanReport
	report.DryRun = opts.DryRun
	if !opts.All && opts.OlderThan <= 0 {
		return report, fmt.Errorf("请指定 --older-than <duration> 或 --all")
	}

	cutoffMs := s.nowFunc().Add(-opts.OlderThan).UnixMilli()
	s.mu.Lock()
	toDeleteIDs := make([]string, 0)
	for id, sess := range s.sessions {
		if opts.All || sess.UpdatedAt < cutoffMs {
			toDeleteIDs = append(toDeleteIDs, id)
		}
	}

	for _, id := range toDeleteIDs {
		dirPath := s.sessionDirs[id]
		if dirPath != "" {
			files, bytesCnt := dirUsage(dirPath)
			report.DeletedFiles += files
			report.FreedBytes += bytesCnt
			report.Paths = append(report.Paths, dirPath)
			if !opts.DryRun {
				_ = os.RemoveAll(dirPath)
			}
		}
		report.DeletedSessions++
		if !opts.DryRun {
			delete(s.sessions, id)
			delete(s.sessionDirs, id)
			delete(s.hotEvents, id)
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

	if !opts.DryRun {
		_ = s.rebuildIndexFile()
	}

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
	dir := filepath.Join(s.baseDir, "sessions", day, sess.ID)
	_ = os.MkdirAll(dir, 0o755)
	s.sessionDirs[sess.ID] = dir
	return dir
}

func (s *Store) persistSessionEvent(sessDir string, sess *model.SessionSummary, ev *model.TraceEvent) error {
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		return err
	}
	// Write session.json metadata snapshot
	metaBytes, err := json.MarshalIndent(sess, "", "  ")
	if err == nil {
		_ = os.WriteFile(filepath.Join(sessDir, "session.json"), metaBytes, 0o644)
	}
	// Append or update events.jsonl
	eventsPath := filepath.Join(sessDir, "events.jsonl")
	f, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	evBytes, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(evBytes, '\n')); err != nil {
		return err
	}

	// Append to index.jsonl when completed
	if ev.Status != "streaming" {
		idxPath := filepath.Join(s.baseDir, "index.jsonl")
		if idxFile, err := os.OpenFile(idxPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
			line, _ := json.Marshal(sess)
			_, _ = idxFile.Write(append(line, '\n'))
			_ = idxFile.Close()
		}
	}
	return nil
}

func (s *Store) rebuildIndexFile() error {
	s.mu.RLock()
	list := make([]*model.SessionSummary, 0, len(s.sessions))
	for _, sess := range s.sessions {
		cp := *sess
		list = append(list, &cp)
	}
	s.mu.RUnlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt < list[j].CreatedAt
	})
	idxPath := filepath.Join(s.baseDir, "index.jsonl")
	f, err := os.OpenFile(idxPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, sess := range list {
		b, err := json.Marshal(sess)
		if err == nil {
			_, _ = f.Write(append(b, '\n'))
		}
	}
	return nil
}

// loadIndexAndHotWindow loads lightweight session summaries from disk, and ONLY loads event payloads for sessions active within hotWindow (default 10m).
func (s *Store) loadIndexAndHotWindow() error {
	sessRoot := filepath.Join(s.baseDir, "sessions")
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
		sessEntries, err := os.ReadDir(dayDir)
		if err != nil {
			continue
		}
		for _, sEnt := range sessEntries {
			if !sEnt.IsDir() {
				continue
			}
			dirPath := filepath.Join(dayDir, sEnt.Name())
			metaBytes, err := os.ReadFile(filepath.Join(dirPath, "session.json"))
			if err != nil {
				continue
			}
			var summary model.SessionSummary
			if err := json.Unmarshal(metaBytes, &summary); err != nil || summary.ID == "" {
				continue
			}
			s.sessions[summary.ID] = &summary
			s.sessionDirs[summary.ID] = dirPath

			// Only pre-load events into memory if updated within the 10-minute hot window
			if summary.UpdatedAt >= hotCutoff {
				evs, err := readEventsFile(filepath.Join(dirPath, "events.jsonl"), hotCutoff, nowMs+1000)
				if err == nil {
					ptrs := make([]*model.TraceEvent, 0, len(evs))
					for i := range evs {
						evCopy := evs[i]
						ptrs = append(ptrs, &evCopy)
					}
					s.hotEvents[summary.ID] = ptrs
				}
			}
		}
	}
	return nil
}

func readEventsFile(path string, fromMs, toMs int64) ([]model.TraceEvent, error) {
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

func truncateRunes(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "..."
}
