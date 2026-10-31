package selfmon

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

	"github.com/google/uuid"
)

type Status string

const (
	StatusOK    Status = "ok"
	StatusWarn  Status = "warn"
	StatusError Status = "error"
)

type Stage string

const (
	StageProbe      Stage = "probe"
	StageTracker    Stage = "tracker"
	StageStream     Stage = "stream"
	StageParser     Stage = "parser"
	StageCorrelator Stage = "correlator"
	StageStore      Stage = "store"
	StageAuth       Stage = "auth"
	StageWeb        Stage = "web"
)

type Event struct {
	ID         string         `json:"id"`
	Timestamp  int64          `json:"ts"` // unix ms
	Status     Status         `json:"status"`
	Stage      Stage          `json:"stage"`
	Action     string         `json:"action"`
	PID        int            `json:"pid,omitempty"`
	Comm       string         `json:"comm,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Bytes      int            `json:"bytes,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type StageMetric struct {
	OK    int64 `json:"ok"`
	Warn  int64 `json:"warn"`
	Error int64 `json:"error"`
}

type Stats struct {
	StartedAt  int64                   `json:"started_at"`
	UptimeMs   int64                   `json:"uptime_ms"`
	TotalOK    int64                   `json:"total_ok"`
	TotalWarn  int64                   `json:"total_warn"`
	TotalError int64                   `json:"total_error"`
	ByStage    map[Stage]*StageMetric  `json:"by_stage"`
	LastError  *Event                  `json:"last_error,omitempty"`
	RecentRate float64                 `json:"recent_events_per_sec"`
}

type Query struct {
	From   int64
	To     int64
	Before int64
	Limit  int
	Status Status
	Stage  Stage
}

type Monitor struct {
	mu          sync.RWMutex
	baseDir     string
	startedAt   time.Time
	hotEvents   []Event
	maxHot      int
	totalOK     int64
	totalWarn   int64
	totalError  int64
	byStage     map[Stage]*StageMetric
	lastError   *Event
	subscribers map[chan Event]struct{}
	nowFunc     func() time.Time
}

func NewMonitor(cacheDir string) (*Monitor, error) {
	selfmonDir := filepath.Join(cacheDir, "selfmon")
	if err := os.MkdirAll(selfmonDir, 0o755); err != nil {
		return nil, fmt.Errorf("create selfmon dir: %w", err)
	}
	m := &Monitor{
		baseDir:     selfmonDir,
		startedAt:   time.Now(),
		hotEvents:   make([]Event, 0, 1024),
		maxHot:      4096,
		byStage:     make(map[Stage]*StageMetric),
		subscribers: make(map[chan Event]struct{}),
		nowFunc:     time.Now,
	}
	_ = m.loadRecentFromDisk(10 * time.Minute)
	return m, nil
}

func (m *Monitor) Record(ev Event) Event {
	m.mu.Lock()
	now := m.nowFunc()
	if ev.ID == "" {
		ev.ID = "sm_" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
	}
	if ev.Timestamp == 0 {
		ev.Timestamp = now.UnixMilli()
	}
	if ev.Status == "" {
		if ev.Error != "" {
			ev.Status = StatusError
		} else {
			ev.Status = StatusOK
		}
	}

	sm, ok := m.byStage[ev.Stage]
	if !ok {
		sm = &StageMetric{}
		m.byStage[ev.Stage] = sm
	}
	switch ev.Status {
	case StatusOK:
		m.totalOK++
		sm.OK++
	case StatusWarn:
		m.totalWarn++
		sm.Warn++
	case StatusError:
		m.totalError++
		sm.Error++
		cp := ev
		m.lastError = &cp
	}

	m.hotEvents = append(m.hotEvents, ev)
	if len(m.hotEvents) > m.maxHot {
		m.hotEvents = append([]Event(nil), m.hotEvents[len(m.hotEvents)-m.maxHot:]...)
	}

	subs := make([]chan Event, 0, len(m.subscribers))
	for ch := range m.subscribers {
		subs = append(subs, ch)
	}
	m.mu.Unlock()

	_ = m.appendDisk(ev)
	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
	return ev
}

func (m *Monitor) RecordOK(stage Stage, action string, detail map[string]any) Event {
	return m.Record(Event{
		Status: StatusOK,
		Stage:  stage,
		Action: action,
		Detail: detail,
	})
}

func (m *Monitor) RecordWarn(stage Stage, action string, warnMsg string, detail map[string]any) Event {
	return m.Record(Event{
		Status: StatusWarn,
		Stage:  stage,
		Action: action,
		Error:  warnMsg,
		Detail: detail,
	})
}

func (m *Monitor) RecordError(stage Stage, action string, err error, detail map[string]any) Event {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	return m.Record(Event{
		Status: StatusError,
		Stage:  stage,
		Action: action,
		Error:  errMsg,
		Detail: detail,
	})
}

func (m *Monitor) Subscribe() (chan Event, func()) {
	ch := make(chan Event, 128)
	m.mu.Lock()
	m.subscribers[ch] = struct{}{}
	m.mu.Unlock()
	return ch, func() {
		m.mu.Lock()
		delete(m.subscribers, ch)
		close(ch)
		m.mu.Unlock()
	}
}

func (m *Monitor) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := m.nowFunc()
	byStageCopy := make(map[Stage]*StageMetric, len(m.byStage))
	for k, v := range m.byStage {
		cp := *v
		byStageCopy[k] = &cp
	}
	var lastErrCopy *Event
	if m.lastError != nil {
		cp := *m.lastError
		lastErrCopy = &cp
	}
	cutoff := now.Add(-60 * time.Second).UnixMilli()
	recentCount := 0
	for i := len(m.hotEvents) - 1; i >= 0; i-- {
		if m.hotEvents[i].Timestamp < cutoff {
			break
		}
		recentCount++
	}
	return Stats{
		StartedAt:  m.startedAt.UnixMilli(),
		UptimeMs:   now.Sub(m.startedAt).Milliseconds(),
		TotalOK:    m.totalOK,
		TotalWarn:  m.totalWarn,
		TotalError: m.totalError,
		ByStage:    byStageCopy,
		LastError:  lastErrCopy,
		RecentRate: float64(recentCount) / 60.0,
	}
}

func (m *Monitor) QueryEvents(q Query) ([]Event, error) {
	nowMs := m.nowFunc().UnixMilli()
	if q.To <= 0 {
		q.To = nowMs + 1000
	}
	if q.Before > 0 && q.Before < q.To {
		q.To = q.Before
	}
	if q.From <= 0 {
		q.From = q.To - int64((10 * time.Minute).Milliseconds())
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}

	m.mu.RLock()
	earliestHot := int64(0)
	if len(m.hotEvents) > 0 {
		earliestHot = m.hotEvents[0].Timestamp
	}
	needDisk := len(m.hotEvents) == 0 || q.From < earliestHot
	hotCopy := make([]Event, len(m.hotEvents))
	copy(hotCopy, m.hotEvents)
	m.mu.RUnlock()

	var source []Event
	if needDisk {
		diskEvents, err := m.readDiskRange(q.From, q.To)
		if err == nil && len(diskEvents) > 0 {
			source = diskEvents
		} else {
			source = hotCopy
		}
	} else {
		source = hotCopy
	}

	matched := make([]Event, 0, 64)
	for _, ev := range source {
		if ev.Timestamp < q.From || ev.Timestamp > q.To {
			continue
		}
		if q.Status != "" && ev.Status != q.Status {
			continue
		}
		if q.Stage != "" && ev.Stage != q.Stage {
			continue
		}
		matched = append(matched, ev)
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Timestamp > matched[j].Timestamp
	})
	if len(matched) > q.Limit {
		matched = matched[:q.Limit]
	}
	return matched, nil
}

func (m *Monitor) appendDisk(ev Event) error {
	day := time.UnixMilli(ev.Timestamp).UTC().Format("2006-01-02")
	path := filepath.Join(m.baseDir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return err
}

func (m *Monitor) loadRecentFromDisk(window time.Duration) error {
	now := m.nowFunc()
	from := now.Add(-window).UnixMilli()
	to := now.UnixMilli() + 1000
	events, err := m.readDiskRange(from, to)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range events {
		m.hotEvents = append(m.hotEvents, ev)
		sm, ok := m.byStage[ev.Stage]
		if !ok {
			sm = &StageMetric{}
			m.byStage[ev.Stage] = sm
		}
		switch ev.Status {
		case StatusOK:
			m.totalOK++
			sm.OK++
		case StatusWarn:
			m.totalWarn++
			sm.Warn++
		case StatusError:
			m.totalError++
			sm.Error++
			cp := ev
			m.lastError = &cp
		}
	}
	if len(m.hotEvents) > m.maxHot {
		m.hotEvents = m.hotEvents[len(m.hotEvents)-m.maxHot:]
	}
	return nil
}

func (m *Monitor) readDiskRange(fromMs, toMs int64) ([]Event, error) {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		dayStr := strings.TrimSuffix(ent.Name(), ".jsonl")
		if dayTime, err := time.Parse("2006-01-02", dayStr); err == nil {
			dayStart := dayTime.UTC().UnixMilli()
			dayEnd := dayTime.UTC().Add(24 * time.Hour).UnixMilli()
			if dayEnd < fromMs || dayStart > toMs {
				continue
			}
		}
		path := filepath.Join(m.baseDir, ent.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var ev Event
			if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
				continue
			}
			if ev.Timestamp >= fromMs && ev.Timestamp <= toMs {
				out = append(out, ev)
			}
		}
		_ = f.Close()
	}
	return out, nil
}
