package selfmon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

const (
	DefaultWriteQueueSize     = 4096
	DefaultPriorityQueueQuota = 512
	DefaultQueryFlushTimeout  = 200 * time.Millisecond
	maxWriteBatchSize         = 256
	defaultHotWindow          = 10 * time.Minute
)

var ErrFlushTimeout = errors.New("selfmon flush timeout")

var allStages = []Stage{
	StageProbe,
	StageTracker,
	StageStream,
	StageParser,
	StageCorrelator,
	StageStore,
	StageAuth,
	StageWeb,
}

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
	StartedAt       int64                  `json:"started_at"`
	UptimeMs        int64                  `json:"uptime_ms"`
	TotalOK         int64                  `json:"total_ok"`
	TotalWarn       int64                  `json:"total_warn"`
	TotalError      int64                  `json:"total_error"`
	ByStage         map[Stage]*StageMetric `json:"by_stage"`
	LastError       *Event                 `json:"last_error,omitempty"`
	RecentRate      float64                `json:"recent_events_per_sec"`
	DroppedEvents   int64                  `json:"dropped_events"`
	DroppedByStatus map[Status]int64       `json:"dropped_by_status"`
	QueueLength     int                    `json:"queue_length"`
	DiskErrors      int64                  `json:"disk_errors"`
}

type Metrics struct {
	TotalOK         int64                 `json:"total_ok"`
	TotalWarn       int64                 `json:"total_warn"`
	TotalError      int64                 `json:"total_error"`
	ByStage         map[Stage]StageMetric `json:"by_stage"`
	DroppedEvents   int64                 `json:"dropped_events"`
	DroppedByStatus map[Status]int64      `json:"dropped_by_status"`
	QueueLength     int                   `json:"queue_length"`
	QueueCapacity   int                   `json:"queue_capacity"`
	DiskErrors      int64                 `json:"disk_errors"`
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
	mu                sync.RWMutex
	subMu             sync.RWMutex
	baseDir           string
	startedAt         time.Time
	hotEvents         []Event
	maxHot            int
	hotCoveredFrom    int64
	totalOK           int64
	totalWarn         int64
	totalError        int64
	byStage           map[Stage]*StageMetric
	lastError         *Event
	subscribers       map[chan Event]struct{}
	nowFunc           func() time.Time
	writeCh           chan Event
	prioCh            chan Event
	queueCapacity     int
	priorityQuota     int
	flushCh           chan chan error
	stopCh            chan struct{}
	doneCh            chan struct{}
	closeOnce         sync.Once
	closed            atomic.Bool
	droppedEvents     atomic.Int64
	droppedOK         atomic.Int64
	droppedWarn       atomic.Int64
	droppedError      atomic.Int64
	droppedMu         sync.Mutex
	droppedOther      map[Status]int64
	diskErrors        atomic.Int64
	flushCount        atomic.Int64
	reopenCount       atomic.Int64
	queryFlushCount   atomic.Int64
	flushTimeouts     atomic.Int64
	queryFlushTimeout time.Duration
	hookMu            sync.RWMutex
	onFlush           func()
	onWriteBatch      func([]Event)
	errMu             sync.Mutex
	lastWriteErr      error
	curDay            string
	curFile           *os.File
}

func calcPriorityQuota(queueSize int) int {
	if queueSize <= 1 {
		return 0
	}
	if queueSize > DefaultPriorityQueueQuota {
		return DefaultPriorityQueueQuota
	}
	q := queueSize / 8
	if q < 1 {
		q = 1
	}
	return q
}

func NewMonitor(cacheDir string) (*Monitor, error) {
	return newMonitor(cacheDir, DefaultWriteQueueSize, true)
}

func newMonitor(cacheDir string, queueSize int, startWriter bool) (*Monitor, error) {
	if queueSize <= 0 {
		queueSize = DefaultWriteQueueSize
	}
	selfmonDir := filepath.Join(cacheDir, "selfmon")
	if err := os.MkdirAll(selfmonDir, 0o755); err != nil {
		return nil, fmt.Errorf("create selfmon dir: %w", err)
	}
	prioQuota := calcPriorityQuota(queueSize)
	normalCap := queueSize - prioQuota
	now := time.Now()
	m := &Monitor{
		baseDir:           selfmonDir,
		startedAt:         now,
		hotEvents:         make([]Event, 0, 1024),
		maxHot:            4096,
		hotCoveredFrom:    now.Add(-defaultHotWindow).UnixMilli(),
		byStage:           make(map[Stage]*StageMetric),
		subscribers:       make(map[chan Event]struct{}),
		nowFunc:           time.Now,
		writeCh:           make(chan Event, normalCap),
		prioCh:            make(chan Event, prioQuota),
		queueCapacity:     queueSize,
		priorityQuota:     prioQuota,
		flushCh:           make(chan chan error),
		stopCh:            make(chan struct{}),
		doneCh:            make(chan struct{}),
		queryFlushTimeout: DefaultQueryFlushTimeout,
	}
	_ = m.loadRecentFromDisk(defaultHotWindow)
	today := m.nowFunc().UTC().Format("2006-01-02")
	if f, err := m.openDayFile(today); err == nil {
		m.curDay = today
		m.curFile = f
	}
	if startWriter {
		go m.writeLoop()
	}
	return m, nil
}

func (m *Monitor) recordDrop(status Status) {
	m.droppedEvents.Add(1)
	switch status {
	case StatusOK:
		m.droppedOK.Add(1)
	case StatusWarn:
		m.droppedWarn.Add(1)
	case StatusError:
		m.droppedError.Add(1)
	default:
		m.droppedMu.Lock()
		if m.droppedOther == nil {
			m.droppedOther = make(map[Status]int64)
		}
		m.droppedOther[status]++
		m.droppedMu.Unlock()
	}
}

func (m *Monitor) snapshotDroppedByStatus() map[Status]int64 {
	out := map[Status]int64{
		StatusOK:    m.droppedOK.Load(),
		StatusWarn:  m.droppedWarn.Load(),
		StatusError: m.droppedError.Load(),
	}
	m.droppedMu.Lock()
	for k, v := range m.droppedOther {
		out[k] = v
	}
	m.droppedMu.Unlock()
	return out
}

func (m *Monitor) appendHotLocked(ev Event) {
	m.hotEvents = append(m.hotEvents, ev)
	for len(m.hotEvents) > m.maxHot {
		evictIdx := 0
		if m.hotEvents[0].Status != StatusOK {
			for i, e := range m.hotEvents {
				if e.Status == StatusOK {
					evictIdx = i
					break
				}
			}
		}
		evictedTs := m.hotEvents[evictIdx].Timestamp
		if evictedTs+1 > m.hotCoveredFrom {
			m.hotCoveredFrom = evictedTs + 1
		}
		if evictIdx > 0 {
			copy(m.hotEvents[1:evictIdx+1], m.hotEvents[:evictIdx])
		}
		m.hotEvents[0] = Event{}
		m.hotEvents = m.hotEvents[1:]
		if cap(m.hotEvents) > m.maxHot*2 {
			compact := make([]Event, len(m.hotEvents), m.maxHot*2)
			copy(compact, m.hotEvents)
			m.hotEvents = compact
		}
	}
}

func (m *Monitor) Record(ev Event) Event {
	if ev.ID == "" {
		ev.ID = "sm_" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
	}
	if ev.Status == "" {
		if ev.Error != "" {
			ev.Status = StatusError
		} else {
			ev.Status = StatusOK
		}
	}
	ev.Detail = sanitizeDetailMap(ev.Detail)

	m.mu.Lock()
	now := m.nowFunc()
	if ev.Timestamp == 0 {
		ev.Timestamp = now.UnixMilli()
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

	m.appendHotLocked(ev)
	m.mu.Unlock()

	if m.closed.Load() {
		m.recordDrop(ev.Status)
	} else if ev.Status == StatusError || ev.Status == StatusWarn {
		select {
		case m.writeCh <- ev:
		default:
			select {
			case m.prioCh <- ev:
			default:
				m.recordDrop(ev.Status)
			}
		}
	} else {
		select {
		case m.writeCh <- ev:
		default:
			m.recordDrop(ev.Status)
		}
	}

	m.subMu.RLock()
	for ch := range m.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
	m.subMu.RUnlock()

	if ev.Detail != nil {
		ev.Detail = sanitizeDetailMap(ev.Detail)
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
	m.subMu.Lock()
	m.subscribers[ch] = struct{}{}
	m.subMu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			m.subMu.Lock()
			delete(m.subscribers, ch)
			close(ch)
			m.subMu.Unlock()
		})
	}
}

// Flush waits for all events currently queued in the async writer to be persisted to disk.
func (m *Monitor) Flush() error {
	return m.FlushWithTimeout(0)
}

// FlushWithTimeout waits for queued events to be persisted to disk, returning ErrFlushTimeout
// if timeout > 0 and the writer does not finish within the deadline.
func (m *Monitor) FlushWithTimeout(timeout time.Duration) error {
	m.flushCount.Add(1)
	m.hookMu.RLock()
	onFlush := m.onFlush
	m.hookMu.RUnlock()
	if onFlush != nil {
		onFlush()
	}

	select {
	case <-m.doneCh:
		return m.getLastWriteErr()
	default:
	}
	ack := make(chan error, 1)
	if timeout <= 0 {
		select {
		case m.flushCh <- ack:
			return <-ack
		case <-m.doneCh:
			return m.getLastWriteErr()
		}
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case m.flushCh <- ack:
		select {
		case err := <-ack:
			return err
		case <-m.doneCh:
			return m.getLastWriteErr()
		case <-timer.C:
			m.flushTimeouts.Add(1)
			return ErrFlushTimeout
		}
	case <-m.doneCh:
		return m.getLastWriteErr()
	case <-timer.C:
		m.flushTimeouts.Add(1)
		return ErrFlushTimeout
	}
}

// Close stops the background disk writer goroutine after flushing any remaining queued events.
// It is idempotent and safe for concurrent calls.
func (m *Monitor) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		close(m.stopCh)
	})
	<-m.doneCh
	return m.getLastWriteErr()
}

// Stop is an alias for Close to match daemon component conventions.
func (m *Monitor) Stop() {
	_ = m.Close()
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
		StartedAt:       m.startedAt.UnixMilli(),
		UptimeMs:        now.Sub(m.startedAt).Milliseconds(),
		TotalOK:         m.totalOK,
		TotalWarn:       m.totalWarn,
		TotalError:      m.totalError,
		ByStage:         byStageCopy,
		LastError:       lastErrCopy,
		RecentRate:      float64(recentCount) / 60.0,
		DroppedEvents:   m.droppedEvents.Load(),
		DroppedByStatus: m.snapshotDroppedByStatus(),
		QueueLength:     len(m.writeCh) + len(m.prioCh),
		DiskErrors:      m.diskErrors.Load(),
	}
}

// Metrics returns a concurrency-safe, non-blocking snapshot of counters and async writer state.
func (m *Monitor) Metrics() Metrics {
	m.mu.RLock()
	totalOK := m.totalOK
	totalWarn := m.totalWarn
	totalError := m.totalError
	byStage := make(map[Stage]StageMetric, len(allStages)+len(m.byStage))
	for _, st := range allStages {
		byStage[st] = StageMetric{}
	}
	for k, v := range m.byStage {
		if v != nil {
			byStage[k] = *v
		}
	}
	m.mu.RUnlock()

	return Metrics{
		TotalOK:         totalOK,
		TotalWarn:       totalWarn,
		TotalError:      totalError,
		ByStage:         byStage,
		DroppedEvents:   m.droppedEvents.Load(),
		DroppedByStatus: m.snapshotDroppedByStatus(),
		QueueLength:     len(m.writeCh) + len(m.prioCh),
		QueueCapacity:   m.queueCapacity,
		DiskErrors:      m.diskErrors.Load(),
	}
}

// ReopenCount returns the number of times the active daily log file handle was reopened due to missing or replaced files.
func (m *Monitor) ReopenCount() int64 {
	return m.reopenCount.Load()
}

func (m *Monitor) needsDiskForQuery(q Query, hotCoveredFrom int64, hotCopy []Event) bool {
	if q.From >= hotCoveredFrom {
		return false
	}
	if q.To < hotCoveredFrom {
		return true
	}
	// q.From < hotCoveredFrom <= q.To: if the guaranteed-complete hot window suffix
	// [hotCoveredFrom, q.To] already contains at least q.Limit matching events,
	// older events on disk cannot enter the newest q.Limit results.
	matchedInCoveredSuffix := 0
	for _, ev := range hotCopy {
		if ev.Timestamp < hotCoveredFrom || ev.Timestamp > q.To {
			continue
		}
		if q.Status != "" && ev.Status != q.Status {
			continue
		}
		if q.Stage != "" && ev.Stage != q.Stage {
			continue
		}
		matchedInCoveredSuffix++
		if matchedInCoveredSuffix >= q.Limit {
			return false
		}
	}
	return true
}

func (m *Monitor) QueryEvents(q Query) ([]Event, error) {
	m.mu.RLock()
	nowMs := m.nowFunc().UnixMilli()
	timeout := m.queryFlushTimeout
	m.mu.RUnlock()

	if q.To <= 0 {
		q.To = nowMs + 1000
	}
	if q.Before > 0 && q.Before < q.To {
		q.To = q.Before
	}
	if q.From <= 0 {
		q.From = q.To - int64(defaultHotWindow.Milliseconds())
	}
	if q.Limit <= 0 {
		q.Limit = 200
	}

	m.mu.RLock()
	hotCoveredFrom := m.hotCoveredFrom
	hotCopy := make([]Event, len(m.hotEvents))
	copy(hotCopy, m.hotEvents)
	m.mu.RUnlock()

	needDisk := m.needsDiskForQuery(q, hotCoveredFrom, hotCopy)

	var source []Event
	if needDisk {
		if timeout <= 0 {
			timeout = DefaultQueryFlushTimeout
		}
		m.queryFlushCount.Add(1)
		_ = m.FlushWithTimeout(timeout)
		diskEvents, err := m.readDiskRange(q.From, q.To)
		if err == nil && len(diskEvents) > 0 {
			seen := make(map[string]struct{}, len(diskEvents)+len(hotCopy))
			source = make([]Event, 0, len(diskEvents)+len(hotCopy))
			for _, ev := range diskEvents {
				if ev.ID != "" {
					seen[ev.ID] = struct{}{}
				}
				source = append(source, ev)
			}
			for _, ev := range hotCopy {
				if ev.ID != "" {
					if _, ok := seen[ev.ID]; ok {
						continue
					}
					seen[ev.ID] = struct{}{}
				}
				source = append(source, ev)
			}
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

func (m *Monitor) setLastWriteErr(err error) {
	if err == nil {
		return
	}
	m.errMu.Lock()
	m.lastWriteErr = err
	m.errMu.Unlock()
}

func (m *Monitor) getLastWriteErr() error {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	return m.lastWriteErr
}

func (m *Monitor) writeLoop() {
	defer close(m.doneCh)
	batch := make([]Event, 0, maxWriteBatchSize)

	drainAndWrite := func() error {
		var firstErr error
		batch = batch[:0]
		for {
			select {
			case ev := <-m.prioCh:
				batch = append(batch, ev)
			default:
				select {
				case ev := <-m.writeCh:
					batch = append(batch, ev)
				default:
					if len(batch) > 0 {
						if err := m.writeBatchToDisk(batch); err != nil {
							m.setLastWriteErr(err)
							if firstErr == nil {
								firstErr = err
							}
						}
						batch = batch[:0]
					}
					return firstErr
				}
			}
			if len(batch) >= maxWriteBatchSize {
				if err := m.writeBatchToDisk(batch); err != nil {
					m.setLastWriteErr(err)
					if firstErr == nil {
						firstErr = err
					}
				}
				batch = batch[:0]
			}
		}
	}

	fillBatch := func(first Event) {
		batch = append(batch[:0], first)
		for len(batch) < maxWriteBatchSize {
			select {
			case next := <-m.prioCh:
				batch = append(batch, next)
			default:
				select {
				case next := <-m.writeCh:
					batch = append(batch, next)
				default:
					return
				}
			}
		}
	}

	for {
		select {
		case ev := <-m.prioCh:
			fillBatch(ev)
			if err := m.writeBatchToDisk(batch); err != nil {
				m.setLastWriteErr(err)
			}
			batch = batch[:0]
			continue
		default:
		}

		select {
		case ev := <-m.prioCh:
			fillBatch(ev)
			if err := m.writeBatchToDisk(batch); err != nil {
				m.setLastWriteErr(err)
			}
			batch = batch[:0]

		case ev := <-m.writeCh:
			fillBatch(ev)
			if err := m.writeBatchToDisk(batch); err != nil {
				m.setLastWriteErr(err)
			}
			batch = batch[:0]

		case ack := <-m.flushCh:
			err := drainAndWrite()
			if err == nil {
				err = m.getLastWriteErr()
			}
			ack <- err

		case <-m.stopCh:
			_ = drainAndWrite()
			if m.curFile != nil {
				_ = m.curFile.Close()
				m.curFile = nil
			}
			return
		}
	}
}

func (m *Monitor) writeBatchToDisk(batch []Event) error {
	if len(batch) == 0 {
		return nil
	}
	m.hookMu.RLock()
	onWriteBatch := m.onWriteBatch
	m.hookMu.RUnlock()
	if onWriteBatch != nil {
		onWriteBatch(batch)
	}

	type dayChunk struct {
		day            string
		onlyCleanCache bool
		buf            bytes.Buffer
	}
	var chunks []dayChunk
	dayIndex := make(map[string]int, 2)

	for _, ev := range batch {
		ev.Detail = sanitizeDetailMap(ev.Detail)
		data, err := json.Marshal(ev)
		if err != nil {
			m.diskErrors.Add(1)
			continue
		}
		isCleanCache := ev.Stage == StageStore && ev.Action == "clean_cache"
		day := time.UnixMilli(ev.Timestamp).UTC().Format("2006-01-02")
		idx, ok := dayIndex[day]
		if !ok {
			idx = len(chunks)
			dayIndex[day] = idx
			chunks = append(chunks, dayChunk{
				day:            day,
				onlyCleanCache: isCleanCache,
			})
		} else if !isCleanCache {
			chunks[idx].onlyCleanCache = false
		}
		chunks[idx].buf.Write(data)
		chunks[idx].buf.WriteByte('\n')
	}

	var firstErr error
	for i := range chunks {
		if chunks[i].buf.Len() == 0 {
			continue
		}
		if err := m.appendDayBuffer(chunks[i].day, chunks[i].buf.Bytes(), chunks[i].onlyCleanCache); err != nil {
			m.diskErrors.Add(1)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (m *Monitor) openDayFile(day string) (*os.File, error) {
	path := filepath.Join(m.baseDir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil && os.IsNotExist(err) {
		if mkErr := os.MkdirAll(m.baseDir, 0o755); mkErr == nil {
			f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		}
	}
	if err != nil {
		return nil, err
	}
	_ = f.Chmod(0o600)
	return f, nil
}

func (m *Monitor) recordSelfHealWarn(day, expectedPath, reason, warnMsg string) Event {
	ev := Event{
		ID:     "sm_" + strings.ReplaceAll(uuid.NewString()[:12], "-", ""),
		Status: StatusWarn,
		Stage:  StageStore,
		Action: "selfmon_logfile_reopened",
		Error:  warnMsg,
		Detail: sanitizeDetailMap(map[string]any{
			"day":    day,
			"path":   expectedPath,
			"reason": reason,
		}),
	}

	m.mu.Lock()
	ev.Timestamp = m.nowFunc().UnixMilli()
	sm, ok := m.byStage[ev.Stage]
	if !ok {
		sm = &StageMetric{}
		m.byStage[ev.Stage] = sm
	}
	m.totalWarn++
	sm.Warn++
	m.appendHotLocked(ev)
	m.mu.Unlock()

	m.subMu.RLock()
	for ch := range m.subscribers {
		select {
		case ch <- ev:
		default:
		}
	}
	m.subMu.RUnlock()
	return ev
}

func (m *Monitor) appendDayBuffer(day string, data []byte, onlyCleanCache bool) error {
	if m.curDay != day || m.curFile == nil {
		f, err := m.openDayFile(day)
		if err != nil {
			return err
		}
		if m.curFile != nil {
			_ = m.curFile.Close()
		}
		m.curDay = day
		m.curFile = f
	} else {
		expectedPath := filepath.Join(m.baseDir, day+".jsonl")
		pathInfo, statErr := os.Stat(expectedPath)
		curInfo, curErr := m.curFile.Stat()
		missing := statErr != nil
		replaced := !missing && (curErr != nil || !os.SameFile(curInfo, pathInfo))
		if missing || replaced {
			if missing && onlyCleanCache && os.IsNotExist(statErr) {
				_, err := m.curFile.Write(data)
				return err
			}
			f, err := m.openDayFile(day)
			if err != nil {
				return err
			}
			_ = m.curFile.Close()
			m.curDay = day
			m.curFile = f
			m.reopenCount.Add(1)

			reason := "logfile_missing"
			warnMsg := "selfmon log file was removed, reopened"
			if replaced {
				reason = "logfile_replaced"
				warnMsg = "selfmon log file was replaced, reopened"
			}
			reopenEv := m.recordSelfHealWarn(day, expectedPath, reason, warnMsg)
			if reopenLine, mErr := json.Marshal(reopenEv); mErr == nil {
				var combined bytes.Buffer
				combined.Grow(len(reopenLine) + 1 + len(data))
				combined.Write(reopenLine)
				combined.WriteByte('\n')
				combined.Write(data)
				data = combined.Bytes()
			}
		}
	}
	_, err := m.curFile.Write(data)
	return err
}

func (m *Monitor) appendDisk(ev Event) error {
	return m.writeBatchToDisk([]Event{ev})
}

func (m *Monitor) loadRecentFromDisk(window time.Duration) error {
	now := m.nowFunc()
	from := now.Add(-window).UnixMilli()
	to := now.UnixMilli() + 1000
	m.mu.Lock()
	m.hotCoveredFrom = from
	m.mu.Unlock()

	events, err := m.readDiskRange(from, to)
	if err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range events {
		ev.Detail = sanitizeDetailMap(ev.Detail)
		m.appendHotLocked(ev)
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
			ev.Detail = sanitizeDetailMap(ev.Detail)
			if ev.Timestamp >= fromMs && ev.Timestamp <= toMs {
				out = append(out, ev)
			}
		}
		_ = f.Close()
	}
	return out, nil
}

// SensitiveQueryKeys is the canonical shared table of lower-case credential/secret query and parameter keys
// used across selfmon and parser redaction.
var SensitiveQueryKeys = map[string]bool{
	"key":                          true,
	"api_key":                      true,
	"apikey":                       true,
	"x-api-key":                    true,
	"x_api_key":                    true,
	"token":                        true,
	"access_token":                 true,
	"refresh_token":                true,
	"id_token":                     true,
	"session_token":                true,
	"security_token":               true,
	"auth_token":                   true,
	"code":                         true,
	"oauth_token":                  true,
	"oauth_verifier":               true,
	"secret":                       true,
	"client_secret":                true,
	"app_secret":                   true,
	"sig":                          true,
	"signature":                    true,
	"x-amz-signature":              true,
	"x-amz-security-token":         true,
	"x-amz-credential":             true,
	"awsaccesskeyid":               true,
	"x-goog-api-key":               true,
	"x_goog_api_key":               true,
	"x-goog-signature":             true,
	"x-goog-credential":            true,
	"x-goog-encryption-key":        true,
	"x-goog-encryption-key-sha256": true,
	"auth":                         true,
	"authorization":                true,
	"password":                     true,
	"passwd":                       true,
	"pwd":                          true,
	"credential":                   true,
	"credentials":                  true,
	"jwt":                          true,
	"bearer":                       true,
	"ticket":                       true,
	"totp":                         true,
	"totp_secret":                  true,
}

var sensitiveQueryKeys = SensitiveQueryKeys

var pathLikeDetailKeys = map[string]bool{
	"path":        true,
	"url":         true,
	"uri":         true,
	"raw_path":    true,
	"request_uri": true,
	"endpoint":    true,
	"target":      true,
	"location":    true,
	"href":        true,
}

var secretDetailKeys = map[string]bool{
	"api_key":       true,
	"apikey":        true,
	"access_token":  true,
	"refresh_token": true,
	"id_token":      true,
	"secret":        true,
	"client_secret": true,
	"password":      true,
	"authorization": true,
	"auth_token":    true,
	"bearer":        true,
	"totp_secret":   true,
}

// IsSensitiveQueryKey reports whether rawKey (after optional URL percent-unescaping) matches
// the shared SensitiveQueryKeys table or common credential key substrings.
func IsSensitiveQueryKey(rawKey string) bool {
	lk := strings.ToLower(strings.TrimSpace(rawKey))
	for i := 0; i < 2 && strings.Contains(lk, "%"); i++ {
		unescaped, err := url.QueryUnescape(lk)
		if err != nil || unescaped == lk {
			break
		}
		lk = strings.ToLower(strings.TrimSpace(unescaped))
	}
	if SensitiveQueryKeys[lk] {
		return true
	}
	for _, sub := range []string{"secret", "token", "password", "signature", "apikey", "api_key", "credential", "accesskey"} {
		if strings.Contains(lk, sub) {
			return true
		}
	}
	return false
}

func isSensitiveQueryKey(rawKey string) bool {
	return IsSensitiveQueryKey(rawKey)
}

var (
	homeCacheMu   sync.RWMutex
	cachedRawHome string
	cachedHomeDir string
	homeCacheInit bool
)

func currentHomeDir() string {
	envHome := os.Getenv("HOME")
	homeCacheMu.RLock()
	if homeCacheInit && envHome == cachedRawHome {
		res := cachedHomeDir
		homeCacheMu.RUnlock()
		return res
	}
	homeCacheMu.RUnlock()

	resolved := ""
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		h = filepath.Clean(h)
		if h != "/" && h != "." && h != `\` {
			resolved = h
		}
	}
	homeCacheMu.Lock()
	cachedRawHome = envHome
	cachedHomeDir = resolved
	homeCacheInit = true
	homeCacheMu.Unlock()
	return resolved
}

func redactHomeDir(raw string) string {
	home := currentHomeDir()
	if home == "" || raw == "" {
		return raw
	}
	if raw == home {
		return "~"
	}
	if strings.HasPrefix(raw, home) {
		next := raw[len(home)]
		if next == '/' || next == '\\' || next == '?' || next == '#' {
			return "~" + raw[len(home):]
		}
	}
	filePrefix := "file://" + home
	if raw == filePrefix {
		return "file://~"
	}
	if strings.HasPrefix(raw, filePrefix) {
		next := raw[len(filePrefix)]
		if next == '/' || next == '\\' || next == '?' || next == '#' {
			return "file://~" + raw[len(filePrefix):]
		}
	}
	return raw
}

// RedactSensitivePath masks credential-like query/fragment parameters, URL userinfo passwords,
// and replaces the host user's home directory prefix with "~".
func RedactSensitivePath(rawPath string) string {
	if rawPath == "" {
		return rawPath
	}
	out := redactHomeDir(redactURLUserinfo(rawPath))

	frag := ""
	if hashIdx := strings.IndexByte(out, '#'); hashIdx >= 0 {
		frag = out[hashIdx+1:]
		out = out[:hashIdx]
		if strings.Contains(frag, "=") || strings.Contains(frag, "sk-") {
			frag = RedactQueryPairs(frag)
		}
		frag = "#" + frag
	}

	qIdx := strings.IndexByte(out, '?')
	if qIdx < 0 {
		return RedactPathMatrixParams(out) + frag
	}
	base := RedactPathMatrixParams(redactHomeDir(out[:qIdx]))
	if qIdx == len(out)-1 {
		return base + "?" + frag
	}
	query := out[qIdx+1:]
	return base + "?" + RedactQueryPairs(query) + frag
}

func redactURLUserinfo(raw string) string {
	if !strings.Contains(raw, "://") {
		return raw
	}
	var b strings.Builder
	pos := 0
	changed := false
	for pos < len(raw) {
		rel := strings.Index(raw[pos:], "://")
		if rel < 0 {
			b.WriteString(raw[pos:])
			break
		}
		schemeEnd := pos + rel + 3
		b.WriteString(raw[pos:schemeEnd])
		rest := raw[schemeEnd:]
		delimIdx := strings.IndexAny(rest, "/?# \t\r\n\"'")
		authority := rest
		nextPos := len(raw)
		if delimIdx >= 0 {
			authority = rest[:delimIdx]
			nextPos = schemeEnd + delimIdx
		}
		if atIdx := strings.LastIndexByte(authority, '@'); atIdx >= 0 {
			userinfo := authority[:atIdx]
			hostport := authority[atIdx+1:]
			if colonIdx := strings.IndexByte(userinfo, ':'); colonIdx >= 0 {
				userinfo = userinfo[:colonIdx] + ":[REDACTED]"
			} else {
				userinfo = "[REDACTED]"
			}
			b.WriteString(userinfo)
			b.WriteByte('@')
			b.WriteString(hostport)
			changed = true
		} else {
			b.WriteString(authority)
		}
		pos = nextPos
	}
	if !changed {
		return raw
	}
	return b.String()
}

func redactURLOrQueryToken(raw string) string {
	if raw == "" {
		return raw
	}
	out := redactURLUserinfo(raw)
	if !strings.ContainsAny(out, "?;#") {
		return out
	}
	frag := ""
	if hashIdx := strings.IndexByte(out, '#'); hashIdx >= 0 {
		frag = out[hashIdx+1:]
		out = out[:hashIdx]
		if strings.Contains(frag, "=") || strings.Contains(frag, "sk-") {
			frag = RedactQueryPairs(frag)
		}
		frag = "#" + frag
	}
	qIdx := strings.IndexByte(out, '?')
	if qIdx < 0 {
		return RedactPathMatrixParams(out) + frag
	}
	base := RedactPathMatrixParams(out[:qIdx])
	if qIdx == len(out)-1 {
		return base + "?" + frag
	}
	query := out[qIdx+1:]
	return base + "?" + RedactQueryPairs(query) + frag
}

// RedactPathMatrixParams masks semicolon-delimited matrix parameters in a URL path
// (such as `/v1/models;key=SECRET` or `/v1/chat;X-Goog-Api-Key=SECRET`).
func RedactPathMatrixParams(basePath string) string {
	if !strings.Contains(basePath, ";") {
		return basePath
	}
	segments := strings.Split(basePath, "/")
	changed := false
	for i, seg := range segments {
		semiIdx := strings.IndexByte(seg, ';')
		if semiIdx < 0 || semiIdx == len(seg)-1 {
			continue
		}
		prefix := seg[:semiIdx+1]
		matrix := seg[semiIdx+1:]
		redactedMatrix := RedactQueryPairs(matrix)
		if redactedMatrix != matrix {
			segments[i] = prefix + redactedMatrix
			changed = true
		}
	}
	if !changed {
		return basePath
	}
	return strings.Join(segments, "/")
}

// RedactQueryPairs masks sensitive key=value pairs in a query/fragment string separated by '&' or ';'.
func RedactQueryPairs(query string) string {
	if query == "" {
		return query
	}
	var b strings.Builder
	b.Grow(len(query))
	changed := false
	start := 0
	for i := 0; i <= len(query); i++ {
		if i < len(query) && query[i] != '&' && query[i] != ';' {
			continue
		}
		part := query[start:i]
		if part != "" {
			k := part
			hasEq := false
			if eq := strings.IndexByte(part, '='); eq >= 0 {
				k = part[:eq]
				hasEq = true
			}
			if IsSensitiveQueryKey(k) {
				if hasEq {
					part = k + "=[REDACTED]"
				} else {
					part = "[REDACTED]"
				}
				changed = true
			}
		}
		b.WriteString(part)
		if i < len(query) {
			b.WriteByte(query[i])
		}
		start = i + 1
	}
	if !changed {
		return query
	}
	return b.String()
}

func redactQueryPairs(query string) string {
	return RedactQueryPairs(query)
}

// IsSensitiveFlagName reports whether a CLI flag name (such as --api-key, --xxx-token, --xxx-secret, --token)
// represents a credential option whose value must be redacted.
func IsSensitiveFlagName(rawFlag string) bool {
	trimmed := strings.TrimSpace(rawFlag)
	if !strings.HasPrefix(trimmed, "-") {
		return false
	}
	name := strings.ToLower(strings.TrimLeft(trimmed, "-"))
	if name == "" {
		return false
	}
	if name == "u" || name == "p" {
		return true
	}
	norm := strings.ReplaceAll(name, "-", "_")
	if SensitiveQueryKeys[name] || SensitiveQueryKeys[norm] {
		return true
	}
	switch norm {
	case "user", "proxy_user", "pass", "proxy_pass", "passphrase":
		return true
	}
	for _, suffix := range []string{
		"-key", "_key",
		"-apikey", "_apikey",
		"-token", "_token",
		"-secret", "_secret",
		"-password", "_password",
		"-passwd", "_passwd",
		"-pwd", "_pwd",
		"-pass", "_pass",
		"-passphrase", "_passphrase",
		"-user", "_user",
		"-credential", "_credential",
		"-credentials", "_credentials",
		"-jwt", "_jwt",
		"-auth", "_auth",
		"-bearer", "_bearer",
		"-totp", "_totp",
	} {
		if strings.HasSuffix(name, suffix) || strings.HasSuffix(norm, suffix) {
			return true
		}
	}
	return false
}

func isUserCredentialFlag(rawFlag string) bool {
	trimmed := strings.TrimSpace(rawFlag)
	if !strings.HasPrefix(trimmed, "-") {
		return false
	}
	if trimmed == "-u" || trimmed == "-U" {
		return true
	}
	name := strings.ToLower(strings.TrimLeft(trimmed, "-"))
	norm := strings.ReplaceAll(name, "-", "_")
	return norm == "user" || norm == "proxy_user"
}

func isHeaderFlag(rawFlag string) bool {
	trimmed := strings.TrimSpace(rawFlag)
	if !strings.HasPrefix(trimmed, "-") {
		return false
	}
	if trimmed == "-H" {
		return true
	}
	name := strings.ToLower(strings.TrimLeft(trimmed, "-"))
	norm := strings.ReplaceAll(name, "-", "_")
	return norm == "header" || norm == "proxy_header"
}

func redactUserPassValue(rawVal string) string {
	if rawVal == "" {
		return "[REDACTED]"
	}
	if strings.Contains(rawVal, "://") {
		return redactSingleTokenValue(rawVal)
	}
	if colonIdx := strings.IndexByte(rawVal, ':'); colonIdx >= 0 {
		return rawVal[:colonIdx] + ":[REDACTED]"
	}
	return "[REDACTED]"
}

func isAuthSchemeWord(s string) bool {
	cleaned := strings.TrimRight(strings.TrimSpace(s), ":")
	switch strings.ToLower(cleaned) {
	case "bearer", "basic", "digest", "token":
		return true
	default:
		return false
	}
}

func redactHeaderSingleArg(rawHdr string) string {
	colonIdx := strings.IndexByte(rawHdr, ':')
	if colonIdx < 0 {
		return "[REDACTED]"
	}
	prefix := rawHdr[:colonIdx+1]
	rest := strings.TrimSpace(rawHdr[colonIdx+1:])
	if rest == "" {
		return prefix + " [REDACTED]"
	}
	parts := strings.Fields(rest)
	if len(parts) >= 2 && isAuthSchemeWord(parts[0]) {
		return prefix + " " + parts[0] + " [REDACTED]"
	}
	if colonIdx+1 < len(rawHdr) && rawHdr[colonIdx+1] == ' ' {
		return prefix + " [REDACTED]"
	}
	return prefix + "[REDACTED]"
}

// RedactArgSlice returns a copy of args with CLI credential flags (--xxx-key=VAL, --token VAL),
// Authorization Bearer tokens, and sk-* API keys masked as [REDACTED].
func RedactArgSlice(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out); i++ {
		leadQuote, core, _ := splitSurroundingQuotes(strings.TrimSpace(out[i]))
		_ = leadQuote
		if !strings.Contains(core, "=") && isUserCredentialFlag(core) {
			if i+1 < len(out) {
				nqLead, nqCore, nqTrail := splitSurroundingQuotes(strings.TrimSpace(out[i+1]))
				out[i+1] = nqLead + redactUserPassValue(nqCore) + nqTrail
				i++
			}
			continue
		}
		if !strings.Contains(core, "=") && isHeaderFlag(core) {
			if i+1 < len(out) {
				nqLead, nqCore, nqTrail := splitSurroundingQuotes(strings.TrimSpace(out[i+1]))
				if strings.HasSuffix(nqCore, ":") && i+2 < len(out) {
					v1Lead, v1Core, v1Trail := splitSurroundingQuotes(strings.TrimSpace(out[i+2]))
					if isAuthSchemeWord(v1Core) && i+3 < len(out) {
						v2Lead, _, v2Trail := splitSurroundingQuotes(strings.TrimSpace(out[i+3]))
						out[i+3] = v2Lead + "[REDACTED]" + v2Trail
						i += 3
						continue
					}
					out[i+2] = v1Lead + "[REDACTED]" + v1Trail
					i += 2
					continue
				}
				out[i+1] = nqLead + redactHeaderSingleArg(nqCore) + nqTrail
				i++
			}
			continue
		}
		if !strings.Contains(core, "=") && IsSensitiveFlagName(core) {
			if i+1 < len(out) {
				nqLead, _, nqTrail := splitSurroundingQuotes(strings.TrimSpace(out[i+1]))
				out[i+1] = nqLead + "[REDACTED]" + nqTrail
				i++
			}
			continue
		}
		if isBearerWord(core) && i+1 < len(out) {
			nqLead, _, nqTrail := splitSurroundingQuotes(strings.TrimSpace(out[i+1]))
			out[i+1] = nqLead + "[REDACTED]" + nqTrail
			i++
			continue
		}
		if strings.HasSuffix(core, ":") {
			hdrKey := strings.TrimSuffix(core, ":")
			if (IsSensitiveFlagName(hdrKey) || IsSensitiveQueryKey(hdrKey)) && i+1 < len(out) {
				v1Lead, v1Core, v1Trail := splitSurroundingQuotes(strings.TrimSpace(out[i+1]))
				if isAuthSchemeWord(v1Core) && i+2 < len(out) {
					v2Lead, _, v2Trail := splitSurroundingQuotes(strings.TrimSpace(out[i+2]))
					out[i+2] = v2Lead + "[REDACTED]" + v2Trail
					i += 2
					continue
				}
				out[i+1] = v1Lead + "[REDACTED]" + v1Trail
				i++
				continue
			}
		}
		out[i] = RedactCmdline(out[i])
	}
	return out
}

// RedactCmdArgs joins and redacts an argv slice into a single command-line string.
func RedactCmdArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return RedactCmdline(strings.Join(RedactArgSlice(args), " "))
}

// RedactCmdline masks sensitive CLI options (--xxx-key=VALUE, --xxx-token=VALUE, --xxx-secret=VALUE,
// --token VALUE), Bearer tokens, and sk-* API keys inside a command line or detail string.
func RedactCmdline(raw string) string {
	if raw == "" {
		return raw
	}
	lower := strings.ToLower(raw)
	if !strings.Contains(raw, "-") && !strings.Contains(raw, "=") && !strings.Contains(raw, ":") &&
		!strings.Contains(raw, "?") && !strings.Contains(raw, ";") && !strings.Contains(lower, "bearer") && !strings.Contains(raw, "sk-") {
		return raw
	}

	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return raw
	}
	changed := false
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		leadQuote, core, trailQuote := splitSurroundingQuotes(tok)

		if !strings.Contains(core, "=") && isUserCredentialFlag(core) {
			if i+1 < len(fields) {
				nqLead, nqCore, nqTrail := splitSurroundingQuotes(fields[i+1])
				fields[i+1] = nqLead + redactUserPassValue(nqCore) + nqTrail
				changed = true
				i++
			}
			continue
		}

		if (strings.HasPrefix(core, "-u") || strings.HasPrefix(core, "-U")) && !strings.HasPrefix(core, "--") && len(core) > 2 && strings.Contains(core[2:], ":") && !strings.Contains(core, "://") {
			fields[i] = leadQuote + core[:2] + redactUserPassValue(core[2:]) + trailQuote
			changed = true
			continue
		}

		if !strings.Contains(core, "=") && isHeaderFlag(core) {
			if i+1 < len(fields) {
				nqLead, nqCore, nqTrail := splitSurroundingQuotes(fields[i+1])
				if strings.HasSuffix(nqCore, ":") && i+2 < len(fields) {
					v1Lead, v1Core, v1Trail := splitSurroundingQuotes(fields[i+2])
					if isAuthSchemeWord(v1Core) && i+3 < len(fields) {
						v2Lead, _, v2Trail := splitSurroundingQuotes(fields[i+3])
						fields[i+3] = v2Lead + "[REDACTED]" + v2Trail
						changed = true
						i += 3
						continue
					}
					fields[i+2] = v1Lead + "[REDACTED]" + v1Trail
					changed = true
					i += 2
					continue
				}
				fields[i+1] = nqLead + redactHeaderSingleArg(nqCore) + nqTrail
				changed = true
				i++
			}
			continue
		}

		if eq := strings.IndexByte(core, '='); eq > 0 && !isURLOrPathBeforeEq(core[:eq]) {
			k := core[:eq]
			v := core[eq+1:]
			if isUserCredentialFlag(k) {
				fields[i] = leadQuote + k + "=" + redactUserPassValue(v) + trailQuote
				changed = true
				continue
			}
			if isHeaderFlag(k) {
				fields[i] = leadQuote + k + "=" + redactHeaderSingleArg(v) + trailQuote
				changed = true
				continue
			}
			if IsSensitiveFlagName(k) || IsSensitiveQueryKey(k) {
				fields[i] = leadQuote + k + "=[REDACTED]" + trailQuote
				changed = true
				continue
			}
			redV := redactSingleTokenValue(v)
			if redV != v {
				fields[i] = leadQuote + k + "=" + redV + trailQuote
				changed = true
				continue
			}
		}

		if !strings.Contains(core, "=") && IsSensitiveFlagName(core) {
			if i+1 < len(fields) {
				nqLead, _, nqTrail := splitSurroundingQuotes(fields[i+1])
				fields[i+1] = nqLead + "[REDACTED]" + nqTrail
				changed = true
				i++
			}
			continue
		}

		if isBearerWord(core) {
			if i+1 < len(fields) {
				nqLead, _, nqTrail := splitSurroundingQuotes(fields[i+1])
				fields[i+1] = nqLead + "[REDACTED]" + nqTrail
				changed = true
				i++
			}
			continue
		}

		if strings.HasSuffix(core, ":") {
			hdrKey := strings.TrimSuffix(core, ":")
			if (IsSensitiveFlagName(hdrKey) || IsSensitiveQueryKey(hdrKey)) && i+1 < len(fields) {
				v1Lead, v1Core, v1Trail := splitSurroundingQuotes(fields[i+1])
				if isAuthSchemeWord(v1Core) && i+2 < len(fields) {
					v2Lead, _, v2Trail := splitSurroundingQuotes(fields[i+2])
					fields[i+2] = v2Lead + "[REDACTED]" + v2Trail
					changed = true
					i += 2
					continue
				}
				fields[i+1] = v1Lead + "[REDACTED]" + v1Trail
				changed = true
				i++
				continue
			}
		}

		redCore := redactSingleTokenValue(core)
		if redCore != core {
			fields[i] = leadQuote + redCore + trailQuote
			changed = true
		}
	}
	if !changed {
		return raw
	}
	return strings.Join(fields, " ")
}

func isURLOrPathBeforeEq(prefix string) bool {
	return strings.Contains(prefix, "://") || strings.ContainsAny(prefix, "/?;")
}

func redactSingleTokenValue(s string) string {
	if s == "" {
		return s
	}
	out := redactURLOrQueryToken(s)
	if !strings.Contains(out, "://") {
		if colonIdx := strings.IndexByte(out, ':'); colonIdx > 0 && colonIdx < len(out)-1 {
			k := out[:colonIdx]
			if IsSensitiveFlagName(k) || IsSensitiveQueryKey(k) {
				return k + ":[REDACTED]"
			}
		}
	}
	return redactInlineTokenSecret(out)
}

func isBearerWord(s string) bool {
	cleaned := strings.TrimRight(strings.TrimSpace(s), ":")
	return strings.EqualFold(cleaned, "bearer")
}

func splitSurroundingQuotes(s string) (lead, core, trail string) {
	core = s
	for len(core) > 0 && (core[0] == '"' || core[0] == '\'') {
		lead += string(core[0])
		core = core[1:]
	}
	for len(core) > 0 && (core[len(core)-1] == '"' || core[len(core)-1] == '\'' || core[len(core)-1] == ',' || core[len(core)-1] == ';') {
		trail = string(core[len(core)-1]) + trail
		core = core[:len(core)-1]
	}
	return lead, core, trail
}

func redactInlineTokenSecret(s string) string {
	if strings.HasPrefix(s, "sk-") && len(s) >= 9 && isLikelySecretTokenChars(s[3:]) {
		return "[REDACTED]"
	}
	return redactEmbeddedSKTokens(s)
}

func redactEmbeddedSKTokens(s string) string {
	idx := strings.Index(s, "sk-")
	if idx < 0 {
		return s
	}
	var b strings.Builder
	pos := 0
	for pos < len(s) {
		rel := strings.Index(s[pos:], "sk-")
		if rel < 0 {
			b.WriteString(s[pos:])
			break
		}
		abs := pos + rel
		if abs > 0 && isAlphaNumByte(s[abs-1]) {
			b.WriteString(s[pos : abs+3])
			pos = abs + 3
			continue
		}
		end := abs + 3
		for end < len(s) && isSecretTokenByte(s[end]) {
			end++
		}
		if end-(abs+3) >= 6 {
			b.WriteString(s[pos:abs])
			b.WriteString("[REDACTED]")
			pos = end
		} else {
			b.WriteString(s[pos : abs+3])
			pos = abs + 3
		}
	}
	return b.String()
}

func isLikelySecretTokenChars(s string) bool {
	if len(s) < 6 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isSecretTokenByte(s[i]) {
			return false
		}
	}
	return true
}

func isSecretTokenByte(c byte) bool {
	return isAlphaNumByte(c) || c == '_' || c == '-'
}

func isAlphaNumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func sanitizeDetailMap(detail map[string]any) map[string]any {
	if detail == nil {
		return nil
	}
	out := make(map[string]any, len(detail))
	for k, v := range detail {
		out[k] = sanitizeDetailValue(k, v)
	}
	return out
}

func sanitizeDetailValue(key string, val any) any {
	lk := strings.ToLower(strings.TrimSpace(key))
	switch tv := val.(type) {
	case string:
		if secretDetailKeys[lk] {
			return "[REDACTED]"
		}
		out := tv
		if pathLikeDetailKeys[lk] || strings.HasSuffix(lk, "_path") || strings.HasSuffix(lk, "_dir") || strings.HasSuffix(lk, "_file") || looksLikePathOrURLWithQuery(tv) || hasHomeDirPrefix(tv) {
			out = RedactSensitivePath(out)
		}
		return RedactCmdline(out)
	case map[string]any:
		return sanitizeDetailMap(tv)
	case map[string]string:
		cp := make(map[string]string, len(tv))
		for mk, mv := range tv {
			if s, ok := sanitizeDetailValue(mk, mv).(string); ok {
				cp[mk] = s
			} else {
				cp[mk] = mv
			}
		}
		return cp
	case []any:
		strSlice := make([]string, len(tv))
		isStr := make([]bool, len(tv))
		for i := 0; i < len(tv); i++ {
			if s, ok := tv[i].(string); ok {
				strSlice[i] = s
				isStr[i] = true
			}
		}
		redactedStrs := RedactArgSlice(strSlice)
		cp := make([]any, len(tv))
		for i := 0; i < len(tv); i++ {
			if isStr[i] {
				cp[i] = sanitizeDetailValue(key, redactedStrs[i])
			} else {
				cp[i] = sanitizeDetailValue(key, tv[i])
			}
		}
		return cp
	case []string:
		redacted := RedactArgSlice(tv)
		cp := make([]string, len(redacted))
		for i, elem := range redacted {
			if s, ok := sanitizeDetailValue(key, elem).(string); ok {
				cp[i] = s
			} else {
				cp[i] = elem
			}
		}
		return cp
	default:
		return val
	}
}

func hasHomeDirPrefix(s string) bool {
	home := currentHomeDir()
	if home == "" || s == "" {
		return false
	}
	return s == home || strings.HasPrefix(s, home+"/") || strings.HasPrefix(s, home+`\`) || strings.HasPrefix(s, "file://"+home)
}

func looksLikePathOrURLWithQuery(s string) bool {
	if strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	if strings.Contains(s, "://") {
		return true
	}
	if (strings.HasPrefix(s, "/") || strings.Contains(s, "?")) && (strings.Contains(s, "?") || strings.Contains(s, "#")) {
		return true
	}
	return false
}
