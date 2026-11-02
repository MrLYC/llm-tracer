package parser

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"golang.org/x/net/http2/hpack"
)

type Direction int

const (
	DirWrite Direction = 0 // Client -> Server (Request)
	DirRead  Direction = 1 // Server -> Client (Response)

	ConnIdleTimeout             = 2 * time.Minute
	MaxConnBufferBytes          = 8 * 1024 * 1024  // 8 MiB per-buffer cap
	MaxTotalBufferBytes         = 64 * 1024 * 1024 // 64 MiB global buffer budget across all connections
	MaxNonHTTPPrefixBytes       = 4096             // 4 KiB cap for non-HTTP prefix / orphan response bytes
	MaxUnknownWarnHosts         = 256              // max distinct hosts tracked in unknownWarnState (LRU)
	MaxH2StreamsPerConn         = 256              // max concurrent HTTP/2 streams tracked per connection
	MaxTrackedConns             = 4096             // max concurrent connections tracked
	UnknownProtocolWarnInterval = 10 * time.Second
	connSweepInterval           = 64
)

type RawTLSChunk struct {
	ConnKey   string
	Direction Direction
	Timestamp int64
	Process   model.ProcessInfo
	Data      []byte
}

type EventHandler func(ev *model.TraceEvent)

type unknownHostWarnState struct {
	lastWarnMs      int64
	suppressedCount int
	suppressedBytes int
}

type StreamReassembler struct {
	mu               sync.Mutex
	conns            map[string]*connBuffer
	recordHeaders    bool
	hostFilter       []string
	dropUnknown      bool
	maxTotalBytes    int
	mon              *selfmon.Monitor
	onEvent          EventHandler
	ingestCount      uint64
	lastSweepTs      int64
	unknownWarnState map[string]*unknownHostWarnState
}

type connBuffer struct {
	key             string
	process         model.ProcessInfo
	isHTTP2         bool
	reqBuf          bytes.Buffer
	respBuf         bytes.Buffer
	activeH1        *activeH1Exchange
	h2ReqBuf        bytes.Buffer
	h2RespBuf       bytes.Buffer
	h2Streams       map[uint32]*h2StreamState
	reqDecoder      *hpack.Decoder
	rspDecoder      *hpack.Decoder
	updatedAt       int64
	truncWarned     bool
	truncSuppressed int
}

func NewStreamReassembler(recordHeaders bool, hostFilter []string, mon *selfmon.Monitor, onEvent EventHandler) *StreamReassembler {
	return &StreamReassembler{
		conns:            make(map[string]*connBuffer),
		recordHeaders:    recordHeaders,
		hostFilter:       hostFilter,
		dropUnknown:      true,
		maxTotalBytes:    MaxTotalBufferBytes,
		mon:              mon,
		onEvent:          onEvent,
		unknownWarnState: make(map[string]*unknownHostWarnState),
	}
}

func (sr *StreamReassembler) SetScope(recordHeaders bool, hostFilter []string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.recordHeaders = recordHeaders
	sr.hostFilter = hostFilter
}

// SetDropUnknown configures whether unknown-protocol exchanges are dropped when hostFilter is empty.
// It defaults to true and is exposed for CLI / collector flag passthrough (wired by G9).
func (sr *StreamReassembler) SetDropUnknown(drop bool) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.dropUnknown = drop
	sr.unknownWarnState = make(map[string]*unknownHostWarnState)
}

// DropUnknown returns whether unknown-protocol exchanges are currently dropped when hostFilter is empty.
func (sr *StreamReassembler) DropUnknown() bool {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.dropUnknown
}

// SetMaxTotalBufferBytes configures the global buffer byte budget across all active connections.
// When total buffered bytes exceed this limit, the oldest connections are evicted first.
// Passing maxBytes <= 0 restores the default MaxTotalBufferBytes (64 MiB).
func (sr *StreamReassembler) SetMaxTotalBufferBytes(maxBytes int) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	if maxBytes <= 0 {
		maxBytes = MaxTotalBufferBytes
	}
	sr.maxTotalBytes = maxBytes
}

// TotalBufferBytes returns the current sum of buffered bytes across all tracked connections.
func (sr *StreamReassembler) TotalBufferBytes() int {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.totalBufferBytesLocked()
}

func (cb *connBuffer) totalBytes() int {
	total := cb.reqBuf.Len() + cb.respBuf.Len() + cb.h2ReqBuf.Len() + cb.h2RespBuf.Len()
	if cb.activeH1 != nil {
		total += len(cb.activeH1.reqBody) + cb.activeH1.respRawBody.Len()
	}
	for _, st := range cb.h2Streams {
		total += st.reqBody.Len() + st.respBody.Len()
	}
	return total
}

func (sr *StreamReassembler) IngestChunk(chunk RawTLSChunk) {
	if len(chunk.Data) == 0 {
		return
	}
	if chunk.Timestamp == 0 {
		chunk.Timestamp = time.Now().UnixMilli()
	}

	sr.mu.Lock()
	sr.ingestCount++
	if sr.ingestCount%connSweepInterval == 0 || sr.lastSweepTs == 0 ||
		chunk.Timestamp-sr.lastSweepTs >= 10_000 || chunk.Timestamp < sr.lastSweepTs {
		sr.evictIdleConnsLocked(chunk.Timestamp)
	}

	cb, ok := sr.conns[chunk.ConnKey]
	if !ok {
		cb = &connBuffer{
			key:       chunk.ConnKey,
			process:   chunk.Process,
			h2Streams: make(map[uint32]*h2StreamState),
			updatedAt: chunk.Timestamp,
		}
		sr.conns[chunk.ConnKey] = cb
	}
	if chunk.Process.PID != 0 {
		cb.process = chunk.Process
	}
	prevUpdatedAt := cb.updatedAt
	cb.updatedAt = chunk.Timestamp

	if !cb.isHTTP2 && bytes.Contains(chunk.Data, []byte(http2ClientPreface)) {
		cb.isHTTP2 = true
	}
	if cb.isHTTP2 {
		sr.handleHTTP2Locked(cb, chunk)
		if sr.enforceConnBufferLimitsLocked(cb) && prevUpdatedAt > 0 && prevUpdatedAt < chunk.Timestamp {
			cb.updatedAt = prevUpdatedAt
		}
		sr.enforceGlobalBufferBudgetLocked(cb.key, chunk.Timestamp)
		sr.mu.Unlock()
		return
	}

	var validProgress bool
	var truncated bool
	if chunk.Direction == DirWrite {
		cb.reqBuf.Write(chunk.Data)
		if cb.reqBuf.Len() > MaxConnBufferBytes {
			truncated = sr.enforceConnBufferLimitsLocked(cb)
		} else {
			validProgress = sr.tryParseH1RequestLocked(cb, chunk.Timestamp)
			truncated = sr.enforceConnBufferLimitsLocked(cb)
		}
	} else {
		cb.respBuf.Write(chunk.Data)
		if cb.respBuf.Len() > MaxConnBufferBytes {
			truncated = sr.enforceConnBufferLimitsLocked(cb)
		} else {
			validProgress = sr.tryParseH1ResponseLocked(cb, chunk.Timestamp)
			truncated = sr.enforceConnBufferLimitsLocked(cb)
		}
	}
	if (truncated || !validProgress) && prevUpdatedAt > 0 && prevUpdatedAt < chunk.Timestamp {
		cb.updatedAt = prevUpdatedAt
	}
	sr.enforceGlobalBufferBudgetLocked(cb.key, chunk.Timestamp)
	sr.mu.Unlock()
}

// EvictIdleConns removes connections whose updatedAt is older than nowMs - ConnIdleTimeout.
// Contract:
//   - Safe for concurrent invocation by an external periodic ticker (e.g. collector housekeeping loop)
//     so idle connections are reclaimed even when no new TLS chunks arrive.
//   - Passing nowMs <= 0 uses time.Now().UnixMilli().
//   - Any in-flight HTTP/1.1 or HTTP/2 exchange (including request-only exchanges that never received
//     response headers, or partial SSE streams) is emitted as a terminal "incomplete" TraceEvent
//     with an explicit reason in TraceEvent.Error so store persists it to disk.
func (sr *StreamReassembler) EvictIdleConns(nowMs int64) int {
	if nowMs <= 0 {
		nowMs = time.Now().UnixMilli()
	}
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.evictIdleConnsLocked(nowMs)
}

func (sr *StreamReassembler) evictIdleConnsLocked(nowMs int64) int {
	sr.lastSweepTs = nowMs
	cutoffMs := nowMs - ConnIdleTimeout.Milliseconds()
	for hostKey, st := range sr.unknownWarnState {
		if st.lastWarnMs > 0 && st.lastWarnMs < cutoffMs {
			delete(sr.unknownWarnState, hostKey)
		}
	}
	evicted := 0
	for _, cb := range sr.conns {
		if cb.updatedAt >= cutoffMs {
			continue
		}
		sr.evictConnLocked(cb, nowMs, "idle_timeout")
		evicted++
	}
	return evicted
}

func (sr *StreamReassembler) evictConnLocked(cb *connBuffer, nowMs int64, reason string) {
	if cb.activeH1 == nil && !cb.isHTTP2 && cb.reqBuf.Len() > 0 {
		cb.activeH1 = sr.extractPartialH1RequestLocked(cb, cb.reqBuf.Bytes(), nowMs)
	}
	hadActiveH1 := cb.activeH1 != nil
	if cb.activeH1 != nil {
		ex := cb.activeH1
		partialResp := sr.extractPartialH1ResponseBodyLocked(cb, ex)
		errReason := reason + ": no response received"
		if ex.respHeaderParsed || len(partialResp) > 0 {
			errReason = reason + ": incomplete response"
		}
		sr.emitH1TerminalExchangeLocked(cb, ex, partialResp, nowMs, "incomplete", errReason)
		cb.activeH1 = nil
	}
	if len(cb.h2Streams) > 0 {
		streamIDs := make([]uint32, 0, len(cb.h2Streams))
		for id := range cb.h2Streams {
			streamIDs = append(streamIDs, id)
		}
		sort.Slice(streamIDs, func(i, j int) bool { return streamIDs[i] < streamIDs[j] })
		for _, id := range streamIDs {
			st := cb.h2Streams[id]
			if st.method != "" || st.path != "" || st.reqBody.Len() > 0 || st.respBody.Len() > 0 {
				errReason := reason + ": no response received"
				if st.status > 0 || st.respBody.Len() > 0 {
					errReason = reason + ": incomplete response"
				}
				sr.emitH2TerminalStreamLocked(cb, st, nowMs, "incomplete", errReason)
			}
			delete(cb.h2Streams, id)
		}
	}
	if sr.mon != nil {
		sr.mon.RecordWarn(selfmon.StageStream, "conn_evicted", "idle connection evicted", map[string]any{
			"conn_key":   cb.key,
			"pid":        cb.process.PID,
			"updated_at": cb.updatedAt,
			"active_h1":  hadActiveH1,
			"reason":     reason,
		})
	}
	delete(sr.conns, cb.key)
}

func (sr *StreamReassembler) totalBufferBytesLocked() int {
	total := 0
	for _, cb := range sr.conns {
		total += cb.totalBytes()
	}
	return total
}

func (sr *StreamReassembler) enforceGlobalBufferBudgetLocked(currentKey string, nowMs int64) {
	limit := sr.maxTotalBytes
	if limit <= 0 {
		limit = MaxTotalBufferBytes
	}
	for (sr.totalBufferBytesLocked() > limit || len(sr.conns) > MaxTrackedConns) && len(sr.conns) > 0 {
		var oldest *connBuffer
		for k, cb := range sr.conns {
			if k == currentKey && len(sr.conns) > 1 {
				continue
			}
			if oldest == nil || cb.updatedAt < oldest.updatedAt || (cb.updatedAt == oldest.updatedAt && cb.key < oldest.key) {
				oldest = cb
			}
		}
		if oldest == nil {
			oldest = sr.conns[currentKey]
		}
		if oldest == nil {
			break
		}
		sr.evictConnLocked(oldest, nowMs, "global_buffer_budget_exceeded")
	}
}

func (sr *StreamReassembler) enforceConnBufferLimitsLocked(cb *connBuffer) bool {
	truncated := false
	ts := cb.updatedAt

	if cb.reqBuf.Len() > MaxConnBufferBytes {
		truncated = true
		origLen := cb.reqBuf.Len()
		sr.recordBufferTruncatedWarnLocked(cb, "reqBuf", origLen)
		reason := fmt.Sprintf("buffer_truncated: reqBuf exceeded %d bytes", MaxConnBufferBytes)
		if cb.activeH1 != nil {
			ex := cb.activeH1
			partialResp := sr.extractPartialH1ResponseBodyLocked(cb, ex)
			sr.emitH1TerminalExchangeLocked(cb, ex, partialResp, ts, "incomplete", reason)
			cb.activeH1 = nil
			cb.respBuf.Reset()
		} else {
			prefix := cb.reqBuf.Bytes()[:MaxConnBufferBytes]
			if ex := sr.extractPartialH1RequestLocked(cb, prefix, ts); ex != nil {
				sr.emitH1TerminalExchangeLocked(cb, ex, nil, ts, "incomplete", reason)
			}
		}
		cb.reqBuf.Reset()
	}

	if cb.respBuf.Len() > MaxConnBufferBytes {
		truncated = true
		origLen := cb.respBuf.Len()
		sr.recordBufferTruncatedWarnLocked(cb, "respBuf", origLen)
		reason := fmt.Sprintf("buffer_truncated: respBuf exceeded %d bytes", MaxConnBufferBytes)
		if cb.activeH1 != nil {
			ex := cb.activeH1
			partialResp := sr.extractPartialH1ResponseBodyLocked(cb, ex)
			sr.emitH1TerminalExchangeLocked(cb, ex, partialResp, ts, "incomplete", reason)
			cb.activeH1 = nil
		}
		cb.respBuf.Reset()
	}

	if cb.activeH1 != nil && cb.activeH1.respRawBody.Len() > MaxConnBufferBytes {
		truncated = true
		origLen := cb.activeH1.respRawBody.Len()
		sr.recordBufferTruncatedWarnLocked(cb, "respRawBody", origLen)
		reason := fmt.Sprintf("buffer_truncated: respRawBody exceeded %d bytes", MaxConnBufferBytes)
		ex := cb.activeH1
		partialResp := append([]byte(nil), ex.respRawBody.Bytes()[:MaxConnBufferBytes]...)
		ex.respRawBody.Reset()
		sr.emitH1TerminalExchangeLocked(cb, ex, partialResp, ts, "incomplete", reason)
		cb.activeH1 = nil
		cb.respBuf.Reset()
	}

	if cb.h2ReqBuf.Len() > MaxConnBufferBytes {
		truncated = true
		origLen := cb.h2ReqBuf.Len()
		sr.recordBufferTruncatedWarnLocked(cb, "h2ReqBuf", origLen)
		reason := fmt.Sprintf("buffer_truncated: h2ReqBuf exceeded %d bytes", MaxConnBufferBytes)
		sr.flushTruncatedH2StreamsLocked(cb, ts, reason)
		cb.h2ReqBuf.Reset()
	}

	if cb.h2RespBuf.Len() > MaxConnBufferBytes {
		truncated = true
		origLen := cb.h2RespBuf.Len()
		sr.recordBufferTruncatedWarnLocked(cb, "h2RespBuf", origLen)
		reason := fmt.Sprintf("buffer_truncated: h2RespBuf exceeded %d bytes", MaxConnBufferBytes)
		sr.flushTruncatedH2StreamsLocked(cb, ts, reason)
		cb.h2RespBuf.Reset()
	}

	for streamID, st := range cb.h2Streams {
		if st.reqBody.Len() > MaxConnBufferBytes {
			truncated = true
			origLen := st.reqBody.Len()
			sr.recordBufferTruncatedWarnLocked(cb, "h2StreamReqBody", origLen)
			st.reqBody.Truncate(MaxConnBufferBytes)
			reason := fmt.Sprintf("buffer_truncated: h2StreamReqBody exceeded %d bytes", MaxConnBufferBytes)
			sr.emitH2TerminalStreamLocked(cb, st, ts, "incomplete", reason)
			delete(cb.h2Streams, streamID)
		} else if st.respBody.Len() > MaxConnBufferBytes {
			truncated = true
			origLen := st.respBody.Len()
			sr.recordBufferTruncatedWarnLocked(cb, "h2StreamRespBody", origLen)
			st.respBody.Truncate(MaxConnBufferBytes)
			reason := fmt.Sprintf("buffer_truncated: h2StreamRespBody exceeded %d bytes", MaxConnBufferBytes)
			sr.emitH2TerminalStreamLocked(cb, st, ts, "incomplete", reason)
			delete(cb.h2Streams, streamID)
		}
	}
	return truncated
}

func (sr *StreamReassembler) recordBufferTruncatedWarnLocked(cb *connBuffer, bufName string, origLen int) {
	if cb.truncWarned {
		cb.truncSuppressed++
		return
	}
	cb.truncWarned = true
	if sr.mon != nil {
		sr.mon.RecordWarn(selfmon.StageStream, "buffer_truncated", fmt.Sprintf("%s exceeded %d bytes", bufName, MaxConnBufferBytes), map[string]any{
			"conn_key":      cb.key,
			"pid":           cb.process.PID,
			"buffer":        bufName,
			"original_size": origLen,
			"truncated_to":  0,
		})
	}
}

// recordUnknownProtocolWarnLocked logs an "unknown_protocol_dropped" warning to selfmon,
// rate-limited per host (at most once per UnknownProtocolWarnInterval = 10s per host)
// with suppressed counts/bytes aggregated to avoid disk I/O storms under high-frequency non-LLM traffic.
// Path query parameters are redacted via RedactSensitivePath, and unknownWarnState is bounded by MaxUnknownWarnHosts (LRU).
func (sr *StreamReassembler) recordUnknownProtocolWarnLocked(host, path string, pid, totalBytes int, ts int64) {
	if sr.mon == nil {
		return
	}
	if ts <= 0 {
		ts = time.Now().UnixMilli()
	}
	hostKey := strings.ToLower(strings.TrimSpace(host))
	if hostKey == "" {
		hostKey = "_unknown_"
	}
	if sr.unknownWarnState == nil {
		sr.unknownWarnState = make(map[string]*unknownHostWarnState)
	}
	st, ok := sr.unknownWarnState[hostKey]
	if !ok {
		if len(sr.unknownWarnState) >= MaxUnknownWarnHosts {
			sr.evictUnknownWarnHostLocked(ts)
		}
		st = &unknownHostWarnState{}
		sr.unknownWarnState[hostKey] = st
	}
	safePath := RedactSensitivePath(path)
	if st.lastWarnMs == 0 || ts-st.lastWarnMs >= UnknownProtocolWarnInterval.Milliseconds() || ts < st.lastWarnMs {
		detail := map[string]any{
			"host":             host,
			"path":             safePath,
			"pid":              pid,
			"bytes":            totalBytes,
			"dropped":          sr.dropUnknown && len(sr.hostFilter) == 0,
			"suppressed_count": st.suppressedCount,
			"suppressed_bytes": st.suppressedBytes,
		}
		st.lastWarnMs = ts
		st.suppressedCount = 0
		st.suppressedBytes = 0
		sr.mon.RecordWarn(selfmon.StageStream, "unknown_protocol_dropped", "unknown protocol traffic", detail)
		return
	}
	st.suppressedCount++
	st.suppressedBytes += totalBytes
}

func (sr *StreamReassembler) evictUnknownWarnHostLocked(nowMs int64) {
	cutoffMs := nowMs - ConnIdleTimeout.Milliseconds()
	for k, st := range sr.unknownWarnState {
		if st.lastWarnMs > 0 && st.lastWarnMs < cutoffMs {
			delete(sr.unknownWarnState, k)
		}
	}
	if len(sr.unknownWarnState) < MaxUnknownWarnHosts {
		return
	}
	oldestKey := ""
	var oldestTs int64
	for k, st := range sr.unknownWarnState {
		if oldestKey == "" || st.lastWarnMs < oldestTs || (st.lastWarnMs == oldestTs && k < oldestKey) {
			oldestKey = k
			oldestTs = st.lastWarnMs
		}
	}
	if oldestKey != "" {
		delete(sr.unknownWarnState, oldestKey)
	}
}

func (sr *StreamReassembler) matchesHost(host string) bool {
	if len(sr.hostFilter) == 0 {
		return true
	}
	h := strings.ToLower(strings.Split(host, ":")[0])
	for _, f := range sr.hostFilter {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if h == f || strings.Contains(h, f) {
			return true
		}
	}
	return false
}
