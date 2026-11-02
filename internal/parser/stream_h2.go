package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"golang.org/x/net/http2/hpack"
)

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type h2StreamState struct {
	streamID         uint32
	startedAt        int64
	method           string
	scheme           string
	authority        string
	path             string
	reqHeaders       map[string]string
	correlationHints []string
	respHeaders      map[string]string
	status           int
	reqBody          bytes.Buffer
	respBody         bytes.Buffer
	reqEnded         bool
	respEnded        bool
	eventID          string
	chunks           int
}

// HTTP/2 frame reassembly using golang.org/x/net/http2/hpack
func (sr *StreamReassembler) handleHTTP2Locked(cb *connBuffer, chunk RawTLSChunk) {
	if chunk.Direction == DirWrite {
		data := chunk.Data
		if idx := bytes.Index(data, []byte(http2ClientPreface)); idx >= 0 {
			data = data[idx+len(http2ClientPreface):]
		}
		cb.h2ReqBuf.Write(data)
		if cb.h2ReqBuf.Len() <= MaxConnBufferBytes {
			sr.consumeH2FramesLocked(cb, &cb.h2ReqBuf, DirWrite, chunk.Timestamp)
		}
	} else {
		cb.h2RespBuf.Write(chunk.Data)
		if cb.h2RespBuf.Len() <= MaxConnBufferBytes {
			sr.consumeH2FramesLocked(cb, &cb.h2RespBuf, DirRead, chunk.Timestamp)
		}
	}
}

func (sr *StreamReassembler) consumeH2FramesLocked(cb *connBuffer, buf *bytes.Buffer, dir Direction, ts int64) {
	for buf.Len() >= 9 {
		hdr := buf.Bytes()[:9]
		length := int(uint32(hdr[0])<<16 | uint32(hdr[1])<<8 | uint32(hdr[2]))
		frameType := hdr[3]
		flags := hdr[4]
		streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff

		if buf.Len() < 9+length {
			return
		}
		payload := make([]byte, length)
		buf.Next(9)
		_, _ = buf.Read(payload)

		if streamID == 0 {
			continue
		}
		if frameType != 0x0 && frameType != 0x1 {
			continue
		}
		st, exists := cb.h2Streams[streamID]
		if !exists {
			if len(cb.h2Streams) >= MaxH2StreamsPerConn {
				sr.evictOldestH2StreamLocked(cb, ts)
			}
			st = &h2StreamState{
				streamID:    streamID,
				startedAt:   ts,
				reqHeaders:  make(map[string]string),
				respHeaders: make(map[string]string),
				eventID:     "ev_" + strings.ReplaceAll(uuid.NewString()[:12], "-", ""),
			}
			cb.h2Streams[streamID] = st
		}

		endStream := (flags & 0x1) != 0
		padded := (flags & 0x8) != 0
		priority := (flags & 0x20) != 0

		switch frameType {
		case 0x0: // DATA
			dataSlice := payload
			if padded && len(dataSlice) > 0 {
				padLen := int(dataSlice[0])
				if 1+padLen <= len(dataSlice) {
					dataSlice = dataSlice[1 : len(dataSlice)-padLen]
				}
			}
			if dir == DirWrite {
				st.reqBody.Write(dataSlice)
				if endStream {
					st.reqEnded = true
				}
			} else {
				st.respBody.Write(dataSlice)
				st.chunks++
				if endStream {
					st.respEnded = true
				} else if strings.Contains(strings.ToLower(st.respHeaders["content-type"]), "text/event-stream") && st.respBody.Len() > 0 && st.respBody.Len() <= MaxConnBufferBytes {
					sr.emitH2StreamLocked(cb, st, ts, false)
				}
			}
		case 0x1: // HEADERS
			frag := payload
			if padded && len(frag) > 0 {
				padLen := int(frag[0])
				if 1+padLen <= len(frag) {
					frag = frag[1 : len(frag)-padLen]
				}
			}
			if priority && len(frag) >= 5 {
				frag = frag[5:]
			}
			sr.decodeH2HeadersLocked(cb, st, frag, dir)
			if endStream {
				if dir == DirWrite {
					st.reqEnded = true
				} else {
					st.respEnded = true
				}
			}
		}

		if st.reqBody.Len() > MaxConnBufferBytes || st.respBody.Len() > MaxConnBufferBytes {
			return
		}
		if st.respEnded {
			sr.emitH2StreamLocked(cb, st, ts, true)
			delete(cb.h2Streams, streamID)
		}
	}
}

func (sr *StreamReassembler) evictOldestH2StreamLocked(cb *connBuffer, ts int64) {
	var oldestID uint32
	var oldest *h2StreamState
	for id, st := range cb.h2Streams {
		if oldest == nil || st.startedAt < oldest.startedAt || (st.startedAt == oldest.startedAt && id < oldestID) {
			oldestID = id
			oldest = st
		}
	}
	if oldest != nil {
		if oldest.method != "" || oldest.path != "" || oldest.reqBody.Len() > 0 || oldest.respBody.Len() > 0 {
			sr.emitH2TerminalStreamLocked(cb, oldest, ts, "incomplete", "h2_stream_limit_evicted: max concurrent streams exceeded")
		}
		delete(cb.h2Streams, oldestID)
	}
}

func (sr *StreamReassembler) flushTruncatedH2StreamsLocked(cb *connBuffer, ts int64, reason string) {
	if len(cb.h2Streams) == 0 {
		return
	}
	ids := make([]uint32, 0, len(cb.h2Streams))
	for id := range cb.h2Streams {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		st := cb.h2Streams[id]
		if st.method != "" || st.path != "" || st.reqBody.Len() > 0 || st.respBody.Len() > 0 {
			sr.emitH2TerminalStreamLocked(cb, st, ts, "incomplete", reason)
		}
		delete(cb.h2Streams, id)
	}
}

func (sr *StreamReassembler) decodeH2HeadersLocked(cb *connBuffer, st *h2StreamState, frag []byte, dir Direction) {
	fields := make([]hpack.HeaderField, 0, 16)
	emitFunc := func(f hpack.HeaderField) {
		fields = append(fields, f)
	}
	if dir == DirWrite {
		if cb.reqDecoder == nil {
			cb.reqDecoder = hpack.NewDecoder(4096, emitFunc)
		} else {
			cb.reqDecoder.SetEmitFunc(emitFunc)
		}
		_, _ = cb.reqDecoder.Write(frag)
		for _, f := range fields {
			name := strings.ToLower(f.Name)
			switch name {
			case ":method":
				st.method = f.Value
			case ":authority":
				st.authority = f.Value
			case ":path":
				st.path = f.Value
			case ":scheme":
				st.scheme = f.Value
			default:
				st.reqHeaders[f.Name] = f.Value
				// Hash immediately; plaintext header values are never retained.
				for _, hint := range extractCorrelationHintsFromHeader(func(key string) string {
					if strings.EqualFold(f.Name, key) {
						return f.Value
					}
					return ""
				}) {
					st.correlationHints = append(st.correlationHints, hint)
				}
			}
		}
	} else {
		if cb.rspDecoder == nil {
			cb.rspDecoder = hpack.NewDecoder(4096, emitFunc)
		} else {
			cb.rspDecoder.SetEmitFunc(emitFunc)
		}
		_, _ = cb.rspDecoder.Write(frag)
		for _, f := range fields {
			if f.Name == ":status" {
				st.status, _ = strconv.Atoi(f.Value)
			} else {
				st.respHeaders[f.Name] = f.Value
			}
		}
	}
}

func (sr *StreamReassembler) emitH2StreamLocked(cb *connBuffer, st *h2StreamState, ts int64, complete bool) {
	status := "streaming"
	if complete {
		status = "ok"
		if st.status >= 400 {
			status = "error"
		}
	}
	sr.emitH2WithStatusLocked(cb, st, ts, status, "", complete)
}

func (sr *StreamReassembler) emitH2TerminalStreamLocked(cb *connBuffer, st *h2StreamState, ts int64, terminalStatus string, reason string) {
	if st == nil || (st.method == "" && st.path == "" && st.reqBody.Len() == 0 && st.respBody.Len() == 0) {
		return
	}
	if terminalStatus == "" {
		terminalStatus = "incomplete"
	}
	sr.emitH2WithStatusLocked(cb, st, ts, terminalStatus, reason, true)
}

func (sr *StreamReassembler) emitH2WithStatusLocked(cb *connBuffer, st *h2StreamState, ts int64, status string, errReason string, isTerminal bool) {
	if !sr.matchesHost(st.authority) {
		return
	}
	safePath := RedactSensitivePath(st.path)
	reqRaw, _ := DecompressBody(st.reqBody.Bytes(), st.reqHeaders["content-encoding"])
	respRaw, _ := DecompressBody(st.respBody.Bytes(), st.respHeaders["content-encoding"])
	proto := DetectProtocol(st.path, reqRaw, respRaw)
	if proto == model.ProtocolUnknown {
		sr.recordUnknownProtocolWarnLocked(st.authority, st.path, cb.process.PID, len(reqRaw)+len(respRaw), ts)
		if sr.dropUnknown && len(sr.hostFilter) == 0 {
			return
		}
	}
	isSSE := strings.Contains(strings.ToLower(st.respHeaders["content-type"]), "text/event-stream")
	dur := ts - st.startedAt
	if dur < 0 {
		dur = 0
	}
	var reqHdrOut, respHdrOut map[string]string
	if sr.recordHeaders {
		reqHdrOut = st.reqHeaders
		respHdrOut = st.respHeaders
	}
	ev := &model.TraceEvent{
		ID:               st.eventID,
		Timestamp:        st.startedAt,
		DurationMs:       dur,
		Status:           status,
		HTTPStatus:       st.status,
		HTTPVersion:      "HTTP/2.0",
		Method:           st.method,
		Host:             st.authority,
		Path:             st.path,
		URL:              fmt.Sprintf("https://%s%s", st.authority, st.path),
		Protocol:         proto,
		Process:          cb.process,
		ConnKey:          cb.key,
		CorrelationHints: st.correlationHints,
		HeadersRecorded:  sr.recordHeaders,
		RequestHeaders:   reqHdrOut,
		ResponseHeaders:  respHdrOut,
		RequestBytes:     len(reqRaw),
		ResponseBytes:    len(respRaw),
		StreamChunks:     st.chunks,
		Error:            errReason,
	}
	_ = ParseExchange(ev, reqRaw, respRaw, isSSE)
	if sr.mon != nil && isTerminal {
		sr.mon.Record(selfmon.Event{
			Status:     selfmon.StatusOK,
			Stage:      selfmon.StageStream,
			Action:     "reassemble_http2_" + string(proto),
			PID:        cb.process.PID,
			Comm:       cb.process.Comm,
			DurationMs: dur,
			Bytes:      len(reqRaw) + len(respRaw),
			Detail:     map[string]any{"stream_id": st.streamID, "host": st.authority, "path": safePath},
		})
	}
	if sr.onEvent != nil {
		sr.onEvent(ev)
	}
}
