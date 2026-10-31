package parser

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"golang.org/x/net/http2/hpack"
)

type Direction int

const (
	DirWrite Direction = 0 // Client -> Server (Request)
	DirRead  Direction = 1 // Server -> Client (Response)
)

type RawTLSChunk struct {
	ConnKey   string
	Direction Direction
	Timestamp int64
	Process   model.ProcessInfo
	Data      []byte
}

type EventHandler func(ev *model.TraceEvent)

type StreamReassembler struct {
	mu            sync.Mutex
	conns         map[string]*connBuffer
	recordHeaders bool
	hostFilter    []string
	mon           *selfmon.Monitor
	onEvent       EventHandler
}

type h2StreamState struct {
	streamID    uint32
	startedAt   int64
	method      string
	scheme      string
	authority   string
	path        string
	reqHeaders  map[string]string
	respHeaders map[string]string
	status      int
	reqBody     bytes.Buffer
	respBody    bytes.Buffer
	reqEnded    bool
	respEnded   bool
	eventID     string
	chunks      int
}

type connBuffer struct {
	key        string
	process    model.ProcessInfo
	isHTTP2    bool
	reqBuf     bytes.Buffer
	respBuf    bytes.Buffer
	activeH1   *activeH1Exchange
	h2ReqBuf   bytes.Buffer
	h2RespBuf  bytes.Buffer
	h2Streams  map[uint32]*h2StreamState
	reqDecoder *hpack.Decoder
	rspDecoder *hpack.Decoder
	updatedAt  int64
}

type activeH1Exchange struct {
	eventID         string
	startedAt       int64
	method          string
	host            string
	path            string
	httpVersion     string
	reqHeaders      map[string]string
	reqBody         []byte
	respHeaderParsed bool
	httpStatus      int
	respHeaders     map[string]string
	contentEncoding string
	isChunked       bool
	isSSE           bool
	contentLength   int64
	respRawBody     bytes.Buffer
	streamChunks    int
}

const http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func NewStreamReassembler(recordHeaders bool, hostFilter []string, mon *selfmon.Monitor, onEvent EventHandler) *StreamReassembler {
	return &StreamReassembler{
		conns:         make(map[string]*connBuffer),
		recordHeaders: recordHeaders,
		hostFilter:    hostFilter,
		mon:           mon,
		onEvent:       onEvent,
	}
}

func (sr *StreamReassembler) SetScope(recordHeaders bool, hostFilter []string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.recordHeaders = recordHeaders
	sr.hostFilter = hostFilter
}

func (sr *StreamReassembler) IngestChunk(chunk RawTLSChunk) {
	if len(chunk.Data) == 0 {
		return
	}
	if chunk.Timestamp == 0 {
		chunk.Timestamp = time.Now().UnixMilli()
	}

	sr.mu.Lock()
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
	cb.updatedAt = chunk.Timestamp

	if !cb.isHTTP2 && bytes.Contains(chunk.Data, []byte(http2ClientPreface)) {
		cb.isHTTP2 = true
	}
	if cb.isHTTP2 {
		sr.handleHTTP2Locked(cb, chunk)
		sr.mu.Unlock()
		return
	}

	if chunk.Direction == DirWrite {
		cb.reqBuf.Write(chunk.Data)
		sr.tryParseH1RequestLocked(cb, chunk.Timestamp)
	} else {
		cb.respBuf.Write(chunk.Data)
		sr.tryParseH1ResponseLocked(cb, chunk.Timestamp)
	}
	sr.mu.Unlock()
}

func (sr *StreamReassembler) tryParseH1RequestLocked(cb *connBuffer, ts int64) {
	if cb.activeH1 != nil {
		return
	}
	data := cb.reqBuf.Bytes()
	reqStart := findHTTPRequestStart(data)
	if reqStart < 0 {
		if bytes.Contains(data, []byte("\r\n\r\n")) || len(data) > 4096 {
			cb.reqBuf.Reset()
		}
		return
	}
	if reqStart > 0 {
		cb.reqBuf.Next(reqStart)
		data = cb.reqBuf.Bytes()
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return
	}
	reqReader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		cb.reqBuf.Next(headerEnd + 4)
		return
	}
	defer req.Body.Close()

	var bodyBytes []byte
	if req.ContentLength > 0 {
		totalNeeded := headerEnd + 4 + int(req.ContentLength)
		if len(data) < totalNeeded {
			return // Wait for remaining request body bytes
		}
		bodyBytes = make([]byte, req.ContentLength)
		_, _ = io.ReadFull(req.Body, bodyBytes)
		cb.reqBuf.Next(totalNeeded)
	} else if len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
		decoded, consumed, complete := decodeChunkedAvailable(data[headerEnd+4:])
		if !complete {
			return
		}
		bodyBytes = decoded
		cb.reqBuf.Next(headerEnd + 4 + consumed)
	} else {
		cb.reqBuf.Next(headerEnd + 4)
	}

	contentEnc := req.Header.Get("Content-Encoding")
	decodedReq, err := DecompressBody(bodyBytes, contentEnc)
	if err != nil && sr.mon != nil {
		sr.mon.RecordWarn(selfmon.StageStream, "decompress_request", err.Error(), map[string]any{
			"pid": cb.process.PID, "encoding": contentEnc,
		})
	}

	reqHeaders := map[string]string{}
	if sr.recordHeaders {
		for k, vals := range req.Header {
			reqHeaders[k] = strings.Join(vals, ", ")
		}
	}

	cb.activeH1 = &activeH1Exchange{
		eventID:     "ev_" + strings.ReplaceAll(uuid.NewString()[:12], "-", ""),
		startedAt:   ts,
		method:      req.Method,
		host:        req.Host,
		path:        req.URL.RequestURI(),
		httpVersion: req.Proto,
		reqHeaders:  reqHeaders,
		reqBody:     decodedReq,
	}
	if cb.respBuf.Len() > 0 {
		sr.tryParseH1ResponseLocked(cb, ts)
	}
}

func (sr *StreamReassembler) tryParseH1ResponseLocked(cb *connBuffer, ts int64) {
	ex := cb.activeH1
	if ex == nil {
		if !bytes.Contains(cb.respBuf.Bytes(), []byte("HTTP/1.")) && cb.respBuf.Len() > 4096 {
			cb.respBuf.Reset()
		}
		return
	}
	data := cb.respBuf.Bytes()
	if !ex.respHeaderParsed {
		respStart := bytes.Index(data, []byte("HTTP/1."))
		if respStart < 0 {
			if bytes.Contains(data, []byte("\r\n\r\n")) || len(data) > 4096 {
				cb.respBuf.Reset()
			}
			return
		}
		if respStart > 0 {
			cb.respBuf.Next(respStart)
			data = cb.respBuf.Bytes()
		}
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return
	}

	if !ex.respHeaderParsed {
		headerSection := data[:headerEnd+4]
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headerSection)), nil)
		if err != nil {
			return
		}
		ex.respHeaderParsed = true
		ex.httpStatus = resp.StatusCode
		ex.contentEncoding = resp.Header.Get("Content-Encoding")
		ex.contentLength = resp.ContentLength
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		ex.isSSE = strings.Contains(ct, "text/event-stream")
		te := strings.ToLower(strings.Join(resp.TransferEncoding, ","))
		ex.isChunked = strings.Contains(te, "chunked") || strings.Contains(strings.ToLower(resp.Header.Get("Transfer-Encoding")), "chunked")
		if sr.recordHeaders {
			ex.respHeaders = make(map[string]string, len(resp.Header))
			for k, vals := range resp.Header {
				ex.respHeaders[k] = strings.Join(vals, ", ")
			}
		}
	}

	rawBodyBytes := data[headerEnd+4:]
	if ex.isChunked {
		decoded, consumed, complete := decodeChunkedAvailable(rawBodyBytes)
		ex.streamChunks++
		if ex.isSSE && isSSEDone(decoded) {
			complete = true
		}
		if ex.isSSE && len(decoded) > 0 && !complete {
			sr.emitH1ExchangeLocked(cb, ex, decoded, ts, false)
		}
		if complete {
			sr.emitH1ExchangeLocked(cb, ex, decoded, ts, true)
			cb.activeH1 = nil
			if consumed > 0 && headerEnd+4+consumed <= cb.respBuf.Len() {
				cb.respBuf.Next(headerEnd + 4 + consumed)
			} else {
				cb.respBuf.Reset()
			}
			sr.advanceKeepAliveLocked(cb, ts)
		}
		return
	}

	if ex.contentLength >= 0 {
		if int64(len(rawBodyBytes)) < ex.contentLength {
			if ex.isSSE && len(rawBodyBytes) > 0 {
				ex.streamChunks++
				sr.emitH1ExchangeLocked(cb, ex, rawBodyBytes, ts, false)
			}
			return
		}
		finalBody := rawBodyBytes[:ex.contentLength]
		sr.emitH1ExchangeLocked(cb, ex, finalBody, ts, true)
		cb.activeH1 = nil
		cb.respBuf.Next(headerEnd + 4 + int(ex.contentLength))
		sr.advanceKeepAliveLocked(cb, ts)
		return
	}

	// Streaming without Content-Length or Chunked
	if ex.isSSE {
		ex.streamChunks++
		done := isSSEDone(rawBodyBytes)
		sr.emitH1ExchangeLocked(cb, ex, rawBodyBytes, ts, done)
		if done {
			cb.activeH1 = nil
			cb.respBuf.Reset()
			sr.advanceKeepAliveLocked(cb, ts)
		}
	} else if len(rawBodyBytes) > 0 {
		decoded, err := DecompressBody(rawBodyBytes, ex.contentEncoding)
		if err == nil && json.Valid(decoded) {
			sr.emitH1ExchangeLocked(cb, ex, rawBodyBytes, ts, true)
			cb.activeH1 = nil
			cb.respBuf.Reset()
			sr.advanceKeepAliveLocked(cb, ts)
		}
	}
}

func isSSEDone(b []byte) bool {
	return bytes.Contains(b, []byte("[DONE]")) ||
		bytes.Contains(b, []byte(`"type":"message_stop"`)) ||
		bytes.Contains(b, []byte(`"type": "message_stop"`)) ||
		bytes.Contains(b, []byte(`"type":"response.completed"`)) ||
		bytes.Contains(b, []byte(`"type": "response.completed"`))
}

func (sr *StreamReassembler) advanceKeepAliveLocked(cb *connBuffer, ts int64) {
	if cb.reqBuf.Len() > 0 {
		sr.tryParseH1RequestLocked(cb, ts)
	}
	if cb.activeH1 != nil && cb.respBuf.Len() > 0 {
		sr.tryParseH1ResponseLocked(cb, ts)
	}
}

func (sr *StreamReassembler) emitH1ExchangeLocked(cb *connBuffer, ex *activeH1Exchange, rawResp []byte, ts int64, complete bool) {
	if !sr.matchesHost(ex.host) {
		return
	}
	decodedResp, err := DecompressBody(rawResp, ex.contentEncoding)
	if err != nil && complete && sr.mon != nil {
		sr.mon.RecordWarn(selfmon.StageStream, "decompress_response", err.Error(), map[string]any{
			"pid": cb.process.PID, "host": ex.host, "path": ex.path,
		})
	}

	proto := DetectProtocol(ex.path, ex.reqBody, decodedResp)
	if proto == model.ProtocolUnknown && len( sr.hostFilter ) == 0 {
		// Ignore non-LLM traffic when auto-sniffing
		return
	}

	status := "streaming"
	if complete {
		status = "ok"
		if ex.httpStatus >= 400 {
			status = "error"
		}
	}
	dur := ts - ex.startedAt
	if dur < 0 {
		dur = 0
	}
	ev := &model.TraceEvent{
		ID:              ex.eventID,
		Timestamp:       ex.startedAt,
		DurationMs:      dur,
		Status:          status,
		HTTPStatus:      ex.httpStatus,
		HTTPVersion:     ex.httpVersion,
		Method:          ex.method,
		Host:            ex.host,
		Path:            ex.path,
		URL:             fmt.Sprintf("https://%s%s", ex.host, ex.path),
		Protocol:        proto,
		Process:         cb.process,
		HeadersRecorded: sr.recordHeaders,
		RequestHeaders:  ex.reqHeaders,
		ResponseHeaders: ex.respHeaders,
		RequestBytes:    len(ex.reqBody),
		ResponseBytes:   len(decodedResp),
		StreamChunks:    ex.streamChunks,
	}
	if err := ParseExchange(ev, ex.reqBody, decodedResp, ex.isSSE); err != nil {
		if sr.mon != nil && complete {
			sr.mon.RecordError(selfmon.StageParser, "parse_"+string(proto), err, map[string]any{
				"pid": cb.process.PID, "path": ex.path,
			})
		}
	} else if sr.mon != nil && complete {
		sr.mon.Record(selfmon.Event{
			Status:     selfmon.StatusOK,
			Stage:      selfmon.StageParser,
			Action:     "parse_" + string(proto),
			PID:        cb.process.PID,
			Comm:       cb.process.Comm,
			DurationMs: dur,
			Bytes:      len(ex.reqBody) + len(decodedResp),
			Detail: map[string]any{
				"host": ex.host, "path": ex.path, "http_status": ex.httpStatus,
			},
		})
	}
	if sr.onEvent != nil {
		sr.onEvent(ev)
	}
}

// HTTP/2 frame reassembly using golang.org/x/net/http2/hpack
func (sr *StreamReassembler) handleHTTP2Locked(cb *connBuffer, chunk RawTLSChunk) {
	if chunk.Direction == DirWrite {
		data := chunk.Data
		if idx := bytes.Index(data, []byte(http2ClientPreface)); idx >= 0 {
			data = data[idx+len(http2ClientPreface):]
		}
		cb.h2ReqBuf.Write(data)
		sr.consumeH2FramesLocked(cb, &cb.h2ReqBuf, DirWrite, chunk.Timestamp)
	} else {
		cb.h2RespBuf.Write(chunk.Data)
		sr.consumeH2FramesLocked(cb, &cb.h2RespBuf, DirRead, chunk.Timestamp)
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
		st, exists := cb.h2Streams[streamID]
		if !exists {
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
				} else if strings.Contains(strings.ToLower(st.respHeaders["content-type"]), "text/event-stream") && st.respBody.Len() > 0 {
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

		if st.respEnded {
			sr.emitH2StreamLocked(cb, st, ts, true)
			delete(cb.h2Streams, streamID)
		}
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
			switch f.Name {
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
	if !sr.matchesHost(st.authority) {
		return
	}
	reqRaw, _ := DecompressBody(st.reqBody.Bytes(), st.reqHeaders["content-encoding"])
	respRaw, _ := DecompressBody(st.respBody.Bytes(), st.respHeaders["content-encoding"])
	proto := DetectProtocol(st.path, reqRaw, respRaw)
	if proto == model.ProtocolUnknown && len(sr.hostFilter) == 0 {
		return
	}
	isSSE := strings.Contains(strings.ToLower(st.respHeaders["content-type"]), "text/event-stream")
	dur := ts - st.startedAt
	if dur < 0 {
		dur = 0
	}
	status := "streaming"
	if complete {
		status = "ok"
		if st.status >= 400 {
			status = "error"
		}
	}
	var reqHdrOut, respHdrOut map[string]string
	if sr.recordHeaders {
		reqHdrOut = st.reqHeaders
		respHdrOut = st.respHeaders
	}
	ev := &model.TraceEvent{
		ID:              st.eventID,
		Timestamp:       st.startedAt,
		DurationMs:      dur,
		Status:          status,
		HTTPStatus:      st.status,
		HTTPVersion:     "HTTP/2.0",
		Method:          st.method,
		Host:            st.authority,
		Path:            st.path,
		URL:             fmt.Sprintf("https://%s%s", st.authority, st.path),
		Protocol:        proto,
		Process:         cb.process,
		HeadersRecorded: sr.recordHeaders,
		RequestHeaders:  reqHdrOut,
		ResponseHeaders: respHdrOut,
		RequestBytes:    len(reqRaw),
		ResponseBytes:   len(respRaw),
		StreamChunks:    st.chunks,
	}
	_ = ParseExchange(ev, reqRaw, respRaw, isSSE)
	if sr.mon != nil && complete {
		sr.mon.Record(selfmon.Event{
			Status:     selfmon.StatusOK,
			Stage:      selfmon.StageStream,
			Action:     "reassemble_http2_" + string(proto),
			PID:        cb.process.PID,
			Comm:       cb.process.Comm,
			DurationMs: dur,
			Bytes:      len(reqRaw) + len(respRaw),
			Detail:     map[string]any{"stream_id": st.streamID, "host": st.authority, "path": st.path},
		})
	}
	if sr.onEvent != nil {
		sr.onEvent(ev)
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

var httpRequestMethods = [][]byte{
	[]byte("POST "),
	[]byte("GET "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("PATCH "),
	[]byte("OPTIONS "),
	[]byte("HEAD "),
}

func findHTTPRequestStart(data []byte) int {
	best := -1
	for _, m := range httpRequestMethods {
		if idx := bytes.Index(data, m); idx >= 0 {
			if best < 0 || idx < best {
				best = idx
			}
		}
	}
	return best
}

func decodeChunkedAvailable(raw []byte) ([]byte, int, bool) {
	var out bytes.Buffer
	pos := 0
	for pos < len(raw) {
		lineEnd := bytes.Index(raw[pos:], []byte("\r\n"))
		if lineEnd < 0 {
			return out.Bytes(), pos, false
		}
		sizeStr := strings.TrimSpace(string(raw[pos : pos+lineEnd]))
		if semi := strings.IndexByte(sizeStr, ';'); semi >= 0 {
			sizeStr = sizeStr[:semi]
		}
		chunkSize, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return raw, pos, false
		}
		pos += lineEnd + 2
		if chunkSize == 0 {
			if pos+2 <= len(raw) && raw[pos] == '\r' && raw[pos+1] == '\n' {
				pos += 2
			}
			return out.Bytes(), pos, true
		}
		if pos+int(chunkSize)+2 > len(raw) {
			out.Write(raw[pos:])
			return out.Bytes(), pos, false
		}
		out.Write(raw[pos : pos+int(chunkSize)])
		pos += int(chunkSize) + 2
	}
	return out.Bytes(), pos, false
}
