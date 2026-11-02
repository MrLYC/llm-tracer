package parser

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type activeH1Exchange struct {
	eventID          string
	startedAt        int64
	method           string
	host             string
	path             string
	httpVersion      string
	reqHeaders       map[string]string
	correlationHints []string
	reqBody          []byte
	respHeaderParsed bool
	httpStatus       int
	respHeaders      map[string]string
	contentEncoding  string
	isChunked        bool
	isSSE            bool
	contentLength    int64
	respRawBody      bytes.Buffer
	streamChunks     int
}

func (sr *StreamReassembler) tryParseH1RequestLocked(cb *connBuffer, ts int64) bool {
	if cb.activeH1 != nil {
		data := cb.reqBuf.Bytes()
		if findHTTPRequestStart(data) < 0 && (bytes.Contains(data, []byte("\r\n\r\n")) || len(data) > MaxNonHTTPPrefixBytes) {
			cb.reqBuf.Reset()
			return false
		}
		return true
	}
	data := cb.reqBuf.Bytes()
	reqStart := findHTTPRequestStart(data)
	if reqStart < 0 {
		if bytes.Contains(data, []byte("\r\n\r\n")) || len(data) > MaxNonHTTPPrefixBytes {
			cb.reqBuf.Reset()
			return false
		}
		return false
	}
	if reqStart > 0 {
		cb.reqBuf.Next(reqStart)
		data = cb.reqBuf.Bytes()
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return true
	}
	reqReader := bufio.NewReader(bytes.NewReader(data))
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		cb.reqBuf.Next(headerEnd + 4)
		return false
	}
	defer req.Body.Close()

	bodyAvail := len(data) - (headerEnd + 4)
	var bodyBytes []byte
	if req.ContentLength > 0 {
		if int64(bodyAvail) < req.ContentLength {
			return true // Wait for remaining request body bytes
		}
		totalNeeded := headerEnd + 4 + int(req.ContentLength)
		bodyBytes = make([]byte, int(req.ContentLength))
		_, _ = io.ReadFull(req.Body, bodyBytes)
		cb.reqBuf.Next(totalNeeded)
	} else if len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
		decoded, consumed, complete := decodeChunkedAvailable(data[headerEnd+4:])
		if !complete {
			return true
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
		eventID:          "ev_" + strings.ReplaceAll(uuid.NewString()[:12], "-", ""),
		startedAt:        ts,
		method:           req.Method,
		host:             req.Host,
		path:             req.URL.RequestURI(),
		httpVersion:      req.Proto,
		reqHeaders:       reqHeaders,
		correlationHints: extractCorrelationHintsFromHeader(req.Header.Get),
		reqBody:          decodedReq,
	}
	if cb.respBuf.Len() > 0 {
		sr.tryParseH1ResponseLocked(cb, ts)
	}
	return true
}

func (sr *StreamReassembler) extractPartialH1RequestLocked(cb *connBuffer, raw []byte, ts int64) *activeH1Exchange {
	reqStart := findHTTPRequestStart(raw)
	if reqStart < 0 {
		return nil
	}
	data := raw[reqStart:]
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil
	}
	headerSection := data[:headerEnd+4]
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(headerSection)))
	if err != nil {
		return nil
	}
	defer req.Body.Close()

	rawBody := data[headerEnd+4:]
	if req.ContentLength > 0 && int64(len(rawBody)) > req.ContentLength {
		rawBody = rawBody[:req.ContentLength]
	} else if len(req.TransferEncoding) > 0 && req.TransferEncoding[0] == "chunked" {
		decoded, _, _ := decodeChunkedAvailable(rawBody)
		rawBody = decoded
	}
	decodedReq, _ := DecompressBody(rawBody, req.Header.Get("Content-Encoding"))

	var reqHeaders map[string]string
	if sr.recordHeaders {
		reqHeaders = make(map[string]string, len(req.Header))
		for k, vals := range req.Header {
			reqHeaders[k] = strings.Join(vals, ", ")
		}
	}
	return &activeH1Exchange{
		eventID:          "ev_" + strings.ReplaceAll(uuid.NewString()[:12], "-", ""),
		startedAt:        ts,
		method:           req.Method,
		host:             req.Host,
		path:             req.URL.RequestURI(),
		httpVersion:      req.Proto,
		reqHeaders:       reqHeaders,
		correlationHints: extractCorrelationHintsFromHeader(req.Header.Get),
		reqBody:          decodedReq,
	}
}

func (sr *StreamReassembler) extractPartialH1ResponseBodyLocked(cb *connBuffer, ex *activeH1Exchange) []byte {
	if ex == nil {
		return nil
	}
	if ex.respRawBody.Len() > 0 {
		raw := ex.respRawBody.Bytes()
		if len(raw) > MaxConnBufferBytes {
			raw = raw[:MaxConnBufferBytes]
		}
		return append([]byte(nil), raw...)
	}
	data := cb.respBuf.Bytes()
	if len(data) == 0 {
		return nil
	}
	if !ex.respHeaderParsed {
		if respStart := bytes.Index(data, []byte("HTTP/1.")); respStart >= 0 {
			data = data[respStart:]
			if headerEnd := bytes.Index(data, []byte("\r\n\r\n")); headerEnd >= 0 {
				if resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data[:headerEnd+4])), nil); err == nil {
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
			}
		}
	}
	if !ex.respHeaderParsed {
		return nil
	}
	hdrEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if hdrEnd < 0 {
		return nil
	}
	partialResp := data[hdrEnd+4:]
	if len(partialResp) > MaxConnBufferBytes {
		partialResp = partialResp[:MaxConnBufferBytes]
	}
	if ex.isChunked && len(partialResp) > 0 {
		decoded, _, _ := decodeChunkedAvailable(partialResp)
		return decoded
	}
	return append([]byte(nil), partialResp...)
}

func (sr *StreamReassembler) tryParseH1ResponseLocked(cb *connBuffer, ts int64) bool {
	ex := cb.activeH1
	if ex == nil {
		data := cb.respBuf.Bytes()
		if cb.respBuf.Len() > MaxNonHTTPPrefixBytes || (!bytes.Contains(data, []byte("HTTP/1.")) && bytes.Contains(data, []byte("\r\n\r\n"))) {
			cb.respBuf.Reset()
		}
		return false
	}
	data := cb.respBuf.Bytes()
	if !ex.respHeaderParsed {
		respStart := bytes.Index(data, []byte("HTTP/1."))
		if respStart < 0 {
			if bytes.Contains(data, []byte("\r\n\r\n")) || len(data) > MaxNonHTTPPrefixBytes {
				cb.respBuf.Reset()
			}
			return false
		}
		if respStart > 0 {
			cb.respBuf.Next(respStart)
			data = cb.respBuf.Bytes()
		}
	}
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return true
	}

	if !ex.respHeaderParsed {
		headerSection := data[:headerEnd+4]
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headerSection)), nil)
		if err != nil {
			cb.respBuf.Next(headerEnd + 4)
			return false
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
		return true
	}

	if ex.contentLength >= 0 {
		if int64(len(rawBodyBytes)) < ex.contentLength {
			if ex.isSSE && len(rawBodyBytes) > 0 {
				ex.streamChunks++
				sr.emitH1ExchangeLocked(cb, ex, rawBodyBytes, ts, false)
			}
			return true
		}
		finalBody := rawBodyBytes[:int(ex.contentLength)]
		sr.emitH1ExchangeLocked(cb, ex, finalBody, ts, true)
		cb.activeH1 = nil
		cb.respBuf.Next(headerEnd + 4 + int(ex.contentLength))
		sr.advanceKeepAliveLocked(cb, ts)
		return true
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
	return true
}

func isSSEDone(b []byte) bool {
	return bytes.Contains(b, []byte("[DONE]")) ||
		bytes.Contains(b, []byte(`"type":"message_stop"`)) ||
		bytes.Contains(b, []byte(`"type": "message_stop"`)) ||
		bytes.Contains(b, []byte(`"type":"response.completed"`)) ||
		bytes.Contains(b, []byte(`"type": "response.completed"`)) ||
		bytes.Contains(b, []byte(`"finishReason":"STOP"`)) ||
		bytes.Contains(b, []byte(`"finishReason": "STOP"`))
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
	status := "streaming"
	if complete {
		status = "ok"
		if ex.httpStatus >= 400 {
			status = "error"
		}
	}
	sr.emitH1WithStatusLocked(cb, ex, rawResp, ts, status, "", complete)
}

func (sr *StreamReassembler) emitH1TerminalExchangeLocked(cb *connBuffer, ex *activeH1Exchange, rawResp []byte, ts int64, terminalStatus string, reason string) {
	if ex == nil || (ex.method == "" && ex.path == "" && len(ex.reqBody) == 0 && len(rawResp) == 0) {
		return
	}
	if terminalStatus == "" {
		terminalStatus = "incomplete"
	}
	sr.emitH1WithStatusLocked(cb, ex, rawResp, ts, terminalStatus, reason, true)
}

func (sr *StreamReassembler) emitH1WithStatusLocked(cb *connBuffer, ex *activeH1Exchange, rawResp []byte, ts int64, status string, errReason string, isTerminal bool) {
	if !sr.matchesHost(ex.host) {
		return
	}
	safePath := RedactSensitivePath(ex.path)
	decodedResp, err := DecompressBody(rawResp, ex.contentEncoding)
	if err != nil && isTerminal && sr.mon != nil {
		sr.mon.RecordWarn(selfmon.StageStream, "decompress_response", err.Error(), map[string]any{
			"pid": cb.process.PID, "host": ex.host, "path": safePath,
		})
	}

	proto := DetectProtocol(ex.path, ex.reqBody, decodedResp)
	if proto == model.ProtocolUnknown {
		sr.recordUnknownProtocolWarnLocked(ex.host, ex.path, cb.process.PID, len(ex.reqBody)+len(decodedResp), ts)
		if sr.dropUnknown && len(sr.hostFilter) == 0 {
			// Ignore non-LLM traffic when auto-sniffing and dropUnknown is enabled
			return
		}
	}

	dur := ts - ex.startedAt
	if dur < 0 {
		dur = 0
	}
	ev := &model.TraceEvent{
		ID:               ex.eventID,
		Timestamp:        ex.startedAt,
		DurationMs:       dur,
		Status:           status,
		HTTPStatus:       ex.httpStatus,
		HTTPVersion:      ex.httpVersion,
		Method:           ex.method,
		Host:             ex.host,
		Path:             ex.path,
		URL:              fmt.Sprintf("https://%s%s", ex.host, ex.path),
		Protocol:         proto,
		Process:          cb.process,
		ConnKey:          cb.key,
		CorrelationHints: ex.correlationHints,
		HeadersRecorded:  sr.recordHeaders,
		RequestHeaders:   ex.reqHeaders,
		ResponseHeaders:  ex.respHeaders,
		RequestBytes:     len(ex.reqBody),
		ResponseBytes:    len(decodedResp),
		StreamChunks:     ex.streamChunks,
		Error:            errReason,
	}
	if err := ParseExchange(ev, ex.reqBody, decodedResp, ex.isSSE); err != nil {
		if sr.mon != nil && isTerminal {
			sr.mon.RecordError(selfmon.StageParser, "parse_"+string(proto), err, map[string]any{
				"pid": cb.process.PID, "path": safePath,
			})
		}
	} else if sr.mon != nil && isTerminal {
		sr.mon.Record(selfmon.Event{
			Status:     selfmon.StatusOK,
			Stage:      selfmon.StageParser,
			Action:     "parse_" + string(proto),
			PID:        cb.process.PID,
			Comm:       cb.process.Comm,
			DurationMs: dur,
			Bytes:      len(ex.reqBody) + len(decodedResp),
			Detail: map[string]any{
				"host": ex.host, "path": safePath, "http_status": ex.httpStatus,
			},
		})
	}
	if sr.onEvent != nil {
		sr.onEvent(ev)
	}
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
		searchFrom := 0
		for searchFrom < len(data) {
			rel := bytes.Index(data[searchFrom:], m)
			if rel < 0 {
				break
			}
			idx := searchFrom + rel
			if isPlausibleHTTPRequestLine(data[idx:]) {
				if best < 0 || idx < best {
					best = idx
				}
				break
			}
			searchFrom = idx + len(m)
		}
	}
	return best
}

func isPlausibleHTTPRequestLine(b []byte) bool {
	lineEnd := bytes.Index(b, []byte("\r\n"))
	if lineEnd < 0 {
		// Incomplete first line: plausible only if reasonably short and has no bare newline.
		return len(b) <= MaxNonHTTPPrefixBytes && bytes.IndexByte(b, '\n') < 0
	}
	line := b[:lineEnd]
	return bytes.Contains(line, []byte(" HTTP/1."))
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
		if err != nil || chunkSize < 0 {
			return raw, pos, false
		}
		pos += lineEnd + 2
		if chunkSize == 0 {
			if pos+2 <= len(raw) && raw[pos] == '\r' && raw[pos+1] == '\n' {
				pos += 2
			}
			return out.Bytes(), pos, true
		}
		rem := len(raw) - pos
		if chunkSize > int64(rem) || int(chunkSize)+2 > rem {
			out.Write(raw[pos:])
			return out.Bytes(), pos, false
		}
		n := int(chunkSize)
		out.Write(raw[pos : pos+n])
		pos += n + 2
	}
	return out.Bytes(), pos, false
}
