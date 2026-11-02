package parser

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func buildH2ExchangeFrames(t *testing.T, authHeader, totpHeader, cookieHeader string) ([]byte, []byte) {
	t.Helper()

	var reqHpack bytes.Buffer
	encReq := hpack.NewEncoder(&reqHpack)
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"}))
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"}))
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.openai.com"}))
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: ":path", Value: "/v1/chat/completions"}))
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"}))
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: "authorization", Value: authHeader}))
	require.NoError(t, encReq.WriteField(hpack.HeaderField{Name: "x-virtx-totp", Value: totpHeader}))

	reqPayload := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello h2"}]}`)
	var clientBuf bytes.Buffer
	clientBuf.WriteString(http2ClientPreface)
	writeH2Frame(&clientBuf, 0x1, 0x4, 1, reqHpack.Bytes())
	writeH2Frame(&clientBuf, 0x0, 0x1, 1, reqPayload)

	var respHpack bytes.Buffer
	encResp := hpack.NewEncoder(&respHpack)
	require.NoError(t, encResp.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}))
	require.NoError(t, encResp.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"}))
	require.NoError(t, encResp.WriteField(hpack.HeaderField{Name: "set-cookie", Value: cookieHeader}))

	respPayload := []byte(`{"choices":[{"message":{"role":"assistant","content":"world h2"},"finish_reason":"stop"}],"usage":{"total_tokens":12}}`)
	var serverBuf bytes.Buffer
	writeH2Frame(&serverBuf, 0x1, 0x4, 1, respHpack.Bytes())
	writeH2Frame(&serverBuf, 0x0, 0x1, 1, respPayload)

	return clientBuf.Bytes(), serverBuf.Bytes()
}

func TestParserLayerHeaderGating_H2StreamReassembler(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)

	clientBytes, serverBytes := buildH2ExchangeFrames(
		t,
		"Bearer sk-live-h2-parser-secret",
		"JBSWY3DPEHPK3PXP",
		"session=h2-resp-secret",
	)

	// 1. Negative case: recordHeaders=false must produce nil headers and HeadersRecorded=false
	var offEvents []*model.TraceEvent
	srOff := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		offEvents = append(offEvents, ev)
	})
	srOff.IngestChunk(RawTLSChunk{
		ConnKey:   "200:h2_off",
		Direction: DirWrite,
		Timestamp: 1000,
		Process:   model.ProcessInfo{PID: 200, Comm: "agent"},
		Data:      clientBytes,
	})
	srOff.IngestChunk(RawTLSChunk{
		ConnKey:   "200:h2_off",
		Direction: DirRead,
		Timestamp: 1010,
		Process:   model.ProcessInfo{PID: 200, Comm: "agent"},
		Data:      serverBytes,
	})

	require.Len(t, offEvents, 1)
	evOff := offEvents[0]
	require.Equal(t, "HTTP/2.0", evOff.HTTPVersion)
	require.Equal(t, model.ProtocolOpenAIChat, evOff.Protocol)
	require.False(t, evOff.HeadersRecorded, "H2 event must have HeadersRecorded=false when recordHeaders=false")
	require.Nil(t, evOff.RequestHeaders, "H2 event RequestHeaders must be nil when recordHeaders=false")
	require.Nil(t, evOff.ResponseHeaders, "H2 event ResponseHeaders must be nil when recordHeaders=false")

	// 2. Positive case: recordHeaders=true must populate RequestHeaders and ResponseHeaders
	var onEvents []*model.TraceEvent
	srOn := NewStreamReassembler(true, nil, mon, func(ev *model.TraceEvent) {
		onEvents = append(onEvents, ev)
	})
	srOn.IngestChunk(RawTLSChunk{
		ConnKey:   "201:h2_on",
		Direction: DirWrite,
		Timestamp: 2000,
		Process:   model.ProcessInfo{PID: 201, Comm: "agent"},
		Data:      clientBytes,
	})
	srOn.IngestChunk(RawTLSChunk{
		ConnKey:   "201:h2_on",
		Direction: DirRead,
		Timestamp: 2015,
		Process:   model.ProcessInfo{PID: 201, Comm: "agent"},
		Data:      serverBytes,
	})

	require.Len(t, onEvents, 1)
	evOn := onEvents[0]
	require.True(t, evOn.HeadersRecorded, "H2 event must have HeadersRecorded=true when recordHeaders=true")
	require.NotNil(t, evOn.RequestHeaders, "H2 event RequestHeaders must be populated when recordHeaders=true")
	require.NotNil(t, evOn.ResponseHeaders, "H2 event ResponseHeaders must be populated when recordHeaders=true")
	require.Equal(t, "Bearer sk-live-h2-parser-secret", evOn.RequestHeaders["authorization"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", evOn.RequestHeaders["x-virtx-totp"])
	require.Equal(t, "session=h2-resp-secret", evOn.ResponseHeaders["set-cookie"])

	// 3. Dynamic SetScope toggle back to false must immediately gate headers off again
	srOn.SetScope(false, nil)
	srOn.IngestChunk(RawTLSChunk{
		ConnKey:   "202:h2_toggled_off",
		Direction: DirWrite,
		Timestamp: 3000,
		Process:   model.ProcessInfo{PID: 202, Comm: "agent"},
		Data:      clientBytes,
	})
	srOn.IngestChunk(RawTLSChunk{
		ConnKey:   "202:h2_toggled_off",
		Direction: DirRead,
		Timestamp: 3010,
		Process:   model.ProcessInfo{PID: 202, Comm: "agent"},
		Data:      serverBytes,
	})
	require.Len(t, onEvents, 2)
	evToggledOff := onEvents[1]
	require.False(t, evToggledOff.HeadersRecorded)
	require.Nil(t, evToggledOff.RequestHeaders)
	require.Nil(t, evToggledOff.ResponseHeaders)
}

func TestParserLayerHeaderGating_H1StreamReassembler(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)

	reqBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping h1"}]}`
	rawReq := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Authorization: Bearer sk-live-h1-parser-secret\r\n" +
		"X-VirtX-TOTP: JBSWY3DPEHPK3PXP\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody

	respBody := `{"choices":[{"message":{"role":"assistant","content":"pong h1"},"finish_reason":"stop"}],"usage":{"total_tokens":8}}`
	rawResp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Set-Cookie: session=h1-resp-secret\r\n" +
		"Content-Length: " + strconv.Itoa(len(respBody)) + "\r\n\r\n" + respBody

	// 1. Negative case: recordHeaders=false
	var offEvents []*model.TraceEvent
	srOff := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		offEvents = append(offEvents, ev)
	})
	srOff.IngestChunk(RawTLSChunk{
		ConnKey:   "300:h1_off",
		Direction: DirWrite,
		Timestamp: 1000,
		Process:   model.ProcessInfo{PID: 300, Comm: "curl"},
		Data:      []byte(rawReq),
	})
	// Before response arrives (before ParseExchange runs), activeH1.reqHeaders must already be empty
	srOff.mu.Lock()
	cbOff := srOff.conns["300:h1_off"]
	require.NotNil(t, cbOff)
	require.NotNil(t, cbOff.activeH1)
	require.Empty(t, cbOff.activeH1.reqHeaders, "H1 active exchange must not record request headers when recordHeaders=false")
	srOff.mu.Unlock()

	srOff.IngestChunk(RawTLSChunk{
		ConnKey:   "300:h1_off",
		Direction: DirRead,
		Timestamp: 1020,
		Process:   model.ProcessInfo{PID: 300, Comm: "curl"},
		Data:      []byte(rawResp),
	})
	require.Len(t, offEvents, 1)
	require.False(t, offEvents[0].HeadersRecorded)
	require.Nil(t, offEvents[0].RequestHeaders)
	require.Nil(t, offEvents[0].ResponseHeaders)

	// 2. Positive case: recordHeaders=true
	var onEvents []*model.TraceEvent
	srOn := NewStreamReassembler(true, nil, mon, func(ev *model.TraceEvent) {
		onEvents = append(onEvents, ev)
	})
	srOn.IngestChunk(RawTLSChunk{
		ConnKey:   "301:h1_on",
		Direction: DirWrite,
		Timestamp: 2000,
		Process:   model.ProcessInfo{PID: 301, Comm: "curl"},
		Data:      []byte(rawReq),
	})
	srOn.IngestChunk(RawTLSChunk{
		ConnKey:   "301:h1_on",
		Direction: DirRead,
		Timestamp: 2020,
		Process:   model.ProcessInfo{PID: 301, Comm: "curl"},
		Data:      []byte(rawResp),
	})
	require.Len(t, onEvents, 1)
	require.True(t, onEvents[0].HeadersRecorded)
	require.NotNil(t, onEvents[0].RequestHeaders)
	require.NotNil(t, onEvents[0].ResponseHeaders)
	require.Equal(t, "Bearer sk-live-h1-parser-secret", onEvents[0].RequestHeaders["Authorization"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", onEvents[0].RequestHeaders["X-Virtx-Totp"])
	require.Equal(t, "session=h1-resp-secret", onEvents[0].ResponseHeaders["Set-Cookie"])
}

func TestParserLayerHeaderGating_ParseExchange(t *testing.T) {
	reqBody := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`)
	respBody := []byte(`{"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`)

	// 1. Negative case: HeadersRecorded=false with pre-populated headers must scrub them to nil
	evOff := &model.TraceEvent{
		Host:            "api.openai.com",
		Path:            "/v1/chat/completions?api_key=sk-query-secret-123",
		URL:             "https://api.openai.com/v1/chat/completions?api_key=sk-query-secret-123",
		HeadersRecorded: false,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer sk-live-parse-exchange-secret",
			"X-VirtX-TOTP":  "JBSWY3DPEHPK3PXP",
		},
		ResponseHeaders: map[string]string{
			"Set-Cookie": "session=parse-exchange-resp-secret",
		},
	}
	require.NoError(t, ParseExchange(evOff, reqBody, respBody, false))
	require.False(t, evOff.HeadersRecorded)
	require.Nil(t, evOff.RequestHeaders, "ParseExchange must clear RequestHeaders when HeadersRecorded=false")
	require.Nil(t, evOff.ResponseHeaders, "ParseExchange must clear ResponseHeaders when HeadersRecorded=false")
	require.NotContains(t, evOff.Path, "sk-query-secret-123")
	require.NotContains(t, evOff.URL, "sk-query-secret-123")

	// 2. Positive case: HeadersRecorded=true must preserve RequestHeaders and ResponseHeaders
	evOn := &model.TraceEvent{
		Host:            "api.openai.com",
		Path:            "/v1/chat/completions?api_key=sk-query-secret-123",
		URL:             "https://api.openai.com/v1/chat/completions?api_key=sk-query-secret-123",
		HeadersRecorded: true,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer sk-live-parse-exchange-secret",
			"X-VirtX-TOTP":  "JBSWY3DPEHPK3PXP",
		},
		ResponseHeaders: map[string]string{
			"Set-Cookie": "session=parse-exchange-resp-secret",
		},
	}
	require.NoError(t, ParseExchange(evOn, reqBody, respBody, false))
	require.True(t, evOn.HeadersRecorded)
	require.NotNil(t, evOn.RequestHeaders)
	require.NotNil(t, evOn.ResponseHeaders)
	require.Equal(t, "Bearer sk-live-parse-exchange-secret", evOn.RequestHeaders["Authorization"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", evOn.RequestHeaders["X-VirtX-TOTP"])
	require.Equal(t, "session=parse-exchange-resp-secret", evOn.ResponseHeaders["Set-Cookie"])
}

// TestParserLayerHeaderGating_H2ConstructorGateIsolation verifies that emitH2WithStatusLocked
// in stream_h2.go independently gates reqHdrOut/respHdrOut and HeadersRecorded behind sr.recordHeaders
// before calling ParseExchange, so a single-layer mutation in stream_h2.go cannot be masked by ParseExchange.
func TestParserLayerHeaderGating_H2ConstructorGateIsolation(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "stream_h2.go", nil, 0)
	require.NoError(t, err)

	var emitFn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "emitH2WithStatusLocked" {
			emitFn = fn
			break
		}
	}
	require.NotNil(t, emitFn, "emitH2WithStatusLocked must exist in stream_h2.go")

	isSRRecordHeaders := func(expr ast.Expr) bool {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "recordHeaders" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "sr"
	}

	isStHeaderAssign := func(stmt ast.Stmt, lhsName, rhsField string) bool {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return false
		}
		lhs, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != lhsName {
			return false
		}
		sel, ok := assign.Rhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != rhsField {
			return false
		}
		xId, ok := sel.X.(*ast.Ident)
		return ok && xId.Name == "st"
	}

	gatedReqHdr := false
	gatedRespHdr := false
	ungatedHeaderAssign := false
	headersRecordedUsesSRField := false

	for _, stmt := range emitFn.Body.List {
		if isStHeaderAssign(stmt, "reqHdrOut", "reqHeaders") || isStHeaderAssign(stmt, "respHdrOut", "respHeaders") {
			ungatedHeaderAssign = true
		}
		if ifStmt, ok := stmt.(*ast.IfStmt); ok {
			if isSRRecordHeaders(ifStmt.Cond) && ifStmt.Else == nil {
				for _, inner := range ifStmt.Body.List {
					if isStHeaderAssign(inner, "reqHdrOut", "reqHeaders") {
						gatedReqHdr = true
					}
					if isStHeaderAssign(inner, "respHdrOut", "respHeaders") {
						gatedRespHdr = true
					}
				}
			}
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if kId, ok := kv.Key.(*ast.Ident); ok && kId.Name == "HeadersRecorded" {
					if isSRRecordHeaders(kv.Value) {
						headersRecordedUsesSRField = true
					}
				}
			}
			return true
		})
	}

	require.False(t, ungatedHeaderAssign, "stream_h2.go must not assign reqHdrOut/respHdrOut outside of `if sr.recordHeaders` gate")
	require.True(t, gatedReqHdr, "stream_h2.go must gate `reqHdrOut = st.reqHeaders` behind `if sr.recordHeaders`")
	require.True(t, gatedRespHdr, "stream_h2.go must gate `respHdrOut = st.respHeaders` behind `if sr.recordHeaders`")
	require.True(t, headersRecordedUsesSRField, "stream_h2.go TraceEvent literal must set `HeadersRecorded: sr.recordHeaders`")
}
