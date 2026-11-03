package parser

import (
	"bytes"
	"compress/gzip"
	"strconv"
	"testing"

	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func TestParseSystemOneAndArgmaxFallback(t *testing.T) {
	reqJSON := []byte(`{
		"model": "startlux-decision-27b-autothink",
		"state": {
			"page": {
				"url": "https://github.com/BurntSushi/ripgrep/releases",
				"title": "Releases · BurntSushi/ripgrep",
				"text": "ripgrep 14.1.1 release assets"
			},
			"elements": [
				{"index": "1", "role": "link", "label": "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz", "operations": ["CLICK"]}
			],
			"recent_actions": [
				{"step": 1, "operation": "CLICK", "element": "[2] Releases"}
			]
		},
		"questions": {
			"operation": {
				"type": "choice",
				"criteria": {
					"CLICK": "Click an element",
					"DONE": "Finish and select download asset",
					"BLOCKED": "Cannot progress"
				},
				"instructions": {
					"goal": "Find ripgrep release for linux/amd64",
					"guide": ["On the release page, choose DONE on the matching asset."]
				}
			},
			"done_target": {
				"type": "choice",
				"criteria": {
					"1": {
						"element": "[1] ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz",
						"role": "link",
						"href": "https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz"
					}
				},
				"instructions": {
					"goal": "Find ripgrep release for linux/amd64",
					"operation": "DONE"
				}
			}
		}
	}`)

	respJSON := []byte(`{
		"model": "startlux-decision-27b-autothink",
		"answers": {
			"operation": {
				"type": "choice",
				"choice": null,
				"confidence": 0.94,
				"probabilities": {
					"CLICK": 0.05,
					"DONE": 0.93,
					"BLOCKED": 0.02
				}
			},
			"done_target": {
				"type": "choice",
				"choice": "1",
				"confidence": 0.98,
				"probabilities": {
					"1": 1.0
				}
			}
		}
	}`)

	proto := DetectProtocol("/v1/systemone", reqJSON, respJSON)
	require.Equal(t, model.ProtocolSystemOne, proto)

	s1, err := ParseSystemOne(reqJSON, respJSON)
	require.NoError(t, err)
	require.Equal(t, "startlux-decision-27b-autothink", s1.Model)
	require.Equal(t, "Find ripgrep release for linux/amd64", s1.Goal)
	require.Equal(t, "DONE", s1.SelectedOp)
	require.Equal(t, "1", s1.SelectedTarget)
	require.Contains(t, s1.SelectedElement, "ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz")
	require.Contains(t, s1.FallbackReason, "operation choice was null; used argmax DONE")
	require.Equal(t, []string{"operation", "done_target"}, s1.QuestionsUsed)
}

func TestParseAllLLMProtocols(t *testing.T) {
	// 1. OpenAI SSE
	oaiReq := []byte(`{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"hello"}]}`)
	oaiSSE := []byte("data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-5\",\"choices\":[{\"delta\":{\"reasoning_content\":\"thinking...\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15}}\n\n" +
		"data: [DONE]\n\n")
	chat, err := ParseOpenAIChat(oaiReq, oaiSSE, true)
	require.NoError(t, err)
	require.Equal(t, "gpt-5", chat.Model)
	require.Equal(t, "world", chat.ResponseText)
	require.Equal(t, "thinking...", chat.ReasoningText)
	require.Equal(t, 15, chat.Usage.TotalTokens)

	// 2. Anthropic SSE
	anthReq := []byte(`{"model":"claude-sonnet-4","system":"You are helpful","messages":[{"role":"user","content":"hi"}]}`)
	anthSSE := []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"step 1\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"done!\"}}\n\n" +
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":12,\"output_tokens\":8}}\n\n")
	ac, err := ParseAnthropic(anthReq, anthSSE, true)
	require.NoError(t, err)
	require.Equal(t, "claude-sonnet-4", ac.Model)
	require.Equal(t, "done!", ac.ResponseText)
	require.Equal(t, "step 1", ac.ReasoningText)
	require.Equal(t, 20, ac.Usage.TotalTokens)

	// 3. OpenAI Responses API
	respReq := []byte(`{"model":"gpt-5-codex","instructions":"be concise","input":"explain ebpf"}`)
	respOut := []byte(`{"id":"resp_123","output_text":"eBPF runs sandboxed programs in kernel.","usage":{"input_tokens":5,"output_tokens":7,"total_tokens":12}}`)
	rc, err := ParseOpenAIResponses(respReq, respOut, false)
	require.NoError(t, err)
	require.Equal(t, "eBPF runs sandboxed programs in kernel.", rc.ResponseText)
}

func TestStreamReassemblerDefaultNoHeadersAndHTTP2(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	var captured []*model.TraceEvent
	// Default recordHeaders = false
	sr := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		captured = append(captured, ev)
	})

	// Feed HTTP/1.1 gzip-compressed response with sensitive Authorization header
	reqBody := `{"model":"deepseek-chat","messages":[{"role":"user","content":"ping"}]}`
	rawReq := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.deepseek.com\r\n" +
		"Authorization: Bearer sk-secret-credential-do-not-record\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	_, _ = gw.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"pong"},"finish_reason":"stop"}],"usage":{"total_tokens":9}}`))
	_ = gw.Close()

	rawResp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Encoding: gzip\r\n" +
		"Set-Cookie: session=topsecret\r\n" +
		"Content-Length: " + string(rune(gzBuf.Len())) + "\r\n\r\n"
	_ = rawResp

	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "100:ssl_1",
		Direction: DirWrite,
		Process:   model.ProcessInfo{PID: 100, Comm: "python3"},
		Data:      []byte(rawReq),
	})
	respPacket := append([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nSet-Cookie: secret=1\r\n\r\n"), gzBuf.Bytes()...)
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "100:ssl_1",
		Direction: DirRead,
		Process:   model.ProcessInfo{PID: 100, Comm: "python3"},
		Data:      respPacket,
	})

	require.Len(t, captured, 1)
	ev := captured[0]
	require.Equal(t, model.ProtocolOpenAIChat, ev.Protocol)
	require.False(t, ev.HeadersRecorded)
	require.Nil(t, ev.RequestHeaders, "headers must be nil by default to prevent credential leak")
	require.Nil(t, ev.ResponseHeaders)
	require.NotContains(t, ev.RequestRaw, "sk-secret-credential")
	require.Equal(t, "pong", ev.Chat.ResponseText)

	// Test HTTP/2 frame reassembly with HPACK
	var reqHpack bytes.Buffer
	enc := hpack.NewEncoder(&reqHpack)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.bamboonode.dev"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/v1/systemone"})
	_ = enc.WriteField(hpack.HeaderField{Name: "authorization", Value: "Bearer secret-jev-key"})

	h2ReqPayload := []byte(`{"model":"jev","state":{"page":{"url":"https://github.com"}},"questions":{"operation":{"type":"choice","criteria":{"DONE":"done"},"instructions":{"goal":"test h2"}}}}`)
	var h2ClientBytes bytes.Buffer
	h2ClientBytes.WriteString(http2ClientPreface)
	writeH2Frame(&h2ClientBytes, 0x1, 0x4, 1, reqHpack.Bytes()) // HEADERS
	writeH2Frame(&h2ClientBytes, 0x0, 0x1, 1, h2ReqPayload)     // DATA + END_STREAM

	var respHpack bytes.Buffer
	encResp := hpack.NewEncoder(&respHpack)
	_ = encResp.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = encResp.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})
	h2RespPayload := []byte(`{"model":"jev","answers":{"operation":{"type":"choice","choice":"DONE","confidence":0.99,"probabilities":{"DONE":1.0}}}}`)
	var h2ServerBytes bytes.Buffer
	writeH2Frame(&h2ServerBytes, 0x1, 0x4, 1, respHpack.Bytes())
	writeH2Frame(&h2ServerBytes, 0x0, 0x1, 1, h2RespPayload)

	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "101:h2",
		Direction: DirWrite,
		Process:   model.ProcessInfo{PID: 101, Comm: "jev-release"},
		Data:      h2ClientBytes.Bytes(),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "101:h2",
		Direction: DirRead,
		Process:   model.ProcessInfo{PID: 101, Comm: "jev-release"},
		Data:      h2ServerBytes.Bytes(),
	})

	require.Len(t, captured, 2)
	h2Ev := captured[1]
	require.Equal(t, "HTTP/2.0", h2Ev.HTTPVersion)
	require.Equal(t, model.ProtocolSystemOne, h2Ev.Protocol)
	require.Equal(t, "DONE", h2Ev.SystemOne.SelectedOp)
	require.Nil(t, h2Ev.RequestHeaders)
}

func TestQueryKeyRedactionKeepAliveAndH2Streaming(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	var events []*model.TraceEvent
	sr := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		cp := *ev
		events = append(events, &cp)
	})

	// 1. Gemini request with ?key=test_gemini_secret_key must redact key in Path and URL when recordHeaders=false
	gemReq := `{"contents":[{"role":"user","parts":[{"text":"hi gemini"}]}]}`
	gemResp := `{"candidates":[{"content":{"parts":[{"text":"hello from gemini"}]}}]}`
	raw1 := "POST /v1beta/models/gemini-2.5-pro:generateContent?key=test_gemini_secret_key&alt=json HTTP/1.1\r\n" +
		"Host: generativelanguage.googleapis.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(gemReq)) + "\r\n\r\n" + gemReq
	resp1 := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(gemResp)) + "\r\n\r\n" + gemResp

	// 2. Second request on the SAME Keep-Alive connection
	oaiReq := `{"model":"gpt-4o","messages":[{"role":"user","content":"second on keepalive"}]}`
	oaiResp := `{"model":"gpt-4o","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"second ok"}}]}`
	raw2 := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(oaiReq)) + "\r\n\r\n" + oaiReq
	resp2 := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(oaiResp)) + "\r\n\r\n" + oaiResp

	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "200:keepalive",
		Direction: DirWrite,
		Process:   model.ProcessInfo{PID: 200, Comm: "agent"},
		Data:      []byte(raw1 + raw2),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "200:keepalive",
		Direction: DirRead,
		Process:   model.ProcessInfo{PID: 200, Comm: "agent"},
		Data:      []byte(resp1 + resp2),
	})

	require.Len(t, events, 2)
	require.Equal(t, model.ProtocolGemini, events[0].Protocol)
	require.Contains(t, events[0].Path, "key=[REDACTED]")
	require.NotContains(t, events[0].Path, "test_gemini_secret_key")
	require.NotContains(t, events[0].URL, "test_gemini_secret_key")
	require.Equal(t, model.ProtocolOpenAIChat, events[1].Protocol)
	require.Equal(t, "second ok", events[1].Chat.ResponseText)

	// 3. HTTP/2 SSE incremental streaming
	events = nil
	var reqHpack bytes.Buffer
	enc := hpack.NewEncoder(&reqHpack)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.openai.com"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/v1/chat/completions"})

	var h2Client bytes.Buffer
	h2Client.WriteString(http2ClientPreface)
	writeH2Frame(&h2Client, 0x1, 0x4, 3, reqHpack.Bytes())
	writeH2Frame(&h2Client, 0x0, 0x1, 3, []byte(`{"model":"gpt-5","stream":true,"messages":[{"role":"user","content":"stream h2"}]}`))

	var respHpack bytes.Buffer
	encResp := hpack.NewEncoder(&respHpack)
	_ = encResp.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = encResp.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/event-stream"})

	var h2ServerPart1, h2ServerPart2 bytes.Buffer
	writeH2Frame(&h2ServerPart1, 0x1, 0x4, 3, respHpack.Bytes())
	writeH2Frame(&h2ServerPart1, 0x0, 0x0, 3, []byte("data: {\"model\":\"gpt-5\",\"choices\":[{\"delta\":{\"content\":\"part1 \"}}]}\n\n"))
	writeH2Frame(&h2ServerPart2, 0x0, 0x1, 3, []byte("data: {\"model\":\"gpt-5\",\"choices\":[{\"delta\":{\"content\":\"part2\"}}]}\n\ndata: [DONE]\n\n"))

	sr.IngestChunk(RawTLSChunk{ConnKey: "201:h2sse", Direction: DirWrite, Data: h2Client.Bytes()})
	sr.IngestChunk(RawTLSChunk{ConnKey: "201:h2sse", Direction: DirRead, Data: h2ServerPart1.Bytes()})
	require.Len(t, events, 1)
	require.Equal(t, "streaming", events[0].Status)
	require.Equal(t, "part1 ", events[0].Chat.ResponseText)

	sr.IngestChunk(RawTLSChunk{ConnKey: "201:h2sse", Direction: DirRead, Data: h2ServerPart2.Bytes()})
	require.Len(t, events, 2)
	require.Equal(t, "ok", events[1].Status)
	require.Equal(t, "part1 part2", events[1].Chat.ResponseText)
}

func TestIdleConnEviction(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	var events []*model.TraceEvent
	sr := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		cp := *ev
		events = append(events, &cp)
	})

	const baseTs int64 = 1_700_000_000_000
	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"unfinished"}]}`
	rawReq := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody

	// Conn 1 sends a request and partial SSE response at baseTs, then goes idle
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "idle:1",
		Direction: DirWrite,
		Timestamp: baseTs,
		Process:   model.ProcessInfo{PID: 301, Comm: "stale-client"},
		Data:      []byte(rawReq),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "idle:1",
		Direction: DirRead,
		Timestamp: baseTs + 100,
		Process:   model.ProcessInfo{PID: 301, Comm: "stale-client"},
		Data:      []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"),
	})

	// Conn 2 sends only a request and never receives response headers before going idle
	reqOnlyBody := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"req only no resp"}]}`
	rawReqOnly := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(reqOnlyBody)) + "\r\n\r\n" + reqOnlyBody
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "idle:req_only",
		Direction: DirWrite,
		Timestamp: baseTs + 200,
		Process:   model.ProcessInfo{PID: 302, Comm: "req-only-client"},
		Data:      []byte(rawReqOnly),
	})

	require.Len(t, events, 1, "initial partial SSE chunk must emit streaming event")
	require.Equal(t, "streaming", events[0].Status)
	streamEventID := events[0].ID

	sr.mu.Lock()
	_, hasIdleBefore := sr.conns["idle:1"]
	_, hasReqOnlyBefore := sr.conns["idle:req_only"]
	sr.mu.Unlock()
	require.True(t, hasIdleBefore)
	require.True(t, hasReqOnlyBefore)

	// Advance past ConnIdleTimeout (2m) and ingest a new chunk on another connection
	laterTs := baseTs + ConnIdleTimeout.Milliseconds() + 5000
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "active:2",
		Direction: DirWrite,
		Timestamp: laterTs,
		Process:   model.ProcessInfo{PID: 303, Comm: "new-client"},
		Data:      []byte(rawReq),
	})

	sr.mu.Lock()
	_, hasIdleAfter := sr.conns["idle:1"]
	_, hasReqOnlyAfter := sr.conns["idle:req_only"]
	_, hasActiveAfter := sr.conns["active:2"]
	sr.mu.Unlock()

	require.False(t, hasIdleAfter, "idle connection older than ConnIdleTimeout must be evicted")
	require.False(t, hasReqOnlyAfter, "request-only idle connection must also be evicted")
	require.True(t, hasActiveAfter)

	// Verify terminal incomplete events were emitted for both idle:1 and idle:req_only
	require.Len(t, events, 3, "evicting 2 in-flight connections must emit 2 terminal incomplete events")
	var partialFinal, reqOnlyFinal *model.TraceEvent
	for _, ev := range events[1:] {
		if ev.ID == streamEventID {
			partialFinal = ev
		} else {
			reqOnlyFinal = ev
		}
	}
	require.NotNil(t, partialFinal, "partial SSE exchange must emit terminal event with same ID")
	require.Equal(t, "incomplete", partialFinal.Status)
	require.Contains(t, partialFinal.Error, "idle_timeout")
	require.Equal(t, "partial", partialFinal.Chat.ResponseText)

	require.NotNil(t, reqOnlyFinal, "request-only exchange without response must emit terminal event instead of being silently dropped")
	require.Equal(t, "incomplete", reqOnlyFinal.Status)
	require.Contains(t, reqOnlyFinal.Error, "no response received")
	require.NotNil(t, reqOnlyFinal.Chat)
	require.Equal(t, "gpt-4o-mini", reqOnlyFinal.Chat.Model)

	// Also verify direct EvictIdleConns(nowMs) when no new traffic arrives
	evictedCount := sr.EvictIdleConns(laterTs + ConnIdleTimeout.Milliseconds() + 1000)
	require.Equal(t, 1, evictedCount)
	require.Len(t, events, 4)
	require.Equal(t, "incomplete", events[3].Status)

	warns, err := mon.QueryEvents(selfmon.Query{
		Status: selfmon.StatusWarn,
		Stage:  selfmon.StageStream,
	})
	require.NoError(t, err)
	foundEvicted := false
	for _, w := range warns {
		if w.Action == "conn_evicted" {
			foundEvicted = true
			break
		}
	}
	require.True(t, foundEvicted, "expected conn_evicted warn in selfmon")
}

func TestConnBufferTruncation(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	var events []*model.TraceEvent
	sr := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		cp := *ev
		events = append(events, &cp)
	})
	const baseTs int64 = 1_700_000_100_000

	// 1. Oversized reqBuf (> 8 MiB) must emit a terminal truncated event, reset buffer, deduplicate warns, and recover on keep-alive
	hugeReq := make([]byte, MaxConnBufferBytes+512*1024)
	reqPrefix := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Length: 99999999\r\n\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"oversized multimodal `
	copy(hugeReq, reqPrefix)
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "trunc:req",
		Direction: DirWrite,
		Timestamp: baseTs,
		Process:   model.ProcessInfo{PID: 401, Comm: "huge-req"},
		Data:      hugeReq,
	})

	sr.mu.Lock()
	reqLen := sr.conns["trunc:req"].reqBuf.Len()
	reqUpdatedAt := sr.conns["trunc:req"].updatedAt
	sr.mu.Unlock()
	require.Equal(t, 0, reqLen, "oversized reqBuf must be reset after emitting truncated event so keep-alive can resync")
	require.Len(t, events, 1)
	require.Equal(t, "incomplete", events[0].Status)
	require.Contains(t, events[0].Error, "buffer_truncated")
	require.Equal(t, model.ProtocolOpenAIChat, events[0].Protocol)

	// Feed another oversized chunk on the same connection: warn must be deduplicated and updatedAt must not advance
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "trunc:req",
		Direction: DirWrite,
		Timestamp: baseTs + 500,
		Process:   model.ProcessInfo{PID: 401, Comm: "huge-req"},
		Data:      hugeReq,
	})
	sr.mu.Lock()
	require.Equal(t, 0, sr.conns["trunc:req"].reqBuf.Len())
	require.Equal(t, reqUpdatedAt, sr.conns["trunc:req"].updatedAt, "truncated chunk must not refresh updatedAt")
	sr.mu.Unlock()

	// Subsequent keep-alive request on "trunc:req" must resynchronize and succeed
	kaReqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"after truncation"}]}`
	kaRespBody := `{"model":"gpt-4o","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"recovered ok"}}]}`
	kaRawReq := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: " + strconv.Itoa(len(kaReqBody)) + "\r\n\r\n" + kaReqBody
	kaRawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(kaRespBody)) + "\r\n\r\n" + kaRespBody
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "trunc:req",
		Direction: DirWrite,
		Timestamp: baseTs + 1000,
		Process:   model.ProcessInfo{PID: 401, Comm: "huge-req"},
		Data:      []byte(kaRawReq),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "trunc:req",
		Direction: DirRead,
		Timestamp: baseTs + 1050,
		Process:   model.ProcessInfo{PID: 401, Comm: "huge-req"},
		Data:      []byte(kaRawResp),
	})
	require.Len(t, events, 3)
	require.Equal(t, "ok", events[2].Status)
	require.Equal(t, "recovered ok", events[2].Chat.ResponseText)

	// 2. Oversized respBuf (> 8 MiB) on an active exchange emits terminal truncated event and resets buffer
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "trunc:resp",
		Direction: DirWrite,
		Timestamp: baseTs + 2000,
		Process:   model.ProcessInfo{PID: 402, Comm: "huge-resp"},
		Data:      []byte(kaRawReq),
	})
	hugeResp := make([]byte, MaxConnBufferBytes+256*1024)
	copy(hugeResp, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 99999999\r\n\r\n{\"model\":\"gpt-4o\"")
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "trunc:resp",
		Direction: DirRead,
		Timestamp: baseTs + 2010,
		Process:   model.ProcessInfo{PID: 402, Comm: "huge-resp"},
		Data:      hugeResp,
	})

	sr.mu.Lock()
	cbResp := sr.conns["trunc:resp"]
	respLen := cbResp.respBuf.Len()
	sr.mu.Unlock()
	require.Equal(t, 0, respLen, "oversized respBuf must be reset")
	require.Len(t, events, 4)
	require.Equal(t, "incomplete", events[3].Status)
	require.Contains(t, events[3].Error, "buffer_truncated")

	// 3. Non-HTTP prefix / orphan response > 4 KiB is discarded immediately without growing to 8 MiB
	nonHTTPGarbage := bytes.Repeat([]byte("binary-non-http-frame-"), 400) // ~8.8 KiB > 4 KiB
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "garbage:conn",
		Direction: DirWrite,
		Timestamp: baseTs + 3000,
		Data:      nonHTTPGarbage,
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "garbage:conn",
		Direction: DirRead,
		Timestamp: baseTs + 3010,
		Data:      nonHTTPGarbage,
	})
	sr.mu.Lock()
	require.Equal(t, 0, sr.conns["garbage:conn"].reqBuf.Len(), "non-HTTP request bytes > 4KiB must be reset")
	require.Equal(t, 0, sr.conns["garbage:conn"].respBuf.Len(), "orphan response bytes > 4KiB without activeH1 must be reset")
	sr.mu.Unlock()

	// 4. Global buffer byte budget evicts oldest connection first and emits terminal incomplete event
	sr.SetMaxTotalBufferBytes(32 * 1024)
	defer sr.SetMaxTotalBufferBytes(MaxTotalBufferBytes)
	partialBody := string(bytes.Repeat([]byte("a"), 20*1024))
	partialReq := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 50000\r\n\r\n" + partialBody
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "budget:oldest",
		Direction: DirWrite,
		Timestamp: baseTs + 10,
		Process:   model.ProcessInfo{PID: 403, Comm: "oldest"},
		Data:      []byte(partialReq),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "budget:newest",
		Direction: DirWrite,
		Timestamp: baseTs + 4000,
		Process:   model.ProcessInfo{PID: 404, Comm: "newest"},
		Data:      []byte(partialReq),
	})
	sr.mu.Lock()
	_, hasOldest := sr.conns["budget:oldest"]
	_, hasNewest := sr.conns["budget:newest"]
	sr.mu.Unlock()
	require.False(t, hasOldest, "oldest connection must be evicted when global buffer budget is exceeded")
	require.True(t, hasNewest, "newest connection must remain within budget")
	require.LessOrEqual(t, sr.TotalBufferBytes(), 32*1024)
	require.Equal(t, "incomplete", events[len(events)-1].Status)
	require.Contains(t, events[len(events)-1].Error, "global_buffer_budget_exceeded")

	warns, err := mon.QueryEvents(selfmon.Query{
		Status: selfmon.StatusWarn,
		Stage:  selfmon.StageStream,
	})
	require.NoError(t, err)
	truncByConn := map[string]int{}
	for _, w := range warns {
		if w.Action == "buffer_truncated" {
			connKey, _ := w.Detail["conn_key"].(string)
			truncByConn[connKey]++
		}
	}
	require.Equal(t, 1, truncByConn["trunc:req"], "buffer_truncated warn must be deduplicated to 1 per connection")
	require.Equal(t, 1, truncByConn["trunc:resp"])
}

func TestUnknownProtocolWarnAndDropToggle(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	var captured []*model.TraceEvent
	sr := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		cp := *ev
		captured = append(captured, &cp)
	})

	const nowMs int64 = 1_700_000_200_000
	unkReqBody := `{"ping":"pong"}`
	unkRespBody := `{"status":"healthy"}`
	rawReq := "POST /internal/health?key=secret_token_123&code=oauth_code_456&env=prod HTTP/1.1\r\n" +
		"Host: telemetry.example.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(unkReqBody)) + "\r\n\r\n" + unkReqBody
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(unkRespBody)) + "\r\n\r\n" + unkRespBody

	// 1. Default dropUnknown = true: event is dropped, selfmon receives unknown_protocol_dropped warn (rate-limited per host)
	for i := 0; i < 3; i++ {
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   "unk:h1",
			Direction: DirWrite,
			Timestamp: nowMs + int64(i*100),
			Process:   model.ProcessInfo{PID: 501, Comm: "curl"},
			Data:      []byte(rawReq),
		})
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   "unk:h1",
			Direction: DirRead,
			Timestamp: nowMs + int64(i*100+50),
			Process:   model.ProcessInfo{PID: 501, Comm: "curl"},
			Data:      []byte(rawResp),
		})
	}
	require.Empty(t, captured, "unknown protocol must be dropped by default")

	warns, err := mon.QueryEvents(selfmon.Query{
		Status: selfmon.StatusWarn,
		Stage:  selfmon.StageStream,
	})
	require.NoError(t, err)
	unkWarns := 0
	for _, w := range warns {
		if w.Action == "unknown_protocol_dropped" {
			unkWarns++
			require.Equal(t, "telemetry.example.com", w.Detail["host"])
			pathVal, _ := w.Detail["path"].(string)
			require.Contains(t, pathVal, "key=[REDACTED]")
			require.Contains(t, pathVal, "code=[REDACTED]")
			require.NotContains(t, pathVal, "secret_token_123")
			require.NotContains(t, pathVal, "oauth_code_456")
		}
	}
	require.Equal(t, 1, unkWarns, "high-frequency unknown protocol on same host within 10s must be rate-limited to 1 warn")

	// Verify unknownWarnState is bounded by MaxUnknownWarnHosts (LRU)
	sr.mu.Lock()
	for i := 0; i < MaxUnknownWarnHosts+64; i++ {
		sr.recordUnknownProtocolWarnLocked("host-"+strconv.Itoa(i)+".example.com", "/ping?token=sec", 501, 10, nowMs+int64(i))
	}
	warnStateLen := len(sr.unknownWarnState)
	sr.mu.Unlock()
	require.LessOrEqual(t, warnStateLen, MaxUnknownWarnHosts)

	// 2. Disable dropUnknown: unknown protocol is both warned and emitted (HTTP/1.1 and HTTP/2)
	sr.SetDropUnknown(false)
	require.False(t, sr.DropUnknown())

	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "unk:h1_emit",
		Direction: DirWrite,
		Timestamp: nowMs + 1000,
		Process:   model.ProcessInfo{PID: 502, Comm: "curl"},
		Data:      []byte(rawReq),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "unk:h1_emit",
		Direction: DirRead,
		Timestamp: nowMs + 1050,
		Process:   model.ProcessInfo{PID: 502, Comm: "curl"},
		Data:      []byte(rawResp),
	})
	require.Len(t, captured, 1)
	require.Equal(t, model.ProtocolUnknown, captured[0].Protocol)
	require.Equal(t, "telemetry.example.com", captured[0].Host)

	// Also verify HTTP/2 unknown protocol path
	var reqHpack, respHpack bytes.Buffer
	encReq := hpack.NewEncoder(&reqHpack)
	_ = encReq.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = encReq.WriteField(hpack.HeaderField{Name: ":authority", Value: "h2-unknown.example.com"})
	_ = encReq.WriteField(hpack.HeaderField{Name: ":path", Value: "/custom/rpc"})
	encResp := hpack.NewEncoder(&respHpack)
	_ = encResp.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = encResp.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})

	var h2Client, h2Server bytes.Buffer
	h2Client.WriteString(http2ClientPreface)
	writeH2Frame(&h2Client, 0x1, 0x4, 1, reqHpack.Bytes())
	writeH2Frame(&h2Client, 0x0, 0x1, 1, []byte(unkReqBody))
	writeH2Frame(&h2Server, 0x1, 0x4, 1, respHpack.Bytes())
	writeH2Frame(&h2Server, 0x0, 0x1, 1, []byte(unkRespBody))

	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "unk:h2_emit",
		Direction: DirWrite,
		Timestamp: nowMs + 2000,
		Process:   model.ProcessInfo{PID: 503, Comm: "h2-client"},
		Data:      h2Client.Bytes(),
	})
	sr.IngestChunk(RawTLSChunk{
		ConnKey:   "unk:h2_emit",
		Direction: DirRead,
		Timestamp: nowMs + 2050,
		Process:   model.ProcessInfo{PID: 503, Comm: "h2-client"},
		Data:      h2Server.Bytes(),
	})
	require.Len(t, captured, 2)
	require.Equal(t, model.ProtocolUnknown, captured[1].Protocol)
	require.Equal(t, "HTTP/2.0", captured[1].HTTPVersion)
}

func TestPlainHTTPSplitWriteReassembly(t *testing.T) {
	mon, err := selfmon.NewMonitor(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })

	var captured []*model.TraceEvent
	sr := NewStreamReassembler(false, nil, mon, func(ev *model.TraceEvent) {
		captured = append(captured, ev)
	})

	body := `{"model":"qwen","messages":[{"role":"user","content":"plain http split"}]}`
	head := "POST /api/chat HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n"
	respBody := `{"model":"qwen","message":{"role":"assistant","content":"plain http split ok"},"done":true}`
	resp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(respBody)) + "\r\nConnection: close\r\n\r\n" + respBody

	proc := model.ProcessInfo{PID: 160, Comm: "plain-http"}
	sr.IngestChunk(RawTLSChunk{ConnKey: "160:ebpf_fd_4", Direction: DirWrite, Process: proc, Data: []byte(head)})
	require.Empty(t, captured, "headers alone must wait for the JSON body")
	sr.IngestChunk(RawTLSChunk{ConnKey: "160:ebpf_fd_4", Direction: DirWrite, Process: proc, Data: []byte(body)})
	require.Empty(t, captured, "request must wait for the HTTP response")
	sr.IngestChunk(RawTLSChunk{ConnKey: "160:ebpf_fd_4", Direction: DirRead, Process: proc, Data: []byte(resp)})

	require.Len(t, captured, 1)
	require.Equal(t, "ok", captured[0].Status)
	require.NotNil(t, captured[0].Chat)
	require.Equal(t, "plain http split ok", captured[0].Chat.ResponseText)
}

func writeH2Frame(buf *bytes.Buffer, ftype byte, flags byte, streamID uint32, payload []byte) {
	l := len(payload)
	hdr := []byte{
		byte(l >> 16), byte(l >> 8), byte(l),
		ftype,
		flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	buf.Write(hdr)
	buf.Write(payload)
}
