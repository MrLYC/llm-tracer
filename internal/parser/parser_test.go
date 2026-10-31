package parser

import (
	"bytes"
	"compress/gzip"
	"strconv"
	"testing"

	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
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
