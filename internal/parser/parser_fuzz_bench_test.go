package parser

import (
	"bytes"
	"fmt"
	"strconv"
	"testing"

	"github.com/mrlyc/llm-tracer/internal/model"
	"golang.org/x/net/http2/hpack"
)

func FuzzIngestChunk(f *testing.F) {
	f.Add("conn:h1", true, []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 55\r\n\r\n{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"))
	f.Add("conn:h1", false, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n15\r\ndata: [DONE]\n\n\r\n0\r\n\r\n"))
	f.Add("conn:h2", true, []byte(http2ClientPreface+"\x00\x00\x04\x01\x05\x00\x00\x00\x01\x83\x86\x84\x41"))
	f.Add("conn:garbage", true, []byte("not-an-http-stream\r\n\r\nrandom-bytes"))

	f.Fuzz(func(t *testing.T, connKey string, isWrite bool, data []byte) {
		sr := NewStreamReassembler(false, nil, nil, func(_ *model.TraceEvent) {})
		sr.SetMaxTotalBufferBytes(512 * 1024)

		dir := DirRead
		if isWrite {
			dir = DirWrite
		}
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   connKey,
			Direction: dir,
			Timestamp: 1_700_000_000_000,
			Process:   model.ProcessInfo{PID: 1000, Comm: "fuzz"},
			Data:      data,
		})
		if len(data) > 2 {
			mid := len(data) / 2
			sr.IngestChunk(RawTLSChunk{
				ConnKey:   connKey,
				Direction: DirWrite,
				Timestamp: 1_700_000_000_010,
				Data:      data[:mid],
			})
			sr.IngestChunk(RawTLSChunk{
				ConnKey:   connKey,
				Direction: DirRead,
				Timestamp: 1_700_000_000_020,
				Data:      data[mid:],
			})
		}
		if got := sr.TotalBufferBytes(); got > 512*1024 {
			t.Fatalf("total buffer bytes %d exceeded budget %d", got, 512*1024)
		}
		sr.EvictIdleConns(1_700_000_000_000 + ConnIdleTimeout.Milliseconds() + 10_000)
	})
}

func FuzzParseExchange(f *testing.F) {
	f.Add("/v1/chat/completions?key=secret", []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`), []byte(`{"choices":[{"message":{"role":"assistant","content":"world"}}]}`), false)
	f.Add("/v1/messages", []byte(`{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hi"}]}`), []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n"), true)
	f.Add("/v1/systemone", []byte(`{"model":"jev","state":{"page":{"url":"https://example.com"}},"questions":{"operation":{"type":"choice","criteria":{"DONE":"done"}}}}`), []byte(`{"answers":{"operation":{"choice":"DONE","confidence":0.9}}}`), false)
	f.Add("/v1/responses", []byte(`{"model":"gpt-5","input":"ping"}`), []byte(`{"output_text":"pong"}`), false)
	f.Add("/v1beta/models/gemini-2.5-pro:generateContent", []byte(`{"contents":[{"parts":[{"text":"hi"}]}]}`), []byte(`{"candidates":[{"content":{"parts":[{"text":"hello"}]}}]}`), false)
	f.Add("/api/chat", []byte(`{"model":"qwen3","messages":[{"role":"user","content":"hi"}]}`), []byte(`{"message":{"role":"assistant","content":"yo"},"done":true}`), false)
	f.Add("/model/anthropic.claude-v3/converse", []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`), []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"hello"}]}}}`), false)
	f.Add("/mcp", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{}}}`), []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"done"}]}}`), false)

	f.Fuzz(func(t *testing.T, path string, reqBody []byte, respBody []byte, isSSE bool) {
		ev := &model.TraceEvent{
			ID:              "ev_fuzz",
			Host:            "api.example.com",
			Path:            path,
			HeadersRecorded: false,
		}
		_ = ParseExchange(ev, reqBody, respBody, isSSE)
	})
}

func BenchmarkStreamReassemblerH1(b *testing.B) {
	sr := NewStreamReassembler(false, nil, nil, func(_ *model.TraceEvent) {})
	reqBody := `{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark h1 keep-alive"}]}`
	respBody := `{"model":"gpt-4o","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`
	rawReq := []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(reqBody)) + "\r\n\r\n" + reqBody)
	rawResp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(respBody)) + "\r\n\r\n" + respBody)
	proc := model.ProcessInfo{PID: 100, Comm: "bench-h1"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts := int64(1_700_000_000_000 + i*10)
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   "bench:h1",
			Direction: DirWrite,
			Timestamp: ts,
			Process:   proc,
			Data:      rawReq,
		})
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   "bench:h1",
			Direction: DirRead,
			Timestamp: ts + 5,
			Process:   proc,
			Data:      rawResp,
		})
	}
}

func BenchmarkStreamReassemblerH2(b *testing.B) {
	sr := NewStreamReassembler(false, nil, nil, func(_ *model.TraceEvent) {})
	var reqHpack, respHpack bytes.Buffer
	encReq := hpack.NewEncoder(&reqHpack)
	_ = encReq.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = encReq.WriteField(hpack.HeaderField{Name: ":authority", Value: "api.openai.com"})
	_ = encReq.WriteField(hpack.HeaderField{Name: ":path", Value: "/v1/chat/completions"})
	_ = encReq.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})

	encResp := hpack.NewEncoder(&respHpack)
	_ = encResp.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = encResp.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/json"})

	reqPayload := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"benchmark h2"}]}`)
	respPayload := []byte(`{"model":"gpt-4o","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"ok"}}],"usage":{"total_tokens":12}}`)
	proc := model.ProcessInfo{PID: 200, Comm: "bench-h2"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		connKey := fmt.Sprintf("bench:h2:%d", i&15)
		streamID := uint32(i*2 + 1)
		var clientBuf, serverBuf bytes.Buffer
		if i < 16 {
			clientBuf.WriteString(http2ClientPreface)
		}
		writeH2Frame(&clientBuf, 0x1, 0x4, streamID, reqHpack.Bytes())
		writeH2Frame(&clientBuf, 0x0, 0x1, streamID, reqPayload)
		writeH2Frame(&serverBuf, 0x1, 0x4, streamID, respHpack.Bytes())
		writeH2Frame(&serverBuf, 0x0, 0x1, streamID, respPayload)

		ts := int64(1_700_000_000_000 + i*10)
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   connKey,
			Direction: DirWrite,
			Timestamp: ts,
			Process:   proc,
			Data:      clientBuf.Bytes(),
		})
		sr.IngestChunk(RawTLSChunk{
			ConnKey:   connKey,
			Direction: DirRead,
			Timestamp: ts + 5,
			Process:   proc,
			Data:      serverBuf.Bytes(),
		})
	}
}
