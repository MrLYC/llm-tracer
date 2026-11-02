package collector

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

// TestNodeWritevHookWithoutListening verifies that node_hook.cjs replaces net.Socket.prototype._writev,
// captures scattered multi-chunk HTTP requests + responses into LLMT frames, and produces a complete
// stored LLM event through Collector.LaunchCommand without listening on any TCP or Unix socket.
func TestNodeWritevHookWithoutListening(t *testing.T) {
	nodeBin, err := findNodeExecutable()
	if err != nil || nodeBin == "" {
		t.Skipf("skipping node _writev hook test: node executable not found: %v", err)
	}

	t.Run("DirectHook_PrototypeReplacementAndBinaryFrameEmission", func(t *testing.T) {
		dir := t.TempDir()
		hooks, err := EnsureRuntimeHooks(dir)
		require.NoError(t, err)
		require.NotEmpty(t, hooks.NodeHookJS)

		pipeFile := filepath.Join(dir, "writev_pipe.bin")
		scriptPath := filepath.Join(dir, "verify_writev_direct.js")
		script := `"use strict";
const net = require("node:net");
const tls = require("node:tls");

const hookPath = process.argv[2];
const pipePath = process.argv[3];
process.env.LLM_TRACER_PIPE = pipePath;

const origNetWritev = net.Socket.prototype._writev;
const origTLSWritev = tls.TLSSocket.prototype._writev;
if (typeof origNetWritev !== "function") {
  console.error("expected net.Socket.prototype._writev to be a function before hook");
  process.exit(2);
}

require(hookPath);

if (net.Socket.prototype._writev === origNetWritev) {
  console.error("net.Socket.prototype._writev was NOT replaced by node_hook.cjs");
  process.exit(3);
}
if (typeof origTLSWritev === "function" && tls.TLSSocket.prototype._writev === origTLSWritev) {
  console.error("tls.TLSSocket.prototype._writev was NOT replaced by node_hook.cjs");
  process.exit(4);
}
if (process.env.LLM_TRACER_NODE_PLAIN_ACTIVE !== "1") {
  console.error("expected LLM_TRACER_NODE_PLAIN_ACTIVE=1 after hook");
  process.exit(5);
}

// 1. Verify guard conditions: encrypted, _isStdio, and server sockets must NOT emit plain HTTP frames.
for (const props of [{ encrypted: true }, { _isStdio: true }, { server: {} }]) {
  const ignoredSock = new net.Socket();
  Object.assign(ignoredSock, props);
  ignoredSock._writeGeneric = function (writev, data, encoding, cb) {
    if (cb) cb();
  };
  ignoredSock._writev([
    { chunk: Buffer.from("POST /v1/chat/completions HTTP/1.1\r\nHost: ignored.local\r\n\r\n"), encoding: "buffer" }
  ], () => {});
}

// 2. Verify plain client net.Socket._writev captures scattered chunks (Buffer + string + Uint8Array)
// and links subsequent sock.push() response chunks under the same connection ID.
const sock = new net.Socket();
let underlyingWritevCalled = false;
sock._writeGeneric = function (writev, data, encoding, cb) {
  if (writev === true && Array.isArray(data)) {
    underlyingWritevCalled = true;
  }
  if (cb) cb();
};

const reqPart1 = '{"model":"qwen3-writev","messages":[{"role":"user",';
const reqPart2 = new TextEncoder().encode('"content":"scattered writev payload"}]}');
const bodyLen = Buffer.byteLength(reqPart1) + reqPart2.byteLength;
const reqHead =
  "POST /v1/chat/completions HTTP/1.1\r\n" +
  "Host: 127.0.0.1:11434\r\n" +
  "Content-Type: application/json\r\n" +
  "Content-Length: " + bodyLen + "\r\n\r\n";

let cbInvoked = false;
sock._writev(
  [
    { chunk: Buffer.from(reqHead), encoding: "buffer" },
    { chunk: reqPart1, encoding: "utf8" },
    { chunk: reqPart2, encoding: "buffer" }
  ],
  () => { cbInvoked = true; }
);

if (!underlyingWritevCalled || !cbInvoked) {
  console.error("origNetWritev delegation failed");
  process.exit(6);
}

const respBody = '{"id":"chatcmpl-wv-direct","model":"qwen3-writev","choices":[{"index":0,"message":{"role":"assistant","content":"direct writev reply"},"finish_reason":"stop"}]}';
const respRaw =
  "HTTP/1.1 200 OK\r\n" +
  "Content-Type: application/json\r\n" +
  "Content-Length: " + Buffer.byteLength(respBody) + "\r\n\r\n" +
  respBody;
sock.push(Buffer.from(respRaw));
sock.push(null);
`
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o644))

		cmd := exec.Command(nodeBin, scriptPath, hooks.NodeHookJS, pipeFile)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "direct node _writev script failed: %s", string(out))

		rawPipe, err := os.ReadFile(pipeFile)
		require.NoError(t, err, "expected node_hook.cjs _writev to create pipe file")
		require.NotEmpty(t, rawPipe)

		type llmtFrame struct {
			magic   uint32
			pid     uint32
			tid     uint32
			connID  uint32
			dir     uint32
			payload string
		}
		var frames []llmtFrame
		offset := 0
		for offset < len(rawPipe) {
			require.LessOrEqual(t, offset+24, len(rawPipe), "truncated 24-byte LLMT header")
			hdr := rawPipe[offset : offset+24]
			magic := binary.LittleEndian.Uint32(hdr[0:4])
			pid := binary.LittleEndian.Uint32(hdr[4:8])
			tid := binary.LittleEndian.Uint32(hdr[8:12])
			connID := binary.LittleEndian.Uint32(hdr[12:16])
			dirFlag := binary.LittleEndian.Uint32(hdr[16:20])
			length := int(binary.LittleEndian.Uint32(hdr[20:24]))
			offset += 24
			require.LessOrEqual(t, offset+length, len(rawPipe), "truncated LLMT frame payload")
			payload := string(rawPipe[offset : offset+length])
			offset += length
			frames = append(frames, llmtFrame{
				magic:   magic,
				pid:     pid,
				tid:     tid,
				connID:  connID,
				dir:     dirFlag,
				payload: payload,
			})
		}

		require.Len(t, frames, 2, "expected exactly 2 frames (1 DirWrite from _writev + 1 DirRead from push)")
		require.Equal(t, uint32(0x4c4c4d54), frames[0].magic)
		require.Equal(t, uint32(0), frames[0].dir)
		require.NotZero(t, frames[0].pid)
		require.Contains(t, frames[0].payload, "POST /v1/chat/completions HTTP/1.1\r\n")
		require.Contains(t, frames[0].payload, `"content":"scattered writev payload"`)
		require.NotContains(t, frames[0].payload, "ignored.local")

		require.Equal(t, uint32(0x4c4c4d54), frames[1].magic)
		require.Equal(t, uint32(1), frames[1].dir)
		require.Equal(t, frames[0].connID, frames[1].connID, "request and response frames must share the same connID")
		require.Contains(t, frames[1].payload, `"content":"direct writev reply"`)
	})

	t.Run("CollectorLaunchCommand_EndToEndStoreCaptureViaWritev", func(t *testing.T) {
		dir := t.TempDir()
		mon, err := selfmon.NewMonitor(dir)
		require.NoError(t, err)
		defer mon.Stop()

		st, err := store.NewStore(dir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer st.Close()

		corr := correlator.NewCorrelator(mon)
		col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		require.NoError(t, col.Start(ctx))
		defer col.Stop()

		scriptPath := filepath.Join(dir, "e2e_writev_only.js")
		// Uses only sock._writev (never sock._write and no OS socket syscall) so only the JS _writev hook can capture it.
		script := `"use strict";
const net = require("node:net");

const sock = new net.Socket();
sock._writeGeneric = function (writev, data, encoding, cb) {
  if (cb) cb();
};

const reqBody = JSON.stringify({
  model: "qwen3-writev-e2e",
  messages: [{ role: "user", content: "hello from node _writev only" }]
});
const reqHead =
  "POST /v1/chat/completions HTTP/1.1\r\n" +
  "Host: 127.0.0.1:11434\r\n" +
  "Content-Type: application/json\r\n" +
  "Content-Length: " + Buffer.byteLength(reqBody) + "\r\n\r\n";

sock._writev(
  [
    { chunk: Buffer.from(reqHead), encoding: "buffer" },
    { chunk: Buffer.from(reqBody), encoding: "buffer" }
  ],
  () => {}
);

const respBody = JSON.stringify({
  id: "chatcmpl-writev-e2e",
  object: "chat.completion",
  model: "qwen3-writev-e2e",
  choices: [{
    index: 0,
    message: { role: "assistant", content: "ack from node _writev hook" },
    finish_reason: "stop"
  }],
  usage: { prompt_tokens: 9, completion_tokens: 6, total_tokens: 15 }
});
const respRaw =
  "HTTP/1.1 200 OK\r\n" +
  "Content-Type: application/json\r\n" +
  "Content-Length: " + Buffer.byteLength(respBody) + "\r\n\r\n" +
  respBody;
sock.push(Buffer.from(respRaw));
sock.push(null);
`
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o644))

		exitCode, err := col.LaunchCommand(ctx, []string{nodeBin, scriptPath})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		col.Flush()

		sessions, err := st.QuerySessions(store.SessionQuery{Limit: 20})
		require.NoError(t, err)
		require.Len(t, sessions, 1, "expected 1 session captured from net.Socket.prototype._writev")

		events, err := st.QuerySessionEvents(store.EventQuery{SessionID: sessions[0].ID, Limit: 20})
		require.NoError(t, err)
		require.Len(t, events, 1, "expected 1 event captured from net.Socket.prototype._writev")

		ev := events[0]
		require.Equal(t, model.ProtocolOpenAIChat, ev.Protocol)
		require.Equal(t, "POST", ev.Method)
		require.Equal(t, "/v1/chat/completions", ev.Path)
		require.NotNil(t, ev.Chat)
		require.Equal(t, "qwen3-writev-e2e", ev.Chat.Model)
		require.Equal(t, "ack from node _writev hook", ev.Chat.ResponseText)
		require.NotEmpty(t, ev.Chat.Messages)
		require.Equal(t, "hello from node _writev only", ev.Chat.Messages[len(ev.Chat.Messages)-1].Content)
	})
}
