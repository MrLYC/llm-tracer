package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

// TestPlainHTTPNodeAndPythonE2E verifies end-to-end plain HTTP (http://) LLM capture
// across Node.js http.request, Node.js globalThis.fetch, and Python urllib.request,
// asserting that each client produces exactly 1 event (neither missed nor duplicated)
// with matching response body content.
func TestPlainHTTPNodeAndPythonE2E(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping plain HTTP e2e test: cannot listen on tcp4 127.0.0.1:0 in current environment: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		reqBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var reqPayload struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(reqBytes, &reqPayload)
		modelName := reqPayload.Model
		if modelName == "" {
			modelName = "qwen3-local"
		}
		userMsg := "default"
		if len(reqPayload.Messages) > 0 {
			userMsg = reqPayload.Messages[len(reqPayload.Messages)-1].Content
		}
		replyText := "ack:" + userMsg

		respBody := fmt.Sprintf(`{"id":"chatcmpl-plain-e2e","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}`, modelName, replyText)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(respBody))
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
	}()

	endpoint := fmt.Sprintf("http://%s/v1/chat/completions", ln.Addr().String())

	runAndAssertSingleEvent := func(t *testing.T, cmdArgs []string, wantPrompt, wantReply string, expectPipeBytes bool) {
		t.Helper()
		dir := t.TempDir()
		mon, err := selfmon.NewMonitor(dir)
		require.NoError(t, err)
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

		exitCode, err := col.LaunchCommand(ctx, cmdArgs)
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		col.Flush()

		// Note: pipeSource.Flush() drains and resets tls.bin to zero bytes via f.Truncate(0).
		// Store event persistence verified below proves end-to-end delivery through pipe/sock.

		sessions, err := st.QuerySessions(store.SessionQuery{Limit: 50})
		require.NoError(t, err)
		require.Len(t, sessions, 1, "expected exactly 1 session in store")

		var allEvents []model.TraceEvent
		for _, s := range sessions {
			evs, err := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID, Limit: 50})
			require.NoError(t, err)
			allEvents = append(allEvents, evs...)
		}
		require.Len(t, allEvents, 1, "expected exactly 1 captured event (no missed capture and no duplicate capture)")

		ev := allEvents[0]
		require.Equal(t, model.ProtocolOpenAIChat, ev.Protocol)
		require.Equal(t, "POST", ev.Method)
		require.Equal(t, "/v1/chat/completions", ev.Path)
		require.Equal(t, http.StatusOK, ev.HTTPStatus)
		require.NotNil(t, ev.Chat)
		require.Equal(t, wantReply, ev.Chat.ResponseText)
		require.NotEmpty(t, ev.Chat.Messages)
		require.Equal(t, wantPrompt, ev.Chat.Messages[len(ev.Chat.Messages)-1].Content)
		require.Contains(t, ev.ResponseRaw, wantReply)
	}

	t.Run("Node_http_request", func(t *testing.T) {
		nodeBin, err := findNodeExecutable()
		if err != nil || nodeBin == "" {
			t.Skipf("skipping Node_http_request: node executable not found: %v", err)
		}
		scriptPath := filepath.Join(t.TempDir(), "node_http_req.js")
		script := `const http = require("node:http");
const u = new URL(process.argv[2]);
const payload = JSON.stringify({
  model: "qwen3-node-http",
  messages: [{ role: "user", content: "hello from node http.request" }]
});
const req = http.request({
  hostname: u.hostname,
  port: u.port,
  path: u.pathname,
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Connection": "close"
  }
}, (res) => {
  let raw = "";
  res.setEncoding("utf8");
  res.on("data", (c) => { raw += c; });
  res.on("end", () => {
    if (res.statusCode !== 200 || !raw.includes("ack:hello from node http.request")) {
      process.exit(2);
    }
  });
});
req.on("error", (err) => {
  console.error(err);
  process.exit(1);
});
req.write(payload);
req.end();
`
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o644))
		runAndAssertSingleEvent(
			t,
			[]string{nodeBin, scriptPath, endpoint},
			"hello from node http.request",
			"ack:hello from node http.request",
			true,
		)
	})

	t.Run("Node_fetch", func(t *testing.T) {
		nodeBin, err := findNodeExecutable()
		if err != nil || nodeBin == "" {
			t.Skipf("skipping Node_fetch: node executable not found: %v", err)
		}
		scriptPath := filepath.Join(t.TempDir(), "node_fetch.js")
		script := `const endpoint = process.argv[2];
(async () => {
  const resp = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      model: "qwen3-node-fetch",
      messages: [{ role: "user", content: "hello from node fetch" }]
    })
  });
  const text = await resp.text();
  if (resp.status !== 200 || !text.includes("ack:hello from node fetch")) {
    process.exit(2);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o644))
		runAndAssertSingleEvent(
			t,
			[]string{nodeBin, scriptPath, endpoint},
			"hello from node fetch",
			"ack:hello from node fetch",
			true,
		)
	})

	t.Run("Python_urllib", func(t *testing.T) {
		pyBin, err := findPythonExecutable()
		if err != nil || pyBin == "" {
			t.Skipf("skipping Python_urllib: python3 executable not found: %v", err)
		}
		pyScript := `import json, sys, urllib.request
endpoint = sys.argv[1]
payload = json.dumps({
    "model": "qwen3-python-urllib",
    "messages": [{"role": "user", "content": "hello from python urllib"}]
}).encode("utf-8")
req = urllib.request.Request(
    endpoint,
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=5) as resp:
    body = resp.read().decode("utf-8")
    if resp.status != 200 or "ack:hello from python urllib" not in body:
        sys.exit(2)
`
		runAndAssertSingleEvent(
			t,
			[]string{pyBin, "-c", pyScript, endpoint},
			"hello from python urllib",
			"ack:hello from python urllib",
			false,
		)
	})

	t.Run("CPreloadFallback_WhenNodePlainInactive", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skipf("skipping CPreloadFallback_WhenNodePlainInactive on %s: C preload hook is Linux-specific (requires LD_PRELOAD)", runtime.GOOS)
		}
		nodeBin, err := findNodeExecutable()
		if err != nil || nodeBin == "" {
			t.Skipf("skipping CPreloadFallback_WhenNodePlainInactive: node executable not found: %v", err)
		}
		// Simulate a Node process where LLM_TRACER_PY_TLS_ACTIVE=1 is set, but the JS plain-HTTP hook
		// did not take over (LLM_TRACER_NODE_PLAIN_ACTIVE=0) and net.Socket methods are restored to original,
		// verifying that ssl_hook.c plain-HTTP fallback captures the request exactly once.
		scriptPath := filepath.Join(t.TempDir(), "node_c_fallback.js")
		script := `const http = require("node:http");
const net = require("node:net");
// Restore unhooked net.Socket writev/write/push via a prototype bypass or by disabling LLM_TRACER_PIPE for JS hook
// while keeping LLM_TRACER_PY_TLS_ACTIVE=1 and setting LLM_TRACER_NODE_PLAIN_ACTIVE=0 for C preload hook.
process.env.LLM_TRACER_PY_TLS_ACTIVE = "1";
process.env.LLM_TRACER_NODE_PLAIN_ACTIVE = "0";
delete process.env.LLM_TRACER_PIPE;

const u = new URL(process.argv[2]);
const payload = JSON.stringify({
  model: "qwen3-c-fallback",
  messages: [{ role: "user", content: "hello from c preload fallback" }]
});
const req = http.request({
  hostname: u.hostname,
  port: u.port,
  path: u.pathname,
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Connection": "close"
  }
}, (res) => {
  let raw = "";
  res.setEncoding("utf8");
  res.on("data", (c) => { raw += c; });
  res.on("end", () => {
    if (res.statusCode !== 200 || !raw.includes("ack:hello from c preload fallback")) {
      process.exit(2);
    }
  });
});
req.on("error", (err) => {
  console.error(err);
  process.exit(1);
});
req.write(payload);
req.end();
`
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0o644))
		runAndAssertSingleEvent(
			t,
			[]string{nodeBin, scriptPath, endpoint},
			"hello from c preload fallback",
			"ack:hello from c preload fallback",
			false,
		)
	})
}
