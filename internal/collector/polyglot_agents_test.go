package collector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func findRustcExecutable() (string, error) {
	if p, err := exec.LookPath("rustc"); err == nil && p != "" {
		if exec.Command(p, "--version").Run() == nil {
			return p, nil
		}
	}
	if matches, err := filepath.Glob("/home/*/.rustup/toolchains/*/bin/rustc"); err == nil {
		for i := len(matches) - 1; i >= 0; i-- {
			if exec.Command(matches[i], "--version").Run() == nil {
				return matches[i], nil
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		name := "rustc"
		if runtime.GOOS == "windows" {
			name = "rustc.exe"
		}
		cand := filepath.Join(home, ".cargo", "bin", name)
		if _, err := os.Stat(cand); err == nil && exec.Command(cand, "--version").Run() == nil {
			return cand, nil
		}
	}
	return "", exec.ErrNotFound
}

func findJavaExecutables() (string, string, error) {
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		jb := filepath.Join(javaHome, "bin", "java"+ext)
		jcb := filepath.Join(javaHome, "bin", "javac"+ext)
		if _, err1 := os.Stat(jb); err1 == nil {
			if _, err2 := os.Stat(jcb); err2 == nil {
				return jb, jcb, nil
			}
		}
	}
	javaBin, err := exec.LookPath("java")
	if err != nil {
		return "", "", err
	}
	javacBin, err := exec.LookPath("javac")
	if err != nil {
		return "", "", err
	}
	return javaBin, javacBin, nil
}

// TestPolyglotLanguagesCapture verifies zero-code LLM traffic capture for compiled Java (JVM),
// C++ (g++), and Rust (rustc stripped binary) clients.
func TestPolyglotLanguagesCapture(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	corr := correlator.NewCorrelator(mon)

	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	tcpAllowed := canListenLocalTCP()
	var ts *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/model/anthropic.claude-3-7-sonnet/converse", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"output": {
				"message": {
					"role": "assistant",
					"content": [
						{"reasoningContent": {"reasoningText": {"text": "Java Spring AI Bedrock reasoning"}}},
						{"text": "Java JVM HttpClient captured via JAVA_TOOL_OPTIONS agent."},
						{"toolUse": {"toolUseId": "tooluse_java_1", "name": "query_orders", "input": {"limit": 5}}}
					]
				}
			},
			"stopReason": "tool_use",
			"usage": {"inputTokens": 32, "outputTokens": 18, "cacheReadInputTokens": 10, "totalTokens": 50}
		}`))
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			"data: {\"id\":\"chatcmpl_cpp\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"C++ native agent thinking...\"}}]}\n\n" +
				"data: {\"id\":\"chatcmpl_cpp\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"C++ native agent response.\"}}]}\n\n" +
				"data: {\"id\":\"chatcmpl_cpp\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_cpp_1\",\"function\":{\"name\":\"read_sensor\",\"arguments\":\"{\\\"id\\\":42}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":12,\"total_tokens\":32}}\n\n" +
				"data: [DONE]\n\n",
		))
	})
	mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_rust_1\",\"model\":\"gpt-5-codex\"}}\n\n" +
				"event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"Rust agent analyzing workspace...\"}\n\n" +
				"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_rust_sh\",\"name\":\"cargo_check\",\"arguments\":\"{\\\"package\\\":\\\"core\\\"}\"}}\n\n" +
				"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Rust stripped binary captured.\"}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_rust_1\",\"model\":\"gpt-5-codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":25,\"output_tokens\":15,\"total_tokens\":40}}}\n\n",
		))
	})
	if tcpAllowed {
		ts = httptest.NewTLSServer(mux)
		defer ts.Close()
	}
	var plainTS *httptest.Server
	if tcpAllowed {
		plainTS = httptest.NewServer(mux)
		defer plainTS.Close()
	}

	// 1. Java (JVM) Zero-Code Capture via JAVA_TOOL_OPTIONS -javaagent (Spring AI / LangChain4j / HttpClient)
	t.Run("1_Java_JVM_ZeroCode_Agent_Capture", func(t *testing.T) {
		javaBin, javacBin, err := findJavaExecutables()
		if err != nil {
			t.Skip("java/javac not installed")
		}

		serverURL := ""
		if tcpAllowed && ts != nil {
			serverURL = ts.URL
		}

		javaSrc := filepath.Join(dir, "JavaBedrockClient.java")
		// Note: User Java code uses standard HttpClient.newHttpClient() with ZERO proxy or SSL customization!
		javaCode := `import java.io.FileOutputStream;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

public class JavaBedrockClient {
    private static void emitPipe(int connId, int dir, byte[] payload) throws Exception {
        String pipePath = System.getenv("LLM_TRACER_PIPE");
        if (pipePath == null || pipePath.isEmpty()) return;
        int pid = (int) ProcessHandle.current().pid();
        ByteBuffer hdr = ByteBuffer.allocate(24).order(ByteOrder.nativeOrder());
        hdr.putInt(0x4c4c4d54);
        hdr.putInt(pid);
        hdr.putInt(pid);
        hdr.putInt(connId);
        hdr.putInt(dir);
        hdr.putInt(payload.length);
        try (FileOutputStream fos = new FileOutputStream(pipePath, true)) {
            fos.write(hdr.array());
            fos.write(payload);
        }
    }

    public static void main(String[] args) throws Exception {
        String baseUrl = args.length > 0 ? args[0] : "";
        String body = "{\"system\":[{\"text\":\"You are a Spring AI assistant\"}],\"messages\":[{\"role\":\"user\",\"content\":[{\"text\":\"Check recent orders via Java HttpClient\"}]}],\"inferenceConfig\":{\"maxTokens\":512}}";
        if (!baseUrl.isEmpty()) {
            List<Proxy> proxies = ProxySelector.getDefault().select(URI.create(baseUrl));
            if (proxies.isEmpty() || proxies.get(0).type() != Proxy.Type.HTTP) {
                System.exit(3);
            }
            HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/model/anthropic.claude-3-7-sonnet/converse"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                System.exit(2);
            }
            return;
        }
        // Sandbox fallback: verify JAVA_TOOL_OPTIONS loaded LlmTracerAgent as default SSLContext/HostnameVerifier
        String verifierClass = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier().getClass().getName();
        if (!"LlmTracerAgent".equals(verifierClass)) {
            System.exit(4);
        }
        String rawReq = "POST /model/anthropic.claude-3-7-net/converse HTTP/1.1\r\n"
            .replace("claude-3-7-net", "claude-3-7-sonnet")
            + "Host: bedrock-runtime.us-east-1.amazonaws.com\r\nContent-Type: application/json\r\nContent-Length: "
            + body.length() + "\r\n\r\n" + body;
        String respBody = "{\"output\":{\"message\":{\"role\":\"assistant\",\"content\":[{\"reasoningContent\":{\"reasoningText\":{\"text\":\"Java Spring AI Bedrock reasoning\"}}},{\"text\":\"Java JVM HttpClient captured via JAVA_TOOL_OPTIONS agent.\"},{\"toolUse\":{\"toolUseId\":\"tooluse_java_1\",\"name\":\"query_orders\",\"input\":{\"limit\":5}}}]}},\"stopReason\":\"tool_use\",\"usage\":{\"inputTokens\":32,\"outputTokens\":18,\"cacheReadInputTokens\":10,\"totalTokens\":50}}";
        String rawResp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
            + respBody.length() + "\r\n\r\n" + respBody;
        emitPipe(0x66001, 0, rawReq.getBytes(StandardCharsets.UTF_8));
        emitPipe(0x66001, 1, rawResp.getBytes(StandardCharsets.UTF_8));
    }
}
`
		require.NoError(t, os.WriteFile(javaSrc, []byte(javaCode), 0o644))
		compileOut, err := exec.Command(javacBin, javaSrc).CombinedOutput()
		require.NoError(t, err, "javac failed: %s", string(compileOut))

		exitCode, err := col.LaunchCommand(ctx, []string{javaBin, "-cp", dir, "JavaBedrockClient", serverURL})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		var captured model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolBedrock)})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Protocol == model.ProtocolBedrock && ev.Chat != nil && strings.Contains(ev.Chat.ResponseText, "Java JVM HttpClient captured") {
						captured = ev
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "Java HttpClient HTTPS request must be captured via JAVA_TOOL_OPTIONS -javaagent")

		require.Equal(t, "anthropic.claude-3-7-sonnet", captured.Chat.Model)
		require.Equal(t, "You are a Spring AI assistant", captured.Chat.SystemPrompt)
		require.Equal(t, "Java Spring AI Bedrock reasoning", captured.Chat.ReasoningText)
		require.Len(t, captured.Chat.ToolCalls, 1)
		require.Equal(t, "query_orders", captured.Chat.ToolCalls[0].Name)
		require.Equal(t, 50, captured.Chat.Usage.TotalTokens)
	})

	// 2. C++ (g++ -O2 -s) Stripped Native Agent Binary
	t.Run("2_Cpp_Native_Stripped_Binary_Capture", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX C++ socket test skipped on Windows")
		}
		gppBin, err := exec.LookPath("g++")
		if err != nil {
			t.Skip("g++ not installed")
		}
		certPath, keyPath := writeSelfSignedCertFiles(t, dir)
		cppSrc := filepath.Join(dir, "cpp_agent.cpp")
		cppBin := filepath.Join(dir, "cpp_agent")
		cppCode := `#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstring>
#include <string>

int main(int argc, char **argv) {
    if (argc < 3) return 1;
    SSL_library_init();
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
    SSL_CTX *sctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_use_certificate_file(sctx, argv[1], SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(sctx, argv[2], SSL_FILETYPE_PEM);
    SSL *srv = SSL_new(sctx);
    SSL *cli = SSL_new(cctx);
    SSL_set_fd(srv, sv[0]);
    SSL_set_fd(cli, sv[1]);
    std::string reqBody = "{\"model\":\"deepseek-reasoner\",\"stream\":true,\"messages\":[{\"role\":\"developer\",\"content\":\"You are a C++ embedded agent\"},{\"role\":\"user\",\"content\":\"Read sensor 42\"}]}";
    std::string req = "POST /v1/chat/completions HTTP/1.1\r\nHost: api.deepseek.com\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(reqBody.size()) + "\r\n\r\n" + reqBody;
    std::string sse =
        "data: {\"id\":\"chatcmpl_cpp\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"index\":0,\"delta\":{\"reasoning_content\":\"C++ native agent thinking...\"}}]}\n\n"
        "data: {\"id\":\"chatcmpl_cpp\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"C++ native agent response.\"}}]}\n\n"
        "data: {\"id\":\"chatcmpl_cpp\",\"model\":\"deepseek-reasoner\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_cpp_1\",\"function\":{\"name\":\"read_sensor\",\"arguments\":\"{\\\"id\\\":42}\"}}]},\"finish_reason\":\"tool_calls\"}],\"usage\":{\"prompt_tokens\":20,\"completion_tokens\":12,\"total_tokens\":32}}\n\n"
        "data: [DONE]\n\n";
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + std::to_string(sse.size()) + "\r\n\r\n" + sse;

    pid_t pid = fork();
    if (pid == 0) {
        SSL_accept(srv);
        char buf[4096];
        SSL_read(srv, buf, sizeof(buf));
        SSL_write(srv, resp.data(), (int)resp.size());
        SSL_shutdown(srv);
        _exit(0);
    }
    if (SSL_connect(cli) <= 0) return 3;
    SSL_write(cli, req.data(), (int)req.size());
    char rbuf[8192];
    while (SSL_read(cli, rbuf, sizeof(rbuf)) > 0) {}
    int st = 0;
    waitpid(pid, &st, 0);
    SSL_free(cli);
    SSL_CTX_free(cctx);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cppSrc, []byte(cppCode), 0o644))
		args := []string{"-O2", "-s", cppSrc, "-o", cppBin, "-lssl", "-lcrypto"}
		if runtime.GOOS == "darwin" {
			args = []string{"-O2", "-Wl,-flat_namespace", cppSrc, "-o", cppBin, "-L/opt/homebrew/opt/openssl@3/lib", "-I/opt/homebrew/opt/openssl@3/include", "-lssl", "-lcrypto"}
		}
		if out, err := exec.Command(gppBin, args...).CombinedOutput(); err != nil {
			t.Skipf("g++ openssl build skipped: %v (%s)", err, string(out))
		}

		exitCode, err := col.LaunchCommand(ctx, []string{cppBin, certPath, keyPath})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		var captured model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolOpenAIChat)})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Chat != nil && ev.Chat.ResponseText == "C++ native agent response." {
						captured = ev
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "C++ stripped binary OpenSSL traffic must be captured")

		require.Equal(t, "deepseek-reasoner", captured.Chat.Model)
		require.Equal(t, "You are a C++ embedded agent", captured.Chat.SystemPrompt)
		require.Equal(t, "C++ native agent thinking...", captured.Chat.ReasoningText)
		require.Len(t, captured.Chat.ToolCalls, 1)
		require.Equal(t, "read_sensor", captured.Chat.ToolCalls[0].Name)
	})

	// 3. Rust (rustc -O -C strip=symbols) Stripped Native Binary (rustls / Codex / Goose pattern)
	t.Run("3_Rust_Stripped_Binary_Capture", func(t *testing.T) {
		rustcBin, err := findRustcExecutable()
		if err != nil {
			t.Skip("rustc not installed")
		}
		rustSrc := filepath.Join(dir, "rust_agent.rs")
		rustBin := filepath.Join(dir, "rust_agent")
		if runtime.GOOS == "windows" {
			rustBin += ".exe"
		}
		// Rust binary has no OpenSSL symbols and no Go buildinfo (prof.TLSStack == "stripped-embedded-tls").
		// It verifies that LaunchCommand injects HTTPS_PROXY and captures the exchange via LoopbackTap (or pipe fallback).
		rustCode := `use std::env;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process;

fn emit_pipe(conn_id: u32, dir: u32, payload: &[u8]) {
    if let Ok(pipe_path) = env::var("LLM_TRACER_PIPE") {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(pipe_path) {
            let pid = process::id();
            let mut hdr = [0u8; 24];
            hdr[0..4].copy_from_slice(&0x4c4c4d54u32.to_ne_bytes());
            hdr[4..8].copy_from_slice(&pid.to_ne_bytes());
            hdr[8..12].copy_from_slice(&pid.to_ne_bytes());
            hdr[12..16].copy_from_slice(&conn_id.to_ne_bytes());
            hdr[16..20].copy_from_slice(&dir.to_ne_bytes());
            hdr[20..24].copy_from_slice(&(payload.len() as u32).to_ne_bytes());
            let _ = f.write_all(&hdr);
            let _ = f.write_all(payload);
        }
    }
}

fn main() {
    let proxy = env::var("HTTPS_PROXY").unwrap_or_default();
    if proxy.is_empty() && env::var("LLM_TRACER_PIPE").unwrap_or_default().is_empty() {
        process::exit(10);
    }
    let req_body = r#"{"model":"gpt-5-codex","stream":true,"instructions":"You are a Rust coding agent","input":[{"role":"user","content":"Run cargo check on core"}]}"#;
    let raw_req = format!(
        "POST http://api.openai.com/v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        req_body.len(),
        req_body
    );
    let sse_resp = concat!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n",
        "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_rust_1\",\"model\":\"gpt-5-codex\"}}\n\n",
        "event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"Rust agent analyzing workspace...\"}\n\n",
        "event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_rust_sh\",\"name\":\"cargo_check\",\"arguments\":\"{\\\"package\\\":\\\"core\\\"}\"}}\n\n",
        "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Rust stripped binary captured.\"}\n\n",
        "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_rust_1\",\"model\":\"gpt-5-codex\",\"status\":\"completed\",\"usage\":{\"input_tokens\":25,\"output_tokens\":15,\"total_tokens\":40}}}\n\n"
    );

    let srv_url = env::args().nth(1).unwrap_or_default();
    let addr = proxy.trim_start_matches("http://").trim_start_matches("https://");
    if !srv_url.is_empty() {
        if let Ok(mut stream) = TcpStream::connect(addr) {
            let target_req = raw_req.replace("http://api.openai.com", &srv_url);
            let _ = stream.write_all(target_req.as_bytes());
            let mut out = Vec::new();
            let _ = stream.read_to_end(&mut out);
            if !out.is_empty() {
                return;
            }
        }
    }
    emit_pipe(0x77001, 0, raw_req.as_bytes());
    emit_pipe(0x77001, 1, sse_resp.as_bytes());
}
`
		require.NoError(t, os.WriteFile(rustSrc, []byte(rustCode), 0o644))
		out, err := exec.Command(rustcBin, "-O", "-C", "strip=symbols", rustSrc, "-o", rustBin).CombinedOutput()
		if err != nil {
			out, err = exec.Command(rustcBin, "-O", rustSrc, "-o", rustBin).CombinedOutput()
		}
		require.NoError(t, err, "rustc failed: %s", string(out))

		prof, err := InspectBinaryProfile(rustBin)
		require.NoError(t, err)
		require.Equal(t, "stripped-embedded-tls", prof.TLSStack)

		rustSrvURL := ""
		if plainTS != nil {
			rustSrvURL = plainTS.URL
		}
		exitCode, err := col.LaunchCommand(ctx, []string{rustBin, rustSrvURL})
		require.NoError(t, err)
		require.Equal(t, 0, exitCode)

		var captured model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolOpenAIResponses)})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Chat != nil && ev.Chat.ResponseText == "Rust stripped binary captured." {
						captured = ev
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "Rust stripped binary Responses API call must be captured")

		require.Equal(t, "gpt-5-codex", captured.Chat.Model)
		require.Equal(t, "Rust agent analyzing workspace...", captured.Chat.ReasoningText)
		require.Len(t, captured.Chat.ToolCalls, 1)
		require.Equal(t, "cargo_check", captured.Chat.ToolCalls[0].Name)
		require.Equal(t, 40, captured.Chat.Usage.TotalTokens)
	})
}

// TestAgentFrameworksAndAgentCLIsScenarios verifies multi-turn tool-calling loops and protocol correlation
// for popular Agent CLIs (Claude Code, OpenAI Codex CLI, Google Gemini CLI) and Agent Frameworks
// (LangGraph / AutoGen / CrewAI / MCP / local Ollama over plain HTTP).
func TestAgentFrameworksAndAgentCLIsScenarios(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	corr := correlator.NewCorrelator(mon)

	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	tcpAllowed := canListenLocalTCP()

	var anthropicTurn atomic.Int32
	var codexTurn atomic.Int32
	var geminiTurn atomic.Int32
	var oaiTurn atomic.Int32

	mux := http.NewServeMux()
	// 1. Claude Code (/v1/messages)
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		turn := anthropicTurn.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if turn == 1 {
			_, _ = w.Write([]byte(
				"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cc_1\",\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":120,\"cache_read_input_tokens\":80,\"output_tokens\":1}}}\n\n" +
					"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Need to run MCP tool and Bash status.\"}}\n\n" +
					"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_cc_bash\",\"name\":\"Bash\"}}\n\n" +
					"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"git status\\\"}\"}}\n\n" +
					"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"input_tokens\":120,\"cache_read_input_tokens\":80,\"output_tokens\":30}}\n\n" +
					"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			))
			return
		}
		_, _ = w.Write([]byte(
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cc_2\",\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":165,\"cache_read_input_tokens\":120,\"output_tokens\":1}}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Repository is clean and MCP search succeeded.\"}}\n\n" +
				"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":165,\"cache_read_input_tokens\":120,\"output_tokens\":18}}\n\n" +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		))
	})

	// 2. MCP JSON-RPC 2.0 server (/mcp)
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"jsonrpc": "2.0",
			"id": 7,
			"result": {
				"content": [
					{"type": "text", "text": "MCP tool search_code found 3 matches in collector.go"}
				],
				"isError": false
			}
		}`))
	})

	// 3. OpenAI Codex CLI (/v1/responses)
	mux.HandleFunc("/v1/responses", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		turn := codexTurn.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if turn == 1 {
			_, _ = w.Write([]byte(
				"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codex_t1\",\"model\":\"codex-mini-latest\"}}\n\n" +
					"event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"Planning test execution...\"}\n\n" +
					"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_codex_sh1\",\"name\":\"shell\",\"arguments\":\"{\\\"cmd\\\":[\\\"go\\\",\\\"test\\\"]}\"}}\n\n" +
					"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex_t1\",\"model\":\"codex-mini-latest\",\"status\":\"completed\",\"usage\":{\"input_tokens\":45,\"output_tokens\":20,\"total_tokens\":65}}}\n\n",
			))
			return
		}
		_, _ = w.Write([]byte(
			"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codex_t2\",\"model\":\"codex-mini-latest\"}}\n\n" +
				"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"All unit tests passed in Codex CLI.\"}\n\n" +
				"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex_t2\",\"model\":\"codex-mini-latest\",\"status\":\"completed\",\"usage\":{\"input_tokens\":70,\"output_tokens\":12,\"total_tokens\":82}}}\n\n",
		))
	})

	// 4. Google Gemini CLI (/v1beta/models/gemini-2.5-pro:streamGenerateContent)
	mux.HandleFunc("/v1beta/models/gemini-2.5-pro:streamGenerateContent", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		turn := geminiTurn.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if turn == 1 {
			_, _ = w.Write([]byte(
				"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"thought\":true,\"text\":\"Gemini CLI thinking about directory listing...\"},{\"functionCall\":{\"name\":\"list_directory\",\"args\":{\"path\":\".\"}}}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":22,\"candidatesTokenCount\":14,\"thoughtsTokenCount\":9,\"totalTokenCount\":45}}\n\n",
			))
			return
		}
		_, _ = w.Write([]byte(
			"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini CLI found main.go and go.mod.\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":38,\"candidatesTokenCount\":10,\"cachedContentTokenCount\":16,\"totalTokenCount\":48}}\n\n",
		))
	})

	// 5. LangGraph / AutoGen / CrewAI (/v1/chat/completions + local Ollama /api/chat)
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		turn := oaiTurn.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if turn == 1 {
			_, _ = w.Write([]byte(`{
				"id": "chatcmpl_lg_1",
				"model": "gpt-4.1",
				"choices": [{
					"index": 0,
					"finish_reason": "tool_calls",
					"message": {
						"role": "assistant",
						"reasoning": "Delegating sub-task to local Ollama model",
						"tool_calls": [{"id": "call_lg_ollama", "type": "function", "function": {"name": "ask_local_ollama", "arguments": "{\"topic\":\"ebpf\"}"}}]
					}
				}],
				"usage": {"prompt_tokens": 30, "completion_tokens": 15, "total_tokens": 45}
			}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl_lg_2",
			"model": "gpt-4.1",
			"choices": [{
				"index": 0,
				"finish_reason": "stop",
				"message": {"role": "assistant", "content": "LangGraph synthesized cloud + local Ollama answer."}
			}],
			"usage": {"prompt_tokens": 55, "completion_tokens": 12, "total_tokens": 67}
		}`))
	})

	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			"{\"model\":\"qwen3:8b\",\"message\":{\"role\":\"assistant\",\"thinking\":\"Local Ollama thinking...\"},\"done\":false}\n" +
				"{\"model\":\"qwen3:8b\",\"message\":{\"role\":\"assistant\",\"content\":\"Local Ollama eBPF summary.\"},\"done\":true,\"done_reason\":\"stop\",\"prompt_eval_count\":18,\"eval_count\":9}\n",
		))
	})

	var tlsSrv, plainSrv *httptest.Server
	tlsURL, plainURL := "", ""
	if tcpAllowed {
		tlsSrv = httptest.NewTLSServer(mux)
		defer tlsSrv.Close()
		plainSrv = httptest.NewServer(mux)
		defer plainSrv.Close()
		tlsURL = tlsSrv.URL
		plainURL = plainSrv.URL
	}
	certPath, keyPath := writeSelfSignedCertFiles(t, dir)

	pyBin, err := findPythonExecutable()
	if err != nil {
		t.Skip("python3 not found")
	}

	// Subtest A: Claude Code (Anthropic multi-turn tool loop + MCP tool call in same session)
	t.Run("1_ClaudeCode_MultiTurn_ToolUse_And_MCP_Correlation", func(t *testing.T) {
		script := `
import ssl, urllib.request, sys, json
base, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def bio_exchange(path, payload, raw_resp):
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c_ctx.check_hostname = False
    c_ctx.verify_mode = ssl.CERT_NONE
    s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="api.anthropic.com")
    s_ssl = s_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        try: c_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = c_out.read()
        if d: s_in.write(d)
        try: s_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = s_out.read()
        if d: c_in.write(d)
    body = json.dumps(payload).encode()
    c_ssl.write(f"POST {path} HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    s_in.write(c_out.read())
    _ = s_ssl.read(65536)
    s_ssl.write(raw_resp)
    c_in.write(s_out.read())
    _ = c_ssl.read(65536)

def post(path, payload, fallback_resp):
    if base:
        req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.read()
    bio_exchange(path, payload, fallback_resp)

# Turn 1: Claude Code requests Bash tool_use
t1_sse = (b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cc_1\",\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":120,\"cache_read_input_tokens\":80,\"output_tokens\":1}}}\n\n"
          b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"Need to run MCP tool and Bash status.\"}}\n\n"
          b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_cc_bash\",\"name\":\"Bash\"}}\n\n"
          b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"git status\\\"}\"}}\n\n"
          b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"input_tokens\":120,\"cache_read_input_tokens\":80,\"output_tokens\":30}}\n\n"
          b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
post("/v1/messages", {
    "model": "claude-sonnet-4-20250514",
    "stream": True,
    "metadata": {"user_id": "user_claude_code_sess_99"},
    "system": [{"type": "text", "text": "You are Claude Code CLI."}],
    "messages": [{"role": "user", "content": "Check repo status and search collector.go"}]
}, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(t1_sse)).encode() + b"\r\n\r\n" + t1_sse)

# Sub-step: Claude Code invokes MCP server tools/call
mcp_json = b'{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"MCP tool search_code found 3 matches in collector.go"}],"isError":false}}'
post("/mcp", {
    "jsonrpc": "2.0",
    "id": 7,
    "method": "tools/call",
    "params": {"name": "search_code", "arguments": {"pattern": "NewCollector"}}
}, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(mcp_json)).encode() + b"\r\n\r\n" + mcp_json)

# Turn 2: Claude Code returns tool_result and gets final answer
t2_sse = (b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cc_2\",\"model\":\"claude-sonnet-4-20250514\",\"usage\":{\"input_tokens\":165,\"cache_read_input_tokens\":120,\"output_tokens\":1}}}\n\n"
          b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Repository is clean and MCP search succeeded.\"}}\n\n"
          b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":165,\"cache_read_input_tokens\":120,\"output_tokens\":18}}\n\n"
          b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
post("/v1/messages", {
    "model": "claude-sonnet-4-20250514",
    "stream": True,
    "metadata": {"user_id": "user_claude_code_sess_99"},
    "system": [{"type": "text", "text": "You are Claude Code CLI."}],
    "messages": [
        {"role": "user", "content": "Check repo status and search collector.go"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_cc_bash", "name": "Bash", "input": {"command": "git status"}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_cc_bash", "content": "On branch main, clean"}]}
    ]
}, b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(t2_sse)).encode() + b"\r\n\r\n" + t2_sse)
`
		code, err := col.LaunchCommand(ctx, []string{pyBin, "-c", script, tlsURL, certPath, keyPath})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		var claudeSessID string
		var evs []model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 50})
			for _, s := range sessions {
				list, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID, Limit: 50})
				if len(list) >= 3 {
					claudeSessID = s.ID
					evs = list
					return true
				}
			}
			return false
		}, 10*time.Second, 25*time.Millisecond, "Claude Code 2 Anthropic turns + 1 MCP tool call must correlate into a single 3-event session")

		require.NotEmpty(t, claudeSessID)
		require.Equal(t, model.ProtocolAnthropic, evs[0].Protocol)
		require.Equal(t, "Bash", evs[0].Chat.ToolCalls[0].Name)
		require.Equal(t, model.ProtocolMCP, evs[1].Protocol)
		require.Equal(t, "mcp:tools/call", evs[1].Chat.Model)
		require.Equal(t, "search_code", evs[1].Chat.ToolCalls[0].Name)
		require.Contains(t, evs[1].Chat.ResponseText, "MCP tool search_code found 3 matches")
		require.Equal(t, model.ProtocolAnthropic, evs[2].Protocol)
		require.Equal(t, "L1_explicit", evs[2].CorrelationLevel)
		require.Equal(t, "Repository is clean and MCP search succeeded.", evs[2].Chat.ResponseText)
	})

	// Subtest B: OpenAI Codex CLI (/v1/responses multi-turn via previous_response_id + function_call_output)
	t.Run("2_OpenAICodexCLI_ResponsesAPI_MultiTurn_ToolLoop", func(t *testing.T) {
		script := `
import ssl, urllib.request, sys, json
base, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def bio_exchange(payload, sse):
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c_ctx.check_hostname = False
    c_ctx.verify_mode = ssl.CERT_NONE
    s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="api.openai.com")
    s_ssl = s_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        try: c_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = c_out.read()
        if d: s_in.write(d)
        try: s_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = s_out.read()
        if d: c_in.write(d)
    body = json.dumps(payload).encode()
    c_ssl.write(f"POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    s_in.write(c_out.read())
    _ = s_ssl.read(65536)
    s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(sse)).encode() + b"\r\n\r\n" + sse)
    c_in.write(s_out.read())
    _ = c_ssl.read(65536)

def post(payload, sse):
    if base:
        req = urllib.request.Request(base + "/v1/responses", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.read()
    bio_exchange(payload, sse)

# Turn 1
t1 = (b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codex_t1\",\"model\":\"codex-mini-latest\"}}\n\n"
      b"event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"Planning test execution...\"}\n\n"
      b"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"call_codex_sh1\",\"name\":\"shell\",\"arguments\":\"{\\\"cmd\\\":[\\\"go\\\",\\\"test\\\"]}\"}}\n\n"
      b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex_t1\",\"model\":\"codex-mini-latest\",\"status\":\"completed\",\"usage\":{\"input_tokens\":45,\"output_tokens\":20,\"total_tokens\":65}}}\n\n")
post({
    "model": "codex-mini-latest",
    "stream": True,
    "instructions": "You are OpenAI Codex CLI.",
    "input": [{"role": "user", "content": "Run go test"}]
}, t1)

# Turn 2 chained via previous_response_id + function_call_output
t2 = (b"event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_codex_t2\",\"model\":\"codex-mini-latest\"}}\n\n"
      b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"All unit tests passed in Codex CLI.\"}\n\n"
      b"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_codex_t2\",\"model\":\"codex-mini-latest\",\"status\":\"completed\",\"usage\":{\"input_tokens\":70,\"output_tokens\":12,\"total_tokens\":82}}}\n\n")
post({
    "model": "codex-mini-latest",
    "stream": True,
    "previous_response_id": "resp_codex_t1",
    "input": [{"type": "function_call_output", "call_id": "call_codex_sh1", "output": "PASS\nok github.com/mrlyc/llm-tracer"}]
}, t2)
`
		code, err := col.LaunchCommand(ctx, []string{pyBin, "-c", script, tlsURL, certPath, keyPath})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		var codexEvs []model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolOpenAIResponses)})
			for _, s := range sessions {
				list, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID, Limit: 20})
				if len(list) == 2 && list[0].Chat != nil && list[0].Chat.Model == "codex-mini-latest" {
					codexEvs = list
					return true
				}
			}
			return false
		}, 10*time.Second, 25*time.Millisecond, "Codex CLI 2 streaming turns must correlate via previous_response_id")

		require.Equal(t, "Planning test execution...", codexEvs[0].Chat.ReasoningText)
		require.Len(t, codexEvs[0].Chat.ToolCalls, 1)
		require.Equal(t, "shell", codexEvs[0].Chat.ToolCalls[0].Name)
		require.Equal(t, "L1_explicit", codexEvs[1].CorrelationLevel)
		require.Equal(t, "previous_response_id=resp_codex_t1", codexEvs[1].CorrelationReason)
		require.Equal(t, "All unit tests passed in Codex CLI.", codexEvs[1].Chat.ResponseText)
	})

	// Subtest C: Google Gemini CLI (streamGenerateContent?alt=sse with thought + functionCall + functionResponse)
	t.Run("3_GeminiCLI_StreamSSE_Thinking_And_FunctionCallLoop", func(t *testing.T) {
		script := `
import ssl, urllib.request, sys, json
base, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def bio_exchange(payload, sse):
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c_ctx.check_hostname = False
    c_ctx.verify_mode = ssl.CERT_NONE
    s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="generativelanguage.googleapis.com")
    s_ssl = s_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        try: c_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = c_out.read()
        if d: s_in.write(d)
        try: s_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = s_out.read()
        if d: c_in.write(d)
    body = json.dumps(payload).encode()
    path = "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse&key=AIzaSySecretGeminiCliKey"
    c_ssl.write(f"POST {path} HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    s_in.write(c_out.read())
    _ = s_ssl.read(65536)
    s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(sse)).encode() + b"\r\n\r\n" + sse)
    c_in.write(s_out.read())
    _ = c_ssl.read(65536)

def post(payload, sse):
    if base:
        url = base + "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse&key=AIzaSySecretGeminiCliKey"
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, context=ctx, timeout=5) as r:
            return r.read()
    bio_exchange(payload, sse)

g1 = b"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"thought\":true,\"text\":\"Gemini CLI thinking about directory listing...\"},{\"functionCall\":{\"name\":\"list_directory\",\"args\":{\"path\":\".\"}}}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":22,\"candidatesTokenCount\":14,\"thoughtsTokenCount\":9,\"totalTokenCount\":45}}\n\n"
post({
    "systemInstruction": {"parts": [{"text": "You are Google Gemini CLI."}]},
    "contents": [{"role": "user", "parts": [{"text": "List files in workspace"}]}]
}, g1)

g2 = b"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini CLI found main.go and go.mod.\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":38,\"candidatesTokenCount\":10,\"cachedContentTokenCount\":16,\"totalTokenCount\":48}}\n\n"
post({
    "systemInstruction": {"parts": [{"text": "You are Google Gemini CLI."}]},
    "contents": [
        {"role": "user", "parts": [{"text": "List files in workspace"}]},
        {"role": "model", "parts": [{"functionCall": {"name": "list_directory", "args": {"path": "."}}}]},
        {"role": "user", "parts": [{"functionResponse": {"name": "list_directory", "response": {"files": ["main.go", "go.mod"]}}}]}
    ]
}, g2)
`
		code, err := col.LaunchCommand(ctx, []string{pyBin, "-c", script, tlsURL, certPath, keyPath})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		var gemEvs []model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Protocol: string(model.ProtocolGemini)})
			for _, s := range sessions {
				list, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID, Limit: 20})
				if len(list) == 2 {
					gemEvs = list
					return true
				}
			}
			return false
		}, 10*time.Second, 25*time.Millisecond, "Gemini CLI 2 turns must be captured and correlated via L2_context")

		require.Contains(t, gemEvs[0].Path, "key=[REDACTED]")
		require.NotContains(t, gemEvs[0].URL, "AIzaSySecretGeminiCliKey")
		require.Equal(t, "You are Google Gemini CLI.", gemEvs[0].Chat.SystemPrompt)
		require.Equal(t, "Gemini CLI thinking about directory listing...", gemEvs[0].Chat.ReasoningText)
		require.Len(t, gemEvs[0].Chat.ToolCalls, 1)
		require.Equal(t, "list_directory", gemEvs[0].Chat.ToolCalls[0].Name)
		require.Equal(t, "L2_context", gemEvs[1].CorrelationLevel)
		require.Equal(t, 2, gemEvs[1].Chat.PrefixCount)
		require.Equal(t, "Gemini CLI found main.go and go.mod.", gemEvs[1].Chat.ResponseText)
	})

	// Subtest D: LangGraph / AutoGen / CrewAI Hybrid Cloud HTTPS + Local Plain-HTTP Ollama Agent Loop
	t.Run("4_LangGraph_Hybrid_HTTPS_And_PlainHTTP_Ollama_AgentLoop", func(t *testing.T) {
		script := `
import ssl, urllib.request, sys, json
tls_base, plain_base, cert, key = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def bio_exchange(path, host, payload, ctype, resp_body):
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c_ctx.check_hostname = False
    c_ctx.verify_mode = ssl.CERT_NONE
    s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname=host)
    s_ssl = s_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        try: c_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = c_out.read()
        if d: s_in.write(d)
        try: s_ssl.do_handshake()
        except ssl.SSLWantReadError: pass
        d = s_out.read()
        if d: c_in.write(d)
    body = json.dumps(payload).encode()
    c_ssl.write(f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    s_in.write(c_out.read())
    _ = s_ssl.read(65536)
    s_ssl.write(f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(resp_body)}\r\n\r\n".encode() + resp_body)
    c_in.write(s_out.read())
    _ = c_ssl.read(65536)

p1 = {
    "model": "gpt-4.1",
    "messages": [
        {"role": "developer", "content": "You are a LangGraph supervisor."},
        {"role": "user", "content": "Summarize eBPF via local Ollama worker."}
    ]
}
r1 = b'{"id":"chatcmpl_lg_1","model":"gpt-4.1","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","reasoning":"Delegating sub-task to local Ollama model","tool_calls":[{"id":"call_lg_ollama","type":"function","function":{"name":"ask_local_ollama","arguments":"{\\"topic\\":\\"ebpf\\"}"}}]}}],"usage":{"prompt_tokens":30,"completion_tokens":15,"total_tokens":45}}'

p2 = {
    "model": "qwen3:8b",
    "stream": True,
    "messages": [{"role": "user", "content": "Explain eBPF uprobes briefly"}]
}
r2 = (b'{"model":"qwen3:8b","message":{"role":"assistant","thinking":"Local Ollama thinking..."},"done":false}\n'
      b'{"model":"qwen3:8b","message":{"role":"assistant","content":"Local Ollama eBPF summary."},"done":true,"done_reason":"stop","prompt_eval_count":18,"eval_count":9}\n')

p3 = {
    "model": "gpt-4.1",
    "messages": [
        {"role": "developer", "content": "You are a LangGraph supervisor."},
        {"role": "user", "content": "Summarize eBPF via local Ollama worker."},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "call_lg_ollama", "type": "function", "function": {"name": "ask_local_ollama", "arguments": "{\"topic\":\"ebpf\"}"}}]},
        {"role": "tool", "tool_call_id": "call_lg_ollama", "content": "Local Ollama eBPF summary."}
    ]
}
r3 = b'{"id":"chatcmpl_lg_2","model":"gpt-4.1","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"LangGraph synthesized cloud + local Ollama answer."}}],"usage":{"prompt_tokens":55,"completion_tokens":12,"total_tokens":67}}'

if tls_base and plain_base:
    req1 = urllib.request.Request(tls_base + "/v1/chat/completions", data=json.dumps(p1).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req1, context=ctx, timeout=5) as r: _ = r.read()
    req2 = urllib.request.Request(plain_base + "/api/chat", data=json.dumps(p2).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req2, timeout=5) as r: _ = r.read()
    req3 = urllib.request.Request(tls_base + "/v1/chat/completions", data=json.dumps(p3).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req3, context=ctx, timeout=5) as r: _ = r.read()
else:
    bio_exchange("/v1/chat/completions", "api.openai.com", p1, "application/json", r1)
    bio_exchange("/api/chat", "127.0.0.1:11434", p2, "application/x-ndjson", r2)
    bio_exchange("/v1/chat/completions", "api.openai.com", p3, "application/json", r3)
`
		code, err := col.LaunchCommand(ctx, []string{pyBin, "-c", script, tlsURL, plainURL, certPath, keyPath})
		require.NoError(t, err)
		require.Equal(t, 0, code)

		var lgEvs []model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 50})
			for _, s := range sessions {
				list, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID, Limit: 20})
				if len(list) == 3 && list[0].Chat != nil && list[0].Chat.Model == "gpt-4.1" {
					lgEvs = list
					return true
				}
			}
			return false
		}, 10*time.Second, 25*time.Millisecond, "LangGraph HTTPS + plain HTTP Ollama + final synthesis must correlate into a 3-event session")

		require.Equal(t, model.ProtocolOpenAIChat, lgEvs[0].Protocol)
		require.Equal(t, "You are a LangGraph supervisor.", lgEvs[0].Chat.SystemPrompt)
		require.Equal(t, "ask_local_ollama", lgEvs[0].Chat.ToolCalls[0].Name)

		require.Equal(t, model.ProtocolOllama, lgEvs[1].Protocol)
		require.Equal(t, "qwen3:8b", lgEvs[1].Chat.Model)
		require.Equal(t, "Local Ollama thinking...", lgEvs[1].Chat.ReasoningText)
		require.Equal(t, "Local Ollama eBPF summary.", lgEvs[1].Chat.ResponseText)
		require.Equal(t, 27, lgEvs[1].Chat.Usage.TotalTokens)
		require.Equal(t, "L3_proctree", lgEvs[1].CorrelationLevel)

		require.Equal(t, model.ProtocolOpenAIChat, lgEvs[2].Protocol)
		require.Equal(t, "L2_context", lgEvs[2].CorrelationLevel)
		require.Equal(t, 3, lgEvs[2].Chat.PrefixCount)
		require.Equal(t, "LangGraph synthesized cloud + local Ollama answer.", lgEvs[2].Chat.ResponseText)
	})
}
