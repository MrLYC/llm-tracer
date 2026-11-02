package collector

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

// TestLivePIDAttachWithoutRestart verifies attaching to ALREADY-RUNNING processes by `--pid`
// without restarting them:
//  1. Stripped Go binary (`go build -ldflags="-s -w"`) -> .gopclntab symbol recovery + eBPF Uprobe when root.
//  2. Already-running Java (JVM) process -> automatic detection (`jvm-jsse`), eBPF limitation prompt,
//     and live JVM Dynamic Attach (`agentmain` via jcmd/AttachSocket) without restarting the JVM.
//  3. Already-running Node.js process -> automatic detection, live `SIGUSR1` V8 Inspector runtime hook injection
//     without restarting Node.js.
//  4. Already-running stripped native C binary -> live `ptrace -p <pid>` (`PTRACE_SEIZE`) attach & clean detach.
func TestLivePIDAttachWithoutRestart(t *testing.T) {
	dir := t.TempDir()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/messages":
			_, _ = w.Write([]byte(`{"id":"msg_live_jvm","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"live jvm dynamic attach without restart ok"}],"stop_reason":"end_turn"}`))
		case "/v1/responses":
			_, _ = w.Write([]byte(`{"id":"resp_live_node","object":"response","model":"gpt-5-codex","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"live node sigusr1 inspector attach ok"}]}]}`))
		default:
			_, _ = w.Write([]byte(`{"id":"chatcmpl-live","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"live stripped gotls pclntab ok"},"finish_reason":"stop"}]}`))
		}
	})
	var ts *httptest.Server
	tsURL := "https://127.0.0.1:1"
	if ln, err := net.Listen("tcp4", "127.0.0.1:0"); err == nil {
		ts = httptest.NewUnstartedServer(handler)
		ts.Listener = ln
		ts.StartTLS()
		defer ts.Close()
		tsURL = ts.URL
	} else if os.Geteuid() == 0 {
		// CI root job must never silently degrade into the no-listener branches,
		// otherwise the "no --- SKIP" guard passes while nothing was exercised.
		t.Fatalf("loopback TLS server must start in root environment: %v", err)
	}

	newPIDCollector := func(t *testing.T, sub string, pid int) (*Collector, *store.Store, func()) {
		subDir := filepath.Join(dir, sub)
		mon, err := selfmon.NewMonitor(subDir)
		require.NoError(t, err)
		st, err := store.NewStore(subDir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()
		defer func() { _ = mon.Close() }()
		corr := correlator.NewCorrelator(mon)
		col, err := NewCollector(subDir, model.ScopeFilter{PIDs: []int{pid}}, corr, st, mon)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, col.Start(ctx))
		cleanup := func() {
			cancel()
			col.Stop()
		}
		return col, st, cleanup
	}

	// 1. Stripped Go Binary (`go build -ldflags="-s -w"`): .gopclntab symbol recovery on running PID
	t.Run("1_StrippedGoBinary_PclntabSymbolRecovery_ForRunningPID", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("ELF .gopclntab uprobe offset test targets Linux ELF")
		}
		goSrc := filepath.Join(dir, "stripped_go_client.go")
		goBin := filepath.Join(dir, "stripped_go_client")
		readyFile := filepath.Join(dir, "go_ready.flag")
		triggerFile := filepath.Join(dir, "go_trigger.flag")
		code := `package main
import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"time"
)
func main() {
	_ = os.WriteFile(os.Args[1], []byte("ready"), 0o644)
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(os.Args[2]); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{Transport: tr}
	reqBody := []byte(` + "`" + `{"model":"gpt-4.1","messages":[{"role":"user","content":"hello from stripped go binary"}]}` + "`" + `)
	resp, err := client.Post(os.Args[3]+"/v1/chat/completions", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		os.Exit(2)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
}
`
		require.NoError(t, os.WriteFile(goSrc, []byte(code), 0o644))
		buildOut, err := exec.Command("go", "build", "-ldflags=-s -w", "-o", goBin, goSrc).CombinedOutput()
		require.NoError(t, err, "build stripped go binary: %s", string(buildOut))

		// Verify .gopclntab recovery finds crypto/tls.(*Conn).Write & Read even though -s -w stripped .symtab!
		gt, err := InspectGoTLSTarget(goBin)
		require.NoError(t, err)
		require.NotNil(t, gt)
		require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Write"], uint64(0), "must recover Write offset from .gopclntab on stripped Go binary")
		require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Read"], uint64(0), "must recover Read offset from .gopclntab on stripped Go binary")
		if runtime.GOARCH == "amd64" {
			require.NotEmpty(t, gt.GoTLSReadRetOffsets, "must recover Read RET offsets from .gopclntab function bounds")
		}

		// Start the stripped Go process FIRST (before Collector is even created!)
		cmd := exec.Command(goBin, readyFile, triggerFile, tsURL)
		require.NoError(t, cmd.Start())
		runningPID := cmd.Process.Pid
		defer func() { _ = cmd.Process.Kill() }()

		require.Eventually(t, func() bool {
			_, err := os.Stat(readyFile)
			return err == nil
		}, 2*time.Second, 10*time.Millisecond, "wait for stripped Go process to start main()")

		col, st, cleanup := newPIDCollector(t, "scen_stripped_go", runningPID)
		defer cleanup()

		plans := col.AnalyzePIDPlans()
		require.Len(t, plans, 1)
		require.Equal(t, "gotls", plans[0].DetectedStack)

		if ts == nil {
			require.Equal(t, "unavailable", plans[0].EBPFStatus)
			require.True(t, plans[0].IntrusiveNeeded)
			return
		}

		// Release the already-running Go process to perform its HTTPS request
		require.NoError(t, os.WriteFile(triggerFile, []byte("go"), 0o644))
		require.NoError(t, cmd.Wait())

		if os.Geteuid() == 0 && runtime.GOARCH == "amd64" {
			require.Equal(t, "attached", plans[0].EBPFStatus)
			require.False(t, plans[0].IntrusiveNeeded)
			require.Eventually(t, func() bool {
				col.Flush()
				sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
				for _, s := range sessions {
					evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
					for _, ev := range evs {
						if ev.Process.PID == runningPID && ev.Chat != nil && ev.Chat.ResponseText == "live stripped gotls pclntab ok" {
							return true
						}
					}
				}
				return false
			}, 3*time.Second, 25*time.Millisecond, "eBPF uprobe via .gopclntab must capture already-running stripped Go binary")
		} else {
			require.Equal(t, "unavailable", plans[0].EBPFStatus)
			require.True(t, plans[0].IntrusiveNeeded)
		}
	})

	// 2. Already-Running Java (JVM) Process: Prompt + Live Dynamic Attach (`agentmain`) Without Restart
	t.Run("2_RunningJavaJVM_EBPFInsufficientPrompt_Then_LiveDynamicAttachWithoutRestart", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX JVM attach socket test runs on Linux/macOS")
		}
		javacPath, err1 := exec.LookPath("javac")
		javaPath, err2 := exec.LookPath("java")
		if err1 != nil || err2 != nil {
			t.Skip("java/javac not installed")
		}

		javaDir := filepath.Join(dir, "live_java_app")
		require.NoError(t, os.MkdirAll(javaDir, 0o755))
		triggerFile := filepath.Join(javaDir, "trigger.txt")
		javaSrc := filepath.Join(javaDir, "LiveJvmApp.java")
		javaCode := `import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;

public class LiveJvmApp {
    public static void main(String[] args) throws Exception {
        File trigger = new File(args[0]);
        String baseUrl = args[1];
        for (int i = 0; i < 1500; i++) {
            if (trigger.exists()) break;
            Thread.sleep(20);
        }
        URL url = new URI(baseUrl + "/v1/messages").toURL();
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        byte[] body = "{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"hello from already running jvm\"}]}".getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
        }
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[4096];
            while (is.read(buf) != -1) {}
        }
    }
}
`
		require.NoError(t, os.WriteFile(javaSrc, []byte(javaCode), 0o644))
		out, err := exec.Command(javacPath, javaSrc).CombinedOutput()
		require.NoError(t, err, "javac failed: %s", string(out))

		// Start the Java process FIRST with NO -javaagent, NO JAVA_TOOL_OPTIONS, NO HTTPS_PROXY!
		cmd := exec.Command(javaPath, "-cp", javaDir, "LiveJvmApp", triggerFile, tsURL)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		require.NoError(t, cmd.Start())
		javaPID := cmd.Process.Pid
		defer func() { _ = cmd.Process.Kill() }()

		// Wait briefly for JVM startup
		time.Sleep(300 * time.Millisecond)

		col, st, cleanup := newPIDCollector(t, "scen_live_jvm", javaPID)
		defer cleanup()

		// Step 1: Verify automatic detection reports jvm-jsse and prompts that eBPF alone cannot decrypt JSSE
		plans := col.AnalyzePIDPlans()
		require.Len(t, plans, 1)
		require.Equal(t, "jvm-jsse", plans[0].DetectedStack)
		require.True(t, plans[0].IntrusiveNeeded, "must flag that JVM JSSE requires intrusive dynamic attach")
		require.Equal(t, "jvm_dynamic_attach", plans[0].RecommendedIntrusive)

		if ts == nil {
			t.Skip("skipping TCP loopback JVM live attach execution in AF_INET-restricted sandbox")
		}

		// Step 2: Execute live intrusive attach (`agentmain` via jcmd / AttachSocket) without restarting JVM!
		injectedPlan, err := col.InjectRunningPID(javaPID)
		require.NoError(t, err, "live JVM dynamic attach must succeed on running Java PID")
		require.True(t, injectedPlan.Injected)
		require.Equal(t, "jvm_dynamic_attach", injectedPlan.ActiveMode)

		// Step 3: Trigger the already-running JVM to send its HTTPS LLM request
		require.NoError(t, os.WriteFile(triggerFile, []byte("go"), 0o644))
		require.NoError(t, cmd.Wait())

		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Protocol == model.ProtocolAnthropic && ev.Chat != nil && ev.Chat.ResponseText == "live jvm dynamic attach without restart ok" {
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "must capture HTTPS LLM call from already-running JVM via dynamic attach without restart")
	})

	// 3. Already-Running Node.js Process: Live SIGUSR1 V8 Inspector Injection Without Restart
	t.Run("3_RunningNodeJS_UnprivilegedPrompt_Then_LiveSIGUSR1InspectorInjectWithoutRestart", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("SIGUSR1 inspector activation runs on POSIX (Linux/macOS)")
		}
		nodePath, err := exec.LookPath("node")
		if err != nil {
			t.Skip("node not installed")
		}
		if realNodeOut, err := exec.Command(nodePath, "-p", "process.execPath").Output(); err == nil {
			if p := filepath.Clean(string(realNodeOut[:len(realNodeOut)-1])); p != "" {
				if _, stErr := os.Stat(p); stErr == nil {
					nodePath = p
				}
			}
		}

		triggerFile := filepath.Join(dir, "node_trigger.flag")
		nodeScript := filepath.Join(dir, "live_node_app.js")
		jsCode := `const fs = require("node:fs");
const https = require("node:https");
const trigger = process.argv[2];
const baseUrl = process.argv[3];

const timer = setInterval(() => {
  if (!fs.existsSync(trigger)) return;
  clearInterval(timer);
  const body = JSON.stringify({
    model: "gpt-5-codex",
    input: "hello from already-running node process"
  });
  const u = new URL(baseUrl + "/v1/responses");
  const req = https.request({
    hostname: u.hostname,
    port: u.port,
    path: u.pathname,
    method: "POST",
    rejectUnauthorized: false,
    headers: {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body)
    }
  }, (res) => {
    res.on("data", () => {});
    res.on("end", () => setTimeout(() => process.exit(0), 50));
  });
  req.write(body);
  req.end();
}, 25);
`
		require.NoError(t, os.WriteFile(nodeScript, []byte(jsCode), 0o644))

		// Start Node.js FIRST with NO NODE_OPTIONS, NO LD_PRELOAD, NO HTTPS_PROXY!
		cmd := exec.Command(nodePath, nodeScript, triggerFile, tsURL)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		require.NoError(t, cmd.Start())
		nodePID := cmd.Process.Pid
		defer func() { _ = cmd.Process.Kill() }()

		time.Sleep(200 * time.Millisecond)

		col, st, cleanup := newPIDCollector(t, "scen_live_node", nodePID)
		defer cleanup()

		// Verify fallback plan when eBPF is unavailable recommends node_inspector_sigusr1
		unprivPlan := col.inspectSinglePIDPlan(nodePID, false)
		require.True(t, unprivPlan.IntrusiveNeeded)
		require.Equal(t, "node_inspector_sigusr1", unprivPlan.RecommendedIntrusive)

		if ts == nil {
			t.Skip("skipping TCP loopback V8 inspector execution in AF_INET-restricted sandbox")
		}

		// Perform live SIGUSR1 V8 Inspector injection into the already-running Node.js process
		require.NoError(t, col.injectRunningNodeJS(nodePID))

		// Trigger the running Node.js process to make its HTTPS request
		require.NoError(t, os.WriteFile(triggerFile, []byte("go"), 0o644))
		require.NoError(t, cmd.Wait())

		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Process.PID == nodePID && ev.Protocol == model.ProtocolOpenAIResponses &&
						ev.Chat != nil && ev.Chat.ResponseText == "live node sigusr1 inspector attach ok" {
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "must capture HTTPS call from already-running Node.js via SIGUSR1 V8 Inspector injection without restart")
	})

	// 4. Already-Running Stripped Native Binary: Live PTRACE_SEIZE Attach & Clean Detach Without Restart
	t.Run("4_RunningStrippedNativeBinary_LivePtraceSeizeAttachAndDetachWithoutRestart", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("PTRACE_SEIZE test runs on Linux")
		}
		if os.Geteuid() != 0 {
			if scopeBytes, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil && len(scopeBytes) > 0 && scopeBytes[0] != '0' {
				t.Skip("skipping non-child PTRACE_SEIZE in unprivileged mode because kernel.yama.ptrace_scope > 0")
			}
		}
		gccPath, err := exec.LookPath("gcc")
		if err != nil {
			t.Skip("gcc not installed")
		}

		triggerFile := filepath.Join(dir, "c_trigger.flag")
		cSrc := filepath.Join(dir, "live_stripped_c.c")
		cBin := filepath.Join(dir, "live_stripped_c")
		cCode := `#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    for (int i = 0; i < 300; i++) {
        if (access(argv[1], F_OK) == 0) break;
        usleep(20000);
    }
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;
	const char *req = "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: 78\r\n\r\n{\"model\":\"gpt-4.1\",\"messages\":[{\"role\":\"user\",\"content\":\"live ptrace seize\"}]}";
	const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"chatcmpl-pt\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"live ptrace seize attach ok\"},\"finish_reason\":\"stop\"}]}";
	char req_buf[512], resp_buf[512], sink[512];
    memcpy(req_buf, req, strlen(req) + 1);
    memcpy(resp_buf, resp, strlen(resp) + 1);
    write(sv[0], req_buf, strlen(req_buf));
    read(sv[1], sink, sizeof(sink));
    write(sv[1], resp_buf, strlen(resp_buf));
    read(sv[0], sink, sizeof(sink));
    close(sv[0]);
    close(sv[1]);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(cCode), 0o644))
		out, err := exec.Command(gccPath, "-static", "-O2", "-s", "-o", cBin, cSrc).CombinedOutput()
		require.NoError(t, err, string(out))

		cmd := exec.Command(cBin, triggerFile)
		require.NoError(t, cmd.Start())
		cPID := cmd.Process.Pid
		defer func() { _ = cmd.Process.Kill() }()

		time.Sleep(100 * time.Millisecond)

		col, st, cleanup := newPIDCollector(t, "scen_live_ptrace", cPID)
		defer cleanup()

		plans := col.AnalyzePIDPlans()
		require.Len(t, plans, 1)
		require.Equal(t, "stripped-native", plans[0].DetectedStack)
		require.Equal(t, "ptrace_seize", plans[0].RecommendedIntrusive)

		_, err = col.InjectRunningPID(cPID)
		require.NoError(t, err, fmt.Sprintf("live ptrace attach to pid %d must succeed", cPID))

		require.NoError(t, os.WriteFile(triggerFile, []byte("go"), 0o644))
		require.NoError(t, cmd.Wait(), "target process must exit cleanly with 0 after ptrace capture")

		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Process.PID == cPID && ev.Chat != nil && ev.Chat.ResponseText == "live ptrace seize attach ok" {
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "must capture stripped native process via live PTRACE_SEIZE without restart")
	})

	// 5. Directly Launched Child Command (`-- <cmd>`): Automatic Intrusive Parameter Completion When Non-Intrusive Cannot Be Used
	t.Run("5_LaunchChildCommand_AutoIntrusiveParameterCompletion", func(t *testing.T) {
		subDir := filepath.Join(dir, "scen_launch_auto_intrusive")
		mon, err := selfmon.NewMonitor(subDir)
		require.NoError(t, err)
		st, err := store.NewStore(subDir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()
		defer func() { _ = mon.Close() }()
		corr := correlator.NewCorrelator(mon)
		col, err := NewCollector(subDir, model.ScopeFilter{}, corr, st, mon)
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			cancel()
			col.Stop()
		}()
		require.NoError(t, col.Start(ctx))

		// 5a. Node.js child command: NonIntrusiveOK == false -> automatically injects `--require <node_hook.cjs>` CLI args
		if nodePath, err := exec.LookPath("node"); err == nil {
			if realNodeOut, err := exec.Command(nodePath, "-p", "process.execPath").Output(); err == nil {
				if p := filepath.Clean(strings.TrimSpace(string(realNodeOut))); p != "" {
					if _, stErr := os.Stat(p); stErr == nil {
						nodePath = p
					}
				}
			}
			nodeChildScript := filepath.Join(dir, "launch_child_node.js")
			nodeChildCode := `const https = require("node:https");
const baseUrl = process.argv[2];
const body = JSON.stringify({ model: "gpt-5-codex", input: "launched child node auto param" });
const u = new URL(baseUrl + "/v1/responses");
const req = https.request({
  hostname: u.hostname, port: u.port, path: u.pathname, method: "POST",
  rejectUnauthorized: false,
  headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) }
}, (res) => { res.on("data", () => {}); res.on("end", () => process.exit(0)); });
req.write(body);
req.end();
`
			require.NoError(t, os.WriteFile(nodeChildScript, []byte(nodeChildCode), 0o644))
			var lp *LaunchAttachPlan
			if ts != nil {
				rc, err := col.LaunchCommand(ctx, []string{nodePath, nodeChildScript, tsURL})
				require.NoError(t, err)
				require.Equal(t, 0, rc)
				lp = col.LastLaunchPlan()
			} else {
				var err error
				lp, _, err = col.PlanLaunchCommand([]string{nodePath, nodeChildScript, tsURL})
				require.NoError(t, err)
			}

			require.NotNil(t, lp)
			require.Equal(t, "nodejs", lp.DetectedStack)
			require.False(t, lp.NonIntrusiveOK)
			require.True(t, lp.AutoIntrusiveTriggered)
			require.GreaterOrEqual(t, len(lp.InjectedArgs), 2)
			require.Equal(t, "--require", lp.InjectedArgs[0])
			require.Contains(t, lp.IntrusiveMethods, "cli_arg:--require")
			if ts != nil {
				require.Eventually(t, func() bool {
					col.Flush()
					sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
					for _, s := range sessions {
						evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
						for _, ev := range evs {
							if ev.Protocol == model.ProtocolOpenAIResponses && ev.Chat != nil && ev.Chat.ResponseText == "live node sigusr1 inspector attach ok" {
								return true
							}
						}
					}
					return false
				}, 3*time.Second, 25*time.Millisecond, "launched Node.js child exchange must be captured via auto-injected --require parameter")
			}
		}

		// 5b. Java child command: NonIntrusiveOK == false -> automatically injects `-javaagent:...` & `-Dhttps.proxyHost=...` CLI args
		javacPath, err1 := exec.LookPath("javac")
		javaPath, err2 := exec.LookPath("java")
		if err1 == nil && err2 == nil {
			javaChildDir := filepath.Join(dir, "launch_java_child")
			require.NoError(t, os.MkdirAll(javaChildDir, 0o755))
			javaChildSrc := filepath.Join(javaChildDir, "LaunchJavaChild.java")
			javaChildCode := `import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
public class LaunchJavaChild {
    public static void main(String[] args) throws Exception {
        URL url = new URI(args[0] + "/v1/messages").toURL();
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        byte[] body = "{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":32,\"messages\":[{\"role\":\"user\",\"content\":\"launched child java auto param\"}]}".getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) { os.write(body); }
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[1024];
            while (is.read(buf) != -1) {}
        }
    }
}
`
			require.NoError(t, os.WriteFile(javaChildSrc, []byte(javaChildCode), 0o644))
			out, err := exec.Command(javacPath, javaChildSrc).CombinedOutput()
			require.NoError(t, err, string(out))

			var lp *LaunchAttachPlan
			if ts != nil {
				rc, err := col.LaunchCommand(ctx, []string{javaPath, "-cp", javaChildDir, "LaunchJavaChild", tsURL})
				require.NoError(t, err)
				require.Equal(t, 0, rc)
				lp = col.LastLaunchPlan()
			} else {
				lp, _, err = col.PlanLaunchCommand([]string{javaPath, "-cp", javaChildDir, "LaunchJavaChild", tsURL})
				require.NoError(t, err)
			}

			require.NotNil(t, lp)
			require.Equal(t, "jvm-jsse", lp.DetectedStack)
			require.False(t, lp.NonIntrusiveOK)
			require.True(t, lp.AutoIntrusiveTriggered)
			require.NotEmpty(t, lp.InjectedArgs)
			require.True(t, strings.HasPrefix(lp.InjectedArgs[0], "-javaagent:"))
			require.Contains(t, lp.IntrusiveMethods, "cli_arg:-javaagent")
			if ts != nil {
				require.Contains(t, lp.IntrusiveMethods, "cli_arg:-Dhttps.proxyHost")
				require.Eventually(t, func() bool {
					col.Flush()
					sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
					for _, s := range sessions {
						evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
						for _, ev := range evs {
							if ev.Protocol == model.ProtocolAnthropic && ev.Chat != nil && ev.Chat.ResponseText == "live jvm dynamic attach without restart ok" {
								return true
							}
						}
					}
					return false
				}, 3*time.Second, 25*time.Millisecond, "launched Java child exchange must be captured via auto-injected -javaagent parameter")
			}
		}
	})

	// 6. Other Process Selectors (--cmd, --cwd, --exe, and --pid parent subtree):
	// Verify automatic discovery, eBPF-first inspection, and live intrusive injection without specifying child PID directly.
	t.Run("6_OtherProcessSelectors_Exe_Cwd_Cmd_Subtree_AutoDetectAndLiveInject", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX JVM attach test runs on Linux/macOS")
		}
		javacPath, err1 := exec.LookPath("javac")
		javaPath, err2 := exec.LookPath("java")
		if err1 != nil || err2 != nil {
			t.Skip("java/javac not installed")
		}

		scopedCwd := filepath.Join(dir, "selector_workspace_cwd")
		require.NoError(t, os.MkdirAll(scopedCwd, 0o755))
		triggerFile := filepath.Join(scopedCwd, "selector_trigger.txt")
		javaSrc := filepath.Join(scopedCwd, "SelectorJvmTarget.java")
		javaCode := `import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.HttpsURLConnection;
public class SelectorJvmTarget {
    public static void main(String[] args) throws Exception {
        File trigger = new File(args[0]);
        String baseUrl = args[1];
        for (int i = 0; i < 300; i++) {
            if (trigger.exists()) break;
            Thread.sleep(20);
        }
        URL url = new URI(baseUrl + "/v1/messages").toURL();
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        byte[] body = "{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":32,\"messages\":[{\"role\":\"user\",\"content\":\"matched by cwd and cmd selector\"}]}".getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) { os.write(body); }
        try (InputStream is = conn.getInputStream()) {
            byte[] buf = new byte[1024];
            while (is.read(buf) != -1) {}
        }
    }
}
`
		require.NoError(t, os.WriteFile(javaSrc, []byte(javaCode), 0o644))
		out, err := exec.Command(javacPath, javaSrc).CombinedOutput()
		require.NoError(t, err, string(out))

		// Start the Java process inside `scopedCwd` with a unique `--cmd` marker, WITHOUT knowing or passing its PID to Collector!
		cmd := exec.Command(javaPath, "-cp", scopedCwd, "SelectorJvmTarget", triggerFile, tsURL, "--unique-selector-tag-991")
		cmd.Dir = scopedCwd
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
		require.NoError(t, cmd.Start())
		targetPID := cmd.Process.Pid
		defer func() { _ = cmd.Process.Kill() }()

		time.Sleep(300 * time.Millisecond)

		subDir := filepath.Join(dir, "scen_other_selectors")
		mon, err := selfmon.NewMonitor(subDir)
		require.NoError(t, err)
		st, err := store.NewStore(subDir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()
		defer func() { _ = mon.Close() }()
		corr := correlator.NewCorrelator(mon)

		// Select ONLY via --cwd, --cmd, and --exe (PIDs is empty!)
		col, err := NewCollector(subDir, model.ScopeFilter{
			Cwds: []string{scopedCwd},
			Cmds: []string{"unique-selector-tag-991"},
			Exes: []string{"java"},
		}, corr, st, mon)
		require.NoError(t, err)
		col.SetAutoInjectLive(true)
		ctx, cancel := context.WithCancel(context.Background())
		defer func() {
			cancel()
			col.Stop()
		}()
		require.NoError(t, col.Start(ctx))

		// Verify DiscoverMatchingPIDs & AutoInjectMatchingPIDs found `targetPID` by --cwd / --cmd / --exe and live-injected it!
		if ts == nil {
			plans := col.AnalyzePIDPlans()
			require.NotEmpty(t, plans, "must discover running process via --cwd / --cmd / --exe without --pid")
			var matchedPlan *PIDAttachPlan
			for i := range plans {
				if plans[i].PID == targetPID {
					matchedPlan = &plans[i]
					break
				}
			}
			require.NotNil(t, matchedPlan, "discovered plans must include targetPID")
			require.Equal(t, "jvm-jsse", matchedPlan.DetectedStack)
			return
		}
		plans := col.AutoInjectMatchingPIDs()
		require.NotEmpty(t, plans, "must discover running process via --cwd / --cmd / --exe without --pid")
		var matchedPlan *PIDAttachPlan
		for i := range plans {
			if plans[i].PID == targetPID {
				matchedPlan = &plans[i]
				break
			}
		}
		require.NotNil(t, matchedPlan, "discovered plans must include targetPID")
		require.Equal(t, "jvm-jsse", matchedPlan.DetectedStack)
		require.True(t, matchedPlan.Injected)
		require.Equal(t, "jvm_dynamic_attach", matchedPlan.ActiveMode)

		require.NoError(t, os.WriteFile(triggerFile, []byte("go"), 0o644))
		require.NoError(t, cmd.Wait())

		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 10})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Protocol == model.ProtocolAnthropic && ev.Chat != nil && ev.Chat.ResponseText == "live jvm dynamic attach without restart ok" {
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "traffic from process selected via --cwd / --cmd / --exe must be captured after live attach")
	})
}

func TestLivePIDAttachLaunchPlannersAndSecurity(t *testing.T) {
	t.Run("PurePlanLaunch_PerRuntimeDispatch", func(t *testing.T) {
		jvmIn := launchPlanInput{
			CmdArgs:       []string{"/usr/bin/java", "-jar", "app.jar"},
			BinPath:       "/usr/bin/java",
			AutoIntrusive: true,
			GOOS:          "linux",
			JavaAgentJar:  "/tmp/hooks/llm_tracer_java.jar",
			TapActive:     true,
			ProxyURL:      "http://127.0.0.1:43111",
			ProxyHost:     "127.0.0.1",
			ProxyPort:     "43111",
			CABundlePath:  "/tmp/hooks/ca.pem",
		}
		jvmPlan := planLaunch(jvmIn)
		require.Equal(t, "jvm-jsse", jvmPlan.DetectedStack)
		require.False(t, jvmPlan.NonIntrusiveOK)
		require.True(t, jvmPlan.AutoIntrusiveTriggered)
		require.Contains(t, jvmPlan.InjectedArgs, "-javaagent:/tmp/hooks/llm_tracer_java.jar=http://127.0.0.1:43111")
		require.Contains(t, jvmPlan.IntrusiveMethods, "cli_arg:-javaagent")
		require.Contains(t, jvmPlan.IntrusiveMethods, "cli_arg:-Dhttps.proxyHost")
		require.Contains(t, jvmPlan.IntrusiveMethods, "env:JAVA_TOOL_OPTIONS")
		require.Contains(t, jvmPlan.IntrusiveMethods, "loopback_tap")

		nodeIn := launchPlanInput{
			CmdArgs:       []string{"/usr/bin/node", "agent.js"},
			BinPath:       "/usr/bin/node",
			AutoIntrusive: true,
			GOOS:          "linux",
			PreloadPath:   "/tmp/hooks/libssl_hook.so",
			NodeHookJS:    "/tmp/hooks/node_hook.cjs",
		}
		nodePlan := planLaunch(nodeIn)
		require.Equal(t, "nodejs", nodePlan.DetectedStack)
		require.False(t, nodePlan.NonIntrusiveOK)
		require.True(t, nodePlan.AutoIntrusiveTriggered)
		require.Equal(t, []string{"--require", "/tmp/hooks/node_hook.cjs"}, nodePlan.InjectedArgs)
		require.Contains(t, nodePlan.IntrusiveMethods, "cli_arg:--require")
		require.Contains(t, nodePlan.IntrusiveMethods, "env:NODE_OPTIONS")
		require.Contains(t, nodePlan.IntrusiveMethods, "preload:ld_preload")

		bunIn := launchPlanInput{
			CmdArgs:       []string{"/usr/local/bin/bun", "run", "index.ts"},
			BinPath:       "/usr/local/bin/bun",
			AutoIntrusive: true,
			GOOS:          "darwin",
			PreloadPath:   "/tmp/hooks/libssl_hook.dylib",
			NodeHookJS:    "/tmp/hooks/node_hook.cjs",
		}
		bunPlan := planLaunch(bunIn)
		require.Equal(t, "bun-boringssl", bunPlan.DetectedStack)
		require.False(t, bunPlan.NonIntrusiveOK)
		require.True(t, bunPlan.AutoIntrusiveTriggered)
		require.Equal(t, []string{"--preload", "/tmp/hooks/node_hook.cjs"}, bunPlan.InjectedArgs)
		require.Contains(t, bunPlan.IntrusiveMethods, "cli_arg:--preload")
		require.Contains(t, bunPlan.IntrusiveMethods, "env:BUN_OPTIONS")
		require.Contains(t, bunPlan.IntrusiveMethods, "preload:dyld_insert_libraries")

		pyIn := launchPlanInput{
			CmdArgs:       []string{"/usr/bin/python3", "main.py"},
			BinPath:       "/usr/bin/python3",
			AutoIntrusive: true,
			GOOS:          "linux",
			PyHookDir:     "/tmp/hooks/py",
		}
		pyPlan := planLaunch(pyIn)
		require.Equal(t, "python", pyPlan.DetectedStack)
		require.False(t, pyPlan.NonIntrusiveOK)
		require.True(t, pyPlan.AutoIntrusiveTriggered)
		require.Contains(t, pyPlan.IntrusiveMethods, "env:PYTHONPATH(sitecustomize)")

		goInEBPF := launchPlanInput{
			CmdArgs:       []string{"/usr/local/bin/my-go-app"},
			BinPath:       "/usr/local/bin/my-go-app",
			GoTarget:      &ProbeTarget{GoVersion: "go1.26.5", Symbols: map[string]uint64{"crypto/tls.(*Conn).Write": 0x1234}},
			EBPFActive:    true,
			AutoIntrusive: true,
			GOOS:          "linux",
		}
		goPlanEBPF := planLaunch(goInEBPF)
		require.Equal(t, "gotls", goPlanEBPF.DetectedStack)
		require.True(t, goPlanEBPF.NonIntrusiveOK)
		require.False(t, goPlanEBPF.AutoIntrusiveTriggered)

		staticIn := launchPlanInput{
			CmdArgs:       []string{"/usr/local/bin/static-agent", "--prompt", "hi"},
			BinPath:       "/usr/local/bin/static-agent",
			Profile:       &BinaryProfile{ResolvedELF: "/usr/local/bin/static-agent", RequiresPtrace: true, TLSStack: "stripped-embedded-tls"},
			AutoIntrusive: true,
			GOOS:          "linux",
			GOARCH:        "amd64",
			PtraceBin:     "/tmp/hooks/llm_tracer_ptrace",
			TapActive:     true,
			ProxyURL:      "http://127.0.0.1:43111",
			ProxyHost:     "127.0.0.1",
			ProxyPort:     "43111",
			CABundlePath:  "/tmp/hooks/ca.pem",
		}
		staticPlan := planLaunch(staticIn)
		require.Equal(t, "static-pie", staticPlan.DetectedStack)
		require.False(t, staticPlan.NonIntrusiveOK)
		require.True(t, staticPlan.AutoIntrusiveTriggered)
		require.True(t, staticPlan.PtraceWrapped)
		require.Equal(t, "/tmp/hooks/llm_tracer_ptrace", staticPlan.ExecBin)
		require.Equal(t, []string{"/usr/local/bin/static-agent", "--prompt", "hi"}, staticPlan.ExecArgs)
		require.Contains(t, staticPlan.IntrusiveMethods, "ptrace_wrapper")

		env := applyLaunchPlan(nil, staticIn, staticPlan, []string{"PATH=/usr/bin", "ALL_PROXY=socks5://127.0.0.1:1080"})
		require.Equal(t, "http://127.0.0.1:43111", staticPlan.InjectedEnv["HTTPS_PROXY"])
		require.Equal(t, "/tmp/hooks/ca.pem", staticPlan.InjectedEnv["SSL_CERT_FILE"])
		require.Empty(t, lookupEnvVar(env, "ALL_PROXY"))

		staticArm64In := staticIn
		staticArm64In.GOARCH = "arm64"
		staticArm64Plan := planLaunch(staticArm64In)
		require.False(t, staticArm64Plan.PtraceWrapped, "arm64 must skip ptrace wrapper")
		require.Equal(t, "/usr/local/bin/static-agent", staticArm64Plan.ExecBin)
		require.NotContains(t, staticArm64Plan.IntrusiveMethods, "ptrace_wrapper")
		require.NotEmpty(t, staticArm64Plan.DegradationNotices)
	})

	t.Run("NoIngestTokenEnvLeak", func(t *testing.T) {
		dir := t.TempDir()
		mon, err := selfmon.NewMonitor(dir)
		require.NoError(t, err)
		st, err := store.NewStore(dir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()
		defer func() { _ = mon.Close() }()
		corr := correlator.NewCorrelator(mon)
		col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
		require.NoError(t, err)
		secret := "super-secret-ingest-credential-998877"
		col.SetIngestToken(secret)

		selfExe, err := os.Executable()
		require.NoError(t, err)
		plan, env, err := col.PlanLaunchCommand([]string{selfExe, "-test.run=^$"})
		require.NoError(t, err)
		require.NotNil(t, plan)
		for k, v := range plan.InjectedEnv {
			require.NotContains(t, strings.ToUpper(k), "INGEST_TOKEN")
			require.NotEqual(t, secret, v)
		}
		for _, kv := range env {
			require.NotContains(t, kv, secret)
		}
	})
}

func TestJVMAttachTriggerFileNoFollowTOCTOU(t *testing.T) {
	dir := t.TempDir()

	triggerPath := filepath.Join(dir, ".attach_pid12345")
	require.NoError(t, createJVMAttachTriggerFile(triggerPath, 0o600))
	fi, err := os.Lstat(triggerPath)
	require.NoError(t, err)
	require.True(t, fi.Mode().IsRegular())
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
	require.NoError(t, removeSocketNoFollow(triggerPath))

	if runtime.GOOS != "windows" {
		victimPath := filepath.Join(dir, "victim_secret_file")
		require.NoError(t, os.WriteFile(victimPath, []byte("secret"), 0o600))
		symlinkPath := filepath.Join(dir, ".attach_pid99999")
		require.NoError(t, os.Symlink(victimPath, symlinkPath))

		err := createJVMAttachTriggerFile(symlinkPath, 0o644)
		require.Error(t, err, "must refuse to follow or chmod symlink at .attach_pid path")

		victimInfo, err := os.Lstat(victimPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), victimInfo.Mode().Perm(), "victim file permissions must remain untouched")
	}
}

func TestNodeInspectorTargetSelectionAndProcLookup(t *testing.T) {
	t.Run("proc_fd_and_net_tcp_multi_node_isolation", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink /proc layout test runs on POSIX")
		}
		fakeProc := t.TempDir()
		otherPID := 4101
		targetPID := 4202

		// Shared netns /proc/<pid>/net/tcp contains BOTH listening sockets:
		// - 127.0.0.1:9229 (0100007F:240D) with inode 88001 (owned by otherPID 4101)
		// - 127.0.0.1:9230 (0100007F:240E) with inode 88002 (owned by targetPID 4202)
		netTCPContent := strings.Join([]string{
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
			"   0: 0100007F:240D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 88001 1 0000000000000000 100 0 0 10 0",
			"   1: 0100007F:240E 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 88002 1 0000000000000000 100 0 0 10 0",
		}, "\n") + "\n"

		for _, p := range []struct {
			pid   int
			inode string
		}{
			{otherPID, "88001"},
			{targetPID, "88002"},
		} {
			netDir := filepath.Join(fakeProc, fmt.Sprintf("%d/net", p.pid))
			fdDir := filepath.Join(fakeProc, fmt.Sprintf("%d/fd", p.pid))
			require.NoError(t, os.MkdirAll(netDir, 0o755))
			require.NoError(t, os.MkdirAll(fdDir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(netDir, "tcp"), []byte(netTCPContent), 0o644))
			require.NoError(t, os.Symlink("socket:["+p.inode+"]", filepath.Join(fdDir, "12")))
		}

		epsTarget, authTarget, err := discoverPIDInspectorEndpoints(fakeProc, targetPID)
		require.NoError(t, err)
		require.True(t, authTarget)
		require.Equal(t, []string{"127.0.0.1:9230"}, epsTarget, "must select only 127.0.0.1:9230 owned by targetPID, never 9229")

		epsOther, authOther, err := discoverPIDInspectorEndpoints(fakeProc, otherPID)
		require.NoError(t, err)
		require.True(t, authOther)
		require.Equal(t, []string{"127.0.0.1:9229"}, epsOther)
	})

	t.Run("proc_target_has_no_inspector_socket_refuses_other_pid_9229", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink /proc layout test runs on POSIX")
		}
		fakeProc := t.TempDir()
		targetPID := 5303
		netDir := filepath.Join(fakeProc, fmt.Sprintf("%d/net", targetPID))
		fdDir := filepath.Join(fakeProc, fmt.Sprintf("%d/fd", targetPID))
		require.NoError(t, os.MkdirAll(netDir, 0o755))
		require.NoError(t, os.MkdirAll(fdDir, 0o755))

		// Port 9229 is open in the network namespace (inode 77001), but targetPID only owns socket inode 99999.
		netTCPContent := strings.Join([]string{
			"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode",
			"   0: 0100007F:240D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 77001 1 0000000000000000 100 0 0 10 0",
		}, "\n") + "\n"
		require.NoError(t, os.WriteFile(filepath.Join(netDir, "tcp"), []byte(netTCPContent), 0o644))
		require.NoError(t, os.Symlink("socket:[99999]", filepath.Join(fdDir, "3")))

		eps, auth, err := discoverPIDInspectorEndpoints(fakeProc, targetPID)
		require.NoError(t, err)
		require.True(t, auth)
		require.Empty(t, eps, "targetPID must have 0 inspector endpoints when 9229 inode belongs to another process")

		wsURL, err := resolveNodeInspectorWSURL(fakeProc, targetPID, "node app.js", nil)
		require.Error(t, err)
		require.Empty(t, wsURL)
		require.Contains(t, err.Error(), "no listening V8 inspector socket")
	})

	t.Run("json_target_pid_and_cmdline_verification", func(t *testing.T) {
		targetsMulti := []nodeInspectorTarget{
			{
				ID:                   "wrong-0",
				Title:                "node[4101]",
				URL:                  "file:///srv/other_service.js",
				WebSocketDebuggerURL: "ws://127.0.0.1:9229/wrong-0",
			},
			{
				ID:                   "right-1",
				Title:                "node[4202]",
				URL:                  "file:///srv/target_agent.js",
				WebSocketDebuggerURL: "ws://127.0.0.1:9229/right-1",
			},
		}
		// 1. Selects target matching PID 4202 rather than targets[0].
		ws, err := selectNodeInspectorTarget(4202, "node /srv/target_agent.js", "127.0.0.1:9229", targetsMulti, false)
		require.NoError(t, err)
		require.Equal(t, "ws://127.0.0.1:9229/right-1", ws)

		// 2. Rejects when only another PID's target is present, even if socketOwnedByPID is true.
		wsWrong, err := selectNodeInspectorTarget(4202, "node /srv/target_agent.js", "127.0.0.1:9229", targetsMulti[:1], true)
		require.Error(t, err)
		require.Empty(t, wsWrong)
		require.Contains(t, err.Error(), "belongs to pid 4101, not target pid 4202")

		// 3. Untagged target without /proc socket ownership and without cmdline match is rejected (no blind injection).
		untagged := []nodeInspectorTarget{
			{
				ID:                   "untagged-0",
				Title:                "node",
				WebSocketDebuggerURL: "ws://127.0.0.1:9229/untagged-0",
			},
		}
		wsBlind, err := selectNodeInspectorTarget(4202, "", "127.0.0.1:9229", untagged, false)
		require.Error(t, err)
		require.Empty(t, wsBlind)
		require.Contains(t, err.Error(), "refusing blind injection")

		// 4. Untagged single target WITH proven /proc socket ownership succeeds.
		wsOwned, err := selectNodeInspectorTarget(4202, "", "127.0.0.1:9229", untagged, true)
		require.NoError(t, err)
		require.Equal(t, "ws://127.0.0.1:9229/untagged-0", wsOwned)

		// 5. Multiple untagged targets that cannot be disambiguated are rejected even when socketOwnedByPID is true.
		ambiguous := []nodeInspectorTarget{
			{ID: "a", Title: "node", WebSocketDebuggerURL: "ws://127.0.0.1:9229/a"},
			{ID: "b", Title: "node", WebSocketDebuggerURL: "ws://127.0.0.1:9229/b"},
		}
		wsAmb, err := selectNodeInspectorTarget(4202, "", "127.0.0.1:9229", ambiguous, true)
		require.Error(t, err)
		require.Empty(t, wsAmb)
		require.Contains(t, err.Error(), "ambiguous V8 inspector targets")
	})

	t.Run("injectable_lookup_and_selfmon_warning_on_ambiguous_target", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("SIGUSR1 test runs on POSIX")
		}
		shBin, err := exec.LookPath("sh")
		if err != nil {
			t.Skip("sh not available")
		}
		// Spawn a harmless child process that traps SIGUSR1 so sendSignalByName("USR1") succeeds cleanly.
		child := exec.Command(shBin, "-c", "trap '' USR1; sleep 5")
		require.NoError(t, child.Start())
		defer func() {
			_ = child.Process.Kill()
			_ = child.Wait()
		}()

		dir := t.TempDir()
		mon, err := selfmon.NewMonitor(dir)
		require.NoError(t, err)
		defer func() { _ = mon.Close() }()
		st, err := store.NewStore(dir, 10*time.Minute, mon)
		require.NoError(t, err)
		defer func() { _ = st.Close() }()
		corr := correlator.NewCorrelator(mon)
		col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
		require.NoError(t, err)
		col.pipePath = filepath.Join(dir, "tls.bin")
		col.runtimeHooks = &RuntimeHookPaths{NodeHookJS: filepath.Join(dir, "node_hook.cjs")}

		prevTimeout := nodeInspectorPollTimeout
		prevHook := nodeInspectorLookupHook
		nodeInspectorPollTimeout = 70 * time.Millisecond
		nodeInspectorLookupHook = func(pid int, _ string) (string, error) {
			return "", fmt.Errorf("ambiguous inspector endpoint for pid %d; refusing blind injection", pid)
		}
		defer func() {
			nodeInspectorPollTimeout = prevTimeout
			nodeInspectorLookupHook = prevHook
		}()

		injectErr := col.injectRunningNodeJS(child.Process.Pid)
		require.Error(t, injectErr)
		require.Contains(t, injectErr.Error(), "refusing blind injection")

		warns, err := mon.QueryEvents(selfmon.Query{Stage: selfmon.StageProbe, Status: selfmon.StatusWarn, Limit: 20})
		require.NoError(t, err)
		foundWarn := false
		for _, w := range warns {
			if w.Action == "node_inspector_target_rejected" {
				foundWarn = true
				break
			}
		}
		require.True(t, foundWarn, "selfmon must record node_inspector_target_rejected warning when inspector target cannot be confirmed")
	})
}
