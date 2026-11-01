package collector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
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

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer ts.Close()

	newPIDCollector := func(t *testing.T, sub string, pid int) (*Collector, *store.Store, func()) {
		subDir := filepath.Join(dir, sub)
		mon, err := selfmon.NewMonitor(subDir)
		require.NoError(t, err)
		st, err := store.NewStore(subDir, 10*time.Minute, mon)
		require.NoError(t, err)
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
		cmd := exec.Command(goBin, readyFile, triggerFile, ts.URL)
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
        for (int i = 0; i < 300; i++) {
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
		cmd := exec.Command(javaPath, "-cp", javaDir, "LiveJvmApp", triggerFile, ts.URL)
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
		cmd := exec.Command(nodePath, nodeScript, triggerFile, ts.URL)
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
			rc, err := col.LaunchCommand(ctx, []string{nodePath, nodeChildScript, ts.URL})
			require.NoError(t, err)
			require.Equal(t, 0, rc)

			lp := col.LastLaunchPlan()
			require.NotNil(t, lp)
			require.Equal(t, "nodejs", lp.DetectedStack)
			require.False(t, lp.NonIntrusiveOK)
			require.True(t, lp.AutoIntrusiveTriggered)
			require.GreaterOrEqual(t, len(lp.InjectedArgs), 2)
			require.Equal(t, "--require", lp.InjectedArgs[0])
			require.Contains(t, lp.IntrusiveMethods, "cli_arg:--require")
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

			rc, err := col.LaunchCommand(ctx, []string{javaPath, "-cp", javaChildDir, "LaunchJavaChild", ts.URL})
			require.NoError(t, err)
			require.Equal(t, 0, rc)

			lp := col.LastLaunchPlan()
			require.NotNil(t, lp)
			require.Equal(t, "jvm-jsse", lp.DetectedStack)
			require.False(t, lp.NonIntrusiveOK)
			require.True(t, lp.AutoIntrusiveTriggered)
			require.NotEmpty(t, lp.InjectedArgs)
			require.True(t, strings.HasPrefix(lp.InjectedArgs[0], "-javaagent:"))
			require.Contains(t, lp.IntrusiveMethods, "cli_arg:-javaagent")
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
		cmd := exec.Command(javaPath, "-cp", scopedCwd, "SelectorJvmTarget", triggerFile, ts.URL, "--unique-selector-tag-991")
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
