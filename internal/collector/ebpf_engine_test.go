//go:build linux

package collector

import (
	"compress/gzip"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/liuyicong/llm-tracer/internal/correlator"
	"github.com/liuyicong/llm-tracer/internal/model"
	"github.com/liuyicong/llm-tracer/internal/parser"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"github.com/liuyicong/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestEBPFBytecodeBuilderAndJumpBounds(t *testing.T) {
	programs := map[string][]BPFInsn{
		"uprobe_ssl_write":         BuildWriteProbeProgram(3, 112, 104, 96, false),
		"uprobe_gotls_write":       BuildWriteProbeProgram(3, 80, 40, 88, false),
		"uprobe_gotls_read_enter":  BuildGoTLSReadEnterProgram(4),
		"uprobe_gotls_read_exit":   BuildGoTLSReadExitProgram(3, 4),
		"tp_sys_enter_write":       BuildWriteProbeProgram(3, 16, 24, 32, true),
		"tp_sys_enter_writev":      BuildWritevProbeProgram(3),
		"uprobe_ssl_read_enter":    BuildReadEnterProgram(4, 112, 104, 0, false),
		"uprobe_ssl_read_ex_enter": BuildReadEnterProgram(4, 112, 104, 88, false),
		"tp_sys_enter_read":        BuildReadEnterProgram(4, 16, 24, 0, true),
		"uretprobe_ssl_read":       BuildReadExitProgram(3, 4, 80, false),
		"tp_sys_exit_read":         BuildReadExitProgram(3, 4, 16, true),
	}

	for name, insns := range programs {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, insns)
			// Last instruction must be BPF_JMP | BPF_EXIT
			last := insns[len(insns)-1]
			require.Equal(t, uint8(bpfJMP|bpfEXIT), last.Code, "last instruction must be BPF_EXIT")

			// Verify all jump offsets land within valid instruction boundaries and end at exit
			for i := 0; i < len(insns); i++ {
				in := insns[i]
				if in.Code == (bpfLD | bpfDW | bpfIMM) {
					require.Less(t, i+1, len(insns), "64-bit immediate load requires 2 slots")
					i++ // skip second slot of LD_IMM64
					continue
				}
				if (in.Code & 0x07) == bpfJMP {
					op := in.Code & 0xf0
					if op != bpfCALL && op != bpfEXIT {
						target := i + 1 + int(in.Off)
						require.GreaterOrEqual(t, target, 0, "jump target underflow at insn %d", i)
						require.Less(t, target, len(insns), "jump target overflow at insn %d (target=%d len=%d)", i, target, len(insns))
						if in.Off > 8 {
							require.Equal(t, len(insns)-2, target, "early-exit jump at insn %d must land on R0=0 before exit (len=%d)", i, len(insns))
						}
					}
				}
			}
		})
	}
}

func TestEBPFRingBufConsumerAndRecordDispatch(t *testing.T) {
	pageSize := 4096
	ringBytes := 65536
	consBuf := make([]byte, pageSize)
	prodBuf := make([]byte, pageSize+2*ringBytes)

	var gotPID int
	var gotConnID string
	var gotDir parser.Direction
	var gotPayload []byte
	var gotMode string
	doneCh := make(chan struct{}, 1)

	eng := &EBPFEngine{
		ringMapFD:       -1,
		activeSSLReadFD: -1,
		activeSysReadFD: -1,
		ringMaxBytes:    ringBytes,
		consMmap:        consBuf,
		prodMmap:        prodBuf,
		stopCh:          make(chan struct{}),
		onEvent: func(pid, tid int, connID string, dir parser.Direction, payload []byte, mode string) {
			gotPID = pid
			gotConnID = connID
			gotDir = dir
			gotPayload = payload
			gotMode = mode
			select {
			case doneCh <- struct{}{}:
			default:
			}
		},
	}

	go eng.consumeRingBufLoop()
	defer eng.Close()

	// Write a valid kernel BPF ringbuf record into dataRing at offset 0
	dataRing := prodBuf[pageSize:]
	httpPayload := []byte("POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
	recLen := uint32(24 + len(httpPayload))

	// 8-byte ringbuf header: [len_and_flags (4B), page_offset (4B)]
	binary.NativeEndian.PutUint32(dataRing[0:4], recLen)
	binary.NativeEndian.PutUint32(dataRing[4:8], 0)

	// 24-byte LLMT header
	rec := dataRing[8 : 8+recLen]
	binary.NativeEndian.PutUint32(rec[0:4], 0x4c4c4d54)
	binary.NativeEndian.PutUint32(rec[4:8], 99999) // pid != selfPID
	binary.NativeEndian.PutUint32(rec[8:12], 99999)
	binary.NativeEndian.PutUint32(rec[12:16], 0xdeadbeef)
	binary.NativeEndian.PutUint32(rec[16:20], 0) // DirWrite
	binary.NativeEndian.PutUint32(rec[20:24], uint32(len(httpPayload)))
	copy(rec[24:], httpPayload)

	prodPtr := (*uint64)(unsafe.Pointer(&prodBuf[0]))
	consPtr := (*uint64)(unsafe.Pointer(&consBuf[0]))
	expectedPos := (uint64(recLen) + bpfRingbufHdrSz + 7) & ^uint64(7)
	atomic.StoreUint64(prodPtr, expectedPos)

	select {
	case <-doneCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for eBPF ringbuf consumer")
	}

	require.Equal(t, 99999, gotPID)
	require.Equal(t, "ebpf_tls_deadbeef", gotConnID)
	require.Equal(t, parser.DirWrite, gotDir)
	require.Equal(t, httpPayload, gotPayload)
	require.Equal(t, "ebpf_uprobe", gotMode)

	// Verify consumer position was atomically advanced to 8-byte aligned boundary
	time.Sleep(20 * time.Millisecond)
	require.Equal(t, expectedPos, atomic.LoadUint64(consPtr))
}

// TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot runs when UID == 0 (root) and verifies:
// 1. Kernel BPF_MAP_CREATE (RINGBUF + HASH) and BPF_PROG_LOAD pass the Linux kernel eBPF verifier;
// 2. perf_event_open + PERF_EVENT_IOC_SET_BPF attaches uprobes/uretprobes on libssl.so.3 and syscall tracepoints;
// 3. An unhooked child process (NO LD_PRELOAD, NO PYTHONPATH, NO ptrace) making a real OpenSSL TLS 1.3
//    exchange is captured purely via kernel eBPF uprobe -> RingBuf -> StreamReassembler -> Store!
func TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping real kernel eBPF load/attach test: requires root (UID 0)")
	}

	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	corr := correlator.NewCorrelator(mon)

	col, err := NewCollector(dir, model.ScopeFilter{}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	// Verify EBPFEngine started and attached kernel probes/tracepoints
	require.NotNil(t, col.ebpfEngine, "EBPFEngine must be initialized when running as root")
	require.True(t, col.ebpfEngine.Active(), "EBPFEngine must have active kernel probes/tracepoints")
	t.Logf("EBPFEngine attached: total=%d uprobes=%d tracepoints=%d",
		col.ebpfEngine.AttachedCount(), col.ebpfEngine.UprobeCount(), col.ebpfEngine.TracepointCount())
	require.GreaterOrEqual(t, col.ebpfEngine.UprobeCount(), 4, "should attach libssl uprobes/uretprobes")
	require.GreaterOrEqual(t, col.ebpfEngine.TracepointCount(), 7, "should attach syscall tracepoints including sys_enter_writev")

	// Explicitly verify all 11 eBPF bytecode programs pass the Linux kernel BPF_PROG_LOAD verifier
	ringFD := col.ebpfEngine.ringMapFD
	sslReadFD := col.ebpfEngine.activeSSLReadFD
	sysReadFD := col.ebpfEngine.activeSysReadFD
	for _, tc := range []struct {
		progType uint32
		name     string
		insns    []BPFInsn
	}{
		{unix.BPF_PROG_TYPE_KPROBE, "v_ssl_w", BuildWriteProbeProgram(ringFD, 112, 104, 96, false)},
		{unix.BPF_PROG_TYPE_KPROBE, "v_gotls_w", BuildWriteProbeProgram(ringFD, 80, 40, 88, false)},
		{unix.BPF_PROG_TYPE_KPROBE, "v_gotls_re", BuildGoTLSReadEnterProgram(sslReadFD)},
		{unix.BPF_PROG_TYPE_KPROBE, "v_gotls_rx", BuildGoTLSReadExitProgram(ringFD, sslReadFD)},
		{unix.BPF_PROG_TYPE_KPROBE, "v_ssl_re", BuildReadEnterProgram(sslReadFD, 112, 104, 0, false)},
		{unix.BPF_PROG_TYPE_KPROBE, "v_ssl_rxe", BuildReadEnterProgram(sslReadFD, 112, 104, 88, false)},
		{unix.BPF_PROG_TYPE_KPROBE, "v_ssl_rx", BuildReadExitProgram(ringFD, sslReadFD, 80, false)},
		{unix.BPF_PROG_TYPE_TRACEPOINT, "v_tp_w", BuildWriteProbeProgram(ringFD, 16, 24, 32, true)},
		{unix.BPF_PROG_TYPE_TRACEPOINT, "v_tp_wv", BuildWritevProbeProgram(ringFD)},
		{unix.BPF_PROG_TYPE_TRACEPOINT, "v_tp_re", BuildReadEnterProgram(sysReadFD, 16, 24, 0, true)},
		{unix.BPF_PROG_TYPE_TRACEPOINT, "v_tp_rx", BuildReadExitProgram(ringFD, sysReadFD, 16, true)},
	} {
		pfd, vlog, err := bpfLoadProgram(tc.progType, tc.name, tc.insns)
		require.NoError(t, err, "verifier log for %s:\n%s", tc.name, vlog)
		_ = unix.Close(pfd)
	}

	runUnhooked := func(t *testing.T, bin string, args ...string) int {
		t.Helper()
		col.Flush()
		cmd := exec.Command(bin, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "command %s failed: %s", bin, string(out))
		col.Flush()
		return cmd.Process.Pid
	}

	waitSessionByPID := func(t *testing.T, pid int, msg string) []model.TraceEvent {
		t.Helper()
		var matched []model.TraceEvent
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, err := st.QuerySessions(store.SessionQuery{Limit: 100})
			if err != nil {
				return false
			}
			matched = nil
			for _, s := range sessions {
				evs, err := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				if err != nil {
					continue
				}
				for _, ev := range evs {
					if ev.Process.PID == pid && ev.Status == "ok" {
						matched = append(matched, ev)
					}
				}
			}
			if len(matched) == 0 {
				for _, s := range sessions {
					evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
					for _, ev := range evs {
						if ev.Process.PID == pid {
							t.Logf("diag found non-ok event for pid=%d status=%s proto=%s", pid, ev.Status, ev.Protocol)
						}
					}
				}
			}
			return len(matched) >= 1
		}, 3*time.Second, 25*time.Millisecond, msg)
		return matched
	}

	// Scenario 1: Dynamic libssl.so.3 TLS 1.3 + Multi-Turn SSE Streaming (Python3 unhooked)
	t.Run("EBPF_Scenario1_DynamicLibSSL_TLS13_MultiTurn_And_SSE", func(t *testing.T) {
		pyScript := `
import ssl, subprocess, os, socket
cert, key = "/tmp/llm_tracer_ebpf_cert.pem", "/tmp/llm_tracer_ebpf_key.pem"
if not os.path.exists(cert):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
s1, s2 = socket.socketpair()
c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
c_ctx.check_hostname = False
c_ctx.verify_mode = ssl.CERT_NONE
s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
s_ctx.load_cert_chain(cert, key)
c_ssl = c_ctx.wrap_socket(s1, do_handshake_on_connect=False)
s_ssl = s_ctx.wrap_socket(s2, server_side=True, do_handshake_on_connect=False)
c_ssl.setblocking(False)
s_ssl.setblocking(False)
for _ in range(20):
    try: c_ssl.do_handshake()
    except ssl.SSLWantReadError: pass
    try: s_ssl.do_handshake()
    except ssl.SSLWantReadError: pass
c_ssl.setblocking(True)
s_ssl.setblocking(True)
req1 = b'{"model":"gpt-4.1","conversation_id":"ebpf_s1","messages":[{"role":"user","content":"turn 1 via libssl uprobe"}]}'
resp1 = b'{"id":"chatcmpl-1","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"ebpf kernel turn 1 ok"},"finish_reason":"stop"}]}'
c_ssl.write(b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: " + str(len(req1)).encode() + b"\r\n\r\n" + req1)
_ = s_ssl.read(65536)
s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(resp1)).encode() + b"\r\n\r\n" + resp1)
_ = c_ssl.read(65536)

req2 = b'{"model":"gpt-4.1","conversation_id":"ebpf_s1","stream":true,"messages":[{"role":"user","content":"turn 1 via libssl uprobe"},{"role":"assistant","content":"ebpf kernel turn 1 ok"},{"role":"user","content":"turn 2 sse stream"}]}'
sse_body = b'data: {"id":"chatcmpl-2","model":"gpt-4.1","choices":[{"index":0,"delta":{"content":"ebpf sse "}}]}\n\ndata: {"id":"chatcmpl-2","model":"gpt-4.1","choices":[{"index":0,"delta":{"content":"stream ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
c_ssl.write(b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: " + str(len(req2)).encode() + b"\r\n\r\n" + req2)
_ = s_ssl.read(65536)
s_ssl.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: " + str(len(sse_body)).encode() + b"\r\n\r\n" + sse_body)
_ = c_ssl.read(65536)
c_ssl.close()
s_ssl.close()
`
		pid := runUnhooked(t, "/usr/bin/python3", "-c", pyScript)
		evs := waitSessionByPID(t, pid, "libssl.so.3 uprobe must capture 2-turn TLS 1.3 + SSE session")
		require.GreaterOrEqual(t, len(evs), 2)
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, "ebpf kernel turn 1 ok", evs[0].Chat.ResponseText)
		require.Equal(t, "ebpf sse stream ok", evs[len(evs)-1].Chat.ResponseText)
	})

	// Scenario 2: Python ssl.MemoryBIO (in-memory BIO_s_mem with NO OS socket FD, SSL_get_fd == -1) + SystemOne JEV Protocol
	t.Run("EBPF_Scenario2_PythonMemoryBIO_NoSocketFD_SystemOneJEV", func(t *testing.T) {
		memBIOScript := `
import ssl
cert, key = "/tmp/llm_tracer_ebpf_cert.pem", "/tmp/llm_tracer_ebpf_key.pem"
c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
c_ctx.check_hostname = False
c_ctx.verify_mode = ssl.CERT_NONE
s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
s_ctx.load_cert_chain(cert, key)
c_obj = c_ctx.wrap_bio(c_in, c_out, server_side=False)
s_obj = s_ctx.wrap_bio(s_in, s_out, server_side=True)
for _ in range(10):
    try: c_obj.do_handshake()
    except ssl.SSLWantReadError: pass
    data = c_out.read()
    if data: s_in.write(data)
    try: s_obj.do_handshake()
    except ssl.SSLWantReadError: pass
    data = s_out.read()
    if data: c_in.write(data)

req = b'{"model":"StartLux-Decision-9B","state":{"page":{"url":"https://example.com","title":"MemoryBIO Page"}},"questions":{"operation":{"type":"enum","instructions":{"goal":"membio kernel ebpf test"},"criteria":["CLICK","DONE"]}}}'
resp = b'{"model":"StartLux-Decision-9B","answers":{"operation":{"choice":"DONE","confidence":0.99,"probabilities":{"DONE":0.99,"CLICK":0.01}}}}'
c_obj.write(b"POST /v1/systemone/jev/infer HTTP/1.1\r\nHost: systemone.internal\r\nContent-Type: application/x-jev+json\r\nContent-Length: " + str(len(req)).encode() + b"\r\n\r\n" + req)
s_in.write(c_out.read())
_ = s_obj.read(65536)
s_obj.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-jev+json\r\nContent-Length: " + str(len(resp)).encode() + b"\r\n\r\n" + resp)
c_in.write(s_out.read())
_ = c_obj.read(65536)
`
		pid := runUnhooked(t, "/usr/bin/python3", "-c", memBIOScript)
		evs := waitSessionByPID(t, pid, "libssl.so.3 uprobe must capture ssl.MemoryBIO (no socket FD) via SSL* pointer key")
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, model.ProtocolSystemOne, evs[0].Protocol)
		require.NotNil(t, evs[0].SystemOne)
		require.Equal(t, "DONE", evs[0].SystemOne.SelectedOp)
		require.Equal(t, "membio kernel ebpf test", evs[0].SystemOne.Goal)
	})

	// Scenario 3: Static Local OpenSSL Symbols (`static int SSL_write / SSL_read` in .symtab 't', no libssl.so)
	t.Run("EBPF_Scenario3_StaticLocalOpenSSLSymbols_InExecutable", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen_ebpf_static_ssl.c")
		binPath := filepath.Join(dir, "scen_ebpf_static_ssl")
		code := `
#include <stdio.h>
#include <string.h>
#include <stdint.h>

__attribute__((noinline, used))
static int SSL_write(void *ssl, const void *buf, int num) {
    asm volatile("" : : "r"(ssl), "r"(buf), "r"(num) : "memory");
    return num;
}

__attribute__((noinline, used))
static int SSL_read(void *ssl, void *buf, int num) {
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"msg_static\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-20250514\",\"content\":[{\"type\":\"text\",\"text\":\"static symtab uprobe ok\"}],\"stop_reason\":\"end_turn\"}";
    int rlen = (int)strlen(resp);
    if (rlen > num) rlen = num;
    memcpy(buf, resp, rlen);
    asm volatile("" : : "r"(ssl), "r"(buf), "r"(rlen) : "memory");
    return rlen;
}

int main(void) {
    void *fake_ssl = (void *)0x778899aabbULL;
    const char *req = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: 109\r\n\r\n{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"static ssl test\"}]}";
    SSL_write(fake_ssl, req, (int)strlen(req));
    char rbuf[4096];
    SSL_read(fake_ssl, rbuf, sizeof(rbuf));
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		out, err := exec.Command("gcc", "-O0", "-g", "-o", binPath, cSrc).CombinedOutput()
		require.NoError(t, err, string(out))

		targets := col.AttachBinaryTargets(binPath)
		require.NotEmpty(t, targets)

		pid := runUnhooked(t, binPath)
		evs := waitSessionByPID(t, pid, "kernel uprobe on static local .symtab SSL_write/SSL_read must capture exchange")
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, "static symtab uprobe ok", evs[0].Chat.ResponseText)
	})

	// Scenario 4: Node.js v24 (Statically Embedded OpenSSL 3 inside bin/node) HTTPS TLS 1.3 Client
	t.Run("EBPF_Scenario4_NodeJS_StaticEmbeddedOpenSSL_UnhookedHTTPS", func(t *testing.T) {
		nodeBin, err := findNodeExecutable()
		if err != nil {
			t.Skip("node not found")
		}
		targets := col.AttachBinaryTargets(nodeBin)
		hasNodeOpenSSLSyms := false
		for _, tgt := range targets {
			if len(tgt.Symbols) > 0 {
				hasNodeOpenSSLSyms = true
				break
			}
		}
		if !hasNodeOpenSSLSyms {
			t.Skip("node binary has stripped symbols and no dynamic libssl")
		}

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-node","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"node static openssl ebpf ok"},"finish_reason":"stop"}]}`))
		}))
		defer ts.Close()

		jsCode := fmt.Sprintf(`
const https = require("node:https");
const body = JSON.stringify({model:"gpt-4.1", messages:[{role:"user", content:"hello from unhooked node"}]});
const req = https.request(%q + "/v1/chat/completions", {
  method: "POST",
  rejectUnauthorized: false,
  headers: {"Content-Type": "application/json", "Content-Length": Buffer.byteLength(body)}
}, (res) => {
  res.on("data", () => {});
  res.on("end", () => process.exit(0));
});
req.write(body);
req.end();
`, ts.URL)
		pid := runUnhooked(t, nodeBin, "-e", jsCode)
		evs := waitSessionByPID(t, pid, "kernel uprobe on static OpenSSL inside bin/node must capture unhooked Node HTTPS")
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, "node static openssl ebpf ok", evs[0].Chat.ResponseText)
	})

	// Scenario 5: Native Go Binary (crypto/tls.(*Conn).Write + crypto/tls.(*Conn).Read post-morestack & RET uprobes)
	t.Run("EBPF_Scenario5_NativeGoBinary_GoTLS_WriteAndReadRetUprobes", func(t *testing.T) {
		goExecutable, err := exec.LookPath("go")
		if err != nil {
			goExecutable = "/home/liuyicong/.local/share/mise/installs/go/1.26.5/bin/go"
		}
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"model":"qwen3:8b","message":{"role":"assistant","content":"gotls kernel uprobe ok"},"done":true}`))
		}))
		defer ts.Close()

		goSrc := filepath.Join(dir, "scen_ebpf_gotls.go")
		goBin := filepath.Join(dir, "scen_ebpf_gotls")
		goCode := fmt.Sprintf(`package main
import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
)
func main() {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	client := &http.Client{Transport: tr}
	reqBody := []byte(%q)
	resp, err := client.Post(%q+"/api/chat", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		panic(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
}
`, `{"model":"qwen3:8b","messages":[{"role":"user","content":"hello from unhooked go tls"}],"stream":false}`, ts.URL)
		require.NoError(t, os.WriteFile(goSrc, []byte(goCode), 0o644))
		buildCmd := exec.Command(goExecutable, "build", "-o", goBin, goSrc)
		if os.Getenv("GOCACHE") != "" {
			buildCmd.Env = os.Environ()
		} else if _, err := os.Stat("/home/liuyicong"); err == nil {
			buildCmd.Env = append(os.Environ(), "GOCACHE=/tmp/go-build")
		}
		out, err := buildCmd.CombinedOutput()
		require.NoError(t, err, string(out))

		targets := col.AttachBinaryTargets(goBin)
		require.NotEmpty(t, targets)
		var goTarget *ProbeTarget
		for i := range targets {
			if targets[i].Type == "gotls" {
				goTarget = &targets[i]
				break
			}
		}
		require.NotNil(t, goTarget, "must identify Go binary as gotls target")
		require.NotEmpty(t, goTarget.GoTLSReadRetOffsets, "must locate RET instruction offsets in crypto/tls.(*Conn).Read")

		pid := runUnhooked(t, goBin)
		evs := waitSessionByPID(t, pid, "GoTLS kernel uprobes on Write + Read entry/RET must capture unhooked Go HTTPS")
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, model.ProtocolOllama, evs[0].Protocol)
		require.Equal(t, "gotls kernel uprobe ok", evs[0].Chat.ResponseText)
	})

	// Scenario 6: Stripped Bun/claude.exe-style Scatter-Gather `writev(fd, iov, 2)` + `read(fd)` Syscall Tracepoints
	t.Run("EBPF_Scenario6_StrippedBinary_ScatterGatherWritevTracepoint", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen_ebpf_writev.c")
		binPath := filepath.Join(dir, "scen_ebpf_writev")
		code := `
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;
    const char *hdr = "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\nContent-Length: 109\r\n\r\n";
    const char *body = "{\"model\":\"claude-sonnet-4-20250514\",\"max_tokens\":64,\"messages\":[{\"role\":\"user\",\"content\":\"ebpf writev iov\"}]}";
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"msg_wv\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-20250514\",\"content\":[{\"type\":\"text\",\"text\":\"ebpf writev tracepoint ok\"}],\"stop_reason\":\"end_turn\"}";
    char hdr_buf[256], body_buf[256], resp_buf[512], sink[512];
    memcpy(hdr_buf, hdr, strlen(hdr) + 1);
    memcpy(body_buf, body, strlen(body) + 1);
    memcpy(resp_buf, resp, strlen(resp) + 1);
    memset(sink, 0, sizeof(sink));
    __asm__ volatile("" : "+m"(hdr_buf), "+m"(body_buf), "+m"(resp_buf), "+m"(sink));
    struct iovec iov[2];
    iov[0].iov_base = hdr_buf;
    iov[0].iov_len = strlen(hdr_buf);
    iov[1].iov_base = body_buf;
    iov[1].iov_len = strlen(body_buf);
    writev(sv[0], iov, 2);
    read(sv[1], sink, sizeof(sink));
    write(sv[1], resp_buf, strlen(resp_buf));
    read(sv[0], sink, sizeof(sink));
    close(sv[0]);
    close(sv[1]);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		out, err := exec.Command("gcc", "-O2", "-s", "-o", binPath, cSrc).CombinedOutput()
		require.NoError(t, err, string(out))

		pid := runUnhooked(t, binPath)
		evs := waitSessionByPID(t, pid, "sys_enter_writev tracepoint must unroll iov[0]+iov[1] and capture exchange")
		require.Equal(t, "ebpf_tracepoint", evs[0].Process.TLSMode)
		require.Equal(t, "ebpf writev tracepoint ok", evs[0].Chat.ResponseText)
	})

	// Scenario 7: Full Static-PIE (`gcc -static -s`, No PT_INTERP, codex-style) Captured via Kernel Syscall Tracepoints
	t.Run("EBPF_Scenario7_FullStaticStrippedBinary_SyscallTracepoint", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen_ebpf_static_pie.c")
		binPath := filepath.Join(dir, "scen_ebpf_static_pie")
		code := `
#include <sys/socket.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    mlockall(MCL_CURRENT | MCL_FUTURE);
    volatile char warmup[8192];
    for (int i = 0; i < (int)sizeof(warmup); i += 64) warmup[i] = (char)i;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;
    const char *req = "POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: 74\r\n\r\n{\"model\":\"gpt-5-codex\",\"input\":\"static binary via kernel ebpf tracepoint\"}";
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"resp_static_tp\",\"object\":\"response\",\"model\":\"gpt-5-codex\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"static pie ebpf tracepoint ok\"}]}]}";
    char req_buf[512], resp_buf[512], sink[512];
    memcpy(req_buf, req, strlen(req) + 1);
    memcpy(resp_buf, resp, strlen(resp) + 1);
    memset(sink, 0, sizeof(sink));
    __asm__ volatile("" : "+m"(req_buf), "+m"(resp_buf), "+m"(sink));
    write(sv[0], req_buf, strlen(req_buf));
    read(sv[1], sink, sizeof(sink));
    write(sv[1], resp_buf, strlen(resp_buf));
    read(sv[0], sink, sizeof(sink));
    close(sv[0]);
    close(sv[1]);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		out, err := exec.Command("gcc", "-static", "-O2", "-s", "-o", binPath, cSrc).CombinedOutput()
		require.NoError(t, err, string(out))

		pid := runUnhooked(t, binPath)
		evs := waitSessionByPID(t, pid, "kernel syscall tracepoints must capture gcc -static -s binary without ptrace")
		require.Equal(t, "ebpf_tracepoint", evs[0].Process.TLSMode)
		require.Equal(t, model.ProtocolOpenAIResponses, evs[0].Protocol)
		require.Equal(t, "static pie ebpf tracepoint ok", evs[0].Chat.ResponseText)
	})

	// Scenario 8: Real `/usr/bin/curl -k --http1.1` Over HTTPS (Unhooked System Binary + Google Gemini Protocol)
	t.Run("EBPF_Scenario8_UnhookedSystemCurl_HTTPS_GeminiGenerateContent", func(t *testing.T) {
		curlBin, err := exec.LookPath("curl")
		if err != nil {
			t.Skip("curl not installed")
		}
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"curl gemini ebpf uprobe ok"}]},"finishReason":"STOP"}],"modelVersion":"gemini-2.5-pro"}`))
		}))
		defer ts.Close()

		pid := runUnhooked(t, curlBin, "-s", "-k", "--http1.1",
			"-X", "POST", ts.URL+"/v1beta/models/gemini-2.5-pro:generateContent",
			"-H", "Content-Type: application/json",
			"-d", `{"contents":[{"role":"user","parts":[{"text":"hello gemini from unhooked curl"}]}]}`)
		evs := waitSessionByPID(t, pid, "kernel uprobe on libssl.so.3 must capture unhooked /usr/bin/curl HTTPS request")
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, model.ProtocolGemini, evs[0].Protocol)
		require.Equal(t, "curl gemini ebpf uprobe ok", evs[0].Chat.ResponseText)
	})

	// Scenario 9: OpenSSL 3.x `SSL_write_ex` + `SSL_read_ex` (Testing `size_t *readbytes` RCX Pointer Dereference in eBPF)
	t.Run("EBPF_Scenario9_OpenSSL3_ExAPI_SSLWriteEx_And_SSLReadEx_PointerDereference", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen_ebpf_ssl_ex.c")
		binPath := filepath.Join(dir, "scen_ebpf_ssl_ex")
		code := `
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    SSL_CTX *c_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *s_ctx = SSL_CTX_new(TLS_server_method());
    if (!c_ctx || !s_ctx) return 1;
    SSL_CTX_set_verify(c_ctx, SSL_VERIFY_NONE, NULL);
    if (SSL_CTX_use_certificate_file(s_ctx, "/tmp/llm_tracer_ebpf_cert.pem", SSL_FILETYPE_PEM) <= 0) return 2;
    if (SSL_CTX_use_PrivateKey_file(s_ctx, "/tmp/llm_tracer_ebpf_key.pem", SSL_FILETYPE_PEM) <= 0) return 3;

    BIO *c_in = BIO_new(BIO_s_mem());
    BIO *c_out = BIO_new(BIO_s_mem());
    BIO *s_in = BIO_new(BIO_s_mem());
    BIO *s_out = BIO_new(BIO_s_mem());
    SSL *c_ssl = SSL_new(c_ctx);
    SSL *s_ssl = SSL_new(s_ctx);
    SSL_set_bio(c_ssl, c_in, c_out);
    SSL_set_connect_state(c_ssl);
    SSL_set_bio(s_ssl, s_in, s_out);
    SSL_set_accept_state(s_ssl);

    unsigned char tmp[16384];
    for (int i = 0; i < 12; i++) {
        SSL_do_handshake(c_ssl);
        int n = BIO_read(c_out, tmp, sizeof(tmp));
        if (n > 0) BIO_write(s_in, tmp, n);
        SSL_do_handshake(s_ssl);
        n = BIO_read(s_out, tmp, sizeof(tmp));
        if (n > 0) BIO_write(c_in, tmp, n);
        if (SSL_is_init_finished(c_ssl) && SSL_is_init_finished(s_ssl)) break;
    }

    const char *req = "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: 93\r\n\r\n{\"model\":\"gpt-4.1\",\"messages\":[{\"role\":\"user\",\"content\":\"testing SSL_write_ex SSL_read_ex\"}]}";
    size_t written = 0;
    if (!SSL_write_ex(c_ssl, req, strlen(req), &written)) return 4;
    int n = BIO_read(c_out, tmp, sizeof(tmp));
    if (n > 0) BIO_write(s_in, tmp, n);

    size_t s_read = 0;
    unsigned char s_buf[8192];
    SSL_read_ex(s_ssl, s_buf, sizeof(s_buf), &s_read);

    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 168\r\n\r\n{\"id\":\"chatcmpl-ex\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"ssl_write_ex and ssl_read_ex pointer ok\"},\"finish_reason\":\"stop\"}]}";
    size_t s_written = 0;
    SSL_write_ex(s_ssl, resp, strlen(resp), &s_written);
    n = BIO_read(s_out, tmp, sizeof(tmp));
    if (n > 0) BIO_write(c_in, tmp, n);

    size_t c_read = 0;
    unsigned char c_buf[8192];
    if (!SSL_read_ex(c_ssl, c_buf, sizeof(c_buf), &c_read) || c_read == 0) return 5;

    SSL_free(c_ssl);
    SSL_free(s_ssl);
    SSL_CTX_free(c_ctx);
    SSL_CTX_free(s_ctx);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		out, err := exec.Command("gcc", "-O2", "-o", binPath, cSrc, "-lssl", "-lcrypto").CombinedOutput()
		require.NoError(t, err, string(out))

		pid := runUnhooked(t, binPath)
		evs := waitSessionByPID(t, pid, "SSL_write_ex + SSL_read_ex (*readbytes pointer in RCX) must be captured by kernel uprobes")
		require.Equal(t, "ebpf_uprobe", evs[0].Process.TLSMode)
		require.Equal(t, "ssl_write_ex and ssl_read_ex pointer ok", evs[0].Chat.ResponseText)
	})

	// Scenario 10: Stripped Binary Using `sendto` + `recvfrom` Syscall Tracepoints
	t.Run("EBPF_Scenario10_StrippedBinary_SendtoRecvfrom_Tracepoints", func(t *testing.T) {
		cSrc := filepath.Join(dir, "scen_ebpf_sendto.c")
		binPath := filepath.Join(dir, "scen_ebpf_sendto")
		code := `
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;
    const char *req = "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\nContent-Length: 82\r\n\r\n{\"model\":\"gpt-4.1\",\"messages\":[{\"role\":\"user\",\"content\":\"sendto recvfrom trace\"}]}";
    char req_buf[512], resp_buf[512];
    memcpy(req_buf, req, strlen(req) + 1);
    sendto(sv[0], req_buf, strlen(req_buf), 0, NULL, 0);
    char sink[4096];
    recvfrom(sv[1], sink, sizeof(sink), 0, NULL, NULL);
    const char *resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":\"chatcmpl-sr\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"sendto recvfrom tracepoint ok\"},\"finish_reason\":\"stop\"}]}";
    memcpy(resp_buf, resp, strlen(resp) + 1);
    sendto(sv[1], resp_buf, strlen(resp_buf), 0, NULL, 0);
    recvfrom(sv[0], sink, sizeof(sink), 0, NULL, NULL);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
`
		require.NoError(t, os.WriteFile(cSrc, []byte(code), 0o644))
		out, err := exec.Command("gcc", "-O2", "-s", "-o", binPath, cSrc).CombinedOutput()
		require.NoError(t, err, string(out))

		pid := runUnhooked(t, binPath)
		evs := waitSessionByPID(t, pid, "sys_enter_sendto + sys_enter_recvfrom/sys_exit_recvfrom tracepoints must capture socket traffic")
		require.Equal(t, "ebpf_tracepoint", evs[0].Process.TLSMode)
		require.Equal(t, "sendto recvfrom tracepoint ok", evs[0].Chat.ResponseText)
	})

	// Scenario 11: Process Tree Scope Filtering (Subtree Grandchild Inheritance vs `--pid-only` Single-PID Isolation)
	t.Run("EBPF_Scenario11_ProcessTreeScope_SubtreeInheritance_vs_PIDOnlyMode", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(string(body), "from_grandchild_allowed") {
				_, _ = w.Write([]byte(`{"id":"chatcmpl-gc","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"grandchild subtree inherited ok"},"finish_reason":"stop"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"id":"chatcmpl-po","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"pid_only child should be ignored"},"finish_reason":"stop"}]}`))
			}
		}))
		defer ts.Close()

		// Subcase A: PIDOnly=false (default) -> parent spawns child -> grandchild makes HTTPS request -> MUST be captured
		parentScriptA := fmt.Sprintf(`
import subprocess, sys, time
time.sleep(0.05)
child_code = """
import urllib.request, ssl, time
ctx = ssl._create_unverified_context()
req = urllib.request.Request(%q + "/v1/chat/completions",
    data=b'{"model":"gpt-4.1","messages":[{"role":"user","content":"from_grandchild_allowed"}]}',
    headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req, context=ctx) as r:
    _ = r.read()
time.sleep(0.15)
"""
p = subprocess.Popen([sys.executable, "-c", child_code])
p.wait()
time.sleep(0.05)
`, ts.URL)
		parentCmdA := exec.Command("/usr/bin/python3", "-c", parentScriptA)
		parentCmdA.Env = []string{"PATH=/usr/bin:/bin"}
		require.NoError(t, parentCmdA.Start())
		parentPIDA := parentCmdA.Process.Pid
		col.UpdateScope(model.ScopeFilter{PIDs: []int{parentPIDA}, PIDOnly: false})
		require.NoError(t, parentCmdA.Wait())
		col.Flush()

		var foundGrandchild bool
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 100})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Chat != nil && ev.Chat.ResponseText == "grandchild subtree inherited ok" {
						foundGrandchild = true
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "descendant process traffic must be captured when PIDOnly=false")
		require.True(t, foundGrandchild)

		// Subcase B: PIDOnly=true (`--pid-only`) -> parent spawns child -> child's traffic MUST be filtered out
		parentScriptB := fmt.Sprintf(`
import subprocess, sys, time
child_code = """
import urllib.request, ssl, time
ctx = ssl._create_unverified_context()
req = urllib.request.Request(%q + "/v1/chat/completions",
    data=b'{"model":"gpt-4.1","messages":[{"role":"user","content":"from_child_blocked_by_pid_only"}]}',
    headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req, context=ctx) as r:
    _ = r.read()
time.sleep(0.08)
"""
time.sleep(0.05)
p = subprocess.Popen([sys.executable, "-c", child_code])
p.wait()
`, ts.URL)
		parentCmdB := exec.Command("/usr/bin/python3", "-c", parentScriptB)
		parentCmdB.Env = []string{"PATH=/usr/bin:/bin"}
		require.NoError(t, parentCmdB.Start())
		parentPIDB := parentCmdB.Process.Pid
		col.UpdateScope(model.ScopeFilter{PIDs: []int{parentPIDB}, PIDOnly: true})
		require.NoError(t, parentCmdB.Wait())
		col.Flush()
		time.Sleep(80 * time.Millisecond)
		col.Flush()

		sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 100})
		for _, s := range sessions {
			evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
			for _, ev := range evs {
				if ev.Chat != nil {
					require.NotEqual(t, "pid_only child should be ignored", ev.Chat.ResponseText,
						"child process traffic must NOT be captured when PIDOnly=true")
				}
			}
		}

		// Restore unrestricted scope for any subsequent checks
		col.UpdateScope(model.ScopeFilter{})
	})

	// Scenario 12: HTTP/1.1 Chunked + Gzip Compressed Response & Default Credential Header Redaction over Kernel eBPF
	t.Run("EBPF_Scenario12_GzipChunkedResponse_And_HeaderRedactionPrivacy", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			flusher, _ := w.(http.Flusher)
			gw := gzip.NewWriter(w)
			_, _ = gw.Write([]byte(`{"id":"chatcmpl-gz","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"gzip chunked ebpf decompressed ok"},"finish_reason":"stop"}]}`))
			_ = gw.Close()
			if flusher != nil {
				flusher.Flush()
			}
		}))
		defer ts.Close()

		curlBin, err := exec.LookPath("curl")
		if err != nil {
			t.Skip("curl not installed")
		}
		// First with RecordHeaders=false (default): headers should be omitted/redacted
		col.UpdateScope(model.ScopeFilter{RecordHeaders: false})
		pid1 := runUnhooked(t, curlBin, "-s", "-k", "--http1.1", "--compressed",
			"-X", "POST", ts.URL+"/v1/chat/completions",
			"-H", "Content-Type: application/json",
			"-H", "Authorization: Bearer sk-live-super-secret-token-12345",
			"-d", `{"model":"gpt-4.1","messages":[{"role":"user","content":"test gzip + header privacy"}]}`)
		evs1 := waitSessionByPID(t, pid1, "kernel uprobe must capture and decompress gzip chunked response")
		require.Equal(t, "ebpf_uprobe", evs1[0].Process.TLSMode)
		require.Equal(t, "gzip chunked ebpf decompressed ok", evs1[0].Chat.ResponseText)
		require.Empty(t, evs1[0].RequestHeaders, "RequestHeaders must be omitted by default when RecordHeaders=false")

		// Second with RecordHeaders=true (--record-headers): headers should be recorded
		col.UpdateScope(model.ScopeFilter{RecordHeaders: true})
		pid2 := runUnhooked(t, curlBin, "-s", "-k", "--http1.1", "--compressed",
			"-X", "POST", ts.URL+"/v1/chat/completions",
			"-H", "Content-Type: application/json",
			"-H", "X-Custom-Trace: ebpf-headers-enabled",
			"-d", `{"model":"gpt-4.1","messages":[{"role":"user","content":"test gzip + headers enabled"}]}`)
		evs2 := waitSessionByPID(t, pid2, "kernel uprobe must record headers when RecordHeaders=true")
		require.NotEmpty(t, evs2[0].RequestHeaders, "RequestHeaders must be recorded when RecordHeaders=true")
		col.UpdateScope(model.ScopeFilter{})
	})

	// Scenario 13: Multi-Dimensional Scope Filtering (--exe, --cwd, --cmd, --host) over Kernel eBPF Uprobes
	t.Run("EBPF_Scenario13_ScopeFilters_Exe_Cwd_Cmd_And_HostFilter", func(t *testing.T) {
		curlBin, err := exec.LookPath("curl")
		if err != nil {
			t.Skip("curl not installed")
		}
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"id":"chatcmpl-scope","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}]}`, "scope_echo:"+string(body))))
		}))
		defer ts.Close()

		subWorkDir := filepath.Join(dir, "scoped_workspace")
		require.NoError(t, os.MkdirAll(subWorkDir, 0o755))

		// 1. Filter by Exes=["curl"], Cwds=[subWorkDir], Cmds=["--http1.1"], Hosts=["127.0.0.1"] -> matching curl in subWorkDir MUST be captured
		col.UpdateScope(model.ScopeFilter{
			Exes:  []string{"curl"},
			Cwds:  []string{subWorkDir},
			Cmds:  []string{"--http1.1"},
			Hosts: []string{"127.0.0.1"},
		})
		pyRunnerMatch := fmt.Sprintf(`
import subprocess, time
p = subprocess.Popen([%q, "-s", "-k", "--http1.1", "-X", "POST", %q + "/v1/chat/completions",
    "-H", "Content-Type: application/json",
    "-d", '{"model":"gpt-4.1","messages":[{"role":"user","content":"matched_scope_req"}]}'],
    cwd=%q)
p.wait()
print(p.pid)
`, curlBin, ts.URL, subWorkDir)
		// Keep process alive briefly by running python3 directly inside subWorkDir with Exes=["python3"]
		col.UpdateScope(model.ScopeFilter{
			Exes:  []string{"python3"},
			Cwds:  []string{subWorkDir},
			Cmds:  []string{"matched_scope_marker"},
			Hosts: []string{"127.0.0.1"},
		})
		_ = pyRunnerMatch
		pyClientCode := fmt.Sprintf(`
# matched_scope_marker
import urllib.request, ssl, time
ctx = ssl._create_unverified_context()
req = urllib.request.Request(%q + "/v1/chat/completions",
    data=b'{"model":"gpt-4.1","messages":[{"role":"user","content":"scope_matched_ok"}]}',
    headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req, context=ctx) as r:
    _ = r.read()
time.sleep(0.12)
`, ts.URL)
		cmdMatch := exec.Command("/usr/bin/python3", "-c", pyClientCode)
		cmdMatch.Dir = subWorkDir
		cmdMatch.Env = []string{"PATH=/usr/bin:/bin"}
		outMatch, err := cmdMatch.CombinedOutput()
		require.NoError(t, err, string(outMatch))
		col.Flush()
		evsMatch := waitSessionByPID(t, cmdMatch.Process.Pid, "process matching --exe, --cwd, --cmd, --host must be captured")
		require.Contains(t, evsMatch[0].Chat.ResponseText, "scope_matched_ok")

		// 2. Mismatched Host filter (Hosts=["nonexistent.llm.internal"]) -> MUST be filtered out
		col.UpdateScope(model.ScopeFilter{
			Hosts: []string{"nonexistent.llm.internal"},
		})
		pidBlocked := runUnhooked(t, curlBin, "-s", "-k", "--http1.1",
			"-X", "POST", ts.URL+"/v1/chat/completions",
			"-H", "Content-Type: application/json",
			"-d", `{"model":"gpt-4.1","messages":[{"role":"user","content":"blocked_by_host_filter"}]}`)
		time.Sleep(80 * time.Millisecond)
		col.Flush()
		sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 100})
		for _, s := range sessions {
			evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
			for _, ev := range evs {
				require.NotEqual(t, pidBlocked, ev.Process.PID, "traffic to non-matching --host must be ignored")
			}
		}
		col.UpdateScope(model.ScopeFilter{})
	})

	// Scenario 14: Concurrent Multi-Process TLS Streams & 3-Tier Session Correlation (L1 Explicit + L2 Prefix Hash) over Kernel eBPF
	t.Run("EBPF_Scenario14_ConcurrentMultiProcess_ParallelTLSStreams_And_Correlation", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			sBody := string(body)
			switch {
			case strings.Contains(sBody, "worker_0"):
				_, _ = w.Write([]byte(`{"id":"chatcmpl-w0","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"parallel_worker_0_ok"},"finish_reason":"stop"}]}`))
			case strings.Contains(sBody, "worker_1"):
				_, _ = w.Write([]byte(`{"id":"chatcmpl-w1","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"parallel_worker_1_ok"},"finish_reason":"stop"}]}`))
			case strings.Contains(sBody, "worker_2"):
				_, _ = w.Write([]byte(`{"id":"chatcmpl-w2","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"parallel_worker_2_ok"},"finish_reason":"stop"}]}`))
			default:
				_, _ = w.Write([]byte(`{"id":"chatcmpl-w3","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"parallel_worker_3_ok"},"finish_reason":"stop"}]}`))
			}
		}))
		defer ts.Close()

		curlBin, err := exec.LookPath("curl")
		if err != nil {
			t.Skip("curl not installed")
		}
		pids := make([]int, 4)
		doneCh := make(chan int, 4)
		for idx := 0; idx < 4; idx++ {
			go func(wIdx int) {
				cmd := exec.Command(curlBin, "-s", "-k", "--http1.1",
					"-X", "POST", ts.URL+"/v1/chat/completions",
					"-H", "Content-Type: application/json",
					"-d", fmt.Sprintf(`{"model":"gpt-4.1","conversation_id":"ebpf_parallel_%d","messages":[{"role":"user","content":"worker_%d"}]}`, wIdx, wIdx))
				cmd.Env = []string{"PATH=/usr/bin:/bin"}
				_ = cmd.Run()
				pids[wIdx] = cmd.Process.Pid
				doneCh <- wIdx
			}(idx)
		}
		for i := 0; i < 4; i++ {
			<-doneCh
		}
		col.Flush()
		for idx := 0; idx < 4; idx++ {
			evs := waitSessionByPID(t, pids[idx], fmt.Sprintf("parallel worker %d must be isolated and captured without stream cross-talk", idx))
			require.Equal(t, fmt.Sprintf("parallel_worker_%d_ok", idx), evs[0].Chat.ResponseText)
		}
	})

	// Scenario 15: End-to-End `LaunchCommand` (`-- <cmd>`) Subprocess Tree Capture & Self-Monitoring Health Audit
	t.Run("EBPF_Scenario15_LaunchCommand_SubprocessTree_And_SelfMonitoringAudit", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"chatcmpl-launch","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"launch_command_ebpf_ok"},"finish_reason":"stop"}]}`))
		}))
		defer ts.Close()

		scriptPath := filepath.Join(dir, "launch_wrapper.sh")
		curlBin, err := exec.LookPath("curl")
		if err != nil {
			t.Skip("curl not installed")
		}
		scriptContent := fmt.Sprintf("#!/usr/bin/env bash\n%s -s -k --http1.1 -X POST %s/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"gpt-4.1\",\"messages\":[{\"role\":\"user\",\"content\":\"via launch_command wrapper\"}]}'\n", curlBin, ts.URL)
		require.NoError(t, os.WriteFile(scriptPath, []byte(scriptContent), 0o755))

		rc, err := col.LaunchCommand(ctx, []string{scriptPath})
		require.NoError(t, err)
		require.Equal(t, 0, rc)

		var foundLaunch bool
		require.Eventually(t, func() bool {
			col.Flush()
			sessions, _ := st.QuerySessions(store.SessionQuery{Limit: 100})
			for _, s := range sessions {
				evs, _ := st.QuerySessionEvents(store.EventQuery{SessionID: s.ID})
				for _, ev := range evs {
					if ev.Chat != nil && ev.Chat.ResponseText == "launch_command_ebpf_ok" {
						foundLaunch = true
						return true
					}
				}
			}
			return false
		}, 3*time.Second, 25*time.Millisecond, "LaunchCommand wrapper child curl request must be captured")
		require.True(t, foundLaunch)

		stats := mon.Stats()
		require.GreaterOrEqual(t, stats.TotalOK, int64(15), "selfmon must record OK events across all 15 scenarios")
	})
}
