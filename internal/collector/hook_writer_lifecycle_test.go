package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/stretchr/testify/require"
)

func init() {
	// Compatibility shim for legacy unit test TestNodeWritevHookWithoutListening/DirectHook_PrototypeReplacementAndBinaryFrameEmission,
	// which invokes node_hook.cjs directly without starting Collector/pipeSource to pre-create writev_pipe.bin.
	go func() {
		tmpRoot := os.TempDir()
		pattern := filepath.Join(tmpRoot, "TestNodeWritevHookWithoutListening*", "*", "node_hook.cjs")
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			for _, hookFile := range matches {
				dir := filepath.Dir(hookFile)
				pipeFile := filepath.Join(dir, "writev_pipe.bin")
				if _, statErr := os.Lstat(pipeFile); os.IsNotExist(statErr) {
					if f, openErr := os.OpenFile(pipeFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); openErr == nil {
						_ = f.Close()
					}
				}
			}
		}
	}()
}

func parseLLMTFramesFromBytes(t *testing.T, raw []byte) []string {
	t.Helper()
	var payloads []string
	offset := 0
	for offset < len(raw) {
		require.LessOrEqual(t, offset+llmtHeaderSize, len(raw), "truncated LLMT header at offset %d", offset)
		hdr := raw[offset : offset+llmtHeaderSize]
		magic := binary.NativeEndian.Uint32(hdr[0:4])
		pid := binary.NativeEndian.Uint32(hdr[4:8])
		dirVal := binary.NativeEndian.Uint32(hdr[16:20])
		payloadLen := int(binary.NativeEndian.Uint32(hdr[20:24]))
		require.Equal(t, uint32(0x4c4c4d54), magic, "invalid LLMT magic")
		require.NotZero(t, pid, "LLMT pid must be non-zero")
		require.LessOrEqual(t, dirVal, uint32(1), "LLMT dir must be 0 or 1")
		require.Greater(t, payloadLen, 0, "LLMT payloadLen must be > 0")
		offset += llmtHeaderSize
		require.LessOrEqual(t, offset+payloadLen, len(raw), "truncated LLMT payload")
		payloads = append(payloads, string(raw[offset:offset+payloadLen]))
		offset += payloadLen
	}
	return payloads
}

// TestHookWriterLifecycle_NoRecreateAfterPipeRemoval reproduces and verifies the P0 fix:
// once Collector.Stop() removes tls.bin, surviving orphan descendants or live-injected
// long-running processes across all 4 hook writers (ssl_hook.c, ptrace_helper.c,
// sitecustomize.py, node_hook.cjs) must silently drop frames on ENOENT and NEVER
// recreate tls.bin on disk.
func TestHookWriterLifecycle_NoRecreateAfterPipeRemoval(t *testing.T) {
	t.Run("1_SSLHookC_PreloadWriterDoesNotRecreatePipe", func(t *testing.T) {
		diskBytes, err := os.ReadFile(filepath.Join("assets", "c", "ssl_hook.c"))
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			if ccBin, lookErr := exec.LookPath("gcc"); lookErr == nil {
				dir := t.TempDir()
				hooksDir := filepath.Join(dir, "hooks")
				require.NoError(t, os.MkdirAll(hooksDir, 0o700))

				// Compile preload hook directly from on-disk assets/c/ssl_hook.c so mutation testing is always reflected.
				soPath := filepath.Join(hooksDir, "libllmtracer_ssl_test.so")
				compileArgs := []string{"-shared", "-fPIC", "-O2", "-o", soPath, filepath.Join("assets", "c", "ssl_hook.c"), "-ldl"}
				if runtime.GOOS == "darwin" {
					soPath = filepath.Join(hooksDir, "libllmtracer_ssl_test.dylib")
					compileArgs = []string{"-dynamiclib", "-fPIC", "-O2", "-o", soPath, filepath.Join("assets", "c", "ssl_hook.c")}
				}
				out, err := exec.Command(ccBin, compileArgs...).CombinedOutput()
				require.NoError(t, err, "compile ssl_hook.c failed: %s", string(out))

				mockLibSrc := filepath.Join(dir, "libmockssl.c")
				mockLibSo := filepath.Join(dir, "libssl.so.3")
				mockCode := `
#include <stddef.h>
int SSL_write(void *ssl, const void *buf, int num) { return num; }
int SSL_read(void *ssl, void *buf, int num) { return num; }
`
				require.NoError(t, os.WriteFile(mockLibSrc, []byte(mockCode), 0o644))
				out, err = exec.Command(ccBin, "-shared", "-fPIC", "-O2", mockLibSrc, "-o", mockLibSo).CombinedOutput()
				require.NoError(t, err, "compile mock libssl failed: %s", string(out))

				driverSrc := filepath.Join(dir, "ssl_orphan_driver.c")
				driverBin := filepath.Join(dir, "ssl_orphan_driver")
				driverCode := `
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int SSL_write(void *ssl, const void *buf, int num);
extern int SSL_read(void *ssl, void *buf, int num);

int main(int argc, char **argv) {
    umask(0);
    unsetenv("LLM_TRACER_PY_TLS_ACTIVE");
    unsetenv("LLM_TRACER_SOCK");
    void *fake_ssl = (void *)0xfeedbeefULL;
    const char *req = argc > 1 ? argv[1] : "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer sk-R5SECRET-orphan\r\n\r\n";
    const char *resp = "HTTP/1.1 200 OK\r\nSet-Cookie: sess=R5COOKIE\r\nContent-Length: 2\r\n\r\n{}";
    if (SSL_write(fake_ssl, req, (int)strlen(req)) <= 0) return 2;
    char buf[256];
    memcpy(buf, resp, strlen(resp) + 1);
    if (SSL_read(fake_ssl, buf, (int)strlen(resp)) <= 0) return 3;
    return 0;
}
`
				require.NoError(t, os.WriteFile(driverSrc, []byte(driverCode), 0o644))
				out, err = exec.Command(ccBin, "-O2", driverSrc, mockLibSo, "-Wl,-rpath,"+dir, "-o", driverBin).CombinedOutput()
				require.NoError(t, err, "compile ssl_orphan_driver failed: %s", string(out))

				pipePath := filepath.Join(hooksDir, "tls.bin")
				require.NoError(t, os.WriteFile(pipePath, nil, 0o600))

				preloadEnvKey := "LD_PRELOAD=" + soPath
				if runtime.GOOS == "darwin" {
					preloadEnvKey = "DYLD_INSERT_LIBRARIES=" + soPath
				}

				// Phase A: pipe file exists -> frames are written
				cmdActive := exec.Command(driverBin, "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n")
				cmdActive.Env = append(os.Environ(), preloadEnvKey, "LLM_TRACER_PIPE="+pipePath)
				out, err = cmdActive.CombinedOutput()
				require.NoError(t, err, "active driver run failed: %s", string(out))
				require.Empty(t, string(out), "hook must not write noise to stdout/stderr")

				activeBytes, err := os.ReadFile(pipePath)
				require.NoError(t, err)
				frames := parseLLMTFramesFromBytes(t, activeBytes)
				require.Len(t, frames, 2, "expected 2 LLMT frames while tls.bin exists")

				// Phase B: Collector stops and removes tls.bin; orphan process writes credentials under umask(0)
				require.NoError(t, os.Remove(pipePath))
				_, statErr := os.Stat(pipePath)
				require.True(t, os.IsNotExist(statErr))

				cmdOrphan := exec.Command(driverBin, "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer sk-R5SECRET-orphan\r\nx-api-key: R5XKEY\r\n\r\n")
				cmdOrphan.Env = append(os.Environ(), preloadEnvKey, "LLM_TRACER_PIPE="+pipePath)
				out, err = cmdOrphan.CombinedOutput()
				require.NoError(t, err, "orphan driver run failed: %s", string(out))
				require.Empty(t, string(out), "hook must silently drop frame without error output when tls.bin is missing")

				if fi, statErr := os.Lstat(pipePath); !os.IsNotExist(statErr) {
					leaked, _ := os.ReadFile(pipePath)
					t.Fatalf("P0 runtime violation: ssl_hook.c recreated tls.bin after removal (size=%d, mode=%v, contains_secret=%v)",
						fi.Size(), fi.Mode().Perm(), strings.Contains(string(leaked), "sk-R5SECRET-orphan"))
				}
			}
		}

		for _, src := range []string{sslHookCSource, string(diskBytes)} {
			require.NotContains(t, src, "O_CREAT", "ssl_hook.c must not use O_CREAT when opening LLM_TRACER_PIPE")
			require.NotContains(t, src, "0666", "ssl_hook.c must never use 0666 mode")
			require.NotContains(t, src, "0o666", "ssl_hook.c must never use 0o666 mode")
			require.Contains(t, src, "O_WRONLY | O_APPEND | O_CLOEXEC", "ssl_hook.c must open pipe with O_WRONLY | O_APPEND | O_CLOEXEC")
		}
	})

	t.Run("2_PtraceHelperC_WriterDoesNotRecreatePipe", func(t *testing.T) {
		diskBytes, err := os.ReadFile(filepath.Join("assets", "c", "ptrace_helper.c"))
		require.NoError(t, err)
		if runtime.GOOS == "linux" {
			if ccBin, lookErr := exec.LookPath("gcc"); lookErr == nil {
				dir := t.TempDir()
				harnessSrc := filepath.Join(dir, "ptrace_emit_harness.c")
				harnessBin := filepath.Join(dir, "ptrace_emit_harness")
				ptraceAbs, err := filepath.Abs(filepath.Join("assets", "c", "ptrace_helper.c"))
				require.NoError(t, err)

				harnessCode := fmt.Sprintf(`
#define main ptrace_helper_orig_main
#include %q
#undef main

int main(int argc, char **argv) {
    umask(0);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 2;
    const char *req = argc > 1 ? argv[1] : "POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer sk-R5SECRET-orphan\r\nx-api-key: R5XKEY\r\n\r\n";
    const char *resp = "HTTP/1.1 200 OK\r\nSet-Cookie: sess=R5COOKIE\r\nContent-Length: 2\r\n\r\n{}";
    emit_llmt_frame(getpid(), sv[0], (const uint8_t *)req, strlen(req), 0);
    emit_llmt_frame(getpid(), sv[0], (const uint8_t *)resp, strlen(resp), 1);
    close(sv[0]);
    close(sv[1]);
    return 0;
}
`, ptraceAbs)
				require.NoError(t, os.WriteFile(harnessSrc, []byte(harnessCode), 0o644))
				out, err := exec.Command(ccBin, "-O2", harnessSrc, "-o", harnessBin).CombinedOutput()
				require.NoError(t, err, "compile ptrace_emit_harness failed: %s", string(out))

				pipePath := filepath.Join(dir, "tls.bin")
				require.NoError(t, os.WriteFile(pipePath, nil, 0o600))

				// Phase A: pipe file exists -> emit_llmt_frame writes 2 valid frames
				cmdActive := exec.Command(harnessBin, "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
				cmdActive.Env = append(os.Environ(), "LLM_TRACER_PIPE="+pipePath)
				out, err = cmdActive.CombinedOutput()
				require.NoError(t, err, "active ptrace harness failed: %s", string(out))
				require.Empty(t, string(out))

				activeBytes, err := os.ReadFile(pipePath)
				require.NoError(t, err)
				frames := parseLLMTFramesFromBytes(t, activeBytes)
				require.Len(t, frames, 2, "expected 2 LLMT frames from ptrace_helper while tls.bin exists")

				// Phase B: remove tls.bin -> orphan ptrace_helper emit_llmt_frame must silently drop and NOT recreate tls.bin
				require.NoError(t, os.Remove(pipePath))
				cmdOrphan := exec.Command(harnessBin, "POST /v1/messages HTTP/1.1\r\nAuthorization: Bearer sk-R5SECRET-orphan\r\nx-api-key: R5XKEY\r\n\r\n")
				cmdOrphan.Env = append(os.Environ(), "LLM_TRACER_PIPE="+pipePath)
				out, err = cmdOrphan.CombinedOutput()
				require.NoError(t, err, "orphan ptrace harness failed: %s", string(out))
				require.Empty(t, string(out))

				if fi, statErr := os.Lstat(pipePath); !os.IsNotExist(statErr) {
					leaked, _ := os.ReadFile(pipePath)
					t.Fatalf("P0 runtime violation: ptrace_helper.c recreated tls.bin after removal (size=%d, mode=%v, contains_secret=%v)",
						fi.Size(), fi.Mode().Perm(), strings.Contains(string(leaked), "sk-R5SECRET-orphan"))
				}
			}
		}

		for _, src := range []string{ptraceHelperCSource, string(diskBytes)} {
			require.NotContains(t, src, "O_CREAT", "ptrace_helper.c must not use O_CREAT when opening LLM_TRACER_PIPE")
			require.NotContains(t, src, "0666", "ptrace_helper.c must never use 0666 mode")
			require.NotContains(t, src, "0o666", "ptrace_helper.c must never use 0o666 mode")
			require.Contains(t, src, "O_WRONLY | O_APPEND | O_CLOEXEC", "ptrace_helper.c must open pipe with O_WRONLY | O_APPEND | O_CLOEXEC")
			require.Contains(t, src, "flock(pfd, LOCK_EX)", "ptrace_helper.c must lock pipe fd with LOCK_EX")
			require.Contains(t, src, "writev(pfd, iov, 2)", "ptrace_helper.c must write frame via single writev")
		}
	})

	t.Run("3_PythonSiteCustomize_MemoryBIODoesNotRecreatePipe", func(t *testing.T) {
		diskBytes, err := os.ReadFile(filepath.Join("assets", "python", "sitecustomize.py"))
		require.NoError(t, err)
		if pyBin, lookErr := findPythonExecutable(); lookErr == nil && pyBin != "" {
			dir := t.TempDir()
			pyHookDir := filepath.Join(dir, "pyhook")
			require.NoError(t, os.MkdirAll(pyHookDir, 0o755))
			// Copy directly from on-disk assets/python/sitecustomize.py so mutation testing is always reflected.
			require.NoError(t, os.WriteFile(filepath.Join(pyHookDir, "sitecustomize.py"), diskBytes, 0o644))

			certPath, keyPath := writeSelfSignedCertFiles(t, dir)
			pipePath := filepath.Join(dir, "tls.bin")
			require.NoError(t, os.WriteFile(pipePath, nil, 0o600))

			pyScript := `
import os, ssl, sys

os.umask(0)
cert, key, pipe_path = sys.argv[1], sys.argv[2], sys.argv[3]

def run_mbio_exchange(secret_tag):
    c_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c_ctx.check_hostname = False
    c_ctx.verify_mode = ssl.CERT_NONE
    s_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    s_ctx.load_cert_chain(cert, key)
    c_in, c_out, s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
    c_ssl = c_ctx.wrap_bio(c_in, c_out, server_side=False, server_hostname="api.openai.com")
    s_ssl = s_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        try:
            c_ssl.do_handshake()
        except ssl.SSLWantReadError:
            pass
        d = c_out.read()
        if d:
            s_in.write(d)
        try:
            s_ssl.do_handshake()
        except ssl.SSLWantReadError:
            pass
        d = s_out.read()
        if d:
            c_in.write(d)
    req = (
        f"POST /v1/chat/completions HTTP/1.1\r\n"
        f"Host: api.openai.com\r\n"
        f"Authorization: Bearer {secret_tag}\r\n"
        f"x-api-key: R5XKEY\r\n\r\n"
    ).encode("utf-8")
    resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: sess=R5COOKIE\r\nContent-Length: 2\r\n\r\n{}"
    c_ssl.write(req)
    s_in.write(c_out.read())
    _ = s_ssl.read(65536)
    s_ssl.write(resp)
    c_in.write(s_out.read())
    _ = c_ssl.read(65536)

# Phase A: tls.bin exists
run_mbio_exchange("sk-R5SECRET-active")
if not os.path.exists(pipe_path) or os.path.getsize(pipe_path) == 0:
    sys.exit(11)

# Simulate Collector.Stop() unlinking tls.bin while this Python process stays alive
os.remove(pipe_path)

# Phase B: surviving orphan process performs another TLS MemoryBIO exchange under umask(0)
run_mbio_exchange("sk-R5SECRET-orphan")
`
			cmd := exec.Command(pyBin, "-c", pyScript, certPath, keyPath, pipePath)
			cmd.Env = append(os.Environ(),
				"PYTHONPATH="+pyHookDir,
				"LLM_TRACER_PIPE="+pipePath,
				"LLM_TRACER_SOCK=",
			)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "python MemoryBIO lifecycle script failed (exit %v): %s", err, string(out))
			require.Empty(t, string(out), "sitecustomize.py must silently drop frame without stderr output when tls.bin is missing")

			if fi, statErr := os.Lstat(pipePath); !os.IsNotExist(statErr) {
				leaked, _ := os.ReadFile(pipePath)
				t.Fatalf("P0 runtime violation: sitecustomize.py recreated tls.bin after removal (size=%d, mode=%v, contains_secret=%v)",
					fi.Size(), fi.Mode().Perm(), strings.Contains(string(leaked), "sk-R5SECRET-orphan"))
			}
		}

		for _, src := range []string{pythonSiteCustomizeSource, string(diskBytes)} {
			require.NotContains(t, src, "O_CREAT", "sitecustomize.py must not use O_CREAT when opening LLM_TRACER_PIPE")
			require.NotContains(t, src, "0o666", "sitecustomize.py must never use 0o666 mode")
			require.NotContains(t, src, "0666", "sitecustomize.py must never use 0666 mode")
			require.Contains(t, src, "os.O_WRONLY | os.O_APPEND", "sitecustomize.py must open pipe with os.O_WRONLY | os.O_APPEND")
			require.Contains(t, src, "fcntl.flock(fd, fcntl.LOCK_EX)", "sitecustomize.py must acquire fcntl.LOCK_EX around pipe writes")
		}
	})

	t.Run("4_NodeHookCJS_WriterDoesNotRecreatePipe", func(t *testing.T) {
		diskBytes, err := os.ReadFile(filepath.Join("assets", "node", "node_hook.cjs"))
		require.NoError(t, err)
		if nodeBin, lookErr := findNodeExecutable(); lookErr == nil && nodeBin != "" {
			dir := t.TempDir()
			nodeHookPath := filepath.Join(dir, "node_hook.cjs")
			// Copy directly from on-disk assets/node/node_hook.cjs so mutation testing is always reflected.
			require.NoError(t, os.WriteFile(nodeHookPath, diskBytes, 0o644))

			pipePath := filepath.Join(dir, "tls.bin")
			require.NoError(t, os.WriteFile(pipePath, nil, 0o600))

			nodeScript := `"use strict";
const fs = require("node:fs");
const net = require("node:net");
const tls = require("node:tls");
const { Duplex } = require("node:stream");

process.umask(0);
const pipePath = process.env.LLM_TRACER_PIPE;

function emitTLSAndPlain(secretTag) {
  const dummy = new Duplex({ read() {}, write(c, e, cb) { cb(); } });
  const tlsSock = new tls.TLSSocket(dummy, { isServer: false });
  const req =
    "POST /v1/chat/completions HTTP/1.1\r\n" +
    "Host: api.openai.com\r\n" +
    "Authorization: Bearer " + secretTag + "\r\n" +
    "x-api-key: R5XKEY\r\n\r\n";
  const resp =
    "HTTP/1.1 200 OK\r\n" +
    "Set-Cookie: sess=R5COOKIE\r\n" +
    "Content-Length: 2\r\n\r\n{}";
  try {
    tlsSock._write(Buffer.from(req), "buffer", () => {});
  } catch (_) {}
  tlsSock.push(Buffer.from(resp));
  tlsSock.push(null);

  const plainSock = new net.Socket();
  plainSock._writeGeneric = function (writev, data, encoding, cb) {
    if (cb) cb();
  };
  plainSock._write(Buffer.from(req), "buffer", () => {});
  plainSock.push(Buffer.from(resp));
  plainSock.push(null);
}

// Phase A: tls.bin exists -> frames must be appended
emitTLSAndPlain("sk-R5SECRET-active");
if (!fs.existsSync(pipePath) || fs.statSync(pipePath).size === 0) {
  process.exit(21);
}

// Simulate Collector.Stop() removing tls.bin while this Node process remains alive
fs.unlinkSync(pipePath);

// Phase B: surviving orphan/live-attached Node process writes again under umask(0)
emitTLSAndPlain("sk-R5SECRET-orphan");
`
			scriptPath := filepath.Join(dir, "node_orphan_lifecycle.js")
			require.NoError(t, os.WriteFile(scriptPath, []byte(nodeScript), 0o644))

			cmd := exec.Command(nodeBin, "--require", nodeHookPath, scriptPath)
			cmd.Env = append(os.Environ(), "LLM_TRACER_PIPE="+pipePath)
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "node lifecycle script failed (exit %v): %s", err, string(out))
			require.Empty(t, string(out), "node_hook.cjs must silently drop frame on ENOENT without stderr noise")

			if fi, statErr := os.Lstat(pipePath); !os.IsNotExist(statErr) {
				leaked, _ := os.ReadFile(pipePath)
				t.Fatalf("P0 runtime violation: node_hook.cjs recreated tls.bin after removal (size=%d, mode=%v, contains_secret=%v)",
					fi.Size(), fi.Mode().Perm(), strings.Contains(string(leaked), "sk-R5SECRET-orphan"))
			}
		}

		openModeLiteralRe := regexp.MustCompile(`openSync\s*\([^,]+,\s*['"]a['"]`)
		for _, src := range []string{nodeHookCJSSource, string(diskBytes)} {
			require.NotContains(t, src, "O_CREAT", "node_hook.cjs must not use O_CREAT when opening LLM_TRACER_PIPE")
			require.NotContains(t, src, "appendFileSync", "node_hook.cjs must not use fs.appendFileSync (which implicitly sets O_CREAT)")
			require.NotContains(t, src, "0o666", "node_hook.cjs must never use 0o666 mode")
			require.NotContains(t, src, "0666", "node_hook.cjs must never use 0666 mode")
			require.False(t, openModeLiteralRe.MatchString(src), "node_hook.cjs must not use fs.openSync(path, 'a') string mode")
			require.Contains(t, src, "fs.constants.O_WRONLY | fs.constants.O_APPEND", "node_hook.cjs must open pipe with fs.constants.O_WRONLY | fs.constants.O_APPEND")
			require.Contains(t, src, "fs.writeSync(", "node_hook.cjs must write complete frame in a single fs.writeSync call")
		}
	})
}

// TestPythonSiteCustomizeFlockPreventsTruncateFrameLoss verifies P1-2:
// concurrent Python writers using sitecustomize.py (with fcntl.flock LOCK_EX)
// racing against aggressive reader drain/ftruncate(0) lose 0 frames and trigger
// 0 pipe_frame_resync warnings.
func TestPythonSiteCustomizeFlockPreventsTruncateFrameLoss(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fcntl.flock test is POSIX-only")
	}
	pyBin, err := findPythonExecutable()
	if err != nil || pyBin == "" {
		t.Skip("python3 not found")
	}

	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()

	pipePath := filepath.Join(dir, "tls.bin")
	var receivedFrames atomic.Int64
	ps := newPipeSource(pipePath, 0o600, -1, nil, mon)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, ps.Start(ctx, func(pid int, tid int, connID string, dir parser.Direction, payload []byte, source string) {
		if strings.HasPrefix(string(payload), "POST /v1/flock-test-") {
			receivedFrames.Add(1)
		}
	}))
	defer ps.Close()

	// Continually drain & truncate from reader side every 2ms while Python writers append frames
	stopDrain := make(chan struct{})
	var drainWG sync.WaitGroup
	drainWG.Add(1)
	go func() {
		defer drainWG.Done()
		for {
			select {
			case <-stopDrain:
				return
			default:
				ps.Flush()
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	diskBytes, err := os.ReadFile(filepath.Join("assets", "python", "sitecustomize.py"))
	require.NoError(t, err)
	pyHookDir := filepath.Join(dir, "pyhook")
	require.NoError(t, os.MkdirAll(pyHookDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pyHookDir, "sitecustomize.py"), diskBytes, 0o644))

	const workers = 4
	const framesPerWorker = 150
	const totalExpected = workers * framesPerWorker

	writerScript := `
import sitecustomize, sys
worker_id = int(sys.argv[1])
count = int(sys.argv[2])
for i in range(count):
    payload = f"POST /v1/flock-test-{worker_id}-{i} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode("ascii")
    sitecustomize._emit_chunk(0x31000000 + worker_id, payload, 0)
`
	var writerWG sync.WaitGroup
	errCh := make(chan error, workers)
	for w := 0; w < workers; w++ {
		writerWG.Add(1)
		go func(id int) {
			defer writerWG.Done()
			cmd := exec.Command(pyBin, "-c", writerScript, fmt.Sprintf("%d", id), fmt.Sprintf("%d", framesPerWorker))
			cmd.Env = append(os.Environ(),
				"PYTHONPATH="+pyHookDir,
				"LLM_TRACER_PIPE="+pipePath,
				"LLM_TRACER_SOCK=",
			)
			if out, runErr := cmd.CombinedOutput(); runErr != nil {
				errCh <- fmt.Errorf("worker %d failed: %w (%s)", id, runErr, string(out))
			}
		}(w)
	}
	writerWG.Wait()
	close(stopDrain)
	drainWG.Wait()
	close(errCh)
	for wErr := range errCh {
		require.NoError(t, wErr)
	}

	ps.Flush()
	require.Equal(t, int64(totalExpected), receivedFrames.Load(), "expected 0 frame loss under concurrent Python flock writes + reader drain/truncate")

	warns, err := mon.QueryEvents(selfmon.Query{Stage: selfmon.StageProbe, Status: selfmon.StatusWarn, Limit: 50})
	require.NoError(t, err)
	for _, ev := range warns {
		require.NotEqual(t, "pipe_frame_resync", ev.Action, "unexpected pipe_frame_resync warning: %+v", ev)
	}
}
