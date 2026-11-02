package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
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

func buildLLMTFrame(pid, tid int, sslTag uint32, dir uint32, payload []byte) []byte {
	var hdr [24]byte
	binary.NativeEndian.PutUint32(hdr[0:4], 0x4c4c4d54)
	binary.NativeEndian.PutUint32(hdr[4:8], uint32(pid))
	binary.NativeEndian.PutUint32(hdr[8:12], uint32(tid))
	binary.NativeEndian.PutUint32(hdr[12:16], sslTag)
	binary.NativeEndian.PutUint32(hdr[16:20], dir)
	binary.NativeEndian.PutUint32(hdr[20:24], uint32(len(payload)))
	out := make([]byte, 24+len(payload))
	copy(out[:24], hdr[:])
	copy(out[24:], payload)
	return out
}

func buildOpenAIExchangeFrames(pid int, sslTag uint32, idx int) ([]byte, []byte) {
	reqBody := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello-secret-test-%d"}]}`, idx)
	reqRaw := fmt.Sprintf(
		"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nAuthorization: Bearer sk-AUTHSECRET-abcdef\r\nx-api-key: XAPIKEYSECRET\r\nCookie: session=COOKIESECRET\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(reqBody),
		reqBody,
	)
	respBody := fmt.Sprintf(`{"id":"chatcmpl-%d","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"reply-%d"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`, idx, idx)
	respRaw := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: srv=SETCOOKIESECRET\r\nContent-Length: %d\r\n\r\n%s",
		len(respBody),
		respBody,
	)
	reqFrame := buildLLMTFrame(pid, pid, sslTag, 0, []byte(reqRaw))
	respFrame := buildLLMTFrame(pid, pid, sslTag, 1, []byte(respRaw))
	return reqFrame, respFrame
}

func countPersistedStoreEvents(t *testing.T, st *store.Store) int {
	t.Helper()
	sessions, err := st.QuerySessions(store.SessionQuery{Limit: 500})
	require.NoError(t, err)
	total := 0
	for _, sess := range sessions {
		events, err := st.QuerySessionEvents(store.EventQuery{SessionID: sess.ID, Limit: 500})
		require.NoError(t, err)
		total += len(events)
	}
	return total
}

func TestPipeSourceFrameResyncAndRecovery(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	corr := correlator.NewCorrelator(mon)

	selfPID := os.Getpid()
	col, err := NewCollector(dir, model.ScopeFilter{PIDs: []int{selfPID}}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))
	defer col.Stop()

	pipePath := filepath.Join(dir, "hooks", "tls.bin")

	// 1. Write 24 zero bytes (bad magic) followed by a valid OpenAI exchange
	var buf bytes.Buffer
	buf.Write(make([]byte, 24))
	req1, resp1 := buildOpenAIExchangeFrames(selfPID, 0x101, 1)
	buf.Write(req1)
	buf.Write(resp1)

	// 2. Write interleaved frames (A.hdr + B.hdr + A.payload + B.payload) followed by a valid exchange
	aPayload := []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
	bPayload := []byte("GET /b HTTP/1.1\r\nHost: y\r\n\r\n")
	aFrame := buildLLMTFrame(selfPID, selfPID, 0x201, 0, aPayload)
	bFrame := buildLLMTFrame(selfPID, selfPID, 0x202, 0, bPayload)
	buf.Write(aFrame[:24])
	buf.Write(bFrame[:24])
	buf.Write(aPayload)
	buf.Write(bPayload)
	req2, resp2 := buildOpenAIExchangeFrames(selfPID, 0x102, 2)
	buf.Write(req2)
	buf.Write(resp2)

	// 3. Write a truncated frame (header claims 200B payload, only 32B present) followed by a valid exchange
	truncHdr := buildLLMTFrame(selfPID, selfPID, 0x301, 0, make([]byte, 200))[:24]
	buf.Write(truncHdr)
	buf.Write(bytes.Repeat([]byte("X"), 32))
	req3, resp3 := buildOpenAIExchangeFrames(selfPID, 0x103, 3)
	buf.Write(req3)
	buf.Write(resp3)

	// 4. Write an oversized frame header (payloadLen = 1MB > 512KB limit) followed by a valid exchange
	var overHdr [24]byte
	binary.NativeEndian.PutUint32(overHdr[0:4], 0x4c4c4d54)
	binary.NativeEndian.PutUint32(overHdr[4:8], uint32(selfPID))
	binary.NativeEndian.PutUint32(overHdr[8:12], uint32(selfPID))
	binary.NativeEndian.PutUint32(overHdr[12:16], 0x401)
	binary.NativeEndian.PutUint32(overHdr[16:20], 0)
	binary.NativeEndian.PutUint32(overHdr[20:24], 1024*1024)
	buf.Write(overHdr[:])
	req4, resp4 := buildOpenAIExchangeFrames(selfPID, 0x104, 4)
	buf.Write(req4)
	buf.Write(resp4)

	f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_APPEND, 0o600)
	require.NoError(t, err)
	_, err = f.Write(buf.Bytes())
	require.NoError(t, err)
	require.NoError(t, f.Close())

	col.Flush()

	require.Equal(t, 4, countPersistedStoreEvents(t, st), "all 4 valid exchanges after corrupt/interleaved/truncated/oversized frames must be persisted")

	warnEvents, err := mon.QueryEvents(selfmon.Query{
		Stage:  selfmon.StageProbe,
		Status: selfmon.StatusWarn,
		Limit:  50,
	})
	require.NoError(t, err)
	resyncCount := 0
	for _, ev := range warnEvents {
		if ev.Action == "pipe_frame_resync" {
			resyncCount++
		}
	}
	require.GreaterOrEqual(t, resyncCount, 4, "expected pipe_frame_resync warnings in selfmon for each corrupted segment")
}

func TestPipeSourceDrainTruncationAndStopReclaim(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	defer mon.Close()
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer func() { _ = st.Close() }()
	corr := correlator.NewCorrelator(mon)

	selfPID := os.Getpid()
	col, err := NewCollector(dir, model.ScopeFilter{PIDs: []int{selfPID}}, corr, st, mon)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, col.Start(ctx))

	pipePath := filepath.Join(dir, "hooks", "tls.bin")

	// Write 100 exchanges (~82.5KB total > 64KB cap) across 10 batches and flush each batch
	var maxObservedAfterDrain int64
	for batch := 0; batch < 10; batch++ {
		f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_APPEND, 0o600)
		require.NoError(t, err)
		lockPipeFile(f)
		for i := 0; i < 10; i++ {
			idx := batch*10 + i + 1
			reqF, respF := buildOpenAIExchangeFrames(selfPID, uint32(0x500+idx), idx)
			_, err = f.Write(reqF)
			require.NoError(t, err)
			_, err = f.Write(respF)
			require.NoError(t, err)
		}
		unlockPipeFile(f)
		require.NoError(t, f.Close())

		col.Flush()

		fi, err := os.Stat(pipePath)
		require.NoError(t, err)
		if fi.Size() > maxObservedAfterDrain {
			maxObservedAfterDrain = fi.Size()
		}
		require.Equal(t, int64(0), fi.Size(), "tls.bin must be truncated to 0 bytes after drain")

		rawAfter, err := os.ReadFile(pipePath)
		require.NoError(t, err)
		require.NotContains(t, string(rawAfter), "AUTHSECRET", "plaintext credentials must not remain in tls.bin after drain")
		require.NotContains(t, string(rawAfter), "XAPIKEYSECRET")
		require.NotContains(t, string(rawAfter), "COOKIESECRET")
		require.NotContains(t, string(rawAfter), "SETCOOKIESECRET")
	}

	require.Equal(t, int64(0), maxObservedAfterDrain)
	require.Equal(t, 100, countPersistedStoreEvents(t, st))

	// Verify Stop truncates and removes tls.bin completely
	col.Stop()
	_, statErr := os.Stat(pipePath)
	require.True(t, os.IsNotExist(statErr), "tls.bin must be deleted when Collector.Stop() returns")
}

func TestPipePermissionsNeverWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode permission check is Unix-specific")
	}
	dir := t.TempDir()
	pipePath := filepath.Join(dir, "tls.bin")

	origGetEUID := getEffectiveUID
	origChown := chownFileFunc
	defer func() {
		getEffectiveUID = origGetEUID
		chownFileFunc = origChown
	}()

	getEffectiveUID = func() int { return 1000 }
	chownFileFunc = func(_ *os.File, _ string, _ int) error {
		return os.ErrPermission
	}

	// 1. Even if 0o666 or cross-UID without CAP_CHOWN or multi-UID (-2) is requested, tls.bin must never be world-readable
	require.NoError(t, initPipeFileNoFollow(pipePath, 0o666, 2002))
	fi, err := os.Stat(pipePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "tls.bin must be 0600, never world-readable")
	require.Zero(t, fi.Mode().Perm()&0o077, "tls.bin must have no group/other permission bits")

	err = applyPipePermissionsNoFollow(pipePath, 0o666, -2)
	require.ErrorIs(t, err, errCrossUIDPermissionDenied)
	fi, err = os.Stat(pipePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "multi-UID target (-2) must not relax tls.bin to 0666")

	// 2. Verify C hook sources use writev and 0600 (never 0666)
	require.Contains(t, sslHookCSource, "writev(")
	require.NotContains(t, sslHookCSource, "0666")
	require.Contains(t, ptraceHelperCSource, "writev(")
	require.NotContains(t, ptraceHelperCSource, "0666")
	require.False(t, strings.Contains(sslHookCSource, "write(pfd, hdr"), "ssl_hook.c must not split header and payload into two write() calls")
	require.False(t, strings.Contains(ptraceHelperCSource, "write(pfd, hdr"), "ptrace_helper.c must not split header and payload into two write() calls")
}

func TestHookArtifactPermissionsAndNoSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions and symlink tests are Unix-specific")
	}

	hooksDir := t.TempDir()

	// 1. Verify EnsureRuntimeHooks artifacts have exact permissions without group/other write (0o022 masked)
	paths, err := EnsureRuntimeHooks(hooksDir)
	require.NoError(t, err)
	require.NotNil(t, paths)

	scPath := filepath.Join(paths.PyHookDir, "sitecustomize.py")
	fiSc, err := os.Stat(scPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fiSc.Mode().Perm(), "sitecustomize.py must be 0644")
	require.Zero(t, fiSc.Mode().Perm()&0o022, "sitecustomize.py must not have group/other write bits")

	fiNode, err := os.Stat(paths.NodeHookJS)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fiNode.Mode().Perm(), "node_hook.cjs must be 0644")
	require.Zero(t, fiNode.Mode().Perm()&0o022, "node_hook.cjs must not have group/other write bits")

	if paths.PtraceBin != "" {
		fiPtrace, err := os.Stat(paths.PtraceBin)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), fiPtrace.Mode().Perm(), "llm_tracer_ptrace binary must be 0755")
		require.Zero(t, fiPtrace.Mode().Perm()&0o022, "llm_tracer_ptrace binary must not have group/other write bits")
	}
	ptraceC := filepath.Join(hooksDir, "llm_tracer_ptrace.c")
	if fiC, err := os.Stat(ptraceC); err == nil {
		require.Equal(t, os.FileMode(0o644), fiC.Mode().Perm(), "llm_tracer_ptrace.c must be 0644")
		require.Zero(t, fiC.Mode().Perm()&0o022, "llm_tracer_ptrace.c must not have group/other write bits")
	}

	// 2. Verify EnsureJavaAgentJar produces 0o644 jar and build files without group/other write
	jarPath, err := EnsureJavaAgentJar(hooksDir)
	require.NoError(t, err)
	fiJar, err := os.Stat(jarPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fiJar.Mode().Perm(), "llm_tracer_java.jar must be 0644")
	require.Zero(t, fiJar.Mode().Perm()&0o022, "llm_tracer_java.jar must not have group/other write bits")

	javaSrc := filepath.Join(hooksDir, "java_build", "LlmTracerAgent.java")
	fiSrc, err := os.Stat(javaSrc)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fiSrc.Mode().Perm(), "LlmTracerAgent.java must be 0644")
	require.Zero(t, fiSrc.Mode().Perm()&0o022, "LlmTracerAgent.java must not have group/other write bits")

	// 3. Verify EnsureSSLPreloadHook produces 0o755 library and 0o644 source
	soPath, err := EnsureSSLPreloadHook(hooksDir)
	if err == nil {
		fiSo, err := os.Stat(soPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), fiSo.Mode().Perm(), "ssl hook library must be 0755")
		require.Zero(t, fiSo.Mode().Perm()&0o022, "ssl hook library must not have group/other write bits")

		cPath := filepath.Join(hooksDir, "libllmtracer_ssl.c")
		fiPreC, err := os.Stat(cPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), fiPreC.Mode().Perm(), "libllmtracer_ssl.c must be 0644")
		require.Zero(t, fiPreC.Mode().Perm()&0o022, "libllmtracer_ssl.c must not have group/other write bits")
	}

	// 4. Verify LoopbackTap CA bundle permissions
	tap, err := NewLoopbackTap(hooksDir, nil)
	if err == nil {
		defer tap.Close()
		fiCA, err := os.Stat(tap.CABundlePath())
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), fiCA.Mode().Perm(), "ca bundle must be 0644")
		require.Zero(t, fiCA.Mode().Perm()&0o022, "ca bundle must not have group/other write bits")
	} else {
		caPath := filepath.Join(hooksDir, "test_ca.pem")
		require.NoError(t, writeArtifactNoFollow(caPath, []byte("fake-ca"), 0o644))
		fiCA, err := os.Stat(caPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o644), fiCA.Mode().Perm())
		require.Zero(t, fiCA.Mode().Perm()&0o022)
	}

	// 5. Verify writeArtifactNoFollow and chmodArtifactNoFollow strip group/other write bits even if requested
	testRelaxed := filepath.Join(hooksDir, "relaxed_mode.bin")
	require.NoError(t, writeArtifactNoFollow(testRelaxed, []byte("data"), 0o666))
	fiRelaxed, err := os.Stat(testRelaxed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), fiRelaxed.Mode().Perm(), "0666 request must be sanitized to 0644")

	require.NoError(t, chmodArtifactNoFollow(testRelaxed, 0o777))
	fiRelaxedChmod, err := os.Stat(testRelaxed)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), fiRelaxedChmod.Mode().Perm(), "0777 request must be sanitized to 0755")

	// 6. Anti-symlink tests: external sensitive file must never be followed or overwritten
	extDir := t.TempDir()
	sensitiveFile := filepath.Join(extDir, "sensitive.txt")
	const originalSensitive = "SUPER_SECRET_PAYLOAD_DO_NOT_TOUCH"
	require.NoError(t, os.WriteFile(sensitiveFile, []byte(originalSensitive), 0o600))

	// 6a. writeArtifactNoFollow refuses symlink
	symlinkArtifact := filepath.Join(hooksDir, "symlink_artifact.bin")
	require.NoError(t, os.Symlink(sensitiveFile, symlinkArtifact))
	err = writeArtifactNoFollow(symlinkArtifact, []byte("OVERWRITTEN"), 0o644)
	require.Error(t, err, "writeArtifactNoFollow must refuse to write to a symlink")
	readBack, err := os.ReadFile(sensitiveFile)
	require.NoError(t, err)
	require.Equal(t, originalSensitive, string(readBack), "external sensitive file must remain untouched")

	// 6b. chmodArtifactNoFollow refuses symlink
	err = chmodArtifactNoFollow(symlinkArtifact, 0o777)
	require.Error(t, err, "chmodArtifactNoFollow must refuse to chmod a symlink")
	fiSens, err := os.Stat(sensitiveFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fiSens.Mode().Perm(), "external sensitive file mode must remain unchanged")

	// 6c. EnsureJavaAgentJar refuses to follow symlink jar
	hooksDirSymlink := t.TempDir()
	jarSymlink := filepath.Join(hooksDirSymlink, "llm_tracer_java.jar")
	require.NoError(t, os.Symlink(sensitiveFile, jarSymlink))
	_, err = EnsureJavaAgentJar(hooksDirSymlink)
	require.Error(t, err, "EnsureJavaAgentJar must reject symlink jar")
	readBack, err = os.ReadFile(sensitiveFile)
	require.NoError(t, err)
	require.Equal(t, originalSensitive, string(readBack), "external file must not be modified by EnsureJavaAgentJar")
	fiSymlink, err := os.Lstat(jarSymlink)
	require.NoError(t, err)
	require.True(t, fiSymlink.Mode()&os.ModeSymlink != 0, "symlink itself must not be deleted or hijacked")

	// 6d. ensureSafeSubDir refuses symlink directory
	symlinkDir := filepath.Join(hooksDir, "symlink_sub_dir")
	require.NoError(t, os.Symlink(extDir, symlinkDir))
	err = ensureSafeSubDir(symlinkDir, 0o755)
	require.Error(t, err, "ensureSafeSubDir must reject symlink directory")
}
