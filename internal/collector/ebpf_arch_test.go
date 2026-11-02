package collector

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func encodeARM64Words(words ...uint32) []byte {
	buf := make([]byte, len(words)*4)
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*4:(i+1)*4], w)
	}
	return buf
}

func TestARM64RetInstructionScanAndPrologue(t *testing.T) {
	// Build a synthetic AArch64 Go function body with stack-split prologue, body instructions,
	// non-RET branch/call instructions (BR, BLR, NOP), and multiple return variants (RET, RETAA, RETAB, RET X16).
	words := []uint32{
		0xf9400b90,     // 0x00: MOVD 16(R28), R16 (Go stackguard0 check)
		0xeb3063ff,     // 0x04: CMP R16, RSP
		0x54001909,     // 0x08: BLS morestack
		0xf8190ffe,     // 0x0c: MOVD.W R30, -112(RSP)
		0xf81f83fd,     // 0x10: MOVD R29, -8(RSP)  <-- prologue frame setup start (offset 16)
		0xd10023fd,     // 0x14: SUB $8, RSP, R29
		0xd503201f,     // 0x18: NOP
		0xd63f0000,     // 0x1c: BLR X0 (indirect call, must NOT match as RET)
		0xd61f0000,     // 0x20: BR X0  (indirect jump, must NOT match as RET)
		arm64InsnRet,   // 0x24: RET (X30 = 0xd65f03c0) -> offset 36
		0xaa0003e1,     // 0x28: MOVD R0, R1
		arm64InsnRetAA, // 0x2c: RETAA (0xd65f0bff) -> offset 44
		arm64InsnRetAB, // 0x30: RETAB (0xd65f0fff) -> offset 48
		0xd65f0200,     // 0x34: RET X16 -> offset 52
	}
	code := encodeARM64Words(words...)

	prologueOff := scanARM64GoPrologueOffset(code)
	require.Equal(t, uint64(0x10), prologueOff, "must advance past arm64 stack-split check to frame pointer setup")

	retOffsets := scanARM64ReturnOffsets(code)
	require.Equal(t, []uint64{0x24, 0x2c, 0x30, 0x34}, retOffsets)

	fileRetOffsets := findGoARM64RetOffsets(0x10000, code)
	require.Equal(t, []uint64{0x10024, 0x1002c, 0x10030, 0x10034}, fileRetOffsets)

	if runtime.GOARCH == "arm64" {
		require.Equal(t, retOffsets, scanReturnOffsets(code))
		require.Equal(t, prologueOff, scanGoPrologueOffset(code))
	}

	// Cross-compile a real linux/arm64 Go TLS binary when go toolchain is available and verify ELF RET resolution.
	if goBin, err := findGoExecutable(); err == nil {
		dir := t.TempDir()
		srcPath := filepath.Join(dir, "arm64_tls_sample.go")
		outBin := filepath.Join(dir, "arm64_tls_sample")
		src := `package main
import (
	"crypto/tls"
)
func main() {
	conn := &tls.Conn{}
	_, _ = conn.Write([]byte("hello"))
	buf := make([]byte, 8)
	_, _ = conn.Read(buf)
}
`
		require.NoError(t, os.WriteFile(srcPath, []byte(src), 0o644))
		cmd := exec.Command(goBin, "build", "-ldflags=-s -w", "-o", outBin, srcPath)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=arm64")
		if out, err := cmd.CombinedOutput(); err == nil {
			gt, err := InspectGoTLSTarget(outBin)
			require.NoError(t, err)
			require.NotNil(t, gt)
			require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Write"], uint64(0))
			require.Greater(t, gt.Symbols["crypto/tls.(*Conn).Read"], uint64(0))
			require.NotEmpty(t, gt.GoTLSReadRetOffsets, "must locate arm64 RET (0xd65f03c0) offsets in stripped linux/arm64 Go binary")

			rawF, err := os.Open(outBin)
			require.NoError(t, err)
			defer rawF.Close()
			var word [4]byte
			for _, off := range gt.GoTLSReadRetOffsets {
				_, err := rawF.ReadAt(word[:], int64(off))
				require.NoError(t, err)
				insn := binary.LittleEndian.Uint32(word[:])
				require.True(t, isARM64ReturnInsn(insn), "file offset 0x%x must be an arm64 RET instruction, got 0x%08x", off, insn)
			}
		} else {
			t.Logf("skipping cross-compiled arm64 binary check: %s", string(out))
		}
	}
}

func TestAMD64RetInstructionScanAndPrologue(t *testing.T) {
	// Prologue: cmp 0x10(%r14),%rsp (49 3b 66 10); jbe (76 20); push %rbp; mov %rsp,%rbp (55 48 89 e5)
	// Epilogue 1: add $0x48,%rsp; pop %rbp; ret (48 83 c4 48 5d c3)
	// Epilogue 2: add $0x80,%rsp; pop %rbp; ret (48 81 c4 80 00 00 00 5d c3)
	code := []byte{
		0x49, 0x3b, 0x66, 0x10, 0x76, 0x20,
		0x55, 0x48, 0x89, 0xe5, // offset 6: push %rbp; mov %rsp, %rbp
		0x90, 0xc3, // standalone 0xc3 without epilogue must be ignored
		0x48, 0x83, 0xc4, 0x48, 0x5d, 0xc3, // ret at offset 17
		0x48, 0x81, 0xc4, 0x80, 0x00, 0x00, 0x00, 0x5d, 0xc3, // ret at offset 26
	}

	require.Equal(t, uint64(6), scanAMD64GoPrologueOffset(code))
	require.Equal(t, []uint64{17, 26}, scanAMD64ReturnOffsets(code))
	require.Equal(t, []uint64{0x2000 + 17, 0x2000 + 26}, findGoX8664RetOffsets(0x2000, code))

	if runtime.GOARCH == "amd64" {
		require.Equal(t, []uint64{17, 26}, scanReturnOffsets(code))
		require.Equal(t, uint64(6), scanGoPrologueOffset(code))
	}
}

func TestArchPtRegsOffsetsAndCapabilityTable(t *testing.T) {
	// 1. Verify arm64 struct user_pt_regs layout: regs[0..30], sp (248), pc (256), pstate (264)
	for i := 0; i <= 30; i++ {
		require.Equal(t, int16(i*8), arm64PtRegsOffsets.Regs[i], "arm64 user_pt_regs.regs[%d] offset", i)
	}
	require.Equal(t, int16(248), arm64PtRegsOffsets.SP, "arm64 user_pt_regs.sp offset")
	require.Equal(t, int16(256), arm64PtRegsOffsets.PC, "arm64 user_pt_regs.pc offset")
	require.Equal(t, int16(264), arm64PtRegsOffsets.PState, "arm64 user_pt_regs.pstate offset")
	require.Equal(t, int16(0), arm64PtRegsOffsets.CArg0)
	require.Equal(t, int16(8), arm64PtRegsOffsets.CArg1)
	require.Equal(t, int16(16), arm64PtRegsOffsets.CArg2)
	require.Equal(t, int16(24), arm64PtRegsOffsets.CArg3)
	require.Equal(t, int16(0), arm64PtRegsOffsets.CRet)
	require.Equal(t, int16(0), arm64PtRegsOffsets.GoArg0)
	require.Equal(t, int16(8), arm64PtRegsOffsets.GoArg1)
	require.Equal(t, int16(16), arm64PtRegsOffsets.GoArg2)
	require.Equal(t, int16(0), arm64PtRegsOffsets.GoRet)
	require.Equal(t, int16(224), arm64PtRegsOffsets.GoGoroutine, "arm64 Go goroutine pointer g is R28 (offset 224)")

	// 2. Verify amd64 struct pt_regs layout
	require.Equal(t, int16(112), amd64PtRegsOffsets.CArg0)
	require.Equal(t, int16(104), amd64PtRegsOffsets.CArg1)
	require.Equal(t, int16(96), amd64PtRegsOffsets.CArg2)
	require.Equal(t, int16(88), amd64PtRegsOffsets.CArg3)
	require.Equal(t, int16(80), amd64PtRegsOffsets.CRet)
	require.Equal(t, int16(80), amd64PtRegsOffsets.GoArg0)
	require.Equal(t, int16(40), amd64PtRegsOffsets.GoArg1)
	require.Equal(t, int16(88), amd64PtRegsOffsets.GoArg2)
	require.Equal(t, int16(8), amd64PtRegsOffsets.GoGoroutine)
	require.Equal(t, int16(152), amd64PtRegsOffsets.SP)
	require.Equal(t, int16(128), amd64PtRegsOffsets.PC)
	require.Equal(t, int16(144), amd64PtRegsOffsets.PState)

	// 3. Verify capability table for amd64, arm64, and unsupported architectures
	amd64Cap := lookupArchCapabilities("amd64")
	require.True(t, amd64Cap.Supported)
	require.True(t, amd64Cap.UprobeSupported)
	require.True(t, amd64Cap.UretprobeSupported)
	require.True(t, amd64Cap.GoTLSUprobeSupported)
	require.False(t, amd64Cap.GoTLSUretprobeSupported, "kernel uretprobe is never safe on Go movable stacks")
	require.True(t, amd64Cap.GoTLSRetScanSupported)
	require.NoError(t, validateArchEBPFSupport("amd64"))

	arm64Cap := lookupArchCapabilities("arm64")
	require.True(t, arm64Cap.Supported)
	require.True(t, arm64Cap.UprobeSupported)
	require.True(t, arm64Cap.UretprobeSupported)
	require.True(t, arm64Cap.GoTLSUprobeSupported)
	require.False(t, arm64Cap.GoTLSUretprobeSupported)
	require.True(t, arm64Cap.GoTLSRetScanSupported)
	require.False(t, arm64Cap.PtraceUserspaceSupported)
	require.NotEmpty(t, arm64Cap.DegradedFeatures)
	require.Contains(t, arm64Cap.DegradationNotice, "0xd65f03c0")
	require.NoError(t, validateArchEBPFSupport("arm64"))

	riscvCap := lookupArchCapabilities("riscv64")
	require.False(t, riscvCap.Supported)
	require.NotEmpty(t, riscvCap.UnsupportedReason)
	err := validateArchEBPFSupport("riscv64")
	require.Error(t, err)
	require.Contains(t, err.Error(), "linux/riscv64")
	require.Contains(t, err.Error(), "supported architectures: amd64, arm64")

	if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
		require.True(t, archSupported)
		require.Equal(t, runtime.GOARCH, archName)
		require.True(t, archCapabilities.Supported)
		require.Greater(t, archPtRegsOffsets.PC, int16(0))
	}
}

func TestCollectorSetCaptureUnknown(t *testing.T) {
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

	// Verify interface{ SetCaptureUnknown(bool) } assertion used by cmd/llm-tracer/main.go
	setter, ok := any(col).(interface{ SetCaptureUnknown(bool) })
	require.True(t, ok, "Collector must implement interface{ SetCaptureUnknown(bool) }")
	require.False(t, col.CaptureUnknown())
	require.True(t, col.reassembler.DropUnknown(), "DropUnknown must default to true")

	selfPID := os.Getpid()
	unkReqBody := `{"ping":"custom_non_llm"}`
	unkRespBody := `{"pong":"ok"}`
	rawReq := "POST /custom/non-llm-endpoint HTTP/1.1\r\nHost: internal.example.com\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(unkReqBody)) + "\r\n\r\n" + unkReqBody
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(unkRespBody)) + "\r\n\r\n" + unkRespBody

	// 1. Default CaptureUnknown=false -> unknown protocol exchange is dropped when Hosts filter is empty
	require.True(t, col.IngestRawChunk(selfPID, selfPID, "conn_drop", parser.DirWrite, []byte(rawReq), "openssl"))
	require.True(t, col.IngestRawChunk(selfPID, selfPID, "conn_drop", parser.DirRead, []byte(rawResp), "openssl"))

	evDirectDropped, okDirectDropped, err := col.IngestDirectExchange(DirectExchangeInput{
		Method:       "POST",
		Host:         "internal.example.com",
		Path:         "/custom/non-llm-direct",
		HTTPStatus:   200,
		PID:          selfPID,
		Comm:         "test",
		RequestBody:  []byte(unkReqBody),
		ResponseBody: []byte(unkRespBody),
	})
	require.NoError(t, err)
	require.False(t, okDirectDropped)
	require.Nil(t, evDirectDropped)

	sessions, err := st.QuerySessions(store.SessionQuery{Limit: 50})
	require.NoError(t, err)
	require.Empty(t, sessions, "unknown protocol exchanges must be dropped when CaptureUnknown is false")

	// 2. Enable CaptureUnknown=true -> unknown protocol exchanges are retained via both stream reassembler and direct ingest
	setter.SetCaptureUnknown(true)
	require.True(t, col.CaptureUnknown())
	require.False(t, col.reassembler.DropUnknown())

	require.True(t, col.IngestRawChunk(selfPID, selfPID, "conn_keep", parser.DirWrite, []byte(rawReq), "openssl"))
	require.True(t, col.IngestRawChunk(selfPID, selfPID, "conn_keep", parser.DirRead, []byte(rawResp), "openssl"))

	evDirectKept, okDirectKept, err := col.IngestDirectExchange(DirectExchangeInput{
		Method:       "POST",
		Host:         "internal.example.com",
		Path:         "/custom/non-llm-direct",
		HTTPStatus:   200,
		PID:          selfPID,
		Comm:         "test",
		RequestBody:  []byte(unkReqBody),
		ResponseBody: []byte(unkRespBody),
	})
	require.NoError(t, err)
	require.True(t, okDirectKept)
	require.NotNil(t, evDirectKept)
	require.Equal(t, model.ProtocolUnknown, evDirectKept.Protocol)

	sessions, err = st.QuerySessions(store.SessionQuery{Limit: 50})
	require.NoError(t, err)
	require.NotEmpty(t, sessions, "unknown protocol exchanges must be stored when CaptureUnknown is true")

	// 3. Concurrent toggling under -race
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				col.SetCaptureUnknown((idx+j)%2 == 0)
				_ = col.CaptureUnknown()
			}
		}(i)
	}
	wg.Wait()
}

func TestArchPtraceUnsupportedLaunchPlanAndLiveAttachDegradation(t *testing.T) {
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

	// 1. Launch planning with arm64 capability table (PtraceUserspaceSupported == false):
	// must NOT wrap with ptrace_wrapper and must record degradation notices + selfmon warning.
	arm64Cap := lookupArchCapabilities("arm64")
	require.False(t, arm64Cap.PtraceUserspaceSupported)

	staticIn := launchPlanInput{
		CmdArgs:          []string{"/usr/local/bin/static-agent", "--prompt", "arm64"},
		BinPath:          "/usr/local/bin/static-agent",
		Profile:          &BinaryProfile{ResolvedELF: "/usr/local/bin/static-agent", RequiresPtrace: true, TLSStack: "static-custom", LinkMode: "static-pie"},
		AutoIntrusive:    true,
		GOOS:             "linux",
		GOARCH:           "arm64",
		ArchCapabilities: &arm64Cap,
		CanUsePtrace:     true,
		PtraceBin:        "/tmp/hooks/llm_tracer_ptrace",
		TapActive:        true,
		ProxyURL:         "http://127.0.0.1:43111",
		ProxyHost:        "127.0.0.1",
		ProxyPort:        "43111",
		CABundlePath:     "/tmp/hooks/ca.pem",
	}
	staticPlan := planLaunch(staticIn)
	require.False(t, staticPlan.PtraceWrapped, "arm64 plan must skip ptrace wrapper when PtraceUserspaceSupported is false")
	require.Equal(t, "/usr/local/bin/static-agent", staticPlan.ExecBin, "ExecBin must remain the original binary without ptrace wrapper")
	require.Equal(t, []string{"--prompt", "arm64"}, staticPlan.ExecArgs)
	require.NotContains(t, staticPlan.IntrusiveMethods, "ptrace_wrapper")
	require.NotEmpty(t, staticPlan.DegradationNotices, "plan must record explicit ptrace degradation notice on arm64")
	require.Contains(t, staticPlan.DegradationNotices[0], "PtraceUserspaceSupported=false")

	env := applyLaunchPlan(col, staticIn, staticPlan, []string{"PATH=/usr/bin"})
	require.Equal(t, "http://127.0.0.1:43111", lookupEnvVar(env, "HTTPS_PROXY"))
	require.Equal(t, "http://127.0.0.1:43111", lookupEnvVar(env, "HTTP_PROXY"), "must inject HTTP_PROXY fallback when ptrace is unsupported by architecture")

	// 2. Live attach planning & execution with injected unsupported ptrace capability table:
	prevOverride := archCapabilitiesOverride
	archCapabilitiesOverride = &arm64Cap
	defer func() {
		archCapabilitiesOverride = prevOverride
	}()

	pidPlan := col.inspectSinglePIDPlan(os.Getpid(), false)
	require.NotEqual(t, "ptrace_seize", pidPlan.RecommendedIntrusive, "live attach plan must skip ptrace_seize when PtraceUserspaceSupported is false")
	require.NotEmpty(t, pidPlan.DegradationNotices, "live attach plan must carry ptrace degradation notice")
	require.Contains(t, pidPlan.DegradationNotices[0], "PtraceUserspaceSupported=false")

	_, injectErr := col.InjectRunningPID(os.Getpid())
	require.Error(t, injectErr)
	require.Contains(t, injectErr.Error(), "PtraceUserspaceSupported=false")

	if runtime.GOOS == "linux" {
		directErr := col.injectRunningPtrace(os.Getpid())
		require.Error(t, directErr)
		require.Contains(t, directErr.Error(), "PtraceUserspaceSupported=false")
	}

	warns, err := mon.QueryEvents(selfmon.Query{Stage: selfmon.StageProbe, Status: selfmon.StatusWarn, Limit: 50})
	require.NoError(t, err)
	hasPtraceArchWarn := false
	for _, w := range warns {
		if w.Action == "ptrace_arch_unsupported" {
			hasPtraceArchWarn = true
			break
		}
	}
	require.True(t, hasPtraceArchWarn, "selfmon must record ptrace_arch_unsupported warning")
}
