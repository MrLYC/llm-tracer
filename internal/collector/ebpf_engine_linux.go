//go:build linux

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/liuyicong/llm-tracer/internal/parser"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"golang.org/x/sys/unix"
)

// BPF instruction classes, opcodes, registers, and helper IDs (Linux kernel uapi/linux/bpf.h)
const (
	bpfLD    = 0x00
	bpfLDX   = 0x01
	bpfST    = 0x02
	bpfSTX   = 0x03
	bpfALU   = 0x04
	bpfJMP   = 0x05
	bpfALU64 = 0x07

	bpfW  = 0x00
	bpfH  = 0x08
	bpfB  = 0x10
	bpfDW = 0x18

	bpfIMM = 0x00
	bpfMEM = 0x60

	bpfADD  = 0x00
	bpfMOV  = 0xb0
	bpfRSH  = 0x70
	bpfLSH  = 0x60
	bpfOR   = 0x40
	bpfAND  = 0x50
	bpfK    = 0x00
	bpfX    = 0x08
	bpfJEQ  = 0x10
	bpfJGT  = 0x20
	bpfJGE  = 0x30
	bpfJSGT = 0x60
	bpfJSGE = 0x70
	bpfJLT  = 0xa0
	bpfJLE  = 0xb0
	bpfJSLE = 0xd0
	bpfCALL = 0x80
	bpfEXIT = 0x90

	bpfReg0  = 0
	bpfReg1  = 1
	bpfReg2  = 2
	bpfReg3  = 3
	bpfReg4  = 4
	bpfReg5  = 5
	bpfReg6  = 6
	bpfReg7  = 7
	bpfReg8  = 8
	bpfReg9  = 9
	bpfReg10 = 10 // Frame pointer

	bpfPseudoMapFD = 1

	bpfFuncMapLookupElem      = 1
	bpfFuncMapUpdateElem      = 2
	bpfFuncMapDeleteElem      = 3
	bpfFuncGetCurrentPidTgid  = 14
	bpfFuncProbeReadUser      = 112
	bpfFuncRingbufReserve     = 131
	bpfFuncRingbufSubmit      = 132

	bpfRingbufBusyBit    = 1 << 31
	bpfRingbufDiscardBit = 1 << 30
	bpfRingbufHdrSz      = 8

	ebpfMaxPayload = 4072
	ebpfEventSize  = 24 + ebpfMaxPayload // 4096 bytes
)

// BPFInsn represents a single 8-byte Linux eBPF instruction (struct bpf_insn).
type BPFInsn struct {
	Code   uint8
	DstSrc uint8
	Off    int16
	Imm    int32
}

func makeInsn(code uint8, dst, src uint8, off int16, imm int32) BPFInsn {
	return BPFInsn{
		Code:   code,
		DstSrc: (src << 4) | (dst & 0x0f),
		Off:    off,
		Imm:    imm,
	}
}

func bpfMov64Reg(dst, src uint8) BPFInsn {
	return makeInsn(bpfALU64|bpfMOV|bpfX, dst, src, 0, 0)
}

func bpfMov64Imm(dst uint8, imm int32) BPFInsn {
	return makeInsn(bpfALU64|bpfMOV|bpfK, dst, 0, 0, imm)
}

func bpfAdd64Imm(dst uint8, imm int32) BPFInsn {
	return makeInsn(bpfALU64|bpfADD|bpfK, dst, 0, 0, imm)
}

func bpfRsh64Imm(dst uint8, imm int32) BPFInsn {
	return makeInsn(bpfALU64|bpfRSH|bpfK, dst, 0, 0, imm)
}

func bpfLsh64Imm(dst uint8, imm int32) BPFInsn {
	return makeInsn(bpfALU64|bpfLSH|bpfK, dst, 0, 0, imm)
}

func bpfOr64Imm(dst uint8, imm int32) BPFInsn {
	return makeInsn(bpfALU64|bpfOR|bpfK, dst, 0, 0, imm)
}

func bpfOr64Reg(dst, src uint8) BPFInsn {
	return makeInsn(bpfALU64|bpfOR|bpfX, dst, src, 0, 0)
}

func bpfAnd64Imm(dst uint8, imm int32) BPFInsn {
	return makeInsn(bpfALU64|bpfAND|bpfK, dst, 0, 0, imm)
}

func bpfLdXMemDW(dst, src uint8, off int16) BPFInsn {
	return makeInsn(bpfLDX|bpfDW|bpfMEM, dst, src, off, 0)
}

func bpfLdXMemW(dst, src uint8, off int16) BPFInsn {
	return makeInsn(bpfLDX|bpfW|bpfMEM, dst, src, off, 0)
}

func bpfStXMemDW(dst, src uint8, off int16) BPFInsn {
	return makeInsn(bpfSTX|bpfDW|bpfMEM, dst, src, off, 0)
}

func bpfStXMemW(dst, src uint8, off int16) BPFInsn {
	return makeInsn(bpfSTX|bpfW|bpfMEM, dst, src, off, 0)
}

func bpfStMemW(dst uint8, off int16, imm int32) BPFInsn {
	return makeInsn(bpfST|bpfW|bpfMEM, dst, 0, off, imm)
}

func bpfLoadMapFD(dst uint8, mapFD int) []BPFInsn {
	return []BPFInsn{
		makeInsn(bpfLD|bpfDW|bpfIMM, dst, bpfPseudoMapFD, 0, int32(mapFD)),
		makeInsn(0, 0, 0, 0, 0),
	}
}

func bpfCall(helperID int32) BPFInsn {
	return makeInsn(bpfJMP|bpfCALL, 0, 0, 0, helperID)
}

func bpfJmpImm(op uint8, dst uint8, imm int32, off int16) BPFInsn {
	return makeInsn(bpfJMP|op|bpfK, dst, 0, off, imm)
}

func bpfExit() BPFInsn {
	return makeInsn(bpfJMP|bpfEXIT, 0, 0, 0, 0)
}

// patchExitJumps resolves any conditional jump with Off == -1 to land on the final `R0 = 0; exit` pair.
func patchExitJumps(insns []BPFInsn) []BPFInsn {
	exitTarget := len(insns) - 2
	for i := 0; i < len(insns); i++ {
		if insns[i].Code == (bpfLD | bpfDW | bpfIMM) {
			i++
			continue
		}
		if (insns[i].Code&0x07) == bpfJMP && insns[i].Off == -1 {
			insns[i].Off = int16(exitTarget - (i + 1))
		}
	}
	return insns
}

// appendSyscallHTTPFilter reads the first 4 bytes of user buffer R8 onto stack [fp-24] before reserving ringbuf space.
// Only HTTP requests/responses, SSE chunks, or JSON payloads on syscall tracepoints proceed to ringbuf reservation.
func appendSyscallHTTPFilter(insns []BPFInsn) []BPFInsn {
	return append(insns,
		bpfStMemW(bpfReg10, -24, 0),
		bpfMov64Reg(bpfReg1, bpfReg10),
		bpfAdd64Imm(bpfReg1, -24),
		bpfMov64Imm(bpfReg2, 4),
		bpfMov64Reg(bpfReg3, bpfReg8),
		bpfCall(bpfFuncProbeReadUser),
		bpfLdXMemW(bpfReg0, bpfReg10, -24),
		bpfJmpImm(bpfJEQ, bpfReg0, 0x54534f50, 8), // "POST"
		bpfJmpImm(bpfJEQ, bpfReg0, 0x20544547, 7), // "GET "
		bpfJmpImm(bpfJEQ, bpfReg0, 0x20545550, 6), // "PUT "
		bpfJmpImm(bpfJEQ, bpfReg0, 0x454c4544, 5), // "DELE"
		bpfJmpImm(bpfJEQ, bpfReg0, 0x50545448, 4), // "HTTP"
		bpfJmpImm(bpfJEQ, bpfReg0, 0x61746164, 3), // "data"
		bpfAnd64Imm(bpfReg0, 0xff),
		bpfJmpImm(bpfJEQ, bpfReg0, 0x7b, 1),      // '{'
		bpfJmpImm(bpfJGE, bpfReg9, 0, -1),        // non-HTTP syscall payload -> exit without reserving ringbuf
	)
}

// BuildWriteProbeProgram constructs a verifier-safe eBPF program that reads (conn_tag, buf_ptr, len)
// from pt_regs or tracepoint context, copies up to 4072 bytes via bpf_probe_read_user, and submits to RingBuf.
// For x86_64:
//   - OpenSSL uprobe (SSL_write):       connOff=112 (rdi), bufOff=104 (rsi), lenOff=96 (rdx), isSyscall=false
//   - GoTLS uprobe (Conn.Write ABI):    connOff=80  (rax), bufOff=40  (rbx), lenOff=88 (rcx), isSyscall=false
//   - Tracepoint sys_enter_write/sendto: connOff=16 (fd),  bufOff=24  (buf), lenOff=32 (count), isSyscall=true
func BuildWriteProbeProgram(ringbufMapFD int, connOff, bufOff, lenOff int16, isSyscall bool) []BPFInsn {
	dirImm := int32(0) // 0 = DirWrite (uprobe)
	if isSyscall {
		dirImm = 2 // 2 = DirWrite (syscall tracepoint)
	}
	selfPID := int32(os.Getpid())
	var insns []BPFInsn
	// R6 = R1 (ctx); filter out selfPID in kernel space
	insns = append(insns,
		bpfMov64Reg(bpfReg6, bpfReg1),
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfRsh64Imm(bpfReg0, 32),
		bpfJmpImm(bpfJEQ, bpfReg0, selfPID, -1),
	)
	// R7 = *(u64 *)(R6 + connOff)
	insns = append(insns, bpfLdXMemDW(bpfReg7, bpfReg6, connOff))
	if isSyscall {
		// Ignore stdin/stdout/stderr (fd <= 2)
		insns = append(insns, bpfJmpImm(bpfJSLE, bpfReg7, 2, -1))
		insns = append(insns, bpfAnd64Imm(bpfReg7, 0xffff))
		insns = append(insns, bpfOr64Imm(bpfReg7, -0x80000000)) // 0x80000000 | fd
	}
	// R8 = *(u64 *)(R6 + bufOff)
	insns = append(insns, bpfLdXMemDW(bpfReg8, bpfReg6, bufOff))
	// R9 = *(u64 *)(R6 + lenOff)
	insns = append(insns, bpfLdXMemDW(bpfReg9, bpfReg6, lenOff))

	// Validate R8 != 0 and 0 < R9 <= 0x0fffffff (rejects both 64-bit and 32-bit negative values)
	insns = append(insns, bpfJmpImm(bpfJEQ, bpfReg8, 0, -1))
	insns = append(insns, bpfJmpImm(bpfJSLE, bpfReg9, 0, -1))
	insns = append(insns, bpfJmpImm(bpfJGT, bpfReg9, 0x0fffffff, -1))
	// Cap R9 to ebpfMaxPayload (4072)
	insns = append(insns, bpfJmpImm(bpfJLE, bpfReg9, ebpfMaxPayload, 1))
	insns = append(insns, bpfMov64Imm(bpfReg9, ebpfMaxPayload))
	if isSyscall {
		insns = appendSyscallHTTPFilter(insns)
	}

	// R0 = bpf_ringbuf_reserve(ringbufMapFD, ebpfEventSize, 0)
	insns = append(insns, bpfLoadMapFD(bpfReg1, ringbufMapFD)...)
	insns = append(insns,
		bpfMov64Imm(bpfReg2, ebpfEventSize),
		bpfMov64Imm(bpfReg3, 0),
		bpfCall(bpfFuncRingbufReserve),
		bpfJmpImm(bpfJEQ, bpfReg0, 0, -1),
		bpfMov64Reg(bpfReg6, bpfReg0), // R6 = reserved event pointer
	)

	// R0 = bpf_get_current_pid_tgid()
	insns = append(insns,
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfMov64Reg(bpfReg1, bpfReg0),
		bpfRsh64Imm(bpfReg1, 32), // R1 = pid (tgid)
		// Write 24-byte LLMT header into R6
		bpfStMemW(bpfReg6, 0, 0x4c4c4d54),
		bpfStXMemW(bpfReg6, bpfReg1, 4),
		bpfStXMemW(bpfReg6, bpfReg0, 8),
		bpfStXMemW(bpfReg6, bpfReg7, 12),
		bpfStMemW(bpfReg6, 16, dirImm),
		bpfStXMemW(bpfReg6, bpfReg9, 20),
	)

	// bpf_probe_read_user(R6 + 24, R9, R8)
	insns = append(insns,
		bpfMov64Reg(bpfReg1, bpfReg6),
		bpfAdd64Imm(bpfReg1, 24),
		bpfMov64Reg(bpfReg2, bpfReg9),
		bpfMov64Reg(bpfReg3, bpfReg8),
		bpfCall(bpfFuncProbeReadUser),
	)

	// bpf_ringbuf_submit(R6, 0)
	insns = append(insns,
		bpfMov64Reg(bpfReg1, bpfReg6),
		bpfMov64Imm(bpfReg2, 0),
		bpfCall(bpfFuncRingbufSubmit),
	)

	// exit: R0 = 0; exit
	insns = append(insns,
		bpfMov64Imm(bpfReg0, 0),
		bpfExit(),
	)
	return patchExitJumps(insns)
}

// BuildReadEnterProgram stashes {conn_tag, buf_ptr, len_ptr} (24 bytes) into activeReadMapFD keyed by pid_tgid.
// If lenPtrOff > 0 (e.g. SSL_read_ex where rcx at offset 88 holds size_t *readbytes), it records that pointer too.
func BuildReadEnterProgram(activeReadMapFD int, connOff, bufOff, lenPtrOff int16, isSyscall bool) []BPFInsn {
	selfPID := int32(os.Getpid())
	var insns []BPFInsn
	insns = append(insns,
		bpfMov64Reg(bpfReg6, bpfReg1),
		bpfLdXMemDW(bpfReg7, bpfReg6, connOff),
	)
	if isSyscall {
		insns = append(insns,
			bpfJmpImm(bpfJSLE, bpfReg7, 2, -1),
			bpfAnd64Imm(bpfReg7, 0xffff),
			bpfOr64Imm(bpfReg7, -0x80000000),
		)
	}
	if lenPtrOff > 0 {
		insns = append(insns, bpfLdXMemDW(bpfReg9, bpfReg6, lenPtrOff))
	} else {
		insns = append(insns, bpfMov64Imm(bpfReg9, 0))
	}
	insns = append(insns,
		bpfLdXMemDW(bpfReg8, bpfReg6, bufOff),
		bpfJmpImm(bpfJEQ, bpfReg8, 0, -1),
		// Stack: [fp-8] = pid_tgid, [fp-32] = conn_tag, [fp-24] = buf_ptr, [fp-16] = len_ptr
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfMov64Reg(bpfReg1, bpfReg0),
		bpfRsh64Imm(bpfReg1, 32),
		bpfJmpImm(bpfJEQ, bpfReg1, selfPID, -1),
		bpfStXMemDW(bpfReg10, bpfReg0, -8),
		bpfStXMemDW(bpfReg10, bpfReg7, -32),
		bpfStXMemDW(bpfReg10, bpfReg8, -24),
		bpfStXMemDW(bpfReg10, bpfReg9, -16),
	)
	insns = append(insns, bpfLoadMapFD(bpfReg1, activeReadMapFD)...)
	insns = append(insns,
		bpfMov64Reg(bpfReg2, bpfReg10),
		bpfAdd64Imm(bpfReg2, -8),
		bpfMov64Reg(bpfReg3, bpfReg10),
		bpfAdd64Imm(bpfReg3, -32),
		bpfMov64Imm(bpfReg4, 0),
		bpfCall(bpfFuncMapUpdateElem),
		bpfMov64Imm(bpfReg0, 0),
		bpfExit(),
	)
	return patchExitJumps(insns)
}

// BuildReadExitProgram looks up {conn_tag, buf_ptr, len_ptr} on uretprobe/sys_exit_read and emits received bytes to RingBuf.
func BuildReadExitProgram(ringbufMapFD, activeReadMapFD int, retOff int16, isSyscall bool) []BPFInsn {
	dirImm := int32(1) // 1 = DirRead (uretprobe)
	if isSyscall {
		dirImm = 3 // 3 = DirRead (syscall tracepoint)
	}
	selfPID := int32(os.Getpid())
	var insns []BPFInsn
	insns = append(insns,
		// R9 = return value (bytes read for SSL_read/read, or 1 for SSL_read_ex)
		bpfLdXMemDW(bpfReg9, bpfReg1, retOff),
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfMov64Reg(bpfReg1, bpfReg0),
		bpfRsh64Imm(bpfReg1, 32),
		bpfJmpImm(bpfJEQ, bpfReg1, selfPID, -1),
		bpfStXMemDW(bpfReg10, bpfReg0, -8),
	)
	// R0 = bpf_map_lookup_elem(activeReadMapFD, fp-8)
	insns = append(insns, bpfLoadMapFD(bpfReg1, activeReadMapFD)...)
	insns = append(insns,
		bpfMov64Reg(bpfReg2, bpfReg10),
		bpfAdd64Imm(bpfReg2, -8),
		bpfCall(bpfFuncMapLookupElem),
		bpfJmpImm(bpfJEQ, bpfReg0, 0, -1),
		// Save conn_tag (R7), buf_ptr (R8), and len_ptr (R6) before deleting map entry
		bpfLdXMemDW(bpfReg7, bpfReg0, 0),
		bpfLdXMemDW(bpfReg8, bpfReg0, 8),
		bpfLdXMemDW(bpfReg6, bpfReg0, 16),
	)
	// bpf_map_delete_elem(activeReadMapFD, fp-8)
	insns = append(insns, bpfLoadMapFD(bpfReg1, activeReadMapFD)...)
	insns = append(insns,
		bpfMov64Reg(bpfReg2, bpfReg10),
		bpfAdd64Imm(bpfReg2, -8),
		bpfCall(bpfFuncMapDeleteElem),
		// Check 0 < R9 <= 0x0fffffff (rejects both 64-bit and 32-bit negative return codes like -1/0xffffffff)
		bpfJmpImm(bpfJSLE, bpfReg9, 0, -1),
		bpfJmpImm(bpfJGT, bpfReg9, 0x0fffffff, -1),
		// If R6 (len_ptr from SSL_read_ex) != 0, dereference *readbytes into R9!
		bpfJmpImm(bpfJEQ, bpfReg6, 0, 8),
		bpfStMemW(bpfReg10, -16, 0),
		bpfStMemW(bpfReg10, -12, 0),
		bpfMov64Reg(bpfReg1, bpfReg10),
		bpfAdd64Imm(bpfReg1, -16),
		bpfMov64Imm(bpfReg2, 8),
		bpfMov64Reg(bpfReg3, bpfReg6),
		bpfCall(bpfFuncProbeReadUser),
		bpfLdXMemDW(bpfReg9, bpfReg10, -16),
		bpfJmpImm(bpfJSLE, bpfReg9, 0, -1),
		bpfJmpImm(bpfJGT, bpfReg9, 0x0fffffff, -1),
		bpfJmpImm(bpfJLE, bpfReg9, ebpfMaxPayload, 1),
		bpfMov64Imm(bpfReg9, ebpfMaxPayload),
	)
	if isSyscall {
		insns = appendSyscallHTTPFilter(insns)
	}
	// Reserve ringbuf
	insns = append(insns, bpfLoadMapFD(bpfReg1, ringbufMapFD)...)
	insns = append(insns,
		bpfMov64Imm(bpfReg2, ebpfEventSize),
		bpfMov64Imm(bpfReg3, 0),
		bpfCall(bpfFuncRingbufReserve),
		bpfJmpImm(bpfJEQ, bpfReg0, 0, -1),
		bpfMov64Reg(bpfReg6, bpfReg0),
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfMov64Reg(bpfReg1, bpfReg0),
		bpfRsh64Imm(bpfReg1, 32),
		bpfStMemW(bpfReg6, 0, 0x4c4c4d54),
		bpfStXMemW(bpfReg6, bpfReg1, 4),
		bpfStXMemW(bpfReg6, bpfReg0, 8),
		bpfStXMemW(bpfReg6, bpfReg7, 12),
		bpfStMemW(bpfReg6, 16, dirImm),
		bpfStXMemW(bpfReg6, bpfReg9, 20),
		bpfMov64Reg(bpfReg1, bpfReg6),
		bpfAdd64Imm(bpfReg1, 24),
		bpfMov64Reg(bpfReg2, bpfReg9),
		bpfMov64Reg(bpfReg3, bpfReg8),
		bpfCall(bpfFuncProbeReadUser),
		bpfMov64Reg(bpfReg1, bpfReg6),
		bpfMov64Imm(bpfReg2, 0),
		bpfCall(bpfFuncRingbufSubmit),
		bpfMov64Imm(bpfReg0, 0),
		bpfExit(),
	)
	return patchExitJumps(insns)
}

// BuildWritevProbeProgram constructs a verifier-safe eBPF tracepoint program for `syscalls/sys_enter_writev(fd, vec, vlen)`
// that unrolls and captures up to 2 scatter-gather `struct iovec { void *base; size_t len; }` segments (e.g. HTTP Header + Body in Bun/uSockets).
func BuildWritevProbeProgram(ringbufMapFD int) []BPFInsn {
	selfPID := int32(os.Getpid())
	var insns []BPFInsn
	// R6 = R1 (tracepoint ctx); filter out selfPID in kernel space
	insns = append(insns,
		bpfMov64Reg(bpfReg6, bpfReg1),
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfRsh64Imm(bpfReg0, 32),
		bpfJmpImm(bpfJEQ, bpfReg0, selfPID, -1),
		bpfLdXMemDW(bpfReg7, bpfReg6, 16), // fd
		bpfJmpImm(bpfJSLE, bpfReg7, 2, -1),
		bpfAnd64Imm(bpfReg7, 0xffff),
		bpfOr64Imm(bpfReg7, -0x80000000),
		bpfLdXMemDW(bpfReg8, bpfReg6, 24), // const struct iovec *vec
		bpfJmpImm(bpfJEQ, bpfReg8, 0, -1),
		bpfLdXMemDW(bpfReg9, bpfReg6, 32), // vlen
		bpfJmpImm(bpfJSLE, bpfReg9, 0, -1),
		// Zero-init 32 bytes on stack [fp-32 .. fp-1] for iov[0] and iov[1]
		bpfStMemW(bpfReg10, -32, 0),
		bpfStMemW(bpfReg10, -28, 0),
		bpfStMemW(bpfReg10, -24, 0),
		bpfStMemW(bpfReg10, -20, 0),
		bpfStMemW(bpfReg10, -16, 0),
		bpfStMemW(bpfReg10, -12, 0),
		bpfStMemW(bpfReg10, -8, 0),
		bpfStMemW(bpfReg10, -4, 0),
		// bpf_probe_read_user(fp-32, 16, vec) -> iov[0]
		bpfMov64Reg(bpfReg1, bpfReg10),
		bpfAdd64Imm(bpfReg1, -32),
		bpfMov64Imm(bpfReg2, 16),
		bpfMov64Reg(bpfReg3, bpfReg8),
		bpfCall(bpfFuncProbeReadUser),
		// If vlen >= 2, bpf_probe_read_user(fp-16, 16, vec + 16) -> iov[1]
		bpfJmpImm(bpfJLT, bpfReg9, 2, 6),
		bpfMov64Reg(bpfReg1, bpfReg10),
		bpfAdd64Imm(bpfReg1, -16),
		bpfMov64Imm(bpfReg2, 16),
		bpfMov64Reg(bpfReg3, bpfReg8),
		bpfAdd64Imm(bpfReg3, 16),
		bpfCall(bpfFuncProbeReadUser),
	)

	// Emit iov[0] ([fp-32]=base0, [fp-24]=len0) and iov[1] ([fp-16]=base1, [fp-8]=len1)
	for _, slot := range []struct {
		baseOff int16
		lenOff  int16
	}{
		{-32, -24},
		{-16, -8},
	} {
		insns = append(insns,
			bpfLdXMemDW(bpfReg8, bpfReg10, slot.baseOff),
			bpfLdXMemDW(bpfReg9, bpfReg10, slot.lenOff),
			bpfJmpImm(bpfJEQ, bpfReg8, 0, -1),
			bpfJmpImm(bpfJSLE, bpfReg9, 0, -1),
			bpfJmpImm(bpfJGT, bpfReg9, 0x0fffffff, -1),
			bpfJmpImm(bpfJLE, bpfReg9, ebpfMaxPayload, 1),
			bpfMov64Imm(bpfReg9, ebpfMaxPayload),
		)
		insns = append(insns, bpfLoadMapFD(bpfReg1, ringbufMapFD)...)
		insns = append(insns,
			bpfMov64Imm(bpfReg2, ebpfEventSize),
			bpfMov64Imm(bpfReg3, 0),
			bpfCall(bpfFuncRingbufReserve),
			bpfJmpImm(bpfJEQ, bpfReg0, 0, -1),
			bpfMov64Reg(bpfReg6, bpfReg0),
			bpfCall(bpfFuncGetCurrentPidTgid),
			bpfMov64Reg(bpfReg1, bpfReg0),
			bpfRsh64Imm(bpfReg1, 32),
			bpfStMemW(bpfReg6, 0, 0x4c4c4d54),
			bpfStXMemW(bpfReg6, bpfReg1, 4),
			bpfStXMemW(bpfReg6, bpfReg0, 8),
			bpfStXMemW(bpfReg6, bpfReg7, 12),
			bpfStMemW(bpfReg6, 16, 2), // dir = 2 (DirWrite syscall tracepoint)
			bpfStXMemW(bpfReg6, bpfReg9, 20),
			bpfMov64Reg(bpfReg1, bpfReg6),
			bpfAdd64Imm(bpfReg1, 24),
			bpfMov64Reg(bpfReg2, bpfReg9),
			bpfMov64Reg(bpfReg3, bpfReg8),
			bpfCall(bpfFuncProbeReadUser),
			bpfMov64Reg(bpfReg1, bpfReg6),
			bpfMov64Imm(bpfReg2, 0),
			bpfCall(bpfFuncRingbufSubmit),
		)
	}

	insns = append(insns,
		bpfMov64Imm(bpfReg0, 0),
		bpfExit(),
	)
	return patchExitJumps(insns)
}

// BuildGoTLSReadEnterProgram stashes {conn_tag (RAX), buf_ptr (RBX), 0} into activeReadMapFD
// keyed by `(pid << 32) | uint32(R14)` (where R14 is the Go goroutine `g` pointer on linux/amd64).
func BuildGoTLSReadEnterProgram(activeReadMapFD int) []BPFInsn {
	var insns []BPFInsn
	insns = append(insns,
		bpfMov64Reg(bpfReg6, bpfReg1),
		bpfLdXMemDW(bpfReg7, bpfReg6, 80), // RAX = c *tls.Conn
		bpfLdXMemDW(bpfReg8, bpfReg6, 40), // RBX = b.ptr
		bpfJmpImm(bpfJEQ, bpfReg8, 0, -1),
		bpfMov64Imm(bpfReg9, 0),
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfRsh64Imm(bpfReg0, 32),
		bpfLsh64Imm(bpfReg0, 32),
		bpfLdXMemW(bpfReg1, bpfReg6, 8), // uint32(pt_regs->r14) = goroutine pointer g
		bpfOr64Reg(bpfReg0, bpfReg1),
		bpfStXMemDW(bpfReg10, bpfReg0, -8),
		bpfStXMemDW(bpfReg10, bpfReg7, -32),
		bpfStXMemDW(bpfReg10, bpfReg8, -24),
		bpfStXMemDW(bpfReg10, bpfReg9, -16),
	)
	insns = append(insns, bpfLoadMapFD(bpfReg1, activeReadMapFD)...)
	insns = append(insns,
		bpfMov64Reg(bpfReg2, bpfReg10),
		bpfAdd64Imm(bpfReg2, -8),
		bpfMov64Reg(bpfReg3, bpfReg10),
		bpfAdd64Imm(bpfReg3, -32),
		bpfMov64Imm(bpfReg4, 0),
		bpfCall(bpfFuncMapUpdateElem),
		bpfMov64Imm(bpfReg0, 0),
		bpfExit(),
	)
	return patchExitJumps(insns)
}

// BuildGoTLSReadExitProgram is attached as a regular uprobe at `ret` (0xc3) instructions inside
// `crypto/tls.(*Conn).Read`, reading return count `n` from RAX (offset 80) and looking up the buffer by `(pid << 32) | uint32(R14)`.
func BuildGoTLSReadExitProgram(ringbufMapFD, activeReadMapFD int) []BPFInsn {
	var insns []BPFInsn
	insns = append(insns,
		bpfMov64Reg(bpfReg6, bpfReg1),
		bpfLdXMemDW(bpfReg9, bpfReg6, 80), // RAX = n (bytes read)
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfRsh64Imm(bpfReg0, 32),
		bpfLsh64Imm(bpfReg0, 32),
		bpfLdXMemW(bpfReg1, bpfReg6, 8), // uint32(pt_regs->r14)
		bpfOr64Reg(bpfReg0, bpfReg1),
		bpfStXMemDW(bpfReg10, bpfReg0, -8),
	)
	insns = append(insns, bpfLoadMapFD(bpfReg1, activeReadMapFD)...)
	insns = append(insns,
		bpfMov64Reg(bpfReg2, bpfReg10),
		bpfAdd64Imm(bpfReg2, -8),
		bpfCall(bpfFuncMapLookupElem),
		bpfJmpImm(bpfJEQ, bpfReg0, 0, -1),
		bpfLdXMemDW(bpfReg7, bpfReg0, 0),
		bpfLdXMemDW(bpfReg8, bpfReg0, 8),
	)
	insns = append(insns, bpfLoadMapFD(bpfReg1, activeReadMapFD)...)
	insns = append(insns,
		bpfMov64Reg(bpfReg2, bpfReg10),
		bpfAdd64Imm(bpfReg2, -8),
		bpfCall(bpfFuncMapDeleteElem),
		bpfJmpImm(bpfJSLE, bpfReg9, 0, -1),
		bpfJmpImm(bpfJGT, bpfReg9, 0x0fffffff, -1),
		bpfJmpImm(bpfJLE, bpfReg9, ebpfMaxPayload, 1),
		bpfMov64Imm(bpfReg9, ebpfMaxPayload),
	)
	insns = append(insns, bpfLoadMapFD(bpfReg1, ringbufMapFD)...)
	insns = append(insns,
		bpfMov64Imm(bpfReg2, ebpfEventSize),
		bpfMov64Imm(bpfReg3, 0),
		bpfCall(bpfFuncRingbufReserve),
		bpfJmpImm(bpfJEQ, bpfReg0, 0, -1),
		bpfMov64Reg(bpfReg6, bpfReg0),
		bpfCall(bpfFuncGetCurrentPidTgid),
		bpfMov64Reg(bpfReg1, bpfReg0),
		bpfRsh64Imm(bpfReg1, 32),
		bpfStMemW(bpfReg6, 0, 0x4c4c4d54),
		bpfStXMemW(bpfReg6, bpfReg1, 4),
		bpfStXMemW(bpfReg6, bpfReg0, 8),
		bpfStXMemW(bpfReg6, bpfReg7, 12),
		bpfStMemW(bpfReg6, 16, 1), // dir = 1 (DirRead uprobe)
		bpfStXMemW(bpfReg6, bpfReg9, 20),
		bpfMov64Reg(bpfReg1, bpfReg6),
		bpfAdd64Imm(bpfReg1, 24),
		bpfMov64Reg(bpfReg2, bpfReg9),
		bpfMov64Reg(bpfReg3, bpfReg8),
		bpfCall(bpfFuncProbeReadUser),
		bpfMov64Reg(bpfReg1, bpfReg6),
		bpfMov64Imm(bpfReg2, 0),
		bpfCall(bpfFuncRingbufSubmit),
		bpfMov64Imm(bpfReg0, 0),
		bpfExit(),
	)
	return patchExitJumps(insns)
}

// Kernel structs for SYS_BPF
type bpfMapCreateAttr struct {
	MapType    uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

type bpfProgLoadAttr struct {
	ProgType    uint32
	InsnCnt     uint32
	Insns       uint64
	License     uint64
	LogLevel    uint32
	LogSize     uint32
	LogBuf      uint64
	KernVersion uint32
	ProgFlags   uint32
	ProgName    [16]byte
}

func bpfCreateMap(mapType, keySize, valueSize, maxEntries uint32) (int, error) {
	attr := bpfMapCreateAttr{
		MapType:    mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_MAP_CREATE, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func bpfLoadProgram(progType uint32, name string, insns []BPFInsn) (int, string, error) {
	if len(insns) == 0 {
		return -1, "", fmt.Errorf("empty bpf program")
	}
	lic := []byte("GPL\x00")
	logBuf := make([]byte, 65536)
	var attr bpfProgLoadAttr
	attr.ProgType = progType
	attr.InsnCnt = uint32(len(insns))
	attr.Insns = uint64(uintptr(unsafe.Pointer(&insns[0])))
	attr.License = uint64(uintptr(unsafe.Pointer(&lic[0])))
	attr.LogLevel = 1
	attr.LogSize = uint32(len(logBuf))
	attr.LogBuf = uint64(uintptr(unsafe.Pointer(&logBuf[0])))
	copy(attr.ProgName[:], name)

	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	verifierLog := strings.TrimRight(string(logBuf), "\x00")
	if errno != 0 {
		return -1, verifierLog, fmt.Errorf("BPF_PROG_LOAD(%s): %w (%s)", name, errno, verifierLog)
	}
	return int(fd), verifierLog, nil
}

// EBPFEngine manages kernel eBPF maps, uprobes/uretprobes, syscall tracepoints, and the mmap RingBuf consumer.
type EBPFEngine struct {
	mu                 sync.Mutex
	ringMu             sync.Mutex
	ringMapFD          int
	activeSSLReadFD    int
	activeSysReadFD    int
	sslWriteProg       int
	sslReadEnterProg   int
	sslReadExEnterProg int
	sslReadExitProg    int
	goTLSWriteProg     int
	goTLSReadEnterProg int
	goTLSReadExitProg  int
	progFDs            []int
	perfFDs            []int
	attachedKeys       map[string]bool
	ringMaxBytes       int
	consMmap           []byte
	prodMmap           []byte
	uprobeCount        int
	tracepointCount    int
	attachedCount      int
	stopCh             chan struct{}
	stopOnce           sync.Once
	mon                *selfmon.Monitor
	onEvent            func(pid, tid int, connID string, dir parser.Direction, payload []byte, mode string)
}

func StartEBPFEngine(
	targets []ProbeTarget,
	mon *selfmon.Monitor,
	onEvent func(pid, tid int, connID string, dir parser.Direction, payload []byte, mode string),
) (*EBPFEngine, error) {
	if runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("ebpf engine currently targets linux/amd64")
	}
	// Raise RLIMIT_MEMLOCK for kernels < 5.11 if permitted
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})

	ringBytes := 16 << 20 // 16 MiB ring buffer (~4072 max-sized 4 KiB events)
	ringFD, err := bpfCreateMap(unix.BPF_MAP_TYPE_RINGBUF, 0, 0, uint32(ringBytes))
	if err != nil {
		return nil, fmt.Errorf("create ringbuf map: %w", err)
	}
	sslReadMapFD, err := bpfCreateMap(unix.BPF_MAP_TYPE_LRU_HASH, 8, 24, 16384)
	if err != nil {
		sslReadMapFD, err = bpfCreateMap(unix.BPF_MAP_TYPE_HASH, 8, 24, 16384)
	}
	if err != nil {
		_ = unix.Close(ringFD)
		return nil, fmt.Errorf("create active_ssl_read hash map: %w", err)
	}
	sysReadMapFD, err := bpfCreateMap(unix.BPF_MAP_TYPE_LRU_HASH, 8, 24, 16384)
	if err != nil {
		sysReadMapFD, err = bpfCreateMap(unix.BPF_MAP_TYPE_HASH, 8, 24, 16384)
	}
	if err != nil {
		_ = unix.Close(ringFD)
		_ = unix.Close(sslReadMapFD)
		return nil, fmt.Errorf("create active_sys_read hash map: %w", err)
	}

	pageSize := os.Getpagesize()
	consMmap, err := unix.Mmap(ringFD, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Close(ringFD)
		_ = unix.Close(sslReadMapFD)
		_ = unix.Close(sysReadMapFD)
		return nil, fmt.Errorf("mmap ringbuf consumer page: %w", err)
	}
	prodMmap, err := unix.Mmap(ringFD, int64(pageSize), pageSize+2*ringBytes, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(consMmap)
		_ = unix.Close(ringFD)
		_ = unix.Close(sslReadMapFD)
		_ = unix.Close(sysReadMapFD)
		return nil, fmt.Errorf("mmap ringbuf producer+data pages: %w", err)
	}

	eng := &EBPFEngine{
		ringMapFD:          ringFD,
		activeSSLReadFD:    sslReadMapFD,
		activeSysReadFD:    sysReadMapFD,
		sslWriteProg:       -1,
		sslReadEnterProg:   -1,
		sslReadExEnterProg: -1,
		sslReadExitProg:    -1,
		goTLSWriteProg:     -1,
		goTLSReadEnterProg: -1,
		goTLSReadExitProg:  -1,
		attachedKeys:       make(map[string]bool),
		ringMaxBytes:       ringBytes,
		consMmap:           consMmap,
		prodMmap:           prodMmap,
		stopCh:             make(chan struct{}),
		mon:                mon,
		onEvent:            onEvent,
	}

	// 1. Load & attach Uprobes/Uretprobes for OpenSSL / Static-OpenSSL / GoTLS targets
	if err := eng.attachUprobeTargets(targets); err != nil && mon != nil {
		mon.RecordWarn(selfmon.StageProbe, "ebpf_attach_uprobes", err.Error(), nil)
	}

	// 2. Load & attach Syscall Tracepoints (sys_enter_write, sys_enter_read, sys_exit_read)
	if err := eng.attachSyscallTracepoints(); err != nil && mon != nil {
		mon.RecordWarn(selfmon.StageProbe, "ebpf_attach_tracepoints", err.Error(), nil)
	}

	go eng.consumeRingBufLoop()
	return eng, nil
}

func (e *EBPFEngine) Active() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attachedCount > 0
}

func (e *EBPFEngine) AttachedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attachedCount
}

func (e *EBPFEngine) UprobeCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.uprobeCount
}

func (e *EBPFEngine) TracepointCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tracepointCount
}

func (e *EBPFEngine) Close() {
	e.stopOnce.Do(func() {
		close(e.stopCh)
		e.Flush()
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, fd := range e.perfFDs {
			_ = unix.Close(fd)
		}
		for _, fd := range e.progFDs {
			_ = unix.Close(fd)
		}
		if e.consMmap != nil {
			_ = unix.Munmap(e.consMmap)
		}
		if e.prodMmap != nil {
			_ = unix.Munmap(e.prodMmap)
		}
		if e.ringMapFD >= 0 {
			_ = unix.Close(e.ringMapFD)
		}
		if e.activeSSLReadFD >= 0 {
			_ = unix.Close(e.activeSSLReadFD)
		}
		if e.activeSysReadFD >= 0 {
			_ = unix.Close(e.activeSysReadFD)
		}
	})
}

func (e *EBPFEngine) attachUprobeTargets(targets []ProbeTarget) error {
	sslWriteProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_ssl_write",
		BuildWriteProbeProgram(e.ringMapFD, 112, 104, 96, false))
	if err != nil {
		return err
	}
	e.sslWriteProg = sslWriteProg
	e.progFDs = append(e.progFDs, sslWriteProg)

	sslReadEnterProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_ssl_r_ent",
		BuildReadEnterProgram(e.activeSSLReadFD, 112, 104, 0, false))
	if err != nil {
		return err
	}
	e.sslReadEnterProg = sslReadEnterProg
	e.progFDs = append(e.progFDs, sslReadEnterProg)

	sslReadExEnterProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_ssl_rx_en",
		BuildReadEnterProgram(e.activeSSLReadFD, 112, 104, 88, false))
	if err != nil {
		return err
	}
	e.sslReadExEnterProg = sslReadExEnterProg
	e.progFDs = append(e.progFDs, sslReadExEnterProg)

	sslReadExitProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_ssl_r_ext",
		BuildReadExitProgram(e.ringMapFD, e.activeSSLReadFD, 80, false))
	if err != nil {
		return err
	}
	e.sslReadExitProg = sslReadExitProg
	e.progFDs = append(e.progFDs, sslReadExitProg)

	goTLSWriteProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_gotls_w",
		BuildWriteProbeProgram(e.ringMapFD, 80, 40, 88, false))
	if err == nil {
		e.goTLSWriteProg = goTLSWriteProg
		e.progFDs = append(e.progFDs, goTLSWriteProg)
	}

	if goTLSReadEnterProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_gotls_re",
		BuildGoTLSReadEnterProgram(e.activeSSLReadFD)); err == nil {
		e.goTLSReadEnterProg = goTLSReadEnterProg
		e.progFDs = append(e.progFDs, goTLSReadEnterProg)
	}

	if goTLSReadExitProg, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_KPROBE, "llmt_gotls_rx",
		BuildGoTLSReadExitProgram(e.ringMapFD, e.activeSSLReadFD)); err == nil {
		e.goTLSReadExitProg = goTLSReadExitProg
		e.progFDs = append(e.progFDs, goTLSReadExitProg)
	}

	e.AttachTargets(targets)
	return nil
}

// AttachTargets dynamically attaches kernel uprobes/uretprobes to newly discovered OpenSSL, Static-OpenSSL,
// or GoTLS binaries (deduplicated by binaryPath + offset + retprobe).
func (e *EBPFEngine) AttachTargets(targets []ProbeTarget) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.attachedKeys == nil {
		e.attachedKeys = make(map[string]bool)
	}
	added := 0
	tryAttach := func(binPath string, off uint64, isRet bool, progFD int) {
		if progFD < 0 || off == 0 || binPath == "" {
			return
		}
		key := fmt.Sprintf("%s:%d:%v:%d", binPath, off, isRet, progFD)
		if e.attachedKeys[key] {
			return
		}
		if pfds, err := openAndAttachUprobe(binPath, off, isRet, progFD); err == nil && len(pfds) > 0 {
			e.attachedKeys[key] = true
			e.perfFDs = append(e.perfFDs, pfds...)
			e.uprobeCount++
			e.attachedCount++
			added++
		}
	}

	for _, t := range targets {
		if t.Type == "openssl" || t.Type == "static_openssl" {
			for _, wSym := range []string{"SSL_write", "SSL_write_ex"} {
				if off, ok := t.Symbols[wSym]; ok && off > 0 {
					tryAttach(t.BinaryPath, off, false, e.sslWriteProg)
				}
			}
			if off, ok := t.Symbols["SSL_read"]; ok && off > 0 {
				tryAttach(t.BinaryPath, off, false, e.sslReadEnterProg)
				tryAttach(t.BinaryPath, off, true, e.sslReadExitProg)
			}
			if off, ok := t.Symbols["SSL_read_ex"]; ok && off > 0 {
				tryAttach(t.BinaryPath, off, false, e.sslReadExEnterProg)
				tryAttach(t.BinaryPath, off, true, e.sslReadExitProg)
			}
		} else if t.Type == "gotls" {
			if off, ok := t.Symbols["crypto/tls.(*Conn).Write"]; ok && off > 0 {
				tryAttach(t.BinaryPath, off, false, e.goTLSWriteProg)
			}
			if off, ok := t.Symbols["crypto/tls.(*Conn).Read"]; ok && off > 0 {
				tryAttach(t.BinaryPath, off, false, e.goTLSReadEnterProg)
				for _, retOff := range t.GoTLSReadRetOffsets {
					tryAttach(t.BinaryPath, retOff, false, e.goTLSReadExitProg)
				}
			}
		}
	}
	return added
}

func (e *EBPFEngine) attachSyscallTracepoints() error {
	specs := []struct {
		tpName   string
		progName string
		insns    []BPFInsn
		required bool
	}{
		{"syscalls/sys_enter_write", "llmt_tp_write", BuildWriteProbeProgram(e.ringMapFD, 16, 24, 32, true), true},
		{"syscalls/sys_enter_sendto", "llmt_tp_sendto", BuildWriteProbeProgram(e.ringMapFD, 16, 24, 32, true), false},
		{"syscalls/sys_enter_writev", "llmt_tp_writev", BuildWritevProbeProgram(e.ringMapFD), false},
		{"syscalls/sys_enter_read", "llmt_tp_r_ent", BuildReadEnterProgram(e.activeSysReadFD, 16, 24, 0, true), true},
		{"syscalls/sys_enter_recvfrom", "llmt_tp_rf_ent", BuildReadEnterProgram(e.activeSysReadFD, 16, 24, 0, true), false},
		{"syscalls/sys_exit_read", "llmt_tp_r_ext", BuildReadExitProgram(e.ringMapFD, e.activeSysReadFD, 16, true), true},
		{"syscalls/sys_exit_recvfrom", "llmt_tp_rf_ext", BuildReadExitProgram(e.ringMapFD, e.activeSysReadFD, 16, true), false},
	}

	for _, sp := range specs {
		progFD, _, err := bpfLoadProgram(unix.BPF_PROG_TYPE_TRACEPOINT, sp.progName, sp.insns)
		if err != nil {
			if sp.required {
				return err
			}
			continue
		}
		e.progFDs = append(e.progFDs, progFD)
		if pfds, err := openAndAttachTracepoint(sp.tpName, progFD); err == nil && len(pfds) > 0 {
			e.perfFDs = append(e.perfFDs, pfds...)
			e.tracepointCount++
			e.attachedCount++
		}
	}
	return nil
}

func onlineCPUs() []int {
	if raw, err := os.ReadFile("/sys/devices/system/cpu/online"); err == nil {
		var cpus []int
		for _, part := range strings.Split(strings.TrimSpace(string(raw)), ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if dash := strings.IndexByte(part, '-'); dash > 0 {
				lo, err1 := strconv.Atoi(part[:dash])
				hi, err2 := strconv.Atoi(part[dash+1:])
				if err1 == nil && err2 == nil && hi >= lo {
					for c := lo; c <= hi; c++ {
						cpus = append(cpus, c)
					}
				}
			} else if c, err := strconv.Atoi(part); err == nil {
				cpus = append(cpus, c)
			}
		}
		if len(cpus) > 0 {
			return cpus
		}
	}
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	cpus := make([]int, n)
	for i := 0; i < n; i++ {
		cpus[i] = i
	}
	return cpus
}

func openAndAttachUprobe(binaryPath string, offset uint64, isRetprobe bool, progFD int) ([]int, error) {
	pmuBytes, err := os.ReadFile("/sys/bus/event_source/devices/uprobe/type")
	if err != nil {
		return nil, err
	}
	pmuType, err := strconv.Atoi(strings.TrimSpace(string(pmuBytes)))
	if err != nil {
		return nil, err
	}
	cPath, err := unix.BytePtrFromString(binaryPath)
	if err != nil {
		return nil, err
	}
	var fds []int
	var lastErr error
	for _, cpu := range onlineCPUs() {
		attr := unix.PerfEventAttr{
			Type:   uint32(pmuType),
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Ext1:   uint64(uintptr(unsafe.Pointer(cPath))),
			Ext2:   offset,
			Sample: 1,
			Wakeup: 1,
		}
		if isRetprobe {
			attr.Config = 1 // format/retprobe = config:0
		}
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			lastErr = err
			continue
		}
		// Note: event->tp_event->prog_array is shared across CPUs for the same trace_event_call.
		// CPU 0 adds progFD to prog_array; subsequent CPUs return EEXIST, which must keep fd open & enabled.
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, progFD); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			lastErr = err
			continue
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			_ = unix.Close(fd)
			lastErr = err
			continue
		}
		fds = append(fds, fd)
	}
	runtime.KeepAlive(cPath)
	if len(fds) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("failed to attach uprobe %s on any CPU", binaryPath)
	}
	return fds, nil
}

func openAndAttachTracepoint(tpSubpath string, progFD int) ([]int, error) {
	var idBytes []byte
	var err error
	for _, base := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		idBytes, err = os.ReadFile(filepath.Join(base, tpSubpath, "id"))
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	tpID, err := strconv.ParseUint(strings.TrimSpace(string(idBytes)), 10, 64)
	if err != nil {
		return nil, err
	}
	var fds []int
	var lastErr error
	for _, cpu := range onlineCPUs() {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_TRACEPOINT,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Config: tpID,
			Sample: 1,
			Wakeup: 1,
		}
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			lastErr = err
			continue
		}
		// Keep per-CPU perf_event open and enabled even when prog_array already contains progFD (EEXIST),
		// ensuring per_cpu(swevent_htable, cpu).swevent_hlist remains allocated on every online CPU.
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, progFD); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			lastErr = err
			continue
		}
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			_ = unix.Close(fd)
			lastErr = err
			continue
		}
		fds = append(fds, fd)
	}
	if len(fds) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, fmt.Errorf("failed to attach tracepoint %s on any CPU", tpSubpath)
	}
	return fds, nil
}

// Flush synchronously drains all ready records from the mmap'd kernel BPF RingBuf.
func (e *EBPFEngine) Flush() {
	e.ringMu.Lock()
	defer e.ringMu.Unlock()
	if len(e.consMmap) < 8 || len(e.prodMmap) < 8 {
		return
	}
	pageSize := 4096
	if len(e.prodMmap) > os.Getpagesize() {
		pageSize = os.Getpagesize()
	}
	consPtr := (*uint64)(unsafe.Pointer(&e.consMmap[0]))
	prodPtr := (*uint64)(unsafe.Pointer(&e.prodMmap[0]))
	dataRing := e.prodMmap[pageSize:]
	mask := uint64(e.ringMaxBytes - 1)
	myPID := os.Getpid()

	consPos := atomic.LoadUint64(consPtr)
	prodPos := atomic.LoadUint64(prodPtr)
	for consPos < prodPos {
		off := consPos & mask
		hdrPtr := (*uint32)(unsafe.Pointer(&dataRing[off]))
		lenAndFlags := atomic.LoadUint32(hdrPtr)
		if lenAndFlags&uint32(bpfRingbufBusyBit) != 0 {
			break
		}
		recLen := lenAndFlags & ^uint32(bpfRingbufBusyBit|bpfRingbufDiscardBit)
		if lenAndFlags&uint32(bpfRingbufDiscardBit) == 0 && recLen >= 24 && int(off+bpfRingbufHdrSz+uint64(recLen)) <= len(dataRing) {
			raw := dataRing[off+bpfRingbufHdrSz : off+bpfRingbufHdrSz+uint64(recLen)]
			e.parseAndDispatchRecord(raw, myPID)
		}
		// Advance consumer position rounded up to 8-byte alignment
		step := (uint64(recLen) + bpfRingbufHdrSz + 7) & ^uint64(7)
		consPos += step
		atomic.StoreUint64(consPtr, consPos)
	}
}

func (e *EBPFEngine) consumeRingBufLoop() {
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.Flush()
		}
	}
}

func (e *EBPFEngine) parseAndDispatchRecord(raw []byte, selfPID int) {
	if len(raw) < 24 || e.onEvent == nil {
		return
	}
	magic := binary.NativeEndian.Uint32(raw[0:4])
	if magic != 0x4c4c4d54 {
		return
	}
	pid := int(binary.NativeEndian.Uint32(raw[4:8]))
	if pid <= 0 || pid == selfPID {
		return
	}
	tid := int(binary.NativeEndian.Uint32(raw[8:12]))
	connTag := binary.NativeEndian.Uint32(raw[12:16])
	dirVal := binary.NativeEndian.Uint32(raw[16:20])
	payloadLen := binary.NativeEndian.Uint32(raw[20:24])
	if payloadLen == 0 || payloadLen > ebpfMaxPayload || 24+int(payloadLen) > len(raw) {
		return
	}
	payload := make([]byte, payloadLen)
	copy(payload, raw[24:24+payloadLen])
	dir := parser.DirWrite
	if (dirVal & 1) != 0 {
		dir = parser.DirRead
	}
	mode := "ebpf_uprobe"
	connID := fmt.Sprintf("ebpf_tls_%x", connTag)
	if (dirVal & 2) != 0 {
		mode = "ebpf_tracepoint"
		connID = fmt.Sprintf("ebpf_fd_%x", connTag&0xffff)
		// Quickly ignore binary ELF/object/file chunks (containing NUL byte in first 32 bytes) on syscall tracepoints
		checkLen := len(payload)
		if checkLen > 32 {
			checkLen = 32
		}
		for i := 0; i < checkLen; i++ {
			if payload[i] == 0 {
				return
			}
		}
	}
	e.onEvent(pid, tid, connID, dir, payload, mode)
}

// TryAttachKernelUprobe attempts to open a Linux uprobe perf_event for the target symbol offset.
// If the current process lacks CAP_BPF/CAP_PERFMON/root, it returns a descriptive error without crashing.
func TryAttachKernelUprobe(binaryPath string, offset uint64) (int, error) {
	pmuTypeBytes, err := os.ReadFile("/sys/bus/event_source/devices/uprobe/type")
	if err != nil {
		return -1, fmt.Errorf("read uprobe pmu type: %w", err)
	}
	pmuType, err := strconv.Atoi(strings.TrimSpace(string(pmuTypeBytes)))
	if err != nil {
		return -1, fmt.Errorf("invalid uprobe pmu type: %w", err)
	}
	cPath, err := unix.BytePtrFromString(binaryPath)
	if err != nil {
		return -1, err
	}

	attr := unix.PerfEventAttr{
		Type:   uint32(pmuType),
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Ext1:   uint64(uintptr(unsafe.Pointer(cPath))),
		Ext2:   offset,
		Sample: 1,
		Wakeup: 1,
	}
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	runtime.KeepAlive(cPath)
	if err != nil {
		return -1, fmt.Errorf("perf_event_open uprobe on %s: %w", filepath.Base(binaryPath), err)
	}
	return fd, nil
}

func closeKernelFD(fd int) {
	_ = unix.Close(fd)
}
