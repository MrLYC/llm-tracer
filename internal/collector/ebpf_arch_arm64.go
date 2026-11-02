//go:build arm64

package collector

const (
	archName      = "arm64"
	archSupported = true
)

// archPtRegsOffsets maps Linux arm64 struct user_pt_regs (regs[0..30], sp, pc, pstate) and tracepoint offsets.
var archPtRegsOffsets = arm64PtRegsOffsets

// archCapabilities describes the eBPF probe/uretprobe capabilities and degradation boundaries on linux/arm64.
var archCapabilities = arm64ArchCapabilities

// scanReturnOffsets scans an arm64 Go function body for 4-byte aligned RET (0xd65f03c0) / RETAA / RETAB instructions.
func scanReturnOffsets(code []byte) []uint64 {
	return scanARM64ReturnOffsets(code)
}

// scanGoPrologueOffset returns the relative byte offset after Go's arm64 stack-split prologue.
func scanGoPrologueOffset(code []byte) uint64 {
	return scanARM64GoPrologueOffset(code)
}
