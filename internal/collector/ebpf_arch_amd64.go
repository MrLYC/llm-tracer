//go:build amd64

package collector

const (
	archName      = "amd64"
	archSupported = true
)

// archPtRegsOffsets maps Linux x86_64 struct pt_regs (uapi/asm/ptrace.h) and tracepoint offsets.
var archPtRegsOffsets = amd64PtRegsOffsets

// archCapabilities describes the eBPF probe/uretprobe capabilities on linux/amd64.
var archCapabilities = amd64ArchCapabilities

// scanReturnOffsets scans an x86_64 Go function body and returns relative byte offsets of RET (0xc3) instructions.
func scanReturnOffsets(code []byte) []uint64 {
	return scanAMD64ReturnOffsets(code)
}

// scanGoPrologueOffset returns the relative byte offset after Go's x86_64 stack-split prologue.
func scanGoPrologueOffset(code []byte) uint64 {
	return scanAMD64GoPrologueOffset(code)
}
