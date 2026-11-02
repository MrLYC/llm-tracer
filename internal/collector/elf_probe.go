package collector

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type ProbeTarget struct {
	BinaryPath          string            `json:"binary_path"`
	Type                string            `json:"type"` // openssl | static_openssl | gotls | static_pie | stripped_tls
	LinkMode            string            `json:"link_mode,omitempty"`
	GoVersion           string            `json:"go_version,omitempty"`
	Symbols             map[string]uint64 `json:"symbols"`
	GoTLSReadRetOffsets []uint64          `json:"gotls_read_ret_offsets,omitempty"`
	Attached            bool              `json:"attached"`
	Note                string            `json:"note,omitempty"`
}

type BinaryProfile struct {
	RequestedPath  string            `json:"requested_path"`
	ResolvedELF    string            `json:"resolved_elf"`
	LinkMode       string            `json:"link_mode"` // dynamic | static-pie
	TLSStack       string            `json:"tls_stack"` // dynamic-libssl | static-openssl | gotls | stripped-embedded-tls | static-custom
	GoVersion      string            `json:"go_version,omitempty"`
	RequiresPtrace bool              `json:"requires_ptrace"`
	Symbols        map[string]uint64 `json:"symbols,omitempty"`
}

// ebpfPtRegsOffsets defines byte offsets within the Linux kernel's struct pt_regs (amd64)
// or struct user_pt_regs (arm64: regs[0..30], sp, pc, pstate) for uprobe/uretprobe and tracepoint contexts.
type ebpfPtRegsOffsets struct {
	Regs   [31]int16
	SP     int16
	PC     int16
	PState int16

	// C ABI (System V AMD64 / AAPCS64) parameter & return offsets for OpenSSL uprobes/uretprobes
	CArg0 int16
	CArg1 int16
	CArg2 int16
	CArg3 int16
	CRet  int16

	// Go ABIInternal register offsets for GoTLS (crypto/tls.(*Conn).Write / Read)
	GoArg0      int16
	GoArg1      int16
	GoArg2      int16
	GoRet       int16
	GoGoroutine int16

	// Syscall tracepoint offsets (trace_event_raw_sys_enter / trace_event_raw_sys_exit)
	SyscallArg0 int16
	SyscallArg1 int16
	SyscallArg2 int16
	SyscallRet  int16
}

// ebpfArchCapabilities describes architecture-level eBPF uprobe/uretprobe/tracepoint support and degradation boundaries.
type ebpfArchCapabilities struct {
	Arch                        string
	Supported                   bool
	UprobeSupported             bool
	UretprobeSupported          bool // Kernel uretprobe feasibility for C ABI (OpenSSL SSL_read/SSL_read_ex)
	GoTLSUprobeSupported        bool // Go ABIInternal uprobe feasibility for GoTLS Write/Read entry
	GoTLSUretprobeSupported     bool // Kernel uretprobe feasibility on Go functions (false due to movable goroutine stacks)
	GoTLSRetScanSupported       bool // RET instruction offset scanning for GoTLS Read exit uprobes
	SyscallTracepointsSupported bool
	PtraceUserspaceSupported    bool
	DegradedFeatures            []string
	DegradationNotice           string
	UnsupportedReason           string
}

// ARM64 A64 return instruction encodings (little-endian 32-bit words).
const (
	arm64InsnRet     uint32 = 0xd65f03c0 // RET (X30)
	arm64InsnRetMask uint32 = 0xfffffc1f // Mask for RET Xn (1101011001011111000000nnnnn00000)
	arm64InsnRetBase uint32 = 0xd65f0000 // Base opcode for RET Xn
	arm64InsnRetAA   uint32 = 0xd65f0bff // RETAA (Pointer Authentication)
	arm64InsnRetAB   uint32 = 0xd65f0fff // RETAB (Pointer Authentication)
)

var amd64PtRegsOffsets = ebpfPtRegsOffsets{
	// Linux x86_64 struct pt_regs: r15=0, r14=8, r13=16, r12=24, rbp=32, rbx=40, r11=48, r10=56,
	// r9=64, r8=72, rax=80, rcx=88, rdx=96, rsi=104, rdi=112, orig_rax=120, rip=128, cs=136, eflags=144, rsp=152, ss=160
	Regs: [31]int16{
		0, 8, 16, 24, 32, 40, 48, 56,
		64, 72, 80, 88, 96, 104, 112, 120,
	},
	SP:          152,
	PC:          128,
	PState:      144,
	CArg0:       112, // rdi
	CArg1:       104, // rsi
	CArg2:       96,  // rdx
	CArg3:       88,  // rcx
	CRet:        80,  // rax
	GoArg0:      80,  // rax (c *tls.Conn)
	GoArg1:      40,  // rbx (b.ptr)
	GoArg2:      88,  // rcx (b.len)
	GoRet:       80,  // rax (n int)
	GoGoroutine: 8,   // r14 (g)
	SyscallArg0: 16,
	SyscallArg1: 24,
	SyscallArg2: 32,
	SyscallRet:  16,
}

var arm64PtRegsOffsets = ebpfPtRegsOffsets{
	// Linux arm64 struct user_pt_regs (arch/arm64/include/uapi/asm/ptrace.h):
	// __u64 regs[31] (offsets 0..240), __u64 sp (offset 248), __u64 pc (offset 256), __u64 pstate (offset 264)
	Regs: [31]int16{
		0, 8, 16, 24, 32, 40, 48, 56,
		64, 72, 80, 88, 96, 104, 112, 120,
		128, 136, 144, 152, 160, 168, 176, 184,
		192, 200, 208, 216, 224, 232, 240,
	},
	SP:          248, // offsetof(user_pt_regs, sp) = 31 * 8
	PC:          256, // offsetof(user_pt_regs, pc) = 32 * 8
	PState:      264, // offsetof(user_pt_regs, pstate) = 33 * 8
	CArg0:       0,   // regs[0] (X0)
	CArg1:       8,   // regs[1] (X1)
	CArg2:       16,  // regs[2] (X2)
	CArg3:       24,  // regs[3] (X3)
	CRet:        0,   // regs[0] (X0)
	GoArg0:      0,   // regs[0] (R0 = c *tls.Conn)
	GoArg1:      8,   // regs[1] (R1 = b.ptr)
	GoArg2:      16,  // regs[2] (R2 = b.len)
	GoRet:       0,   // regs[0] (R0 = n int)
	GoGoroutine: 224, // regs[28] (R28 = g on Go arm64 ABIInternal)
	SyscallArg0: 16,
	SyscallArg1: 24,
	SyscallArg2: 32,
	SyscallRet:  16,
}

var amd64ArchCapabilities = ebpfArchCapabilities{
	Arch:                        "amd64",
	Supported:                   true,
	UprobeSupported:             true,
	UretprobeSupported:          true,
	GoTLSUprobeSupported:        true,
	GoTLSUretprobeSupported:     false, // Go growable stacks cannot use kernel uretprobe; uses RET-offset uprobes
	GoTLSRetScanSupported:       true,
	SyscallTracepointsSupported: true,
	PtraceUserspaceSupported:    true,
}

var arm64ArchCapabilities = ebpfArchCapabilities{
	Arch:                        "arm64",
	Supported:                   true,
	UprobeSupported:             true,
	UretprobeSupported:          true,
	GoTLSUprobeSupported:        true,
	GoTLSUretprobeSupported:     false, // Kernel uretprobe replaces X30/LR and breaks Go stack growth/unwinding
	GoTLSRetScanSupported:       true,
	SyscallTracepointsSupported: true,
	PtraceUserspaceSupported:    false,
	DegradedFeatures: []string{
		"gotls_native_uretprobe",
		"arm64_pac_bti_uretprobe",
		"ptrace_userspace_inject",
	},
	DegradationNotice: "linux/arm64 eBPF running with capability boundaries: kernel uretprobe is disabled on GoTLS (using RET 0xd65f03c0 instruction uprobes via user_pt_regs X0/X1/X2/X28); if GoTLS RET offsets are unavailable or PAC/BTI blocks uretprobe, capture degrades to syscall tracepoints / userspace hooks",
}

var archCapabilityTable = map[string]ebpfArchCapabilities{
	"amd64": amd64ArchCapabilities,
	"arm64": arm64ArchCapabilities,
}

var (
	archCapabilitiesOverride *ebpfArchCapabilities
	lastCollectorMonitor     atomic.Pointer[selfmon.Monitor]
)

// currentArchCapabilities returns the active architecture capability entry, honoring any test override.
func currentArchCapabilities() ebpfArchCapabilities {
	if archCapabilitiesOverride != nil {
		return *archCapabilitiesOverride
	}
	if archCapabilities.Arch != "" {
		return archCapabilities
	}
	return lookupArchCapabilities(runtime.GOARCH)
}

// lookupArchCapabilities returns the capability entry for goarch, or an explicit unsupported descriptor.
func lookupArchCapabilities(goarch string) ebpfArchCapabilities {
	if capSpec, ok := archCapabilityTable[goarch]; ok {
		return capSpec
	}
	return ebpfArchCapabilities{
		Arch:              goarch,
		Supported:         false,
		DegradedFeatures:  []string{"ebpf_uprobe", "ebpf_uretprobe", "ebpf_gotls", "ebpf_tracepoint"},
		DegradationNotice: fmt.Sprintf("linux/%s is not in the eBPF capability table; degrading all capture to userspace hooks / loopback tap", goarch),
		UnsupportedReason: fmt.Sprintf("ebpf engine unsupported on linux/%s (supported architectures: amd64, arm64; missing pt_regs ABI mapping and RET instruction scanner): falling back to userspace hooks / loopback tap", goarch),
	}
}

// validateArchEBPFSupport checks whether goarch is supported by the eBPF engine capability table.
func validateArchEBPFSupport(goarch string) error {
	capSpec := lookupArchCapabilities(goarch)
	if !capSpec.Supported {
		if capSpec.UnsupportedReason != "" {
			return fmt.Errorf("%s", capSpec.UnsupportedReason)
		}
		return fmt.Errorf("ebpf engine unsupported on linux/%s (supported architectures: amd64, arm64)", goarch)
	}
	return nil
}

// DiscoverOpenSSLTargets finds system libssl.so AND static OpenSSL embedded in target executables (e.g. uv python3.14, node).
func DiscoverOpenSSLTargets(pids []int, exes ...string) []ProbeTarget {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib64/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
		"/usr/local/opt/openssl@3/lib/libssl.3.dylib",
		"/opt/homebrew/lib/libssl.dylib",
		"/usr/local/lib/libssl.dylib",
	}
	for _, pid := range pids {
		if exeLink, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && exeLink != "" {
			candidates = append(candidates, exeLink)
		}
		candidates = append(candidates, findMappedLibraries(pid, "libssl.so")...)
		candidates = append(candidates, findMappedLibraries(pid, "_ssl")...)
		candidates = append(candidates, findMappedExecutables(pid)...)
	}
	for _, exe := range exes {
		if exe != "" {
			candidates = append(candidates, unwrapScriptTarget(exe))
		}
	}
	seen := make(map[string]bool)
	var out []ProbeTarget
	for _, p := range candidates {
		realPath, err := filepath.EvalSymlinks(p)
		if err != nil {
			realPath = p
		}
		if seen[realPath] {
			continue
		}
		if _, err := os.Stat(realPath); err != nil {
			continue
		}
		syms, err := ResolveOpenSSLSymbols(realPath)
		if err != nil || len(syms) == 0 {
			continue
		}
		seen[realPath] = true
		probeType := "openssl"
		base := strings.ToLower(filepath.Base(realPath))
		if !strings.Contains(base, "libssl") && !strings.Contains(base, "ssleay") {
			probeType = "static_openssl"
		}
		out = append(out, ProbeTarget{
			BinaryPath: realPath,
			Type:       probeType,
			Symbols:    syms,
		})
	}
	return out
}

// ResolveOpenSSLSymbols parses an ELF, Mach-O, or PE shared library or executable and returns file offsets for SSL_write/SSL_read
// and Python MemoryBIO functions.
func ResolveOpenSSLSymbols(elfPath string) (map[string]uint64, error) {
	wanted := map[string]bool{
		"SSL_write":            true,
		"SSL_write_ex":         true,
		"SSL_read":             true,
		"SSL_read_ex":          true,
		"_ssl_MemoryBIO_write": true,
		"_ssl_MemoryBIO_read":  true,
	}
	offsets := make(map[string]uint64)

	if f, err := elf.Open(elfPath); err == nil {
		defer f.Close()
		collectSyms := func(syms []elf.Symbol) {
			for _, s := range syms {
				baseName := strings.Split(s.Name, "@")[0]
				if wanted[baseName] && s.Value > 0 {
					offsets[baseName] = vaddrToFileOffset(f, s.Value)
				}
			}
		}
		if dynSyms, err := f.DynamicSymbols(); err == nil {
			collectSyms(dynSyms)
		}
		if stdSyms, err := f.Symbols(); err == nil {
			collectSyms(stdSyms)
		}
		return offsets, nil
	}

	if mf, err := macho.Open(elfPath); err == nil {
		defer mf.Close()
		if mf.Symtab != nil {
			for _, s := range mf.Symtab.Syms {
				name := strings.TrimPrefix(s.Name, "_")
				if wanted[name] && s.Value > 0 {
					offsets[name] = s.Value
				} else if wanted[s.Name] && s.Value > 0 {
					offsets[s.Name] = s.Value
				}
			}
		}
		return offsets, nil
	}

	if pf, err := pe.Open(elfPath); err == nil {
		defer pf.Close()
		for _, s := range pf.Symbols {
			name := strings.TrimPrefix(s.Name, "_")
			if wanted[name] && s.Value > 0 {
				offsets[name] = uint64(s.Value)
			}
		}
		return offsets, nil
	}

	return nil, fmt.Errorf("unsupported binary format: %s", elfPath)
}

// InspectBinaryProfile analyzes an executable (or wrapper script) to classify its linkage and TLS stack.
func InspectBinaryProfile(binaryPath string) (*BinaryProfile, error) {
	targetPath := unwrapScriptTarget(binaryPath)
	realPath, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		realPath = targetPath
	}

	if gt, err := InspectGoTLSTarget(realPath); err == nil && gt != nil {
		return &BinaryProfile{
			RequestedPath:  binaryPath,
			ResolvedELF:    realPath,
			LinkMode:       "dynamic",
			TLSStack:       "gotls",
			GoVersion:      gt.GoVersion,
			RequiresPtrace: true,
			Symbols:        gt.Symbols,
		}, nil
	}

	if mf, err := macho.Open(realPath); err == nil {
		defer mf.Close()
		libs, _ := mf.ImportedLibraries()
		for _, lib := range libs {
			if strings.Contains(strings.ToLower(filepath.Base(lib)), "libssl") {
				syms, _ := ResolveOpenSSLSymbols(realPath)
				return &BinaryProfile{
					RequestedPath:  binaryPath,
					ResolvedELF:    realPath,
					LinkMode:       "dynamic",
					TLSStack:       "dynamic-libssl",
					RequiresPtrace: false,
					Symbols:        syms,
				}, nil
			}
		}
		if syms, err := ResolveOpenSSLSymbols(realPath); err == nil && len(syms) > 0 {
			return &BinaryProfile{
				RequestedPath:  binaryPath,
				ResolvedELF:    realPath,
				LinkMode:       "dynamic",
				TLSStack:       "static-openssl",
				RequiresPtrace: false,
				Symbols:        syms,
			}, nil
		}
		return &BinaryProfile{
			RequestedPath:  binaryPath,
			ResolvedELF:    realPath,
			LinkMode:       "dynamic",
			TLSStack:       "stripped-embedded-tls",
			RequiresPtrace: false,
		}, nil
	}

	if pf, err := pe.Open(realPath); err == nil {
		defer pf.Close()
		syms, _ := ResolveOpenSSLSymbols(realPath)
		tlsStack := "stripped-embedded-tls"
		if len(syms) > 0 {
			tlsStack = "static-openssl"
		}
		return &BinaryProfile{
			RequestedPath:  binaryPath,
			ResolvedELF:    realPath,
			LinkMode:       "dynamic",
			TLSStack:       tlsStack,
			RequiresPtrace: false,
			Symbols:        syms,
		}, nil
	}

	f, err := elf.Open(realPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hasInterp := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			break
		}
	}

	if !hasInterp {
		return &BinaryProfile{
			RequestedPath:  binaryPath,
			ResolvedELF:    realPath,
			LinkMode:       "static-pie",
			TLSStack:       "static-custom",
			RequiresPtrace: true,
		}, nil
	}

	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		if strings.HasPrefix(filepath.Base(lib), "libssl.so") {
			syms, _ := ResolveOpenSSLSymbols(realPath)
			return &BinaryProfile{
				RequestedPath:  binaryPath,
				ResolvedELF:    realPath,
				LinkMode:       "dynamic",
				TLSStack:       "dynamic-libssl",
				RequiresPtrace: false,
				Symbols:        syms,
			}, nil
		}
	}

	if syms, err := ResolveOpenSSLSymbols(realPath); err == nil && len(syms) > 0 {
		return &BinaryProfile{
			RequestedPath:  binaryPath,
			ResolvedELF:    realPath,
			LinkMode:       "dynamic",
			TLSStack:       "static-openssl",
			RequiresPtrace: false,
			Symbols:        syms,
		}, nil
	}

	return &BinaryProfile{
		RequestedPath:  binaryPath,
		ResolvedELF:    realPath,
		LinkMode:       "dynamic",
		TLSStack:       "stripped-embedded-tls",
		RequiresPtrace: false,
	}, nil
}

func unwrapScriptTarget(binPath string) string {
	realPath, err := filepath.EvalSymlinks(binPath)
	if err != nil {
		realPath = binPath
	}
	f, err := os.Open(realPath)
	if err != nil {
		return realPath
	}
	defer f.Close()
	var hdr [512]byte
	n, _ := f.Read(hdr[:])
	if n >= 4 && hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' {
		return realPath
	}
	if n >= 2 && hdr[0] == 'M' && hdr[1] == 'Z' {
		return realPath
	}
	if n >= 4 && ((hdr[0] == 0xcf && hdr[1] == 0xfa && hdr[2] == 0xed && hdr[3] == 0xfe) ||
		(hdr[0] == 0xfe && hdr[1] == 0xed && hdr[2] == 0xfa && hdr[3] == 0xcf) ||
		(hdr[0] == 0xca && hdr[1] == 0xfe && hdr[2] == 0xba && hdr[3] == 0xbe)) {
		return realPath
	}
	content := string(hdr[:n])
	// Check for @openai/codex wrapper layout
	if strings.Contains(content, "codex") {
		dir := filepath.Dir(realPath)
		candidates := []string{
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-linux-x64", "vendor", "x86_64-unknown-linux-musl", "bin", "codex"),
			filepath.Join(dir, "..", "vendor", "x86_64-unknown-linux-musl", "bin", "codex"),
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-linux-arm64", "vendor", "aarch64-unknown-linux-musl", "bin", "codex"),
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-darwin-arm64", "vendor", "aarch64-apple-darwin", "bin", "codex"),
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-darwin-x64", "vendor", "x86_64-apple-darwin", "bin", "codex"),
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-win32-x64", "vendor", "x86_64-pc-windows-msvc", "bin", "codex.exe"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	return realPath
}

// InspectGoTLSTarget checks if binaryPath is a Go executable and locates crypto/tls.(*Conn).Write/Read symbols.
func InspectGoTLSTarget(binaryPath string) (*ProbeTarget, error) {
	realPath, err := filepath.EvalSymlinks(binaryPath)
	if err != nil {
		realPath = binaryPath
	}
	bi, err := buildinfo.ReadFile(realPath)
	if err != nil {
		return nil, err
	}
	rawFile, err := os.Open(realPath)
	if err != nil {
		return nil, err
	}
	defer rawFile.Close()

	syms := make(map[string]uint64)
	var readRetOffsets []uint64
	if f, err := elf.Open(realPath); err == nil {
		defer f.Close()
		goarch := ""
		switch f.Machine {
		case elf.EM_X86_64:
			goarch = "amd64"
		case elf.EM_AARCH64:
			goarch = "arm64"
		}
		if goarch != "" && !SupportsGoRegisterABI(bi.GoVersion, goarch) {
			return &ProbeTarget{
				BinaryPath:          realPath,
				Type:                "gotls",
				GoVersion:           bi.GoVersion,
				Symbols:             make(map[string]uint64),
				GoTLSReadRetOffsets: nil,
				Note:                "Go version " + bi.GoVersion + " uses stack ABI; register-based GoTLS uprobe disabled",
			}, nil
		}
		processGoFunc := func(name string, vaddr, fnSize uint64) {
			switch name {
			case "crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext":
				if vaddr == 0 {
					return
				}
				baseOff := vaddrToFileOffset(f, vaddr)
				entryOff := baseOff
				if (f.Machine == elf.EM_X86_64 || f.Machine == elf.EM_AARCH64) && fnSize > 16 {
					code := make([]byte, fnSize)
					if _, err := rawFile.ReadAt(code, int64(baseOff)); err == nil {
						entryOff = baseOff + scanGoPrologueOffsetForMachine(f.Machine, code)
						if name == "crypto/tls.(*Conn).Read" && len(readRetOffsets) == 0 {
							readRetOffsets = findGoRetOffsetsForMachine(f.Machine, baseOff, code)
						}
					}
				}
				syms[name] = entryOff
			}
		}
		if elfSyms, err := f.Symbols(); err == nil {
			for _, s := range elfSyms {
				processGoFunc(s.Name, s.Value, s.Size)
			}
		}
		// DWARF is the second recovery channel: -s strips .symtab but can
		// leave .debug_info intact, and it also supplies exact function sizes.
		dwarfFuncs := extractGoDWARFFuncs(f)
		for name, fn := range dwarfFuncs {
			processGoFunc(name, fn.Addr, fn.Size)
		}
		// Fallback for stripped Go binaries (`go build -ldflags="-s -w"`): recover symbols from .gopclntab
		if len(syms) == 0 {
			var pclnSec *elf.Section
			for _, secName := range []string{".gopclntab", ".data.rel.ro.gopclntab"} {
				if s := f.Section(secName); s != nil {
					pclnSec = s
					break
				}
			}
			if pclnSec != nil {
				if pclnData, err := pclnSec.Data(); err == nil && len(pclnData) > 16 {
					var textStart uint64
					if txtSec := f.Section(".text"); txtSec != nil {
						textStart = txtSec.Addr
					}
					lt := gosym.NewLineTable(pclnData, textStart)
					if tab, err := gosym.NewTable(nil, lt); err == nil && tab != nil {
						for _, fn := range tab.Funcs {
							var sz uint64
							if fn.End > fn.Entry {
								sz = fn.End - fn.Entry
							}
							processGoFunc(fn.Name, fn.Entry, sz)
						}
					}
				}
			}
		}
	} else if mf, err := macho.Open(realPath); err == nil {
		defer mf.Close()
		goarch := ""
		switch mf.Cpu {
		case macho.CpuAmd64:
			goarch = "amd64"
		case macho.CpuArm64:
			goarch = "arm64"
		}
		if goarch != "" && !SupportsGoRegisterABI(bi.GoVersion, goarch) {
			return &ProbeTarget{
				BinaryPath:          realPath,
				Type:                "gotls",
				GoVersion:           bi.GoVersion,
				Symbols:             make(map[string]uint64),
				GoTLSReadRetOffsets: nil,
				Note:                "Go version " + bi.GoVersion + " uses stack ABI; register-based GoTLS uprobe disabled",
			}, nil
		}
		processGoFunc := func(name string, vaddr, fnSize uint64) {
			_ = fnSize
			switch name {
			case "crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext":
				if vaddr > 0 {
					syms[name] = vaddr
				}
			}
		}
		if mf.Symtab != nil {
			for _, s := range mf.Symtab.Syms {
				name := strings.TrimPrefix(s.Name, "_")
				switch name {
				case "crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext":
					if s.Value > 0 {
						syms[name] = s.Value
					}
				}
			}
		}
		if len(syms) == 0 {
			dwarfFuncs := extractMachoGoDWARFFuncs(mf)
			for name, fn := range dwarfFuncs {
				if fn.Addr > 0 {
					syms[name] = fn.Addr
				}
			}
		}
		if len(syms) == 0 {
			if pclnSec := mf.Section("__gopclntab"); pclnSec != nil {
				if pclnData, err := pclnSec.Data(); err == nil && len(pclnData) > 16 {
					var textStart uint64
					if txtSec := mf.Section("__text"); txtSec != nil {
						textStart = txtSec.Addr
					}
					lt := gosym.NewLineTable(pclnData, textStart)
					if tab, err := gosym.NewTable(nil, lt); err == nil && tab != nil {
						for _, fn := range tab.Funcs {
							var sz uint64
							if fn.End > fn.Entry {
								sz = fn.End - fn.Entry
							}
							processGoFunc(fn.Name, fn.Entry, sz)
						}
					}
				}
			}
		}
	} else if pf, err := pe.Open(realPath); err == nil {
		defer pf.Close()
		for _, s := range pf.Symbols {
			switch s.Name {
			case "crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext":
				if s.Value > 0 {
					syms[s.Name] = uint64(s.Value)
				}
			}
		}
	}

	return &ProbeTarget{
		BinaryPath:          realPath,
		Type:                "gotls",
		GoVersion:           bi.GoVersion,
		Symbols:             syms,
		GoTLSReadRetOffsets: readRetOffsets,
	}, nil
}

// scanAMD64GoPrologueOffset advances past Go's x86_64 stack-split prologue (`cmp 0x10(%r14),%rsp; jbe morestack`)
// to `push %rbp; mov %rsp, %rbp` (`55 48 89 e5`) so the uprobe fires after any goroutine stack growth.
func scanAMD64GoPrologueOffset(code []byte) uint64 {
	prologueWindow := code
	if len(prologueWindow) > 48 {
		prologueWindow = prologueWindow[:48]
	}
	if idx := bytes.Index(prologueWindow, []byte{0x55, 0x48, 0x89, 0xe5}); idx >= 0 {
		return uint64(idx)
	}
	// Large Go frames may save rbp at an offset after subtracting stack space:
	// sub $imm, %rsp; mov %rbp, imm8(%rsp).
	if idx := bytes.Index(prologueWindow, []byte{0x48, 0x89, 0x6c, 0x24}); idx >= 4 {
		isImm8Sub := prologueWindow[idx-4] == 0x48 && prologueWindow[idx-3] == 0x83 &&
			prologueWindow[idx-2] == 0xec
		isImm32Sub := idx >= 7 && prologueWindow[idx-7] == 0x48 &&
			prologueWindow[idx-6] == 0x81 && prologueWindow[idx-5] == 0xec
		if isImm8Sub || isImm32Sub {
			return uint64(idx)
		}
	}
	return 0
}

// scanARM64GoPrologueOffset advances past Go's arm64 stack-split prologue (`MOVD 16(R28), R16; CMP R16, RSP; BLS morestack`)
// to the frame setup (`MOVD R29, -8(RSP); SUB $8, RSP, R29` or `MOV R29, RSP`) so the uprobe fires after stack growth.
func scanARM64GoPrologueOffset(code []byte) uint64 {
	prologueWindow := code
	if len(prologueWindow) > 48 {
		prologueWindow = prologueWindow[:48]
	}
	// Go 1.20+ arm64 frame pointer setup: MOVD R29, -8(RSP) (0xf81f83fd); SUB $8, RSP, R29 (0xd10023fd)
	for i := 0; i+8 <= len(prologueWindow); i += 4 {
		w0 := binary.LittleEndian.Uint32(prologueWindow[i : i+4])
		w1 := binary.LittleEndian.Uint32(prologueWindow[i+4 : i+8])
		if w0 == 0xf81f83fd && w1 == 0xd10023fd {
			return uint64(i)
		}
	}
	// Alternative arm64 frame pointer setup: MOV R29, RSP (0x910003fd)
	for i := 0; i+4 <= len(prologueWindow); i += 4 {
		if binary.LittleEndian.Uint32(prologueWindow[i:i+4]) == 0x910003fd {
			return uint64(i)
		}
	}
	// STP X29, X30, [SP, #-imm]! establishes a full frame in one instruction.
	for i := 0; i+4 <= len(prologueWindow); i += 4 {
		w0 := binary.LittleEndian.Uint32(prologueWindow[i : i+4])
		if (w0 & 0xffc07fff) == 0xa9807bfd {
			return uint64(i)
		}
	}
	// STR X30, [SP, #-imm]! is used by frames that save only the link register.
	for i := 0; i+4 <= len(prologueWindow); i += 4 {
		w0 := binary.LittleEndian.Uint32(prologueWindow[i : i+4])
		if (w0 & 0xffe0ffff) == 0xf81f0ffe {
			return uint64(i)
		}
	}
	return 0
}

func scanGoPrologueOffsetForMachine(machine elf.Machine, code []byte) uint64 {
	switch machine {
	case elf.EM_X86_64:
		if archName == "amd64" {
			return scanGoPrologueOffset(code)
		}
		return scanAMD64GoPrologueOffset(code)
	case elf.EM_AARCH64:
		if archName == "arm64" {
			return scanGoPrologueOffset(code)
		}
		return scanARM64GoPrologueOffset(code)
	default:
		return 0
	}
}

// scanAMD64ReturnOffsets scans an x86_64 Go function body for frame epilogues (`add $imm, %rsp; pop %rbp; ret`)
// and returns the relative byte offsets of the `ret` (0xc3) instructions.
func scanAMD64ReturnOffsets(code []byte) []uint64 {
	var out []uint64
	for i := 0; i < len(code); i++ {
		if code[i] != 0xc3 {
			continue
		}
		// add $imm8, %rsp; pop %rbp; ret
		if i >= 5 && code[i-5] == 0x48 && code[i-4] == 0x83 && code[i-3] == 0xc4 &&
			code[i-1] == 0x5d {
			out = appendUniqueOffset(out, uint64(i))
			continue
		}
		// add $imm32, %rsp; pop %rbp; ret
		if i >= 8 && code[i-8] == 0x48 && code[i-7] == 0x81 && code[i-6] == 0xc4 &&
			code[i-1] == 0x5d {
			out = appendUniqueOffset(out, uint64(i))
			continue
		}
		// pop %rbp; add $imm8, %rsp; ret
		if i >= 5 && code[i-5] == 0x5d && code[i-4] == 0x48 && code[i-3] == 0x83 &&
			code[i-2] == 0xc4 {
			out = appendUniqueOffset(out, uint64(i))
			continue
		}
		// pop %rbp; add $imm32, %rsp; ret
		if i >= 8 && code[i-8] == 0x5d && code[i-7] == 0x48 && code[i-6] == 0x81 &&
			code[i-5] == 0xc4 {
			out = appendUniqueOffset(out, uint64(i))
			continue
		}
		// leave; ret
		if i >= 1 && code[i-1] == 0xc9 {
			out = appendUniqueOffset(out, uint64(i))
			continue
		}
		// add $imm8, %rsp; ret (frame-pointer omitted)
		if i >= 4 && code[i-4] == 0x48 && code[i-3] == 0x83 && code[i-2] == 0xc4 {
			out = appendUniqueOffset(out, uint64(i))
			continue
		}
		// add $imm32, %rsp; ret (frame-pointer omitted)
		if i >= 7 && code[i-7] == 0x48 && code[i-6] == 0x81 && code[i-5] == 0xc4 {
			out = appendUniqueOffset(out, uint64(i))
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func appendUniqueOffset(offsets []uint64, offset uint64) []uint64 {
	for _, existing := range offsets {
		if existing == offset {
			return offsets
		}
	}
	return append(offsets, offset)
}

// isARM64ReturnInsn reports whether a 32-bit little-endian A64 instruction word is RET (0xd65f03c0),
// RET Xn ((insn & 0xfffffc1f) == 0xd65f0000), RETAA (0xd65f0bff), or RETAB (0xd65f0fff).
func isARM64ReturnInsn(insn uint32) bool {
	return insn == arm64InsnRet ||
		(insn&arm64InsnRetMask) == arm64InsnRetBase ||
		insn == arm64InsnRetAA ||
		insn == arm64InsnRetAB
}

// scanARM64ReturnOffsets scans a 4-byte aligned arm64 Go function body for RET (0xd65f03c0) / RETAA / RETAB instructions
// and returns their relative byte offsets within code.
func scanARM64ReturnOffsets(code []byte) []uint64 {
	var out []uint64
	for i := 0; i+4 <= len(code); i += 4 {
		insn := binary.LittleEndian.Uint32(code[i : i+4])
		if isARM64ReturnInsn(insn) {
			out = append(out, uint64(i))
		}
	}
	return out
}

// findGoX8664RetOffsets scans a Go amd64 function body for frame epilogues (`add $imm, %rsp; pop %rbp; ret`)
// and returns the file offsets of the `ret` (0xc3) instructions so regular uprobes can capture return values
// without installing kernel uretprobe trampolines on Go's growable goroutine stacks.
func findGoX8664RetOffsets(baseOff uint64, code []byte) []uint64 {
	rel := scanAMD64ReturnOffsets(code)
	if archName == "amd64" {
		rel = scanReturnOffsets(code)
	}
	out := make([]uint64, len(rel))
	for i, off := range rel {
		out[i] = baseOff + off
	}
	return out
}

// findGoARM64RetOffsets scans a Go arm64 function body for RET (0xd65f03c0) instructions and returns file offsets.
func findGoARM64RetOffsets(baseOff uint64, code []byte) []uint64 {
	rel := scanARM64ReturnOffsets(code)
	if archName == "arm64" {
		rel = scanReturnOffsets(code)
	}
	out := make([]uint64, len(rel))
	for i, off := range rel {
		out[i] = baseOff + off
	}
	return out
}

func findGoRetOffsetsForMachine(machine elf.Machine, baseOff uint64, code []byte) []uint64 {
	switch machine {
	case elf.EM_X86_64:
		return findGoX8664RetOffsets(baseOff, code)
	case elf.EM_AARCH64:
		return findGoARM64RetOffsets(baseOff, code)
	default:
		return nil
	}
}

func ProbeAndRecordTargets(pids []int, exes []string, mon *selfmon.Monitor) []ProbeTarget {
	if mon != nil {
		lastCollectorMonitor.Store(mon)
	}
	var results []ProbeTarget
	resolvedExes := make([]string, 0, len(exes))
	for _, e := range exes {
		if e == "" {
			continue
		}
		if _, err := os.Stat(e); err != nil {
			if lp, lerr := exec.LookPath(e); lerr == nil {
				e = lp
			}
		}
		resolvedExes = append(resolvedExes, e)
	}
	sslTargets := DiscoverOpenSSLTargets(pids, resolvedExes...)
	for _, t := range sslTargets {
		var firstOff uint64
		for _, off := range t.Symbols {
			firstOff = off
			break
		}
		fd, err := TryAttachKernelUprobe(t.BinaryPath, firstOff)
		if err == nil && fd >= 0 {
			closeKernelFD(fd)
			t.Attached = true
			t.Note = "eBPF uprobe attached"
			if mon != nil {
				mon.RecordOK(selfmon.StageProbe, "attach_openssl_uprobe", map[string]any{
					"library": t.BinaryPath,
					"symbols": t.Symbols,
				})
			}
		} else {
			t.Attached = false
			t.Note = "resolved ELF symbols; user-space hook / socket tap active (" + err.Error() + ")"
			if mon != nil {
				mon.RecordOK(selfmon.StageProbe, "resolve_openssl_symbols", map[string]any{
					"library": t.BinaryPath,
					"symbols": t.Symbols,
					"mode":    "userspace_preload_and_tap",
				})
			}
		}
		results = append(results, t)
	}

	allExes := append([]string(nil), resolvedExes...)
	for _, pid := range pids {
		if exeLink, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil && exeLink != "" {
			allExes = append(allExes, exeLink)
		}
	}
	seenExe := make(map[string]bool)
	for _, exePath := range allExes {
		if exePath == "" {
			continue
		}
		realExe, err := filepath.EvalSymlinks(exePath)
		if err != nil {
			realExe = exePath
		}
		if seenExe[realExe] {
			continue
		}
		seenExe[realExe] = true
		if gt, err := InspectGoTLSTarget(exePath); err == nil && gt != nil {
			if len(gt.Symbols) > 0 {
				for _, off := range gt.Symbols {
					if fd, err := TryAttachKernelUprobe(gt.BinaryPath, off); err == nil && fd >= 0 {
						closeKernelFD(fd)
						gt.Attached = true
					}
					break
				}
				gt.Note = fmt.Sprintf("GoTLS (%s) symbols resolved", gt.GoVersion)
				if mon != nil {
					mon.RecordOK(selfmon.StageProbe, "resolve_gotls_symbols", map[string]any{
						"binary":     gt.BinaryPath,
						"go_version": gt.GoVersion,
						"symbols":    gt.Symbols,
					})
				}
			} else {
				gt.Note = fmt.Sprintf("Go binary (%s) symbol table stripped", gt.GoVersion)
				if mon != nil {
					mon.RecordWarn(selfmon.StageProbe, "inspect_gotls_binary", gt.Note, map[string]any{
						"binary": gt.BinaryPath,
					})
				}
			}
			results = append(results, *gt)
			continue
		}
		if prof, err := InspectBinaryProfile(exePath); err == nil && prof != nil {
			if prof.LinkMode == "static-pie" || prof.TLSStack == "stripped-embedded-tls" {
				pt := ProbeTarget{
					BinaryPath: prof.ResolvedELF,
					Type:       prof.TLSStack,
					LinkMode:   prof.LinkMode,
					Symbols:    prof.Symbols,
					Note:       fmt.Sprintf("link=%s tls=%s ptrace=%v", prof.LinkMode, prof.TLSStack, prof.RequiresPtrace),
				}
				if mon != nil {
					mon.RecordOK(selfmon.StageProbe, "inspect_binary_profile", map[string]any{
						"binary":          prof.ResolvedELF,
						"link_mode":       prof.LinkMode,
						"tls_stack":       prof.TLSStack,
						"requires_ptrace": prof.RequiresPtrace,
					})
				}
				results = append(results, pt)
			}
		}
	}
	return results
}

func vaddrToFileOffset(f *elf.File, vaddr uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && vaddr >= prog.Vaddr && vaddr < prog.Vaddr+prog.Memsz {
			return vaddr - prog.Vaddr + prog.Off
		}
	}
	return vaddr
}

func findMappedLibraries(pid int, substr string) []string {
	if pid <= 0 {
		return nil
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		path := fields[len(fields)-1]
		if strings.Contains(path, substr) && strings.HasPrefix(path, "/") && !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

func findMappedExecutables(pid int) []string {
	if pid <= 0 {
		return nil
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		perms := fields[1]
		path := fields[len(fields)-1]
		if strings.Contains(perms, "x") && strings.HasPrefix(path, "/") && !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}
