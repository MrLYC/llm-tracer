package collector

import (
	"bufio"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/liuyicong/llm-tracer/internal/selfmon"
	"golang.org/x/sys/unix"
)

type ProbeTarget struct {
	BinaryPath string            `json:"binary_path"`
	Type       string            `json:"type"` // openssl | gotls
	GoVersion  string            `json:"go_version,omitempty"`
	Symbols    map[string]uint64 `json:"symbols"`
	Attached   bool              `json:"attached"`
	Note       string            `json:"note,omitempty"`
}

// DiscoverOpenSSLTargets finds system libssl.so and resolves SSL_read/SSL_write file offsets.
func DiscoverOpenSSLTargets(pids []int) []ProbeTarget {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib64/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
	}
	for _, pid := range pids {
		candidates = append(candidates, findMappedLibraries(pid, "libssl.so")...)
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
		out = append(out, ProbeTarget{
			BinaryPath: realPath,
			Type:       "openssl",
			Symbols:    syms,
		})
	}
	return out
}

// ResolveOpenSSLSymbols parses an ELF shared library and returns file offsets for SSL_write/SSL_read functions.
func ResolveOpenSSLSymbols(elfPath string) (map[string]uint64, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	wanted := map[string]bool{
		"SSL_write":    true,
		"SSL_write_ex": true,
		"SSL_read":     true,
		"SSL_read_ex":  true,
	}
	offsets := make(map[string]uint64)
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
	f, err := elf.Open(realPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	syms := make(map[string]uint64)
	if elfSyms, err := f.Symbols(); err == nil {
		for _, s := range elfSyms {
			switch s.Name {
			case "crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext":
				if s.Value > 0 {
					syms[s.Name] = vaddrToFileOffset(f, s.Value)
				}
			}
		}
	}
	return &ProbeTarget{
		BinaryPath: realPath,
		Type:       "gotls",
		GoVersion:  bi.GoVersion,
		Symbols:    syms,
	}, nil
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

	attr := unix.PerfEventAttr{
		Type:   uint32(pmuType),
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample: 1,
		Wakeup: 1,
	}
	_ = offset
	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("perf_event_open uprobe on %s: %w", filepath.Base(binaryPath), err)
	}
	return fd, nil
}

func ProbeAndRecordTargets(pids []int, exes []string, mon *selfmon.Monitor) []ProbeTarget {
	var results []ProbeTarget
	sslTargets := DiscoverOpenSSLTargets(pids)
	for _, t := range sslTargets {
		var firstOff uint64
		for _, off := range t.Symbols {
			firstOff = off
			break
		}
		fd, err := TryAttachKernelUprobe(t.BinaryPath, firstOff)
		if err == nil && fd >= 0 {
			_ = unix.Close(fd)
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

	for _, exePath := range exes {
		if gt, err := InspectGoTLSTarget(exePath); err == nil && gt != nil {
			if len(gt.Symbols) > 0 {
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
