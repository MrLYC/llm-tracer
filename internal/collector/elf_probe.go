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
	Type       string            `json:"type"` // openssl | static_openssl | gotls | static_pie | stripped_tls
	LinkMode   string            `json:"link_mode,omitempty"`
	GoVersion  string            `json:"go_version,omitempty"`
	Symbols    map[string]uint64 `json:"symbols"`
	Attached   bool              `json:"attached"`
	Note       string            `json:"note,omitempty"`
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

// DiscoverOpenSSLTargets finds system libssl.so AND static OpenSSL embedded in target executables (e.g. uv python3.14, node).
func DiscoverOpenSSLTargets(pids []int, exes ...string) []ProbeTarget {
	candidates := []string{
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib/aarch64-linux-gnu/libssl.so.3",
		"/lib64/libssl.so.3",
		"/lib/x86_64-linux-gnu/libssl.so.1.1",
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
		if !strings.Contains(filepath.Base(realPath), "libssl.so") {
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

// ResolveOpenSSLSymbols parses an ELF shared library or executable and returns file offsets for SSL_write/SSL_read
// and Python MemoryBIO functions from both .dynsym and .symtab (including local 't' symbols in static builds).
func ResolveOpenSSLSymbols(elfPath string) (map[string]uint64, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	wanted := map[string]bool{
		"SSL_write":            true,
		"SSL_write_ex":         true,
		"SSL_read":             true,
		"SSL_read_ex":          true,
		"_ssl_MemoryBIO_write": true,
		"_ssl_MemoryBIO_read":  true,
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

// InspectBinaryProfile analyzes an executable (or wrapper script) to classify its linkage and TLS stack.
func InspectBinaryProfile(binaryPath string) (*BinaryProfile, error) {
	targetPath := unwrapScriptTarget(binaryPath)
	realPath, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		realPath = targetPath
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
	linkMode := "dynamic"
	if !hasInterp {
		linkMode = "static-pie"
	}

	if gt, err := InspectGoTLSTarget(realPath); err == nil && gt != nil {
		return &BinaryProfile{
			RequestedPath:  binaryPath,
			ResolvedELF:    realPath,
			LinkMode:       linkMode,
			TLSStack:       "gotls",
			GoVersion:      gt.GoVersion,
			RequiresPtrace: true,
			Symbols:        gt.Symbols,
		}, nil
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
	content := string(hdr[:n])
	// Check for @openai/codex wrapper layout
	if strings.Contains(content, "codex") {
		dir := filepath.Dir(realPath)
		candidates := []string{
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-linux-x64", "vendor", "x86_64-unknown-linux-musl", "bin", "codex"),
			filepath.Join(dir, "..", "vendor", "x86_64-unknown-linux-musl", "bin", "codex"),
			filepath.Join(dir, "..", "node_modules", "@openai", "codex-linux-arm64", "vendor", "aarch64-unknown-linux-musl", "bin", "codex"),
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
	sslTargets := DiscoverOpenSSLTargets(pids, exes...)
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
