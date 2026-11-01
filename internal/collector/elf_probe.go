package collector

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liuyicong/llm-tracer/internal/selfmon"
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
		if elfSyms, err := f.Symbols(); err == nil {
			for _, s := range elfSyms {
				switch s.Name {
				case "crypto/tls.(*Conn).Write", "crypto/tls.(*Conn).Read", "crypto/tls.(*Conn).HandshakeContext":
					if s.Value > 0 {
						baseOff := vaddrToFileOffset(f, s.Value)
						entryOff := baseOff
						if f.Machine == elf.EM_X86_64 && s.Size > 16 {
							code := make([]byte, s.Size)
							if _, err := rawFile.ReadAt(code, int64(baseOff)); err == nil {
								// Advance past Go's stack-split prologue (`cmp 0x10(%r14),%rsp; jbe morestack`)
								// to `push %rbp; mov %rsp, %rbp` (`55 48 89 e5`) so uprobe fires after any stack growth.
								prologueWindow := code
								if len(prologueWindow) > 32 {
									prologueWindow = prologueWindow[:32]
								}
								if idx := bytes.Index(prologueWindow, []byte{0x55, 0x48, 0x89, 0xe5}); idx >= 0 {
									entryOff = baseOff + uint64(idx)
								}
								if s.Name == "crypto/tls.(*Conn).Read" {
									readRetOffsets = findGoX8664RetOffsets(baseOff, code)
								}
							}
						}
						syms[s.Name] = entryOff
					}
				}
			}
		}
	} else if mf, err := macho.Open(realPath); err == nil {
		defer mf.Close()
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

// findGoX8664RetOffsets scans a Go amd64 function body for frame epilogues (`add $imm, %rsp; pop %rbp; ret`)
// and returns the file offsets of the `ret` (0xc3) instructions so regular uprobes can capture return values
// without installing kernel uretprobe trampolines on Go's growable goroutine stacks.
func findGoX8664RetOffsets(baseOff uint64, code []byte) []uint64 {
	var out []uint64
	for i := 0; i+1 < len(code); i++ {
		if code[i] != 0x5d || code[i+1] != 0xc3 {
			continue
		}
		isAddRspImm8 := i >= 4 && code[i-4] == 0x48 && code[i-3] == 0x83 && code[i-2] == 0xc4
		isAddRspImm32 := i >= 7 && code[i-7] == 0x48 && code[i-6] == 0x81 && code[i-5] == 0xc4
		if isAddRspImm8 || isAddRspImm32 {
			out = append(out, baseOff+uint64(i)+1)
		}
	}
	return out
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
