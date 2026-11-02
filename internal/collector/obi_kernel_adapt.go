package collector

import (
	"debug/dwarf"
	"debug/elf"
	"errors"
	"os"
	"strconv"
	"strings"
)

// ParseTracepointFormat parses a tracefs event format file and returns field
// name to byte offset mappings. Malformed lines are ignored; a file without any
// valid field declarations returns an error so callers can safely use defaults.
func ParseTracepointFormat(content string) (map[string]int16, error) {
	fields := make(map[string]int16)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "field:") {
			continue
		}

		parts := strings.Split(line, ";")
		var name string
		var offset int64 = -1
		for _, part := range parts {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, "field:"):
				field := strings.TrimSpace(strings.TrimPrefix(part, "field:"))
				// The format is "type name". The type may itself contain spaces,
				// so only the final token is the field name.
				tokens := strings.Fields(field)
				if len(tokens) < 2 {
					continue
				}
				name = tokens[len(tokens)-1]
			case strings.HasPrefix(part, "offset:"):
				value, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(part, "offset:")), 10, 16)
				if err != nil {
					continue
				}
				offset = value
			}
		}
		if name != "" && offset >= 0 {
			fields[name] = int16(offset)
		}
	}
	if len(fields) == 0 {
		return nil, errors.New("no tracepoint fields found")
	}
	return fields, nil
}

// ResolveSyscallTracepointOffsets reads the live syscall tracepoint layouts and
// replaces static pt_regs assumptions with offsets reported by the kernel.
// Any read/parse failure preserves the architecture-provided defaults.
func ResolveSyscallTracepointOffsets(baseOffsets ebpfPtRegsOffsets) ebpfPtRegsOffsets {
	const enterWrite = "/sys/kernel/tracing/events/syscalls/sys_enter_write/format"
	const enterWriteDebug = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format"
	const enterRead = "/sys/kernel/tracing/events/syscalls/sys_enter_read/format"
	const enterReadDebug = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format"
	const exitRead = "/sys/kernel/tracing/events/syscalls/sys_exit_read/format"
	const exitReadDebug = "/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/format"

	enter, err := readTracepointFormat(enterWrite, enterWriteDebug)
	if err != nil {
		if enter, err = readTracepointFormat(enterRead, enterReadDebug); err != nil {
			return baseOffsets
		}
	}

	if offset, ok := firstFieldOffset(enter, "fd"); ok {
		baseOffsets.SyscallArg0 = offset
	}
	if offset, ok := firstFieldOffset(enter, "buf", "vec"); ok {
		baseOffsets.SyscallArg1 = offset
	}
	if offset, ok := firstFieldOffset(enter, "count", "vlen"); ok {
		baseOffsets.SyscallArg2 = offset
	}

	if exit, err := readTracepointFormat(exitRead, exitReadDebug); err == nil {
		if offset, ok := firstFieldOffset(exit, "ret"); ok {
			baseOffsets.SyscallRet = offset
		}
	}
	return baseOffsets
}

func readTracepointFormat(paths ...string) (map[string]int16, error) {
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if fields, err := ParseTracepointFormat(string(content)); err == nil {
			return fields, nil
		}
	}
	return nil, os.ErrNotExist
}

func firstFieldOffset(fields map[string]int16, names ...string) (int16, bool) {
	for _, name := range names {
		if offset, ok := fields[name]; ok {
			return offset, true
		}
	}
	return 0, false
}

// ParseGoVersionMajorMinor parses build info versions such as go1.21.5.
func ParseGoVersionMajorMinor(goVer string) (int, int, bool) {
	goVer = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(goVer), "go"))
	if goVer == "" {
		return 0, 0, false
	}
	parts := strings.SplitN(goVer, ".", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minorDigits := parts[1]
	if idx := strings.IndexFunc(minorDigits, func(r rune) bool { return r < '0' || r > '9' }); idx >= 0 {
		minorDigits = minorDigits[:idx]
	}
	minor, err := strconv.Atoi(minorDigits)
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// SupportsGoRegisterABI reports whether the target's Go compiler used the
// register-based ABIInternal calling convention.
func SupportsGoRegisterABI(goVer string, goarch string) bool {
	major, minor, ok := ParseGoVersionMajorMinor(goVer)
	if !ok {
		return false
	}
	switch goarch {
	case "amd64":
		return major > 1 || (major == 1 && minor >= 17)
	case "arm64":
		return major > 1 || (major == 1 && minor >= 18)
	default:
		return false
	}
}

type goDWARFFunc struct {
	Addr uint64
	Size uint64
}

// extractGoDWARFFuncs recovers TLS function entries and sizes from DWARF
// subprogram entries. It complements .symtab and .gopclntab for stripped
// binaries that still retain their debug information.
func extractGoDWARFFuncs(f *elf.File) map[string]goDWARFFunc {
	wanted := map[string]bool{
		"crypto/tls.(*Conn).Write":             true,
		"crypto/tls.(*Conn).Read":              true,
		"crypto/tls.(*Conn).HandshakeContext": true,
	}
	out := make(map[string]goDWARFFunc)
	dw, err := f.DWARF()
	if err != nil {
		return out
	}
	reader := dw.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			return out
		}
		if entry.Tag != dwarf.TagSubprogram {
			continue
		}
		nameVal, ok := entry.Val(dwarf.AttrName).(string)
		if !ok || !wanted[nameVal] {
			continue
		}
		lowpc, ok := entry.Val(dwarf.AttrLowpc).(uint64)
		if !ok || lowpc == 0 {
			continue
		}
		var size uint64
		switch highpc := entry.Val(dwarf.AttrHighpc).(type) {
		case uint64:
			if highpc > lowpc {
				size = highpc - lowpc
			}
		case int64:
			// DWARF encodes AttrHighpc as a relative offset in DWARF 4+.
			if highpc > 0 {
				size = uint64(highpc)
			}
		}
		if size > 0 {
			out[nameVal] = goDWARFFunc{Addr: lowpc, Size: size}
		}
	}
}
