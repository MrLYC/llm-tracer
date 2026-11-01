//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/liuyicong/llm-tracer/internal/model"
	"golang.org/x/sys/windows"
)

func InspectProcess(pid int) model.ProcessInfo {
	info := model.ProcessInfo{PID: pid}
	if pid <= 0 {
		return info
	}
	if entry, ok := findProcessEntry(uint32(pid)); ok {
		info.PPID = int(entry.ParentProcessID)
		info.Comm = windows.UTF16ToString(entry.ExeFile[:])
	}
	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)); err == nil {
		var buf [windows.MAX_PATH * 2]uint16
		size := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil && size > 0 {
			info.Exe = windows.UTF16ToString(buf[:size])
			if info.Comm == "" {
				info.Comm = filepath.Base(info.Exe)
			}
		}
		_ = windows.CloseHandle(h)
	}
	if pid == os.Getpid() {
		if info.Exe == "" {
			if exe, err := os.Executable(); err == nil {
				info.Exe = exe
			}
		}
		if info.Cwd == "" {
			if cwd, err := os.Getwd(); err == nil {
				info.Cwd = cwd
			}
		}
		if info.Cmdline == "" {
			info.Cmdline = strings.Join(os.Args, " ")
		}
	} else if info.Cmdline == "" && info.Exe != "" {
		info.Cmdline = info.Exe
	}
	return info
}

func readPPID(pid int) int {
	if pid <= 0 {
		return 0
	}
	if entry, ok := findProcessEntry(uint32(pid)); ok {
		return int(entry.ParentProcessID)
	}
	return 0
}

func readTaskChildren(_ int) []int {
	return nil
}

func scanAllPPIDs() map[int]int {
	out := make(map[int]int, 256)
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return out
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return out
	}
	for {
		if entry.ProcessID > 0 && entry.ParentProcessID > 0 {
			out[int(entry.ProcessID)] = int(entry.ParentProcessID)
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return out
}

func findProcessEntry(targetPID uint32) (windows.ProcessEntry32, bool) {
	var entry windows.ProcessEntry32
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return entry, false
	}
	defer windows.CloseHandle(snap)

	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return entry, false
	}
	for {
		if entry.ProcessID == targetPID {
			return entry, true
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		if err := windows.Process32Next(snap, &entry); err != nil {
			break
		}
	}
	return entry, false
}
