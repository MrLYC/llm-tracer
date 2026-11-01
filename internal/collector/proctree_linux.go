//go:build linux

package collector

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/liuyicong/llm-tracer/internal/model"
)

func InspectProcess(pid int) model.ProcessInfo {
	info := model.ProcessInfo{PID: pid}
	if pid <= 0 {
		return info
	}
	procDir := fmt.Sprintf("/proc/%d", pid)
	if commBytes, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		info.Comm = strings.TrimSpace(string(commBytes))
	}
	if cmdBytes, err := os.ReadFile(filepath.Join(procDir, "cmdline")); err == nil && len(cmdBytes) > 0 {
		parts := bytes.Split(bytes.TrimRight(cmdBytes, "\x00"), []byte{0})
		strs := make([]string, 0, len(parts))
		for _, p := range parts {
			if len(p) > 0 {
				strs = append(strs, string(p))
			}
		}
		info.Cmdline = strings.Join(strs, " ")
	}
	if exe, err := os.Readlink(filepath.Join(procDir, "exe")); err == nil {
		info.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if cwd, err := os.Readlink(filepath.Join(procDir, "cwd")); err == nil {
		info.Cwd = cwd
	}
	info.PPID = readPPID(pid)
	return info
}

func readPPID(pid int) int {
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(statBytes)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeParen+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

func readTaskChildren(pid int) []int {
	var out []int
	tasksDir := fmt.Sprintf("/proc/%d/task", pid)
	entries, err := os.ReadDir(tasksDir)
	if err != nil {
		return nil
	}
	for _, ent := range entries {
		b, err := os.ReadFile(filepath.Join(tasksDir, ent.Name(), "children"))
		if err != nil {
			continue
		}
		for _, f := range strings.Fields(string(b)) {
			if ch, err := strconv.Atoi(f); err == nil && ch > 0 {
				out = append(out, ch)
			}
		}
	}
	return out
}

func scanAllPPIDs() map[int]int {
	out := make(map[int]int, 256)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if ppid := readPPID(pid); ppid > 0 {
			out[pid] = ppid
		}
	}
	return out
}
