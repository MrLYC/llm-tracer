//go:build darwin

package collector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/liuyicong/llm-tracer/internal/model"
	"golang.org/x/sys/unix"
)

func InspectProcess(pid int) model.ProcessInfo {
	info := model.ProcessInfo{PID: pid}
	if pid <= 0 {
		return info
	}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil && kp != nil {
		info.PPID = int(kp.Eproc.Ppid)
		info.Comm = unix.ByteSliceToString(kp.Proc.P_comm[:])
	}
	if out, err := exec.Command("ps", "-o", "ppid=,comm=,args=", "-p", strconv.Itoa(pid)).Output(); err == nil {
		line := strings.TrimSpace(string(out))
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if ppid, err := strconv.Atoi(fields[0]); err == nil && info.PPID == 0 {
				info.PPID = ppid
			}
			if info.Exe == "" && strings.HasPrefix(fields[1], "/") {
				info.Exe = fields[1]
			}
			if info.Comm == "" {
				info.Comm = filepath.Base(fields[1])
			}
			if len(fields) >= 3 {
				info.Cmdline = strings.Join(fields[2:], " ")
			} else {
				info.Cmdline = fields[1]
			}
		}
	}
	if out, err := exec.Command("lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd,txt", "-Fn").Output(); err == nil {
		var curFD string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "f") {
				curFD = line[1:]
			} else if strings.HasPrefix(line, "n") {
				val := line[1:]
				if curFD == "cwd" && info.Cwd == "" {
					info.Cwd = val
				} else if curFD == "txt" && info.Exe == "" && strings.HasPrefix(val, "/") {
					info.Exe = val
				}
			}
		}
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
	}
	return info
}

func readPPID(pid int) int {
	if pid <= 0 {
		return 0
	}
	if kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid); err == nil && kp != nil {
		return int(kp.Eproc.Ppid)
	}
	return 0
}

func readTaskChildren(_ int) []int {
	return nil
}

func scanAllPPIDs() map[int]int {
	out := make(map[int]int, 256)
	kprocs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return out
	}
	for i := range kprocs {
		pid := int(kprocs[i].Proc.P_pid)
		ppid := int(kprocs[i].Eproc.Ppid)
		if pid > 0 && ppid > 0 {
			out[pid] = ppid
		}
	}
	return out
}
