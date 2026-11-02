package collector

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type RuntimeHookPaths struct {
	PyHookDir    string
	NodeHookJS   string
	JavaAgentJar string
	PtraceBin    string
}

//go:embed assets/python/sitecustomize.py
var pythonSiteCustomizeSource string

//go:embed assets/node/node_hook.cjs
var nodeHookCJSSource string

//go:embed assets/c/ptrace_helper.c
var ptraceHelperCSource string

// EnsureRuntimeHooks writes Python sitecustomize.py, Node/Bun preload CJS, and compiles the C ptrace helper.
func EnsureRuntimeHooks(hooksDir string) (*RuntimeHookPaths, error) {
	if fi, err := os.Lstat(hooksDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return nil, fmt.Errorf("hooks path %s is not a regular directory", hooksDir)
		}
	} else if os.IsNotExist(err) {
		if err := ensureSafeHooksDir(hooksDir); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	out := &RuntimeHookPaths{}

	// 1. Python hook directory with sitecustomize.py
	pyDir := filepath.Join(hooksDir, "pyhook")
	if err := ensureSafeSubDir(pyDir, 0o755); err == nil {
		scPath := filepath.Join(pyDir, "sitecustomize.py")
		if err := writeArtifactNoFollow(scPath, []byte(pythonSiteCustomizeSource), 0o644); err == nil {
			out.PyHookDir = pyDir
		}
	}

	// 2. Node.js & Bun preload hook
	nodePath := filepath.Join(hooksDir, "node_hook.cjs")
	if err := writeArtifactNoFollow(nodePath, []byte(nodeHookCJSSource), 0o644); err == nil {
		out.NodeHookJS = nodePath
	}

	// 3. Java Agent JAR for zero-code JVM capture via JAVA_TOOL_OPTIONS
	if jarPath, err := EnsureJavaAgentJar(hooksDir); err == nil {
		out.JavaAgentJar = jarPath
	}

	// 4. Ptrace syscall helper for Linux static-pie (codex) and Go binaries
	if runtime.GOOS == "linux" {
		ptraceC := filepath.Join(hooksDir, "llm_tracer_ptrace.c")
		ptraceBin := filepath.Join(hooksDir, "llm_tracer_ptrace")
		if err := writeArtifactNoFollow(ptraceC, []byte(ptraceHelperCSource), 0o644); err == nil {
			if fi, err := os.Lstat(ptraceBin); err == nil {
				if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
					return out, fmt.Errorf("refusing to compile over symlink or non-regular file: %s", ptraceBin)
				}
			} else if !os.IsNotExist(err) {
				return out, err
			}
			if gccPath, err := exec.LookPath("gcc"); err == nil {
				cmd := exec.Command(gccPath, "-O2", ptraceC, "-o", ptraceBin)
				if outBytes, err := cmd.CombinedOutput(); err == nil {
					if err := chmodArtifactNoFollow(ptraceBin, 0o755); err != nil {
						return out, err
					}
					out.PtraceBin = ptraceBin
				} else {
					return out, fmt.Errorf("compile ptrace helper: %w (%s)", err, string(outBytes))
				}
			}
		}
	}
	return out, nil
}

// CanUsePtrace tests whether the current process/sandbox permits PTRACE_TRACEME on a child process.
func CanUsePtrace() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	cmd := exec.Command("sh", "-c", "exit 0")
	if cmd.SysProcAttr == nil {
		// Quick probe via python3 or ptrace_scope
	}
	// Check using a tiny child or python3 ctypes if available
	if out, err := exec.Command("python3", "-c", "import ctypes; libc=ctypes.CDLL('libc.so.6'); raise SystemExit(0 if libc.ptrace(0,0,0,0)==0 else 1)").CombinedOutput(); err == nil && len(out) == 0 {
		return true
	}
	return false
}
