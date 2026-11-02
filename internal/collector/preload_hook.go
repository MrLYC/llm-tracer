package collector

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

//go:embed assets/c/ssl_hook.c
var sslHookCSource string

// EnsureSSLPreloadHook compiles libllmtracer_ssl.so (Linux) or libllmtracer_ssl.dylib (macOS) into hooksDir.
func EnsureSSLPreloadHook(hooksDir string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("preload hook not used on windows")
	}
	if fi, err := os.Lstat(hooksDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return "", fmt.Errorf("hooks path %s is not a regular directory", hooksDir)
		}
	} else if os.IsNotExist(err) {
		if err := ensureSafeHooksDir(hooksDir); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	cPath := filepath.Join(hooksDir, "libllmtracer_ssl.c")
	soPath := filepath.Join(hooksDir, "libllmtracer_ssl.so")
	if runtime.GOOS == "darwin" {
		soPath = filepath.Join(hooksDir, "libllmtracer_ssl.dylib")
	}
	if existingC, err := os.ReadFile(cPath); err == nil && string(existingC) == sslHookCSource {
		if info, err := os.Lstat(soPath); err == nil && info.Mode()&os.ModeSymlink == 0 && info.Mode().IsRegular() && info.Size() > 0 {
			_ = chmodArtifactNoFollow(soPath, 0o755)
			return soPath, nil
		}
	}
	if fi, err := os.Lstat(soPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return "", fmt.Errorf("refusing to compile over symlink or non-regular file: %s", soPath)
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	ccPath, err := exec.LookPath("gcc")
	if err != nil {
		ccPath, err = exec.LookPath("cc")
		if err != nil {
			return "", fmt.Errorf("c compiler not found: %w", err)
		}
	}
	if err := writeArtifactNoFollow(cPath, []byte(sslHookCSource), 0o644); err != nil {
		return "", err
	}
	args := []string{"-shared", "-fPIC", "-O2", "-o", soPath, cPath, "-ldl"}
	if runtime.GOOS == "darwin" {
		fatArgs := []string{"-dynamiclib", "-arch", "arm64", "-arch", "arm64e", "-fPIC", "-O2", "-o", soPath, cPath}
		if err := exec.Command(ccPath, fatArgs...).Run(); err == nil {
			if err := chmodArtifactNoFollow(soPath, 0o755); err != nil {
				return "", err
			}
			return soPath, nil
		}
		args = []string{"-dynamiclib", "-fPIC", "-O2", "-o", soPath, cPath}
	}
	cmd := exec.Command(ccPath, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("compile ssl hook: %w (%s)", err, string(out))
	}
	if err := chmodArtifactNoFollow(soPath, 0o755); err != nil {
		return "", err
	}
	return soPath, nil
}
