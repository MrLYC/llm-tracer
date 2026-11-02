//go:build !windows

package collector

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

var errCrossUIDPermissionDenied = errors.New("refusing world-readable 0666 mode for cross-UID hook channel without CAP_CHOWN")

var (
	lookupProcessUID = defaultProcessUID
	getEffectiveUID  = os.Geteuid
	chownFileFunc    = defaultChownFile
	lchownSocketFunc = defaultLchownSocket
)

func sanitizePrivateMode(perm os.FileMode) os.FileMode {
	if perm == 0 || perm&0o077 != 0 {
		return 0o600
	}
	return perm
}

func defaultChownFile(f *os.File, _ string, uid int) error {
	return f.Chown(uid, -1)
}

func defaultLchownSocket(sockPath string, uid int) error {
	return os.Lchown(sockPath, uid, -1)
}

func ensureSafeHooksDir(hooksDir string) error {
	if fi, err := os.Lstat(hooksDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("hooks path %s is not a regular directory", hooksDir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(hooksDir, 0o700); err != nil {
		return err
	}

	fi, err := os.Lstat(hooksDir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("hooks path %s is not a regular directory after creation", hooksDir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		selfUID := getEffectiveUID()
		if selfUID >= 0 && int(st.Uid) != selfUID {
			return fmt.Errorf("hooks directory %s is owned by uid %d, expected %d", hooksDir, st.Uid, selfUID)
		}
	}

	df, err := os.OpenFile(hooksDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Chmod(0o700)
}

func ensureSafeSubDir(dir string, perm os.FileMode) error {
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("sub-directory path %s is not a regular directory", dir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	cleanPerm := perm &^ 0o022
	if err := os.MkdirAll(dir, cleanPerm); err != nil {
		return err
	}

	df, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer df.Close()

	dfStat, err := df.Stat()
	if err != nil {
		return err
	}
	if !dfStat.IsDir() {
		return fmt.Errorf("sub-directory path %s is not a regular directory after open", dir)
	}
	return df.Chmod(cleanPerm)
}

func createArtifactFileNoFollow(path string, perm os.FileMode) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing to open symlink or non-regular artifact path: %s", path)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	cleanPerm := perm &^ 0o022
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, cleanPerm)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("artifact fd is not a regular file: %s", path)
	}
	return f, nil
}

func writeArtifactNoFollow(path string, data []byte, perm os.FileMode) error {
	f, err := createArtifactFileNoFollow(path, perm)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	if _, err := f.Write(data); err != nil {
		return err
	}
	cleanPerm := perm &^ 0o022
	if err := f.Chmod(cleanPerm); err != nil {
		return err
	}
	err = f.Close()
	f = nil
	return err
}

func chmodArtifactNoFollow(path string, perm os.FileMode) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to chmod symlink or non-regular artifact path: %s", path)
	}

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(fi, fStat) || !fStat.Mode().IsRegular() {
		return fmt.Errorf("artifact path changed during open: %s", path)
	}

	cleanPerm := perm &^ 0o022
	return f.Chmod(cleanPerm)
}

func setHooksDirModeNoFollow(hooksDir string, perm os.FileMode) error {
	if hooksDir == "" {
		return nil
	}
	fi, err := os.Lstat(hooksDir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("hooks path %s is not a regular directory", hooksDir)
	}
	df, err := os.OpenFile(hooksDir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer df.Close()
	return df.Chmod(perm)
}

func initPipeFileNoFollow(pipePath string, perm os.FileMode, targetUID int) error {
	if fi, err := os.Lstat(pipePath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing to open symlink or non-regular pipe path: %s", pipePath)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	f, err := os.OpenFile(pipePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("pipe fd is not a regular file: %s", pipePath)
	}
	if err := applyFdPermissions(f, pipePath, perm, targetUID); err != nil && !errors.Is(err, errCrossUIDPermissionDenied) {
		return err
	}
	return nil
}

func openReadNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func openReadWriteNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	}
	return f, nil
}

func lockPipeFile(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
	}
}

func unlockPipeFile(f *os.File) {
	if f != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
}

func truncateAndRemovePipeNoFollow(pipePath string) error {
	if pipePath == "" {
		return nil
	}
	fi, err := os.Lstat(pipePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to truncate or remove symlink or non-regular pipe path: %s", pipePath)
	}
	if f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, 0); err == nil {
		_ = f.Truncate(0)
		_ = f.Close()
	}
	if err := os.Remove(pipePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func applyPipePermissionsNoFollow(pipePath string, perm os.FileMode, targetUID int) error {
	if pipePath == "" {
		return nil
	}
	fi, err := os.Lstat(pipePath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to modify symlink or non-regular pipe path: %s", pipePath)
	}
	f, err := os.OpenFile(pipePath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fStat, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(fi, fStat) || !fStat.Mode().IsRegular() {
		return fmt.Errorf("pipe path changed during open: %s", pipePath)
	}
	return applyFdPermissions(f, pipePath, perm, targetUID)
}

func applyFdPermissions(f *os.File, path string, perm os.FileMode, targetUID int) error {
	safePerm := sanitizePrivateMode(perm)
	selfUID := getEffectiveUID()
	switch {
	case targetUID >= 0 && targetUID != selfUID:
		if err := chownFileFunc(f, path, targetUID); err == nil {
			return f.Chmod(0o600)
		}
		if selfUID >= 0 {
			_ = chownFileFunc(f, path, selfUID)
		}
		_ = f.Chmod(0o600)
		return errCrossUIDPermissionDenied
	case targetUID == -2:
		if selfUID >= 0 {
			_ = chownFileFunc(f, path, selfUID)
		}
		_ = f.Chmod(0o600)
		return errCrossUIDPermissionDenied
	default:
		if selfUID >= 0 {
			_ = chownFileFunc(f, path, selfUID)
		}
		return f.Chmod(safePerm)
	}
}

func removeSocketNoFollow(sockPath string) error {
	fi, err := os.Lstat(sockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() {
		return fmt.Errorf("refusing to remove symlink or directory at socket path: %s", sockPath)
	}
	return os.Remove(sockPath)
}

func applySocketPermissionsNoFollow(sockPath string, perm os.FileMode, targetUID int) error {
	if sockPath == "" {
		return nil
	}
	fi, err := os.Lstat(sockPath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to chmod non-socket or symlink path: %s", sockPath)
	}
	safePerm := sanitizePrivateMode(perm)
	selfUID := getEffectiveUID()
	switch {
	case targetUID >= 0 && targetUID != selfUID:
		if err := lchownSocketFunc(sockPath, targetUID); err == nil {
			return os.Chmod(sockPath, 0o600)
		}
		if selfUID >= 0 {
			_ = lchownSocketFunc(sockPath, selfUID)
		}
		_ = os.Chmod(sockPath, 0o600)
		return errCrossUIDPermissionDenied
	case targetUID == -2:
		if selfUID >= 0 {
			_ = lchownSocketFunc(sockPath, selfUID)
		}
		_ = os.Chmod(sockPath, 0o600)
		return errCrossUIDPermissionDenied
	default:
		if selfUID >= 0 {
			_ = lchownSocketFunc(sockPath, selfUID)
		}
		return os.Chmod(sockPath, safePerm)
	}
}

func defaultProcessUID(pid int) (int, bool) {
	if pid <= 0 {
		return -1, false
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
				if len(fields) > 0 {
					if uid, err := strconv.Atoi(fields[0]); err == nil {
						return uid, true
					}
				}
				break
			}
		}
	}
	if fi, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return int(st.Uid), true
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("ps", "-o", "uid=", "-p", strconv.Itoa(pid)).Output(); err == nil {
			if uid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
				return uid, true
			}
		}
	}
	return -1, false
}
