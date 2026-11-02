//go:build windows

package collector

import (
	"errors"
	"fmt"
	"os"
)

var errCrossUIDPermissionDenied = errors.New("refusing world-readable 0666 mode for cross-UID hook channel without CAP_CHOWN")

var (
	lookupProcessUID = defaultProcessUID
	getEffectiveUID  = func() int { return -1 }
	chownFileFunc    = func(_ *os.File, _ string, _ int) error { return nil }
	lchownSocketFunc = func(_ string, _ int) error { return nil }
)

func sanitizePrivateMode(perm os.FileMode) os.FileMode {
	if perm == 0 || perm&0o077 != 0 {
		return 0o600
	}
	return perm
}

func ensureSafeHooksDir(hooksDir string) error {
	if fi, err := os.Lstat(hooksDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return fmt.Errorf("hooks path %s is not a regular directory", hooksDir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(hooksDir, 0o700)
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
	return os.Chmod(dir, cleanPerm)
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, cleanPerm)
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
	cleanPerm := perm &^ 0o022
	return os.Chmod(path, cleanPerm)
}

func setHooksDirModeNoFollow(_ string, _ os.FileMode) error {
	return nil
}

func initPipeFileNoFollow(pipePath string, perm os.FileMode, _ int) error {
	safePerm := sanitizePrivateMode(perm)
	if fi, err := os.Lstat(pipePath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing to open symlink or non-regular pipe path: %s", pipePath)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(pipePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, safePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(safePerm)
}

func openReadNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func openReadWriteNoFollow(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return os.Open(path)
	}
	return f, nil
}

func lockPipeFile(_ *os.File)   {}
func unlockPipeFile(_ *os.File) {}

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
	if f, err := os.OpenFile(pipePath, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		_ = f.Truncate(0)
		_ = f.Close()
	}
	if err := os.Remove(pipePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func applyPipePermissionsNoFollow(pipePath string, perm os.FileMode, _ int) error {
	if pipePath == "" {
		return nil
	}
	safePerm := sanitizePrivateMode(perm)
	fi, err := os.Lstat(pipePath)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return fmt.Errorf("refusing to modify symlink or non-regular pipe path: %s", pipePath)
	}
	return os.Chmod(pipePath, safePerm)
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

func applySocketPermissionsNoFollow(sockPath string, perm os.FileMode, _ int) error {
	if sockPath == "" {
		return nil
	}
	return os.Chmod(sockPath, sanitizePrivateMode(perm))
}

func defaultProcessUID(_ int) (int, bool) {
	return -1, false
}
