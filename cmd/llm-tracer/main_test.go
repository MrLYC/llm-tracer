package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseDurationWithDaysAndCLI(t *testing.T) {
	d, err := parseDurationWithDays("7d")
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, d)

	d2, err := parseDurationWithDays("10m")
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, d2)

	selfExe, err := os.Executable()
	require.NoError(t, err)

	dir := t.TempDir()
	cmd := newRootCmd()
	cmd.SetArgs([]string{"capture", "-d", dir, "-l", "off", "--exit-with-child", "--", selfExe, "-test.run=^$"})
	require.NoError(t, cmd.Execute())

	statusCmd := newRootCmd()
	statusCmd.SetArgs([]string{"status", "-d", dir})
	require.NoError(t, statusCmd.Execute())

	cleanCmd := newRootCmd()
	cleanCmd.SetArgs([]string{"clean", "-d", dir, "--all", "--dry-run"})
	require.NoError(t, cleanCmd.Execute())
}
