//go:build !amd64 && !arm64

package collector

import "runtime"

var (
	archName          = runtime.GOARCH
	archSupported     = false
	archPtRegsOffsets = ebpfPtRegsOffsets{}
	archCapabilities  = lookupArchCapabilities(runtime.GOARCH)
)

func scanReturnOffsets(_ []byte) []uint64 {
	return nil
}

func scanGoPrologueOffset(_ []byte) uint64 {
	return 0
}
