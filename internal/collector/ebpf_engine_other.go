//go:build !linux

package collector

import (
	"fmt"
	"runtime"

	"github.com/liuyicong/llm-tracer/internal/parser"
	"github.com/liuyicong/llm-tracer/internal/selfmon"
)

// EBPFEngine is a no-op stub on non-Linux platforms (darwin, windows) where user-space runtime hooks
// and LoopbackTap provide TLS/HTTP capture.
type EBPFEngine struct{}

func StartEBPFEngine(
	_ []ProbeTarget,
	_ *selfmon.Monitor,
	_ func(pid, tid int, connID string, dir parser.Direction, payload []byte, mode string),
) (*EBPFEngine, error) {
	return nil, fmt.Errorf("linux eBPF engine not supported on %s", runtime.GOOS)
}

func (e *EBPFEngine) AttachTargets(_ []ProbeTarget) {}
func (e *EBPFEngine) Active() bool                  { return false }
func (e *EBPFEngine) AttachedCount() int            { return 0 }
func (e *EBPFEngine) Flush()                        {}
func (e *EBPFEngine) Close()                        {}

func TryAttachKernelUprobe(_ string, _ uint64) (int, error) {
	return -1, fmt.Errorf("linux kernel uprobe not available on %s", runtime.GOOS)
}

func closeKernelFD(_ int) {}
