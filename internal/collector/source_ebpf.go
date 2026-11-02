package collector

import (
	"context"
	"fmt"
	"sync"

	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type ebpfSource struct {
	mu            sync.RWMutex
	probes        []ProbeTarget
	mon           *selfmon.Monitor
	eng           *EBPFEngine
	isUserHookPID func(pid int) bool
	onReady       func(eng *EBPFEngine, probes []ProbeTarget)
}

func newEBPFSource(
	probes []ProbeTarget,
	mon *selfmon.Monitor,
	isUserHookPID func(pid int) bool,
	onReady func(eng *EBPFEngine, probes []ProbeTarget),
) *ebpfSource {
	cp := make([]ProbeTarget, len(probes))
	copy(cp, probes)
	return &ebpfSource{
		probes:        cp,
		mon:           mon,
		isUserHookPID: isUserHookPID,
		onReady:       onReady,
	}
}

func (s *ebpfSource) Name() string {
	return "ebpf"
}

func (s *ebpfSource) Start(_ context.Context, sink Sink) error {
	s.mu.RLock()
	probes := make([]ProbeTarget, len(s.probes))
	copy(probes, s.probes)
	s.mu.RUnlock()

	eng, err := StartEBPFEngine(probes, s.mon, func(pid, tid int, connID string, dir parser.Direction, payload []byte, mode string) {
		if s.isUserHookPID != nil && s.isUserHookPID(pid) {
			return
		}
		if sink != nil {
			sink(pid, tid, connID, dir, payload, mode)
		}
	})
	if err != nil || eng == nil {
		if s.onReady != nil {
			s.onReady(nil, probes)
		}
		return err
	}

	for i := range probes {
		if len(probes[i].Symbols) > 0 {
			probes[i].Attached = eng.Active()
			probes[i].Note = fmt.Sprintf("eBPF kernel engine active (attached=%d)", eng.AttachedCount())
		}
	}

	s.mu.Lock()
	s.eng = eng
	s.probes = probes
	s.mu.Unlock()

	if s.onReady != nil {
		s.onReady(eng, probes)
	}
	if s.mon != nil {
		s.mon.RecordOK(selfmon.StageProbe, "start_ebpf_engine", map[string]any{
			"attached_count": eng.AttachedCount(),
		})
	}
	return nil
}

func (s *ebpfSource) Flush() {
	s.mu.RLock()
	eng := s.eng
	s.mu.RUnlock()
	if eng != nil {
		eng.Flush()
	}
}

func (s *ebpfSource) Close() error {
	s.mu.Lock()
	eng := s.eng
	s.eng = nil
	s.mu.Unlock()
	if eng != nil {
		eng.Close()
	}
	return nil
}
