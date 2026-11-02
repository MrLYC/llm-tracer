package collector

import (
	"context"
	"os"
	"sync"

	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type tapSource struct {
	mu         sync.RWMutex
	hooksDir   string
	insecure   bool
	mon        *selfmon.Monitor
	resolvePID func() int
	onReady    func(tap *LoopbackTap)
	tap        *LoopbackTap
}

func newTapSource(
	hooksDir string,
	insecure bool,
	mon *selfmon.Monitor,
	resolvePID func() int,
	onReady func(tap *LoopbackTap),
) *tapSource {
	return &tapSource{
		hooksDir:   hooksDir,
		insecure:   insecure,
		mon:        mon,
		resolvePID: resolvePID,
		onReady:    onReady,
	}
}

func (s *tapSource) Name() string {
	return "loopback_tap"
}

func (s *tapSource) Start(_ context.Context, sink Sink) error {
	s.mu.RLock()
	insecure := s.insecure
	s.mu.RUnlock()

	tap, err := NewLoopbackTap(s.hooksDir, func(connID string, dir parser.Direction, data []byte) {
		pid := 0
		if s.resolvePID != nil {
			pid = s.resolvePID()
		}
		if pid <= 0 {
			pid = os.Getpid()
		}
		if sink != nil {
			sink(pid, pid, connID, dir, data, "loopback_tap")
		}
	}, WithTapInsecure(insecure), WithTapMonitor(s.mon))
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.tap = tap
	s.mu.Unlock()

	if s.onReady != nil {
		s.onReady(tap)
	}
	if s.mon != nil {
		s.mon.RecordOK(selfmon.StageProbe, "start_loopback_tap", map[string]any{
			"proxy_url": tap.ProxyURL(),
			"ca_bundle": tap.CABundlePath(),
		})
	}
	return nil
}

func (s *tapSource) SetInsecure(insecure bool) {
	s.mu.Lock()
	s.insecure = insecure
	tap := s.tap
	s.mu.Unlock()
	if tap != nil {
		tap.SetInsecure(insecure)
	}
}

func (s *tapSource) Close() error {
	s.mu.Lock()
	tap := s.tap
	s.tap = nil
	s.mu.Unlock()
	if tap != nil {
		tap.Close()
	}
	return nil
}
