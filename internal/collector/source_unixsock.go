package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type unixSockSource struct {
	mu               sync.Mutex
	sockPath         string
	fallbackPipePath string
	perm             os.FileMode
	targetUID        int
	mon              *selfmon.Monitor
	onReady          func(sockPath string, ln net.Listener)
	onUserHookPID    func(pid int)
	ln               net.Listener
	stopCh           chan struct{}
	stopOnce         sync.Once
}

func newUnixSockSource(
	sockPath string,
	fallbackPipePath string,
	perm os.FileMode,
	targetUID int,
	mon *selfmon.Monitor,
	onReady func(sockPath string, ln net.Listener),
	onUserHookPID func(pid int),
) *unixSockSource {
	return &unixSockSource{
		sockPath:         sockPath,
		fallbackPipePath: fallbackPipePath,
		perm:             perm,
		targetUID:        targetUID,
		mon:              mon,
		onReady:          onReady,
		onUserHookPID:    onUserHookPID,
		stopCh:           make(chan struct{}),
	}
}

func (s *unixSockSource) Name() string {
	return "unixsock"
}

func (s *unixSockSource) Start(ctx context.Context, sink Sink) error {
	if err := removeSocketNoFollow(s.sockPath); err != nil {
		if s.mon != nil {
			s.mon.RecordWarn(selfmon.StageProbe, "listen_unix_sock_fallback_pipe", err.Error(), map[string]any{"pipe": s.fallbackPipePath})
		}
		return err
	}
	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		if s.mon != nil {
			s.mon.RecordWarn(selfmon.StageProbe, "listen_unix_sock_fallback_pipe", err.Error(), map[string]any{"pipe": s.fallbackPipePath})
		}
		return err
	}
	if err := applySocketPermissionsNoFollow(s.sockPath, s.perm, s.targetUID); err != nil {
		_ = ln.Close()
		if s.mon != nil {
			s.mon.RecordWarn(selfmon.StageProbe, "listen_unix_sock_fallback_pipe", err.Error(), map[string]any{"pipe": s.fallbackPipePath})
		}
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	if s.onReady != nil {
		s.onReady(s.sockPath, ln)
	}
	go s.acceptLoop(ctx, ln, sink)
	return nil
}

func (s *unixSockSource) acceptLoop(ctx context.Context, ln net.Listener, sink Sink) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-s.stopCh:
				return
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		s.handleConn(conn, sink)
	}
}

func (s *unixSockSource) handleConn(conn net.Conn, sink Sink) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var hdr [24]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return
	}
	magic := binary.NativeEndian.Uint32(hdr[0:4])
	if magic != 0x4c4c4d54 {
		return
	}
	pid := int(binary.NativeEndian.Uint32(hdr[4:8]))
	tid := int(binary.NativeEndian.Uint32(hdr[8:12]))
	sslLow := binary.NativeEndian.Uint32(hdr[12:16])
	dirVal := binary.NativeEndian.Uint32(hdr[16:20])
	payloadLen := binary.NativeEndian.Uint32(hdr[20:24])
	if payloadLen == 0 || payloadLen > 512*1024 {
		return
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return
	}
	dir := parser.DirWrite
	if dirVal != 0 {
		dir = parser.DirRead
	}
	if s.onUserHookPID != nil {
		s.onUserHookPID(pid)
	}
	if sink != nil {
		connID := fmt.Sprintf("ssl_%x", sslLow)
		sink(pid, tid, connID, dir, payload, "openssl_hook")
	}
}

func (s *unixSockSource) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.mu.Lock()
		ln := s.ln
		sock := s.sockPath
		s.ln = nil
		s.mu.Unlock()
		if ln != nil {
			_ = ln.Close()
		}
		if sock != "" {
			_ = removeSocketNoFollow(sock)
		}
	})
	return nil
}
