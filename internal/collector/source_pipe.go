package collector

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/mrlyc/llm-tracer/internal/parser"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

const (
	llmtFrameMagic          uint32 = 0x4c4c4d54
	llmtHeaderSize                 = 24
	maxPipeFramePayloadSize uint32 = 512 * 1024
	defaultMaxPipeFileSize  int64  = 64 * 1024
)

type pipeSource struct {
	mu            sync.Mutex
	pipePath      string
	perm          os.FileMode
	targetUID     int
	offset        int64
	maxFileSize   int64
	peakSize      int64
	sink          Sink
	mon           *selfmon.Monitor
	onUserHookPID func(pid int)
	stopCh        chan struct{}
	stopOnce      sync.Once
}

func newPipeSource(
	pipePath string,
	perm os.FileMode,
	targetUID int,
	onUserHookPID func(pid int),
	mon ...*selfmon.Monitor,
) *pipeSource {
	var m *selfmon.Monitor
	if len(mon) > 0 {
		m = mon[0]
	}
	return &pipeSource{
		pipePath:      pipePath,
		perm:          sanitizePrivateMode(perm),
		targetUID:     targetUID,
		maxFileSize:   defaultMaxPipeFileSize,
		mon:           m,
		onUserHookPID: onUserHookPID,
		stopCh:        make(chan struct{}),
	}
}

func (s *pipeSource) Name() string {
	return "pipe"
}

func (s *pipeSource) PeakSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peakSize
}

func (s *pipeSource) Start(ctx context.Context, sink Sink) error {
	s.mu.Lock()
	s.sink = sink
	s.mu.Unlock()

	if err := initPipeFileNoFollow(s.pipePath, s.perm, s.targetUID); err != nil {
		return err
	}
	go s.tailLoop(ctx)
	return nil
}

func (s *pipeSource) tailLoop(ctx context.Context) {
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.drain()
		}
	}
}

func (s *pipeSource) Flush() {
	s.drain()
}

func (s *pipeSource) recordResync(offset int64, skipped int, reason string, magic uint32, payloadLen uint32) {
	if s.mon == nil {
		return
	}
	s.mon.RecordWarn(
		selfmon.StageProbe,
		"pipe_frame_resync",
		fmt.Sprintf("resynced pipe frame stream (%s)", reason),
		map[string]any{
			"pipe":          s.pipePath,
			"offset":        offset,
			"skipped_bytes": skipped,
			"reason":        reason,
			"magic":         fmt.Sprintf("0x%08x", magic),
			"payload_len":   payloadLen,
		},
	)
}

func (s *pipeSource) resetPipeToZero(f *os.File) {
	if f == nil {
		return
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.Seek(0, io.SeekStart)
		s.offset = 0
	}
}

func (s *pipeSource) drain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pipePath == "" {
		return
	}
	f, err := openReadWriteNoFollow(s.pipePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.offset = 0
		}
		return
	}
	defer f.Close()
	lockPipeFile(f)
	defer unlockPipeFile(f)

	for pass := 0; pass < 4; pass++ {
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return
		}
		fileSize := info.Size()
		if fileSize > s.peakSize {
			s.peakSize = fileSize
		}
		if fileSize < s.offset {
			s.offset = 0
		}
		if fileSize == 0 {
			s.offset = 0
			return
		}
		if fileSize == s.offset {
			s.resetPipeToZero(f)
			return
		}
		if _, err := f.Seek(s.offset, io.SeekStart); err != nil {
			return
		}
		data := make([]byte, fileSize-s.offset)
		n, err := io.ReadFull(f, data)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return
		}
		data = data[:n]
		if len(data) == 0 {
			return
		}

		pos := 0
		for pos < len(data) {
			if pos+llmtHeaderSize > len(data) {
				s.recordResync(s.offset+int64(pos), len(data)-pos, "truncated_header", 0, 0)
				pos = len(data)
				break
			}
			hdr := data[pos : pos+llmtHeaderSize]
			magic := binary.NativeEndian.Uint32(hdr[0:4])
			pid := int(binary.NativeEndian.Uint32(hdr[4:8]))
			tid := int(binary.NativeEndian.Uint32(hdr[8:12]))
			sslLow := binary.NativeEndian.Uint32(hdr[12:16])
			dirVal := binary.NativeEndian.Uint32(hdr[16:20])
			payloadLen := binary.NativeEndian.Uint32(hdr[20:24])
			if magic != 0x4c4c4d54 || pid <= 0 || dirVal > 1 || payloadLen == 0 || payloadLen > maxPipeFramePayloadSize || !isCompleteUninterleavedFrame(data, pos, int(payloadLen)) {
				reason := "bad_magic"
				if magic == 0x4c4c4d54 {
					if payloadLen == 0 || payloadLen > maxPipeFramePayloadSize {
						reason = "payload_len_out_of_bounds"
					} else if pid <= 0 || dirVal > 1 {
						reason = "invalid_header_fields"
					} else {
						reason = "interleaved_or_truncated_frame"
					}
				}
				scanStart := pos + 1
				nextRel := findNextValidLLMTFrame(data[scanStart:])
				if nextRel < 0 {
					s.recordResync(s.offset+int64(pos), len(data)-pos, reason, magic, payloadLen)
					pos = len(data)
					break
				}
				skip := (scanStart - pos) + nextRel
				s.recordResync(s.offset+int64(pos), skip, reason, magic, payloadLen)
				pos += skip
				continue
			}

			frameEnd := pos + llmtHeaderSize + int(payloadLen)
			payload := make([]byte, int(payloadLen))
			copy(payload, data[pos+llmtHeaderSize:frameEnd])
			pos = frameEnd

			dir := parser.DirWrite
			if dirVal != 0 {
				dir = parser.DirRead
			}
			if s.onUserHookPID != nil {
				s.onUserHookPID(pid)
			}
			if s.sink != nil {
				connID := fmt.Sprintf("ssl_%x", sslLow)
				s.sink(pid, tid, connID, dir, payload, "openssl_hook")
			}
		}

		s.offset += int64(pos)
		afterInfo, err := f.Stat()
		if err != nil {
			return
		}
		if afterInfo.Size() == s.offset {
			s.resetPipeToZero(f)
			return
		}
		if s.maxFileSize > 0 && s.offset >= s.maxFileSize && afterInfo.Size() > s.offset {
			remLen := afterInfo.Size() - s.offset
			remBuf := make([]byte, remLen)
			if _, rErr := f.ReadAt(remBuf, s.offset); rErr == nil {
				if _, wErr := f.WriteAt(remBuf, 0); wErr == nil {
					if tErr := f.Truncate(remLen); tErr == nil {
						s.offset = 0
					}
				}
			}
		}
	}
}

func isCompleteUninterleavedFrame(data []byte, pos int, payloadLen int) bool {
	frameEnd := pos + llmtHeaderSize + payloadLen
	if frameEnd > len(data) {
		return false
	}
	payload := data[pos+llmtHeaderSize : frameEnd]
	if len(payload) >= 4 && binary.NativeEndian.Uint32(payload[0:4]) == llmtFrameMagic {
		return false
	}
	if frameEnd < len(data) {
		nextMagicOK := frameEnd+4 <= len(data) && binary.NativeEndian.Uint32(data[frameEnd:frameEnd+4]) == llmtFrameMagic
		if !nextMagicOK && containsLLMTMagic(payload) {
			return false
		}
	}
	return true
}

func containsLLMTMagic(buf []byte) bool {
	for i := 0; i+4 <= len(buf); i++ {
		if binary.NativeEndian.Uint32(buf[i:i+4]) == llmtFrameMagic {
			return true
		}
	}
	return false
}

func findNextValidLLMTFrame(buf []byte) int {
	fallback := -1
	for i := 0; i+llmtHeaderSize <= len(buf); i++ {
		if binary.NativeEndian.Uint32(buf[i:i+4]) != llmtFrameMagic {
			continue
		}
		pid := int(binary.NativeEndian.Uint32(buf[i+4 : i+8]))
		dirVal := binary.NativeEndian.Uint32(buf[i+16 : i+20])
		payloadLen := binary.NativeEndian.Uint32(buf[i+20 : i+24])
		if pid <= 0 || dirVal > 1 || payloadLen == 0 || payloadLen > maxPipeFramePayloadSize {
			continue
		}
		if !isCompleteUninterleavedFrame(buf, i, int(payloadLen)) {
			continue
		}
		frameEnd := i + llmtHeaderSize + int(payloadLen)
		if frameEnd == len(buf) || (frameEnd+4 <= len(buf) && binary.NativeEndian.Uint32(buf[frameEnd:frameEnd+4]) == llmtFrameMagic) {
			return i
		}
		if fallback < 0 {
			fallback = i
		}
	}
	return fallback
}

func (s *pipeSource) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		s.drain()
		s.mu.Lock()
		pipePath := s.pipePath
		s.offset = 0
		s.mu.Unlock()
		if pipePath != "" {
			_ = truncateAndRemovePipeNoFollow(pipePath)
		}
	})
	return nil
}
