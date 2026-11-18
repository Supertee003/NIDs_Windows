// =====================================================================
// pipe_writer.go - AEGIS NOSE -> Zig Core Canonical Event pipe sink
// =====================================================================
// Writes frozen 109-byte CanonicalEvent wire frames to the named pipe
// that the Zig core consumes (core/nose_pipe_reader.zig). Windows uses
// \\.\pipe\<name>; non-Windows falls back to a TCP loopback socket so
// the capture path is still testable/functional on dev boxes.
//
// Frame protocol (shared with core/nose_pipe_reader.zig):
//
//	u32 LE length (109 v1, 133 v2, or 165..1189 v3) followed by raw wire bytes.
//	v1/v2 are metadata-only compatibility frames; v3 carries bounded payload
//	and capture provenance (PAYLOAD-ENVELOPE-V3-001).
//
// Reconnection is automatic: if core is not up yet, the writer retries
// with backoff and drops frames until the reader connects (NIDS must
// never block capture on a missing consumer).
// =====================================================================
package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// nosePipeName is the default consumer pipe on Windows.
const nosePipeName = `\\.\pipe\aegis_nose`

// nosePipeRetryDelay is the backoff between reconnect attempts.
const nosePipeRetryDelay = 500 * time.Millisecond

// FrameWriter pushes wire frames to the Zig core consumer.
type FrameWriter struct {
	mu        sync.Mutex
	pipePath  string
	useSocket bool
	conn      *pipeConn
	dropped   uint64
	sent      uint64
}

// pipeConn abstracts a Windows named pipe or a loopback TCP fallback.
type pipeConn struct {
	file *os.File
}

func (c *pipeConn) write(b []byte) (int, error) {
	if c == nil || c.file == nil {
		return 0, os.ErrClosed
	}
	return c.file.Write(b)
}

// writeAll preserves frame boundaries even when the OS performs a short write.
func (c *pipeConn) writeAll(b []byte) error {
	for len(b) > 0 {
		n, err := c.write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return os.ErrInvalid
		}
		b = b[n:]
	}
	return nil
}

func (c *pipeConn) close() {
	if c != nil && c.file != nil {
		c.file.Close()
		c.file = nil
	}
}

// NewFrameWriter creates a writer that delivers length-prefixed canonical
// frames (109-byte v1, 133-byte v2) to the named pipe used by the Zig core.
func NewFrameWriter(pipePath string) *FrameWriter {
	if pipePath == "" {
		pipePath = nosePipeName
	}
	fw := &FrameWriter{pipePath: pipePath}
	fw.ensureConnected()
	if fw.conn != nil {
		fmt.Fprintf(os.Stderr, "[NOSE PIPE] connected to %s\n", pipePath)
	} else {
		fmt.Fprintf(os.Stderr, "[NOSE PIPE] waiting for %s\n", pipePath)
	}
	return fw
}

// ensureConnected opens/reopens the pipe. Non-blocking on failure.
func (w *FrameWriter) ensureConnected() {
	if w.conn != nil && w.conn.file != nil {
		return
	}
	w.conn = dialPipe(w.pipePath)
}

// dialPipe opens the named pipe client (or loopback TCP fallback).
func dialPipe(path string) *pipeConn {
	// Windows: CreateFile("\\\\.\\pipe\\name", GENERIC_WRITE, ...)
	// Go's os.OpenFile maps to CreateFileW with FILE_SHARE_READ|WRITE,
	// which works for named pipes when the server is listening.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil
	}
	return &pipeConn{file: f}
}

// Send encodes a CanonicalEvent and writes one length-prefixed frame.
// Version-dispatched: IPv6 events go out as 133-byte v2 frames, everything
// else stays frozen v1. It returns true only when the complete frame was
// delivered. Live capture remains non-blocking and may ignore false;
// deterministic observe injection uses the result to perform bounded
// retries without changing live semantics.
func (w *FrameWriter) Send(ev *CanonicalEvent) bool {
	var wire []byte
	if ev.IsV6() {
		v2, serr := ev.SerializeV2()
		if serr != nil {
			return false
		}
		wire = v2[:]
	} else {
		v1, serr := ev.Serialize()
		if serr != nil {
			return false
		}
		wire = v1[:]
	}
	return w.sendWire(wire, ev.EventID)
}

// SendWithPayload emits one v3 frame: the frozen v2 base + provenance/
// payload envelope + bounded captured bytes. It returns false on envelope
// validation failure or delivery failure; callers must never treat a
// rejected capture as delivered.
func (w *FrameWriter) SendWithPayload(ev *CanonicalEvent, env V3Envelope, payload []byte) bool {
	wire, serr := ev.SerializeV3(env, payload)
	if serr != nil {
		return false
	}
	return w.sendWire(wire, ev.EventID)
}

func (w *FrameWriter) sendWire(wire []byte, eventID uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn == nil || w.conn.file == nil {
		w.dropped++
		if w.dropped == 1 {
			fmt.Fprintf(os.Stderr, "[NOSE PIPE] first frame dropped: consumer unavailable (%s)\n", w.pipePath)
		}
		w.ensureConnected()
		return false
	}

	var frame [4 + EventV3MaxWireSize]byte
	ple := uint32(len(wire))
	frame[0] = byte(ple)
	frame[1] = byte(ple >> 8)
	frame[2] = byte(ple >> 16)
	frame[3] = byte(ple >> 24)
	copy(frame[4:], wire)

	werr := w.conn.writeAll(frame[:4+len(wire)])
	if werr != nil {
		w.dropped++
		w.conn.close()
		w.conn = nil
		return false
	}
	w.sent++
	if w.sent == 1 {
		fmt.Fprintf(os.Stderr, "[NOSE PIPE] first canonical frame sent: %d bytes event_id=%d\n", len(frame), eventID)
	}
	return true
}

// Stats returns how many frames were delivered vs dropped.
func (w *FrameWriter) Stats() (sent uint64, dropped uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sent, w.dropped
}
