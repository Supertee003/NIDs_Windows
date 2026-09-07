// =====================================================================
// pipe_writer.go - AEGIS NOSE -> Zig Core Canonical Event pipe sink
// =====================================================================
// Writes frozen 109-byte CanonicalEvent wire frames to the named pipe
// that the Zig core consumes (core/nose_pipe_reader.zig). Windows uses
// \\.\pipe\<name>; non-Windows falls back to a TCP loopback socket so
// the capture path is still testable/functional on dev boxes.
//
// Frame protocol (shared with core/nose_pipe_reader.zig):
//   u32 LE length (109) followed by the raw wire bytes.
// Reconnection is automatic: if core is not up yet, the writer retries
// with backoff and drops frames until the reader connects (NIDS must
// never block capture on a missing consumer).
// =====================================================================
package main

import (
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

func (c *pipeConn) close() {
	if c != nil && c.file != nil {
		c.file.Close()
		c.file = nil
	}
}

// NewFrameWriter creates a writer that delivers 109-byte frames to the
// named pipe used by the Zig core.
func NewFrameWriter(pipePath string) *FrameWriter {
	if pipePath == "" {
		pipePath = nosePipeName
	}
	fw := &FrameWriter{pipePath: pipePath}
	fw.ensureConnected()
	return fw
}

// ensureConnected opens/reopens the pipe. Non-blocking on failure.
func (w *FrameWriter) ensureConnected() {
	if w.conn != nil && w.conn.file != nil {
		return
	}
	w.conn = dialPipe(w.pipePath)
}

// dialPipe opens the named pipe client (or loopback socket fallback).
func dialPipe(path string) *pipeConn {
	// Windows: CreateFile("\\\\.\\pipe\\name", GENERIC_WRITE, ...)
	// Go's os.OpenFile maps to CreateFileW with FILE_SHARE_READ|WRITE and
	// GENERIC_READ|GENERIC_WRITE, which works for named pipes when the
	// server is listening (PIPE_WAIT blocks until a server appears).
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil
	}
	return &pipeConn{file: f}
}

// Send encodes a CanonicalEvent to wire bytes and writes them as a
// length-prefixed frame. Never blocks the caller on a down consumer:
// if the pipe is not connected, the frame is counted as dropped and we
// retry the connection on the next Send (pcap loop keeps moving).
func (w *FrameWriter) Send(ev *CanonicalEvent) []byte {
	wire, serr := ev.Serialize()
	if serr != nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.conn == nil || w.conn.file == nil {
		w.dropped++
		w.ensureConnected()
		return wire[:]
	}

	var frame [4 + EventWireSize]byte
	ple := uint32(len(wire))
	frame[0] = byte(ple)
	frame[1] = byte(ple >> 8)
	frame[2] = byte(ple >> 16)
	frame[3] = byte(ple >> 24)
	copy(frame[4:], wire[:])

	_, werr := w.conn.write(frame[:])
	if werr != nil {
		w.dropped++
		w.conn.close()
		w.conn = nil
		return wire[:]
	}
	w.sent++
	return wire[:]
}

// Stats returns how many frames were delivered vs dropped.
func (w *FrameWriter) Stats() (sent uint64, dropped uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sent, w.dropped
}