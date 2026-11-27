// =====================================================================
// pipe_writer.go - AEGIS NOSE -> Zig Core Canonical Event pipe sink
// =====================================================================
// Writes frozen 109-byte CanonicalEvent wire frames to the named pipe
// that the Zig core consumes (src/capture/nose_pipe_reader.zig). Windows uses
// \\.\pipe\<name>; no TCP fallback is implemented (dialPipe uses os.OpenFile only).
// `core/*` names in manifests are module-ID aliases, not filesystem paths.
//
// Frame protocol (shared with src/capture/nose_pipe_reader.zig):
//
//	u32 LE length (109 v1, 133 v2, or 165..1189 v3) followed by raw wire bytes.
//	v1/v2 are metadata-only compatibility frames; v3 carries bounded payload
//	and capture provenance (PAYLOAD-ENVELOPE-V3-001).
//
// Reconnection is lazy: if core is not up yet, the writer drops the current
// frame and dials again on the next frame (NIDS must never block capture on a
// missing consumer). There is no sleep/backoff in the live path.
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
	mu       sync.Mutex
	pipePath string
	conn     *pipeConn
	dropped  uint64
	sent     uint64
}

// pipeSink is the minimal sink contract used by writeAll. Production uses an
// *os.File named-pipe handle; tests inject an in-memory sink so short writes
// and mid-frame errors are exercised without a pipe or host handle.
type pipeSink interface {
	Write([]byte) (int, error)
	Close() error
}

// pipeConn wraps a Windows named-pipe file handle; there is no TCP socket path.
type pipeConn struct {
	file *os.File
	sink pipeSink // nil in production; hermetic test seam only
}

func (c *pipeConn) write(b []byte) (int, error) {
	if c == nil {
		return 0, os.ErrClosed
	}
	if c.sink != nil {
		return c.sink.Write(b)
	}
	if c.file == nil {
		return 0, os.ErrClosed
	}
	return c.file.Write(b)
}

// connected reports whether the next write has a usable sink or file. Test
// sinks are treated exactly like an opened pipe handle for framing purposes.
func (c *pipeConn) connected() bool {
	return c != nil && (c.file != nil || c.sink != nil)
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
	if c == nil {
		return
	}
	if c.sink != nil {
		_ = c.sink.Close()
		c.sink = nil
	}
	if c.file != nil {
		_ = c.file.Close()
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
	if w.conn.connected() {
		return
	}
	w.conn = dialPipe(w.pipePath)
}

// dialPipe opens the Windows named pipe client via os.OpenFile only (no TCP fallback).
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

	// Defense in depth: SerializeV3 already bounds payloads, but a direct
	// caller must never desynchronise the u32 length prefix from the bytes
	// written. Reject oversize wires instead of truncating or slicing past
	// the fixed frame buffer (wire layout is unchanged).
	if len(wire) > EventV3MaxWireSize {
		w.dropped++
		if w.dropped == 1 {
			fmt.Fprintf(os.Stderr, "[NOSE PIPE] first frame dropped: oversize wire %d > %d event_id=%d\n",
				len(wire), EventV3MaxWireSize, eventID)
		}
		return false
	}

	if !w.conn.connected() {
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
