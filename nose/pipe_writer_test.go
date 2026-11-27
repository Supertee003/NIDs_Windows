package main

// PIPE-096: fail-closed pins for the frame writer transport. A nil or
// closed connection must surface an error (never a silent partial frame);
// the short-write loop itself needs an OS pipe and stays covered by the
// live capture path, not by unit pins.
import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestWriteAllFailsClosedOnNilConn(t *testing.T) {
	var c *pipeConn
	if err := c.writeAll([]byte{0x01, 0x02}); err == nil {
		t.Fatal("nil conn writeAll must fail, got nil error")
	}
}

func TestWriteAllFailsClosedOnClosedConn(t *testing.T) {
	c := &pipeConn{}
	if err := c.writeAll([]byte{0x01, 0x02}); err == nil {
		t.Fatal("closed conn writeAll must fail, got nil error")
	}
}

// WIRE-GUARD-001: an oversize wire must be rejected, never truncated or sliced
// past the fixed frame buffer; the u32 length prefix stays in sync with bytes.
func TestSendWireRejectsOversizeFrame(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "aegis-pipe-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &FrameWriter{pipePath: "test", conn: &pipeConn{file: f}}
	if w.sendWire(make([]byte, EventV3MaxWireSize+1), 1) {
		t.Fatal("oversize wire must be rejected")
	}
	sent, dropped := w.Stats()
	if sent != 0 || dropped != 1 {
		t.Fatalf("want sent=0 dropped=1, got sent=%d dropped=%d", sent, dropped)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("rejected frame must write nothing, got %d bytes", info.Size())
	}
}

// scriptedSink is an in-memory pipeConn sink. It never touches the host pipe.
type scriptedSink struct {
	maxWrite  int // 0 means accept the whole buffer
	failAfter int // bytes accepted before failErr; -1 means never fail
	failErr   error
	written   []byte
	closed    bool
}

func (s *scriptedSink) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := len(p)
	if s.maxWrite > 0 && n > s.maxWrite {
		n = s.maxWrite
	}
	if s.failAfter >= 0 && len(s.written)+n >= s.failAfter {
		remaining := s.failAfter - len(s.written)
		if remaining <= 0 {
			if s.failErr == nil {
				return 0, errors.New("scripted sink failure")
			}
			return 0, s.failErr
		}
		if remaining < n {
			n = remaining
		}
		s.written = append(s.written, p[:n]...)
		return n, s.failErr
	}
	s.written = append(s.written, p[:n]...)
	return n, nil
}

func (s *scriptedSink) Close() error {
	s.closed = true
	return nil
}

func lengthPrefixedFrame(wire []byte) []byte {
	frame := make([]byte, 4+len(wire))
	n := uint32(len(wire))
	frame[0] = byte(n)
	frame[1] = byte(n >> 8)
	frame[2] = byte(n >> 16)
	frame[3] = byte(n >> 24)
	copy(frame[4:], wire)
	return frame
}

// A short OS write must be completed by writeAll without losing or
// duplicating frame bytes; the u32 prefix stays in front of the whole wire.
func TestSendWireCompletesShortWrite(t *testing.T) {
	wire := bytes.Repeat([]byte{0x5A}, 24)
	sink := &scriptedSink{maxWrite: 7, failAfter: -1}
	w := &FrameWriter{conn: &pipeConn{sink: sink}}
	if !w.sendWire(wire, 9) {
		t.Fatal("short write must be completed, not reported as failure")
	}
	if want := lengthPrefixedFrame(wire); !bytes.Equal(sink.written, want) {
		t.Fatalf("short-write frame = % x, want % x", sink.written, want)
	}
	if sink.closed {
		t.Fatal("successful frame must not close the sink")
	}
	if sent, dropped := w.Stats(); sent != 1 || dropped != 0 {
		t.Fatalf("want sent=1 dropped=0, got sent=%d dropped=%d", sent, dropped)
	}
}

// A mid-frame error must fail closed, close the sink and clear conn so the
// next frame cannot be appended to a partially written frame.
func TestSendWireMidFrameErrorDropsConnection(t *testing.T) {
	wire := bytes.Repeat([]byte{0xA5}, 24)
	midErr := errors.New("scripted mid-frame failure")
	sink := &scriptedSink{maxWrite: 9, failAfter: 13, failErr: midErr}
	w := &FrameWriter{pipePath: "scripted", conn: &pipeConn{sink: sink}}
	if w.sendWire(wire, 10) {
		t.Fatal("mid-frame write error must fail closed")
	}
	if len(sink.written) != 13 {
		t.Fatalf("accepted %d bytes before error, want 13", len(sink.written))
	}
	if !sink.closed {
		t.Fatal("failed sink must be closed")
	}
	if w.conn != nil {
		t.Fatal("failed sink must be detached so the next frame reconnects")
	}
	if sent, dropped := w.Stats(); sent != 0 || dropped != 1 {
		t.Fatalf("want sent=0 dropped=1, got sent=%d dropped=%d", sent, dropped)
	}
}

// With no consumer the first frame is dropped and a connection is attempted;
// the next frame uses that connection and carries only its own prefix+wire.
func TestSendWireReconnectsOnNextFrame(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "aegis-reconnect-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &FrameWriter{pipePath: f.Name()}
	if w.sendWire([]byte{1, 2, 3}, 11) {
		t.Fatal("missing consumer must drop the frame")
	}
	if w.conn == nil {
		t.Fatal("ensureConnected must have dialed the available sink")
	}
	if !w.sendWire([]byte{4, 5}, 12) {
		t.Fatal("frame after reconnect must be delivered")
	}
	if sent, dropped := w.Stats(); sent != 1 || dropped != 1 {
		t.Fatalf("want sent=1 dropped=1, got sent=%d dropped=%d", sent, dropped)
	}
	w.conn.close()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if want := lengthPrefixedFrame([]byte{4, 5}); !bytes.Equal(data, want) {
		t.Fatalf("file after reconnect = % x, want % x", data, want)
	}
}
