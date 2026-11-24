package main

// PIPE-096: fail-closed pins for the frame writer transport. A nil or
// closed connection must surface an error (never a silent partial frame);
// the short-write loop itself needs an OS pipe and stays covered by the
// live capture path, not by unit pins.
import (
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
