package main

// PIPE-096: fail-closed pins for the frame writer transport. A nil or
// closed connection must surface an error (never a silent partial frame);
// the short-write loop itself needs an OS pipe and stays covered by the
// live capture path, not by unit pins.
import "testing"

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
