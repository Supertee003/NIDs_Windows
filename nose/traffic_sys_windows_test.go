package main

// WRAP-096: 32-bit NIC counter wrap pins for ratePerSec. A wrapped counter
// misread as a negative (or clamped) delta would zero out traffic gauges
// silently; the single-wrap branch must produce the exact resumed rate.
import "testing"

func TestRatePerSecNormalDelta(t *testing.T) {
	if got := ratePerSec(100, 0, 10); got != 10.0 {
		t.Fatalf("normal delta: got %v, want 10.0", got)
	}
	if got := ratePerSec(50, 50, 10); got != 0.0 {
		t.Fatalf("no change: got %v, want 0.0", got)
	}
}

func TestRatePerSecRejectsNonPositiveInterval(t *testing.T) {
	if got := ratePerSec(100, 0, 0); got != 0.0 {
		t.Fatalf("zero dt: got %v, want 0.0", got)
	}
	if got := ratePerSec(100, 0, -5); got != 0.0 {
		t.Fatalf("negative dt: got %v, want 0.0", got)
	}
}

func TestRatePerSecSingleWrap(t *testing.T) {
	// Counter sat at 2^32-10, wrapped once, now reads 10: true delta is 20.
	const max32 = uint64(1) << 32
	if got := ratePerSec(10, max32-10, 10); got != 2.0 {
		t.Fatalf("single wrap: got %v, want 2.0", got)
	}
}
