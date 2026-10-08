package main

// FFI-096: frozen v1 golden-vector pins for the cross-language Deserialize
// path. Field expectations below are copied from
// tests/contracts/event_vectors/event_vectors/golden_vectors.json
// (event_v1_001.bin: benign forward 192.168.1.100 -> 10.0.0.1:80); if the
// fixtures ever regenerate, this test MUST be re-anchored deliberately,
// never loosened. Negative cases are fixture-derived (mutate one gate at
// a time) so they depend on no unstated valid-set membership.
import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func mustDeserializeFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorsDir(), "event_v1_001.bin"))
	if err != nil {
		t.Fatalf("fixture unreadable: %v", err)
	}
	return raw
}

func TestDeserializeFrozenV1Vector(t *testing.T) {
	ev, err := Deserialize(mustDeserializeFixture(t))
	if err != nil {
		t.Fatalf("frozen vector must deserialize: %v", err)
	}
	if ev.EventID != 1001 {
		t.Fatalf("EventID = %d, want 1001", ev.EventID)
	}
	if ev.Source != 1 {
		t.Fatalf("Source = %d, want 1", ev.Source)
	}
	if ev.SourceIP != 0xC0A80164 {
		t.Fatalf("SourceIP = %#x, want 0xC0A80164", ev.SourceIP)
	}
	if ev.DestIP != 0x0A000001 {
		t.Fatalf("DestIP = %#x, want 0x0A000001", ev.DestIP)
	}
	if ev.DestPort != 80 || ev.Protocol != 6 {
		t.Fatalf("ports/proto = %d/%d, want 80/6", ev.DestPort, ev.Protocol)
	}
	if ev.EventType != 2 || ev.PolicyAction != 0 || ev.Confidence != 0 {
		t.Fatalf("type/action/confidence = %d/%d/%d, want 2/0/0",
			ev.EventType, ev.PolicyAction, ev.Confidence)
	}
}

func TestDeserializeRejectsMalformedFrames(t *testing.T) {
	valid := mustDeserializeFixture(t)
	mutate := func(f func([]byte)) []byte {
		b := append([]byte(nil), valid...)
		f(b)
		return b
	}
	cases := map[string][]byte{
		"short":        valid[:10],
		"long":         append(append([]byte(nil), valid...), 0x00),
		"bad magic":    mutate(func(b []byte) { b[0] ^= 0xFF }),
		"bad version":  mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[4:6], 0xFFFF) }),
		"bad size":     mutate(func(b []byte) { binary.LittleEndian.PutUint16(b[6:8], 0xFFFF) }),
		"bad conf":     mutate(func(b []byte) { b[93+ResOffConfidence] = 101 }),
		"empty":        {},
		"nil":          nil,
	}
	for name, frame := range cases {
		if _, err := Deserialize(frame); err == nil {
			t.Fatalf("%s frame must be rejected, got nil error", name)
		}
	}
}
