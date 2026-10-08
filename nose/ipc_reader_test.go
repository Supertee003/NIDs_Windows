package main

// IPC-096: Bridge status-file reader fail-closed pins. The reader polls a
// JSON file another process owns, so every input shape must degrade to
// explicit unavailable/defaults: missing file, malformed JSON, and
// out-of-range DEFCON. Hermetic via t.TempDir (no tree writes); the poll
// goroutine is never started (readStatusFile is called directly).
import (
	"os"
	"path/filepath"
	"testing"
)

func writeStatusFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bridge_status.json")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMissingStatusFileIsUnavailable(t *testing.T) {
	r := NewIPCReader(filepath.Join(t.TempDir(), "absent.json"), 0)
	r.readStatusFile()
	if r.IsAvailable() {
		t.Fatal("missing file must read as unavailable")
	}
	if got := r.GetStatus(); got.DEFCONLevel != 5 {
		t.Fatalf("missing file must keep SAFE default, got %d", got.DEFCONLevel)
	}
}

func TestMalformedStatusJSONStaysUnavailable(t *testing.T) {
	r := NewIPCReader(writeStatusFile(t, "{bad json"), 0)
	r.readStatusFile()
	if r.IsAvailable() {
		t.Fatal("malformed JSON must read as unavailable")
	}
	if got := r.GetStatus(); got.DEFCONLevel != 5 {
		t.Fatalf("malformed JSON must keep SAFE default, got %d", got.DEFCONLevel)
	}
}

func TestValidStatusParsesAndReportsAvailable(t *testing.T) {
	r := NewIPCReader(writeStatusFile(t,
		`{"defcon_level":2,"defcon_label":"SEVERE","event_count":7,"blocked_ips":1}`), 0)
	r.readStatusFile()
	if !r.IsAvailable() {
		t.Fatal("valid file must read as available")
	}
	got := r.GetStatus()
	if got.DEFCONLevel != 2 || got.EventCount != 7 || got.BlockedIPs != 1 {
		t.Fatalf("parsed values mismatch: %+v", got)
	}
}

func TestOutOfRangeDefconClampsToSafe(t *testing.T) {
	r := NewIPCReader(writeStatusFile(t,
		`{"defcon_level":9,"defcon_label":"BOGUS","event_count":1}`), 0)
	r.readStatusFile()
	if !r.IsAvailable() {
		t.Fatal("structurally valid file must read as available")
	}
	got := r.GetStatus()
	if got.DEFCONLevel != 5 || got.DEFCONLabel != "SAFE" {
		t.Fatalf("out-of-range DEFCON must clamp to SAFE, got %+v", got)
	}
}
