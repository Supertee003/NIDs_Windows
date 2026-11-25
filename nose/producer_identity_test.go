package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestIssueProducerGenerationAdvancesAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nose_producer_generation.json")
	g1, err := issueProducerGeneration("eth0", path, 1_700_000_000)
	if err != nil {
		t.Fatalf("first issue: %v", err)
	}
	g2, err := issueProducerGeneration("eth0", path, 1_700_000_005)
	if err != nil {
		t.Fatalf("second issue: %v", err)
	}
	if g1 != 1 || g2 != 2 {
		t.Fatalf("generation must advance 1 -> 2, got %d -> %d", g1, g2)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var st producerState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("state json: %v", err)
	}
	if st.Version != producerStateVersion || st.Generations["eth0"] != 2 || st.UpdatedUnix != 1_700_000_005 {
		t.Fatalf("state shape: %+v", st)
	}
}

func TestIssueProducerGenerationIsPerInterface(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nose_producer_generation.json")
	if _, err := issueProducerGeneration("eth0", path, 1); err != nil {
		t.Fatalf("eth0 issue: %v", err)
	}
	g, err := issueProducerGeneration("eth1", path, 2)
	if err != nil {
		t.Fatalf("eth1 issue: %v", err)
	}
	if g != 1 {
		t.Fatalf("new interface must start at generation 1, got %d", g)
	}
}

func TestIssueProducerGenerationFailsClosedOnStaleLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nose_producer_generation.json")
	lockPath := path + ".lock"
	if err := os.WriteFile(lockPath, []byte("held"), 0o600); err != nil {
		t.Fatalf("seed lock: %v", err)
	}
	if _, err := issueProducerGeneration("eth0", path, 3); err == nil {
		t.Fatal("stale/exclusive lock must fail closed, not issue a duplicate generation")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("failed issue must not create state: %v", err)
	}
}

func TestNewLiveCaptureProvenanceUsesConfiguredState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nose_producer_generation.json")
	t.Setenv(producerStateEnv, path)
	p1, err := newLiveCaptureProvenance("iface-1")
	if err != nil {
		t.Fatalf("first live tuple: %v", err)
	}
	p2, err := newLiveCaptureProvenance("iface-1")
	if err != nil {
		t.Fatalf("second live tuple: %v", err)
	}
	if p1.generation != 1 || p2.generation != 2 {
		t.Fatalf("restart generations must differ: %+v -> %+v", p1, p2)
	}
	if p1.epoch == 0 || p1.interfaceID == 0 || p1.interfaceID != p2.interfaceID {
		t.Fatalf("epoch/interface tuple invalid: %+v -> %+v", p1, p2)
	}
}

func TestNextCaptureSequenceIsDedicatedAndMonotonic(t *testing.T) {
	before := atomic.LoadUint64(&captureSequence)
	a := nextCaptureSequence()
	b := nextCaptureSequence()
	if a != before+1 || b != before+2 {
		t.Fatalf("capture sequence must be dedicated and monotonic: %d, %d after %d", a, b, before)
	}
}
