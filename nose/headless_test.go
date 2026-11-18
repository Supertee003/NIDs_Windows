// =====================================================================
// headless_test.go - NOSE-JSON-166 headless beacon contract pins (TDD)
//
// Seam under test: the headless stdout JSON beacon (RUNTIME_CONTRACT
// §4.1 "stdout JSON line" transport, consumed by the supervisor and
// tests/runtime). Expected values below are independent hand-written
// literals, never recomputed from the implementation.
package main

import (
	"reflect"
	"testing"
	"time"
)

func TestBuildHeadlessStateContractKeys(t *testing.T) {
	start := time.Now().Add(-90 * time.Second)
	traf := TrafficData{RxPktsPerSec: 10, TxPktsPerSec: 5, ActiveConns: 2, Simulated: true}
	state := buildHeadlessState(ResourceData{}, traf, ThreatData{}, &headlessTelemetry{}, start, 4242)

	for _, k := range []string{"op", "component", "state", "version",
		"pid", "uptime_ms", "last_event_ms", "counters", "deps",
		"timestamp", "resource", "traffic", "threat"} {
		if _, ok := state[k]; !ok {
			t.Fatalf("missing contract key %q", k)
		}
	}
	if state["op"] != "HEALTH" {
		t.Fatalf("op must be HEALTH, got %v", state["op"])
	}
	if state["component"] != "nose" {
		t.Fatalf("component must be nose, got %v", state["component"])
	}
	if state["pid"] != 4242 {
		t.Fatalf("pid must pass through, got %v", state["pid"])
	}
	counters, ok := state["counters"].(map[string]interface{})
	if !ok {
		t.Fatalf("counters must be an object, got %T", state["counters"])
	}
	for _, k := range []string{"in_events", "out_events", "errors", "dropped"} {
		if _, ok := counters[k]; !ok {
			t.Fatalf("missing counter %q", k)
		}
	}
	if !reflect.DeepEqual(state["traffic"], traf) {
		t.Fatalf("traffic section must carry the input struct unchanged")
	}
	uptime, ok := state["uptime_ms"].(int64)
	if !ok || uptime < 89000 {
		t.Fatalf("uptime_ms must reflect the 90s-old start, got %v", state["uptime_ms"])
	}
}

// DEADCODE-QUARANTINE: the headless beacon's counters used to be hardcoded
// zeros, so a supervisor could not tell a live collector loop from a dead
// one. In headless mode nose's "events" are its collector samples: in_events
// counts consumed samples, out_events counts emitted beacons, and
// last_event_ms is the age of the most recent sample (0 = none yet, honest;
// >5x health interval = soft failure per RUNTIME_CONTRACT §4.1).
func TestHeadlessTelemetryCountersMoveWithWork(t *testing.T) {
	tel := &headlessTelemetry{}
	if age := tel.lastEventAgeMs(time.Now()); age != 0 {
		t.Fatalf("no events yet must age 0 (honest never), got %d", age)
	}
	base := time.Now()
	tel.noteSamples(0, base)
	if tel.inEvents != 0 {
		t.Fatalf("consuming no samples must not count, got %d", tel.inEvents)
	}
	tel.noteSamples(2, base)
	tel.noteBeacon()
	tel.noteBeacon()
	if tel.inEvents != 2 || tel.outEvents != 2 {
		t.Fatalf("counters must move with work: in=%d out=%d", tel.inEvents, tel.outEvents)
	}
	if age := tel.lastEventAgeMs(base.Add(1500 * time.Millisecond)); age != 1500 {
		t.Fatalf("age must track the last sample (1500ms), got %d", age)
	}
}

func TestBuildHeadlessStateReportsTelemetryNotZeros(t *testing.T) {
	start := time.Now().Add(-90 * time.Second)
	tel := &headlessTelemetry{}
	tel.noteSamples(3, time.Now().Add(-2*time.Second))
	tel.noteBeacon()
	state := buildHeadlessState(ResourceData{}, TrafficData{}, ThreatData{}, tel, start, 4242)
	counters, ok := state["counters"].(map[string]interface{})
	if !ok {
		t.Fatalf("counters must be an object, got %T", state["counters"])
	}
	if counters["in_events"] != uint64(3) {
		t.Fatalf("in_events must carry telemetry, got %v", counters["in_events"])
	}
	if counters["out_events"] != uint64(1) {
		t.Fatalf("out_events must carry telemetry, got %v", counters["out_events"])
	}
	age, ok := state["last_event_ms"].(int64)
	if !ok || age < 1800 || age > 10000 {
		t.Fatalf("last_event_ms must age ~2s, got %v", state["last_event_ms"])
	}
}
