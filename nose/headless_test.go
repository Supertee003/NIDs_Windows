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
	state := buildHeadlessState(ResourceData{}, traf, ThreatData{}, start, 4242)

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
