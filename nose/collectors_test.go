// =====================================================================
// collectors_test.go - NOSE-SIM-139 synthesis-contract pins
// =====================================================================
// The fallback numbers and the TopTalkers block are synthetic by
// construction. These tests pin the Simulated flag and its wire form so
// no consumer can mistake synthesis for live telemetry.
package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestFallbackTrafficMarksSimulated(t *testing.T) {
	d := fallbackTraffic(1700000000, 7)
	if !d.Simulated {
		t.Fatal("fallback numbers must carry Simulated=true")
	}
	if d.RxPktsPerSec <= 0 || d.TxPktsPerSec <= 0 || d.ActiveConns <= 0 {
		t.Fatalf("fallback numbers must stay positive, got %+v", d)
	}
	// Deterministic for fixed inputs: same tick/now, same output.
	// (reflect: the struct carries slice fields, so == would panic.)
	again := fallbackTraffic(1700000000, 7)
	if !reflect.DeepEqual(d, again) {
		t.Fatalf("fallback must be deterministic:\n%+v\n%+v", d, again)
	}
}

func TestSimulatedFlagSurvivesJSON(t *testing.T) {
	d := fallbackTraffic(1700000000, 7)
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"simulated":true`) {
		t.Fatalf("wire form must carry the flag: %s", raw)
	}
}

func TestTrafficTitlesFollowTheFlag(t *testing.T) {
	if trafficTitle(TrafficData{Simulated: true}) != "Network Traffic (simulated)" {
		t.Fatal("synthetic data must be labeled simulated")
	}
	if trafficTitle(TrafficData{Simulated: false}) != "Network Traffic (live)" {
		t.Fatal("real data must be labeled live")
	}
	if talkersTitle(TrafficData{Simulated: true}) != "Top Talkers (simulated)" {
		t.Fatal("synthetic talkers must be labeled simulated")
	}
	if talkersTitle(TrafficData{Simulated: false}) != "Top Talkers (live)" {
		t.Fatal("real talkers must be labeled live")
	}
}
