// C6 capture visibility / shutdown pins. No pipe, Npcap, elevation or
// host effect. No CanonicalEvent layout or rule changes.
package main

import (
	"strings"
	"testing"
	"time"
)

func TestNoseCaptureBPFAdmitsVLAN(t *testing.T) {
	for _, term := range []string{"vlan", "ip", "ip6", "or"} {
		if !strings.Contains(noseCaptureBPF, term) {
			t.Fatalf("noseCaptureBPF %q missing %q", noseCaptureBPF, term)
		}
	}
}

func TestMonotonicNowNSIsProcessRelative(t *testing.T) {
	first := monotonicNowNS()
	// Wall-clock UnixNano is ~1.7e18; process-relative must be < one hour.
	const oneHourNS uint64 = 3_600_000_000_000
	if first >= oneHourNS {
		t.Fatalf("monotonic_ns %d is wall-clock, not process-relative", first)
	}
	time.Sleep(time.Millisecond)
	second := monotonicNowNS()
	if second < first {
		t.Fatalf("monotonic_ns went backwards: %d -> %d", first, second)
	}
}

func TestCollectorStopHelpersRespectClosedChannel(t *testing.T) {
	stop := make(chan struct{})
	if collectorStopped(stop) {
		t.Fatal("open stop channel must not report stopped")
	}
	if sleepOrStop(stop, time.Millisecond) {
		t.Fatal("sleepOrStop must return false on timer")
	}
	close(stop)
	if !collectorStopped(stop) {
		t.Fatal("closed stop channel must report stopped")
	}
	started := time.Now()
	if !sleepOrStop(stop, time.Hour) {
		t.Fatal("sleepOrStop must return true immediately on closed stop")
	}
	if time.Since(started) > time.Second {
		t.Fatal("sleepOrStop blocked despite closed stop channel")
	}
}
