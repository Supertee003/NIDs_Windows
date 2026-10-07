// =====================================================================
// collectors_test.go - NOSE-SIM-139 synthesis-contract pins
// =====================================================================
// The fallback numbers and the TopTalkers block are synthetic by
// construction. These tests pin the Simulated flag and its wire form so
// no consumer can mistake synthesis for live telemetry.
package main

import (
	"encoding/binary"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestRatePerSecNormal(t *testing.T) {
	if got := ratePerSec(1500, 1000, 1.0); got != 500 {
		t.Fatalf("want 500, got %v", got)
	}
	if got := ratePerSec(1000, 1000, 1.0); got != 0 {
		t.Fatalf("no delta must be 0, got %v", got)
	}
}

func TestRatePerSecBadDt(t *testing.T) {
	if got := ratePerSec(9999, 0, 0); got != 0 {
		t.Fatalf("zero dt must be 0, got %v", got)
	}
	if got := ratePerSec(9999, 0, -2.5); got != 0 {
		t.Fatalf("negative dt must be 0, got %v", got)
	}
}

func TestRatePerSecWrap(t *testing.T) {
	// 32-bit source counter wrapped: (2^32 - prev) + cur over dt.
	const max32 = uint64(1) << 32
	prev := max32 - 100
	cur := uint64(400)
	if got := ratePerSec(cur, prev, 1.0); got != 500 {
		t.Fatalf("wrap delta must be 500, got %v", got)
	}
}

func tcpRow(state uint32) []byte {
	b := make([]byte, tcpRowSize)
	binary.LittleEndian.PutUint32(b[0:4], state)
	return b
}

func TestParseTcpTableCountsEstabOnly(t *testing.T) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[0:4], 3)
	buf = append(buf, tcpRow(5)...) // ESTABLISHED
	buf = append(buf, tcpRow(2)...) // LISTEN
	buf = append(buf, tcpRow(5)...) // ESTABLISHED
	n, err := parseTcpTable(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n != 2 {
		t.Fatalf("want 2 established, got %d", n)
	}
}

func TestParseTcpTableRejectsShort(t *testing.T) {
	if _, err := parseTcpTable([]byte{1, 2, 3}); err == nil {
		t.Fatal("short header must error")
	}
	short := make([]byte, 4)
	binary.LittleEndian.PutUint32(short[0:4], 2)
	short = append(short, tcpRow(5)...) // one row short of two
	if _, err := parseTcpTable(short); err == nil {
		t.Fatal("truncated rows must error")
	}
	empty := make([]byte, 4)
	if n, err := parseTcpTable(empty); err != nil || n != 0 {
		t.Fatalf("zero rows must be (0, nil), got (%d, %v)", n, err)
	}
}

func resetLiveTalkers() {
	liveTalkerTable.Lock()
	defer liveTalkerTable.Unlock()
	liveTalkerTable.byIP = map[string]*talkerStat{}
	liveTalkerTable.proto = [4]int64{}
	liveTalkerTable.updated = 0
}

func TestObserveMapsDirections(t *testing.T) {
	resetLiveTalkers()
	observeLivePacket("10.0.0.1", "10.0.0.2", 100, 6)
	observeLivePacket("10.0.0.1", "10.0.0.2", 50, 6)
	observeLivePacket("10.0.0.2", "10.0.0.1", 25, 17)
	talkers, proto, ok := snapshotLiveTalkersAt(time.Now().UnixNano(), 5)
	if !ok {
		t.Fatal("fresh table must snapshot ok")
	}
	if len(talkers) != 2 {
		t.Fatalf("want 2 endpoints, got %d", len(talkers))
	}
	// 10.0.0.1: tx=150, rx=25, total=175. 10.0.0.2: tx=25, rx=150, total=175.
	// Tie on total breaks by IP ascending: 10.0.0.1 first.
	if talkers[0].IP != "10.0.0.1" || talkers[0].TxBytes != 150 || talkers[0].RxBytes != 25 {
		t.Fatalf("first talker wrong: %+v", talkers[0])
	}
	if talkers[1].IP != "10.0.0.2" || talkers[1].TxBytes != 25 || talkers[1].RxBytes != 150 {
		t.Fatalf("second talker wrong: %+v", talkers[1])
	}
	if proto != [4]int64{2, 1, 0, 0} {
		t.Fatalf("proto buckets wrong: %v", proto)
	}
	resetLiveTalkers()
}

func TestObserveIgnoresEmpty(t *testing.T) {
	resetLiveTalkers()
	observeLivePacket("10.0.0.1", "10.0.0.2", 0, 6)
	observeLivePacket("10.0.0.1", "10.0.0.2", -5, 6)
	if _, _, ok := snapshotLiveTalkersAt(time.Now().UnixNano(), 5); ok {
		t.Fatal("empty observations must not create entries")
	}
}

func TestSnapshotExpiresStaleTable(t *testing.T) {
	resetLiveTalkers()
	observeLivePacket("10.0.0.1", "10.0.0.2", 100, 6)
	if _, _, ok := snapshotLiveTalkersAt(time.Now().UnixNano(), 5); !ok {
		t.Fatal("fresh table must snapshot ok")
	}
	// Far-future now exceeds the freshness window.
	if _, _, ok := snapshotLiveTalkersAt(time.Now().UnixNano()+talkersFreshnessNs*2, 5); ok {
		t.Fatal("stale table must not snapshot ok")
	}
	resetLiveTalkers()
}

func TestTableEvictionBoundsMemory(t *testing.T) {
	resetLiveTalkers()
	for i := 0; i < talkersTableCap+100; i++ {
		observeLivePacket(string(rune('a'+i%26))+string(rune('0'+i/26%10))+string(rune('0'+i/260%10)), "dst", 10, 6)
	}
	liveTalkerTable.Lock()
	n := len(liveTalkerTable.byIP)
	liveTalkerTable.Unlock()
	if n > talkersTableCap {
		t.Fatalf("table must stay bounded, got %d entries", n)
	}
	resetLiveTalkers()
}

func TestApplyLiveTalkersBranches(t *testing.T) {
	resetLiveTalkers()
	// Stale/empty table: synthetic kept, flag set.
	d := TrafficData{}
	applyLiveTalkers(&d, true)
	if !d.Simulated {
		t.Fatal("without live data the flag must stay set")
	}
	if len(d.TopTalkers) != 0 {
		t.Fatal("without live data no talkers must be installed")
	}
	// Fresh table + real numbers: live installed, flag cleared.
	observeLivePacket("10.9.9.9", "10.9.9.10", 1000, 6)
	d2 := TrafficData{Simulated: true}
	applyLiveTalkers(&d2, true)
	if d2.Simulated {
		t.Fatal("fully real sections must clear the flag")
	}
	if len(d2.TopTalkers) == 0 || d2.TopTalkers[0].Total != 1000 {
		t.Fatalf("live talkers must be installed: %+v", d2.TopTalkers)
	}
	if len(d2.Protocols) != 4 || d2.Protocols[0].Count != 1 {
		t.Fatalf("live protocol shares must be installed: %+v", d2.Protocols)
	}
	// Fresh table + failed numbers: mixed state stays flagged.
	d3 := TrafficData{}
	applyLiveTalkers(&d3, false)
	if !d3.Simulated {
		t.Fatal("mixed real/synthetic must stay flagged")
	}
	if len(d3.TopTalkers) == 0 {
		t.Fatal("live talkers install even when numbers failed")
	}
	resetLiveTalkers()
}
