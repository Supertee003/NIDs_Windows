package main

// TALKERS-096: endpoint-symmetry pins for live talker attribution.
// observeLivePacket must credit tx to the source and rx to the destination
// with no local-IP knowledge. The table is package-global with no reset,
// so these pins use documentation-range IPs no other test touches and
// look entries up by key (residue-tolerant); they never assert global
// emptiness or exact table size.
import (
	"testing"
	"time"
)

const (
	talkersTestSrc = "198.51.100.99"
	talkersTestDst = "203.0.113.7"
)

func snapshotTestEntries(t *testing.T) map[string]TopTalkerEntry {
	t.Helper()
	entries, _, ok := snapshotLiveTalkersAt(time.Now().UnixNano(), 128)
	if !ok {
		t.Fatal("table must be non-empty after observe")
	}
	byIP := make(map[string]TopTalkerEntry, len(entries))
	for _, e := range entries {
		byIP[e.IP] = e
	}
	return byIP
}

func TestObserveLivePacketIsEndpointSymmetric(t *testing.T) {
	observeLivePacket(talkersTestSrc, talkersTestDst, 1000, 6)
	byIP := snapshotTestEntries(t)
	s, okS := byIP[talkersTestSrc]
	d, okD := byIP[talkersTestDst]
	if !okS || !okD {
		t.Fatal("observed endpoints missing from snapshot")
	}
	if s.TxBytes < 1000 || d.RxBytes < 1000 {
		t.Fatalf("symmetry broken: src.tx=%d dst.rx=%d, want >=1000 both",
			s.TxBytes, d.RxBytes)
	}
	if s.Total != s.TxBytes+s.RxBytes || d.Total != d.TxBytes+d.RxBytes {
		t.Fatalf("total must equal tx+rx: src=%+v dst=%+v", s, d)
	}
}

func TestObserveLivePacketIgnoresEmptyFrames(t *testing.T) {
	// Self-seeding: never assume another test ran first.
	observeLivePacket(talkersTestSrc, talkersTestDst, 10, 6)
	before := len(snapshotTestEntries(t))
	observeLivePacket(talkersTestSrc, talkersTestDst, 0, 6)
	observeLivePacket(talkersTestSrc, talkersTestDst, -5, 6)
	after := len(snapshotTestEntries(t))
	if before != after {
		t.Fatalf("empty frames must not create entries: %d -> %d", before, after)
	}
}
