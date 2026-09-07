// =====================================================================
// canonical_test.go - cross-language golden-vector verification
// =====================================================================
// This test reproduces the EXACT wire bytes that core/canonical_event.zig
// produces for the same field values (the T2 golden vector). If Zig and
// Go ever diverge, one of the two golden tests fails — the schema is
// therefore verified consistently across both languages.
// =====================================================================
package main

import (
	"encoding/binary"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// goldenEvent builds the same event the Zig golden-vector test uses.
func goldenEvent() *CanonicalEvent {
	return &CanonicalEvent{
		EventID:           0x1122334455667788,
		TimestampMS:       0xAABBCCDDEEFF0011,
		MonotonicNS:       0x9988776655443322,
		Source:            SourceNpcapSensor, // 9
		SourceIP:          0xC0A80164,
		SourcePort:        49152,
		DestIP:            0xAC1F0A0A,
		DestPort:          443,
		SessionID:         0xDEADBEEFCAFEBABE,
		Protocol:          6,
		LayerID:           0,
		EventType:         TypeMatch, // 1
		Severity:          2,
		RuleID:            0x01020304,
		RulesetVersion:    7,
		PayloadLength:     1500,
		PayloadHash:       0x0BADF00DBEEFDEAD,
		PolicyAction:      ActionAlert, // 1
		EnforcementStatus: 1,
		DefconImpact:      4,
		ContextFlags:      0x00000003,
		PID:               4242,
		PPID:              800,
		NodeID:            0x00007B00,
		Confidence:        95,
	}
}

// goldenBytes is the frozen wire output — byte-for-byte identical to
// the Zig golden vector embedded in core/canonical_event.zig.
func goldenBytes() [109]byte {
	return [109]byte{
		0x31, 0x47, 0x45, 0x41, 0x01, 0x00, 0x80, 0x00,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
		0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		0x09, 0x64, 0x01, 0xA8, 0xC0, 0x00, 0xC0, 0x0A,
		0x0A, 0x1F, 0xAC, 0xBB, 0x01, 0xBE, 0xBA, 0xFE,
		0xCA, 0xEF, 0xBE, 0xAD, 0xDE, 0x06, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x04, 0x03,
		0x02, 0x01, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0xDC, 0x05, 0x00, 0x00, 0xAD, 0xDE,
		0xEF, 0xBE, 0x0D, 0xF0, 0xAD, 0x0B, 0x01, 0x01,
		0x04, 0x03, 0x00, 0x00, 0x00, 0x92, 0x10, 0x00,
		0x00, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x7B, 0x00, 0x00, 0x5F,
	}
}

func TestGoldenVector(t *testing.T) {
	ev := goldenEvent()
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	gold := goldenBytes()
	if wire != gold {
		t.Fatalf("golden vector mismatch:\n  got  % x\n  want % x", wire, gold)
	}
}

func TestSchemaVersionAndOffsets(t *testing.T) {
	ev := goldenEvent()
	wire, _ := ev.Serialize()
	if binary.LittleEndian.Uint16(wire[4:6]) != EventSchemaVersion {
		t.Fatal("schema version != 1 at wire offset 4")
	}
	if wire[32] != SourceNpcapSensor {
		t.Fatal("source != npcap_sensor at wire offset 32")
	}
	if binary.LittleEndian.Uint64(wire[45:53]) != 0xDEADBEEFCAFEBABE {
		t.Fatal("session_id/source_id mismatch at wire offset 45")
	}
}

func TestSourceClassificationMatchesZig(t *testing.T) {
	// Mirrors SourceKind.classify in Zig — every T2-required kind.
	cases := map[byte]string{
		SourceNpcapSensor:      "network",
		SourceWfpSensor:        "network",
		SourceHostTelemetry:    "host",
		SourceProcessSensor:    "process",
		SourceFileSensor:       "file",
		SourceRegistrySensor:   "registry",
		SourceMlDetector:       "ml",
		SourceClusterFed:       "federation",
		SourceReplaySensor:     "replay",
		SourceGoAggregator:     "core",
		SourceExternal:         "external",
	}
	const (
		kindNetwork byte = iota
		kindHost
		kindProcess
		kindFile
		kindRegistry
		kindML
		kindFederation
		kindReplay
		kindCore
	)
	want := map[byte]byte{
		SourceNpcapSensor:    kindNetwork,
		SourceWfpSensor:      kindNetwork,
		SourceHostTelemetry:  kindHost,
		SourceProcessSensor:  kindProcess,
		SourceFileSensor:     kindFile,
		SourceRegistrySensor: kindRegistry,
		SourceMlDetector:     kindML,
		SourceClusterFed:     kindFederation,
		SourceReplaySensor:   kindReplay,
		SourceGoAggregator:   kindCore,
		SourceExternal:       255, // canonical external kind, matches Zig
	}
	for src, expected := range want {
		got := classifyGo(src)
		if got != expected {
			t.Fatalf("classify(%s): got %d want %d", cases[src], got, expected)
		}
	}
	_ = cases
}

func TestMalformedInput(t *testing.T) {
	if _, err := (&CanonicalEvent{Confidence: 200}).Serialize(); err == nil {
		t.Fatal("confidence > 100 should be rejected")
	}
}

func TestEventFromPacketSynthetic(t *testing.T) {
	// Build a synthetic in-memory TCP/IPv4 packet via gopacket —
	// no live interface required. (Live capture covered by self-test + E2E.)
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{172, 31, 10, 10},
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 49152,
		DstPort: 443,
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}, ip, tcp, gopacket.Payload([]byte("hello-aegis"))); err != nil {
		t.Fatalf("serialize synthetic packet: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy)
	ev := eventFromPacket(pkt)
	if ev.Source != SourceNpcapSensor {
		t.Fatal("captured event must carry npcap_sensor source")
	}
	if ev.Protocol != 6 {
		t.Fatalf("expected tcp protocol 6, got %d", ev.Protocol)
	}
	if ev.SourcePort != 49152 || ev.DestPort != 443 {
		t.Fatalf("expected 49152/443, got %d/%d", ev.SourcePort, ev.DestPort)
	}
	if ev.PayloadLength != 11 { // "hello-aegis"
		t.Fatalf("expected payload len 11, got %d", ev.PayloadLength)
	}
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize captured event: %v", err)
	}
	if len(wire) != EventWireSize {
		t.Fatalf("wire size %d", len(wire))
	}
}