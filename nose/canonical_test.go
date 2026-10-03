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
	"os"
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

func TestDeserializeRoundTripPreservesEventID(t *testing.T) {
	original := goldenEvent()
	wire, err := original.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var decoded CanonicalEvent
	if !decoded.Deserialize(wire) {
		t.Fatal("deserialize rejected a valid golden wire frame")
	}
	if decoded.EventID != original.EventID {
		t.Fatalf("event_id round-trip mismatch: got %#x want %#x", decoded.EventID, original.EventID)
	}
	if decoded.TimestampMS != original.TimestampMS || decoded.Source != original.Source {
		t.Fatalf("decoded canonical identity mismatch")
	}
}

func TestSourceClassificationMatchesZig(t *testing.T) {
	// Mirrors SourceKind.classify in Zig — every T2-required kind.
	cases := map[byte]string{
		SourceNpcapSensor:    "network",
		SourceWfpSensor:      "network",
		SourceHostTelemetry:  "host",
		SourceProcessSensor:  "process",
		SourceFileSensor:     "file",
		SourceRegistrySensor: "registry",
		SourceMlDetector:     "ml",
		SourceClusterFed:     "federation",
		SourceReplaySensor:   "replay",
		SourceGoAggregator:   "core",
		SourceExternal:       "external",
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

func TestCanonicalOrdinalsMatchZig(t *testing.T) {
	if TypeForward != 2 {
		t.Fatalf("forward event ordinal: got %d want 2", TypeForward)
	}
	if TypeMatch != 1 {
		t.Fatalf("match event ordinal: got %d want 1", TypeMatch)
	}
	if ActionLogOnly != 5 {
		t.Fatalf("log-only policy ordinal: got %d want 5", ActionLogOnly)
	}
	// VOL01-FOUNDATION-002: pin the full frozen vocabularies against Zig.
	sources := map[string]byte{
		"zig_core": 0, "wfp_sensor": 1, "pipe_sensor": 2, "minifilter": 3,
		"pipe_monitor": 4, "python_brain": 5, "cpp_bridge": 6,
		"rust_shield": 7, "go_aggregator": 8, "npcap_sensor": 9,
		"host_telemetry": 10, "ml_detector": 11, "cluster_federation": 12,
		"process_sensor": 13, "file_sensor": 14, "registry_sensor": 15,
		"replay_sensor": 16, "external": 255,
	}
	got := map[string]byte{
		"zig_core": SourceZigCore, "wfp_sensor": SourceWfpSensor,
		"pipe_sensor": SourcePipeSensor, "minifilter": SourceMinifilter,
		"pipe_monitor": SourcePipeMonitor, "python_brain": SourcePythonBrain,
		"cpp_bridge": SourceCppBridge, "rust_shield": SourceRustShield,
		"go_aggregator": SourceGoAggregator, "npcap_sensor": SourceNpcapSensor,
		"host_telemetry": SourceHostTelemetry, "ml_detector": SourceMlDetector,
		"cluster_federation": SourceClusterFed, "process_sensor": SourceProcessSensor,
		"file_sensor": SourceFileSensor, "registry_sensor": SourceRegistrySensor,
		"replay_sensor": SourceReplaySensor, "external": SourceExternal,
	}
	for name, want := range sources {
		if got[name] != want {
			t.Fatalf("source %s: got %d want %d", name, got[name], want)
		}
	}
	events := map[EventType]uint32{
		EventBlock: 0, EventMatch: 1, EventForward: 2, EventIpBlocked: 3,
		EventRejected: 4, EventSessionStart: 5, EventSessionEnd: 6,
		EventRulesetReload: 7, EventShutdown: 8, EventStartup: 9,
		EventCustom: 0xFFFFFFFF,
	}
	for ev, want := range events {
		if uint32(ev) != want {
			t.Fatalf("event_type: got %d want %d", uint32(ev), want)
		}
	}
	policies := map[PolicyAction]byte{
		PolicyAllow: 0, PolicyAlert: 1, PolicyBlock: 2,
		PolicyQuarantine: 3, PolicyRateLimit: 4, PolicyLogOnly: 5,
	}
	for pol, want := range policies {
		if byte(pol) != want {
			t.Fatalf("policy_action: got %d want %d", byte(pol), want)
		}
	}
}

func TestDeserializeRejectsContractViolations(t *testing.T) {
	ev := goldenEvent()
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	var decoded CanonicalEvent

	bad := wire
	bad[0] ^= 0xFF // corrupt magic
	if decoded.Deserialize(bad) {
		t.Fatal("deserialize accepted bad magic")
	}
	bad = wire
	bad[32] = 17 // no EventSource between replay(16) and external(255)
	if decoded.Deserialize(bad) {
		t.Fatal("deserialize accepted unknown source")
	}
	bad = wire
	binary.LittleEndian.PutUint32(bad[57:61], 10) // no EventType 10
	if decoded.Deserialize(bad) {
		t.Fatal("deserialize accepted unknown event_type")
	}
	bad = wire
	bad[86] = 6 // no PolicyAction above log_only(5)
	if decoded.Deserialize(bad) {
		t.Fatal("deserialize accepted unknown policy_action")
	}
	bad = wire
	bad[93+ResOffConfidence] = 101
	if decoded.Deserialize(bad) {
		t.Fatal("deserialize accepted confidence > 100")
	}
	bad = wire
	binary.LittleEndian.PutUint16(bad[6:8], 109) // struct_size must be 128 (Zig @sizeOf parity)
	if decoded.Deserialize(bad) {
		t.Fatal("deserialize accepted wrong struct_size")
	}
	if _, err := (&CanonicalEvent{Source: 17}).Serialize(); err == nil {
		t.Fatal("serialize accepted unknown source")
	}
}

func TestFFIDeserializeRejectsContractViolations(t *testing.T) {
	ev := goldenEvent()
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	cases := map[string]func(*[109]byte){
		"bad magic":      func(b *[109]byte) { b[0] ^= 0xFF },
		"unknown source": func(b *[109]byte) { b[32] = 17 },
		"unknown type":   func(b *[109]byte) { binary.LittleEndian.PutUint32(b[57:61], 10) },
		"unknown action": func(b *[109]byte) { b[86] = 6 },
		"confidence":     func(b *[109]byte) { b[93+ResOffConfidence] = 101 },
		"struct size":    func(b *[109]byte) { binary.LittleEndian.PutUint16(b[6:8], 109) },
	}
	for name, corrupt := range cases {
		bad := wire
		corrupt(&bad)
		if _, err := Deserialize(bad[:]); err == nil {
			t.Fatalf("FFI deserialize accepted %s", name)
		}
	}
	if _, err := Deserialize(wire[:]); err != nil {
		t.Fatalf("FFI deserialize rejected valid golden frame: %v", err)
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

func TestSignatureClassifierSetsCanonicalMetadata(t *testing.T) {
	activeNoseSignatureRules = []noseSignatureRule{
		{RuleID: "TEST1", MatchPattern: "GET", Severity: "High"},
	}
	defer func() { activeNoseSignatureRules = nil }()

	ip := &layers.IPv4{Version: 4, IHL: 5, SrcIP: []byte{192, 168, 1, 10}, DstIP: []byte{192, 168, 1, 20}, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: 50000, DstPort: 80}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, tcp, gopacket.Payload([]byte("GET / HTTP/1.1\r\n"))); err != nil {
		t.Fatalf("serialize classifier packet: %v", err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy)
	ev := eventFromPacket(pkt)
	classifyNosePacket(ev, pkt)

	if ev.EventType != TypeMatch {
		t.Fatalf("event type: got %d want %d", ev.EventType, TypeMatch)
	}
	if ev.RuleID != hashNoseRuleID("TEST1") {
		t.Fatalf("rule id mismatch: got %#x want %#x", ev.RuleID, hashNoseRuleID("TEST1"))
	}
	if ev.Severity != 2 {
		t.Fatalf("severity: got %d want 2 for High", ev.Severity)
	}
	wire, err := ev.Serialize()
	if err != nil {
		t.Fatalf("serialize classified event: %v", err)
	}
	if len(wire) != EventWireSize {
		t.Fatalf("wire size changed: got %d want %d", len(wire), EventWireSize)
	}
}

func TestSignatureClassifierIgnoresNonMatchingPayload(t *testing.T) {
	activeNoseSignatureRules = []noseSignatureRule{
		{RuleID: "TEST1", MatchPattern: "GET", Severity: "High"},
	}
	defer func() { activeNoseSignatureRules = nil }()

	pkt := gopacket.NewPacket([]byte{}, layers.LayerTypeIPv4, gopacket.NoCopy)
	ev := eventFromPacket(pkt)
	classifyNosePacket(ev, pkt)
	if ev.EventType != TypeForward || ev.RuleID != 0 || ev.Severity != 0 {
		t.Fatalf("non-match mutated canonical metadata: type=%d rule=%d severity=%d", ev.EventType, ev.RuleID, ev.Severity)
	}
}

// v6ProbeEvent mirrors the Zig v2 test probe: 2001:0db8::1/::2 with the
// truncated flag and first-4-byte u32 identity (BigEndian.Uint32(addr[:4])).
func v6ProbeEvent() *CanonicalEvent {
	ev := goldenEvent()
	ev.SourceIP = 0x20010DB8
	ev.DestIP = 0x20010DB8
	ev.ContextFlags |= ContextV6Truncated
	ev.Src6 = [16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	ev.Dst6 = [16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	return ev
}

func TestSerializeV2RoundTrip(t *testing.T) {
	ev := v6ProbeEvent()
	wire, err := ev.SerializeV2()
	if err != nil {
		t.Fatalf("SerializeV2: %v", err)
	}
	if len(wire) != EventV2WireSize {
		t.Fatalf("v2 size: got %d want %d", len(wire), EventV2WireSize)
	}
	if binary.LittleEndian.Uint16(wire[4:6]) != EventSchemaVersionV2 {
		t.Fatalf("v2 version field: got %d", binary.LittleEndian.Uint16(wire[4:6]))
	}
	// v1 prefix intact (first-4 identity + flags).
	if binary.LittleEndian.Uint32(wire[33:37]) != ev.SourceIP {
		t.Fatalf("v1 prefix source mismatch")
	}
	if binary.LittleEndian.Uint32(wire[89:93])&ContextV6Truncated == 0 {
		t.Fatalf("bit2 must survive the v2 round-trip")
	}
	back, err := DeserializeDispatch(wire[:])
	if err != nil {
		t.Fatalf("DeserializeDispatch: %v", err)
	}
	if back.Src6 != ev.Src6 || back.Dst6 != ev.Dst6 {
		t.Fatalf("full addresses differ:\n  got  % x / % x\n  want % x / % x",
			back.Src6, back.Dst6, ev.Src6, ev.Dst6)
	}
	if back.SourceIP != ev.SourceIP || back.DestIP != ev.DestIP {
		t.Fatalf("v1 identity fields differ after v2 round-trip")
	}
}

func TestSerializeV2Guards(t *testing.T) {
	ev := goldenEvent() // no bit2
	if _, err := ev.SerializeV2(); err == nil {
		t.Fatalf("v2 without ContextV6Truncated must fail")
	}
	ev = v6ProbeEvent()
	ev.SourceIP = 0x0A000001 // first-4 no longer matches Src6[:4]
	if _, err := ev.SerializeV2(); err == nil {
		t.Fatalf("v2 with mismatched first-4 must fail")
	}
}

func TestDeserializeDispatchVersions(t *testing.T) {	// v1 still dispatches with zero sidecars.
	gold := goldenBytes()
	back, err := DeserializeDispatch(gold[:])
	if err != nil {
		t.Fatalf("v1 dispatch: %v", err)
	}
	var zero [16]byte
	if back.Src6 != zero || back.Dst6 != zero {
		t.Fatalf("v1 must decode with zero v6 sidecars")
	}
	// Unknown version rejected.
	bad := gold
	bad[4] = 9
	if _, err := DeserializeDispatch(bad[:]); err == nil {
		t.Fatalf("unknown version must be rejected")
	}
	// Short buffer rejected.
	if _, err := DeserializeDispatch(gold[:10]); err == nil {
		t.Fatalf("short buffer must be rejected")
	}
	// Version 2 with only 109 bytes is malformed.
	v2 := v6ProbeEvent()
	wire, err := v2.SerializeV2()
	if err != nil {
		t.Fatalf("SerializeV2: %v", err)
	}
	if _, err := DeserializeDispatch(wire[:EventWireSize]); err == nil {
		t.Fatalf("truncated v2 frame must be rejected, never silently truncated")
	}
}

// TestV2Vector006MatchesCommittedBin pins Go/Zig/Python byte identity:
// the same logical v2 event must serialize to the committed
// event_v2_006.bin (frozen by generate_test_vectors.py) in every language.
func TestV2Vector006MatchesCommittedBin(t *testing.T) {
	raw, err := os.ReadFile("../tests/contracts/event_vectors/event_vectors/event_v2_006.bin")
	if err != nil {
		t.Fatalf("read committed v2 vector: %v", err)
	}
	if len(raw) != EventV2WireSize {
		t.Fatalf("v2 vector size: got %d want %d", len(raw), EventV2WireSize)
	}
	ev := &CanonicalEvent{
		EventID:           6006,
		TimestampMS:       1700000006000,
		MonotonicNS:       6000000000,
		Source:            SourceNpcapSensor,
		SourceIP:          0x20010DB8,
		SourcePort:        49152,
		DestIP:            0x20010DB8,
		DestPort:          443,
		SessionID:         6060,
		Protocol:          6,
		EventType:         TypeForward,
		Severity:          1,
		RulesetVersion:    3,
		PayloadLength:     1500,
		PolicyAction:      byte(PolicyAllow),
		DefconImpact:      5,
		ContextFlags:      ContextV6Truncated,
		Src6:              [16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Dst6:              [16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
	wire, err := ev.SerializeV2()
	if err != nil {
		t.Fatalf("SerializeV2: %v", err)
	}
	if string(wire[:]) != string(raw) {
		t.Fatalf("v2 bytes differ from committed vector:\n  got  % x\n  want % x", wire, raw)
	}
	back, err := DeserializeDispatch(raw)
	if err != nil {
		t.Fatalf("DeserializeDispatch(006): %v", err)
	}
	if back.Src6 != ev.Src6 || back.Dst6 != ev.Dst6 {
		t.Fatalf("v2 vector full addresses differ")
	}
	if back.ContextFlags&ContextV6Truncated == 0 {
		t.Fatalf("bit2 must survive the committed v2 vector")
	}
}
