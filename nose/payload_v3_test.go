// =====================================================================
// payload_v3_test.go - PAYLOAD-ENVELOPE-V3-001 cross-language pins
// =====================================================================
// The committed v3 vectors (frozen by generate_test_vectors.py) must
// serialize byte-identically from the Go reference codec and decode back
// to the exact payload + provenance. Envelope guards fail closed.
// =====================================================================
package main

import (
	"hash/crc32"
	"os"
	"testing"

	"github.com/google/gopacket"
)

func v3VectorPath(name string) string {
	return "../tests/contracts/event_vectors/event_vectors/" + name
}

func readV3Vector(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(v3VectorPath(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return raw
}

func payload007() []byte {
	p := make([]byte, 32)
	for i := range p {
		p[i] = byte(0x40 + i)
	}
	return p
}

func payload008() []byte {
	p := make([]byte, 64)
	for i := range p {
		p[i] = byte((i*7 + 3) & 0xFF)
	}
	return p
}

func eventV3_007() *CanonicalEvent {
	return &CanonicalEvent{
		EventID:        7007,
		TimestampMS:    1700000007000,
		MonotonicNS:    7000000000,
		Source:         SourceNpcapSensor,
		SourceIP:       0x20010DB8,
		SourcePort:     49152,
		DestIP:         0x20010DB8,
		DestPort:       443,
		SessionID:      7070,
		Protocol:       6,
		EventType:      TypeForward,
		Severity:       1,
		RulesetVersion: 4,
		PayloadLength:  uint32(len(payload007())),
		PolicyAction:   byte(PolicyAllow),
		DefconImpact:   5,
		ContextFlags:   ContextV6Truncated,
		Src6:           [16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		Dst6:           [16]byte{0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}
}

func envV3_007() V3Envelope {
	return V3Envelope{
		Flags:              V3FlagPayloadPresent | V3FlagProvenanceValid,
		Completeness:       PayloadComplete,
		PayloadLen:         uint16(len(payload007())),
		OriginalLen:        uint16(len(payload007())),
		PayloadCRC32:       crc32.ChecksumIEEE(payload007()),
		CaptureSequence:    7007,
		ProducerEpoch:      0x5F5E1000,
		ProducerGeneration: 5,
		InterfaceID:        0x0A0B0C0D,
	}
}

func eventV3_008() *CanonicalEvent {
	return &CanonicalEvent{
		EventID:        8008,
		TimestampMS:    1700000008000,
		MonotonicNS:    8000000000,
		Source:         SourceNpcapSensor,
		SourceIP:       0xC0A80164,
		SourcePort:     40000,
		DestIP:         0x0A000001,
		DestPort:       53,
		SessionID:      8080,
		Protocol:       17,
		Direction:      1,
		EventType:      TypeForward,
		Severity:       0,
		RulesetVersion: 4,
		PayloadLength:  uint32(len(payload008())),
		PolicyAction:   byte(PolicyLogOnly),
		DefconImpact:   5,
	}
}

func envV3_008() V3Envelope {
	return V3Envelope{
		Flags:              V3FlagPayloadPresent | V3FlagProvenanceValid,
		Completeness:       PayloadTruncated,
		PayloadLen:         uint16(len(payload008())),
		OriginalLen:        1514,
		PayloadCRC32:       crc32.ChecksumIEEE(payload008()),
		CaptureSequence:    8008,
		ProducerEpoch:      0x5F5E1000,
		ProducerGeneration: 2,
		InterfaceID:        0x01020304,
	}
}

func eventV3_009() *CanonicalEvent {
	return &CanonicalEvent{
		EventID:        9009,
		TimestampMS:    1700000009000,
		MonotonicNS:    9000000000,
		Source:         SourceNpcapSensor,
		SourceIP:       0xC0A80164,
		SourcePort:     40000,
		DestIP:         0x0A000001,
		DestPort:       80,
		SessionID:      9090,
		Protocol:       6,
		Direction:      1,
		EventType:      TypeForward,
		Severity:       0,
		RulesetVersion: 4,
		PayloadLength:  0,
		PolicyAction:   byte(PolicyAllow),
		DefconImpact:   5,
	}
}

// V1: Go serializer reproduces the committed bytes exactly.
func TestV3Vector007MatchesCommittedBin(t *testing.T) {
	raw := readV3Vector(t, "event_v3_007.bin")
	if len(raw) != EventV3HeaderSize+len(payload007()) {
		t.Fatalf("vector 007 size: got %d", len(raw))
	}
	wire, err := eventV3_007().SerializeV3(envV3_007(), payload007())
	if err != nil {
		t.Fatalf("SerializeV3(007): %v", err)
	}
	if string(wire) != string(raw) {
		t.Fatalf("v3 007 bytes differ from committed vector:\n got  % x\n want % x", wire, raw)
	}
}

func TestV3Vector008MatchesCommittedBin(t *testing.T) {
	raw := readV3Vector(t, "event_v3_008.bin")
	if len(raw) != EventV3HeaderSize+len(payload008()) {
		t.Fatalf("vector 008 size: got %d", len(raw))
	}
	wire, err := eventV3_008().SerializeV3(envV3_008(), payload008())
	if err != nil {
		t.Fatalf("SerializeV3(008): %v", err)
	}
	if string(wire) != string(raw) {
		t.Fatalf("v3 008 bytes differ from committed vector:\n got  % x\n want % x", wire, raw)
	}
}

func TestV3Vector009MatchesCommittedBin(t *testing.T) {
	raw := readV3Vector(t, "event_v3_009.bin")
	if len(raw) != EventV3HeaderSize {
		t.Fatalf("vector 009 size: got %d want %d", len(raw), EventV3HeaderSize)
	}
	wire, err := eventV3_009().SerializeV3(V3Envelope{Completeness: PayloadMetadataOnly}, nil)
	if err != nil {
		t.Fatalf("SerializeV3(009): %v", err)
	}
	if string(wire) != string(raw) {
		t.Fatalf("v3 009 bytes differ from committed vector:\n got  % x\n want % x", wire, raw)
	}
}

// V2: committed bytes decode to the exact event + payload + provenance.
func TestV3CommittedVectorsDecode(t *testing.T) {
	ev, err := DeserializeDispatch(readV3Vector(t, "event_v3_007.bin"))
	if err != nil {
		t.Fatalf("decode 007: %v", err)
	}
	if ev.Envelope == nil || ev.Envelope.Completeness != PayloadComplete {
		t.Fatalf("007 completeness: %+v", ev.Envelope)
	}
	if string(ev.Payload) != string(payload007()) {
		t.Fatalf("007 payload differs")
	}
	if ev.ContextFlags&ContextV6Truncated == 0 {
		t.Fatalf("007 must keep bit2")
	}
	if ev.Envelope.CaptureSequence != 7007 || ev.Envelope.InterfaceID != 0x0A0B0C0D {
		t.Fatalf("007 provenance differs: %+v", ev.Envelope)
	}

	ev, err = DeserializeDispatch(readV3Vector(t, "event_v3_008.bin"))
	if err != nil {
		t.Fatalf("decode 008: %v", err)
	}
	if ev.Envelope == nil || ev.Envelope.Completeness != PayloadTruncated ||
		ev.Envelope.OriginalLen != 1514 {
		t.Fatalf("008 envelope: %+v", ev.Envelope)
	}
	if string(ev.Payload) != string(payload008()) {
		t.Fatalf("008 payload differs")
	}

	ev, err = DeserializeDispatch(readV3Vector(t, "event_v3_009.bin"))
	if err != nil {
		t.Fatalf("decode 009: %v", err)
	}
	if ev.Envelope == nil || ev.Envelope.Completeness != PayloadMetadataOnly {
		t.Fatalf("009 envelope: %+v", ev.Envelope)
	}
	if len(ev.Payload) != 0 {
		t.Fatalf("009 must carry no payload")
	}
}

// V3: envelope guards fail closed.
func TestV3EnvelopeRejects(t *testing.T) {
	p := payload007()

	bad := envV3_007()
	bad.PayloadCRC32 ^= 0xFFFFFFFF
	if err := bad.Validate(p); err == nil {
		t.Fatalf("crc mismatch must be rejected")
	}

	bad = envV3_007()
	bad.PayloadLen++
	if err := bad.Validate(p); err == nil {
		t.Fatalf("length mismatch must be rejected")
	}

	bad = envV3_007()
	bad.Flags = V3FlagProvenanceValid
	if err := bad.Validate(p); err == nil {
		t.Fatalf("complete without payload flag must be rejected")
	}

	bad = envV3_008()
	bad.OriginalLen = bad.PayloadLen
	if err := bad.Validate(payload008()); err == nil {
		t.Fatalf("truncated without growth must be rejected")
	}

	bad = V3Envelope{Completeness: PayloadMetadataOnly, Flags: V3FlagPayloadPresent}
	if err := bad.Validate(nil); err == nil {
		t.Fatalf("metadata-only with payload flag must be rejected")
	}

	bad = V3Envelope{Completeness: PayloadMetadataOnly, OriginalLen: 1}
	if err := bad.Validate(nil); err == nil {
		t.Fatalf("metadata-only with original length must be rejected")
	}

	bad = envV3_007()
	bad.Completeness = 9
	if err := bad.Validate(p); err == nil {
		t.Fatalf("unknown completeness must be rejected")
	}

	bad = envV3_007()
	bad.Flags = V3FlagPayloadPresent
	if err := bad.Validate(p); err == nil {
		t.Fatalf("provenance without valid flag must be rejected")
	}
}

func TestDeserializeV3RejectsDirtyTailAndTrailing(t *testing.T) {
	raw := readV3Vector(t, "event_v3_008.bin")
	dirty := append([]byte(nil), raw...)
	dirty[EventWireSize] = 0x01 // non-v6 tail must be zero
	if _, err := DeserializeV3(dirty); err == nil {
		t.Fatalf("dirty non-v6 tail must be rejected")
	}
	if _, err := DeserializeV3(append(append([]byte(nil), raw...), 0)); err == nil {
		t.Fatalf("trailing byte must be rejected")
	}
	if _, err := DeserializeV3(raw[:EventV3HeaderSize-EventV3EnvelopeSize]); err == nil {
		t.Fatalf("short frame must be rejected")
	}
	// wire_v3.md pins the reserved envelope byte to 0; a set byte is a
	// corrupt/foreign frame and must fail closed on every decoder.
	reserved := append([]byte(nil), raw...)
	reserved[EventV3BaseSize+3] = 0x01
	if _, err := DeserializeV3(reserved); err == nil {
		t.Fatalf("non-zero reserved byte must be rejected")
	}
}

// captureAttachment semantics: presence, completeness, bounded payload.
func TestCaptureAttachmentSemantics(t *testing.T) {
	prov := captureProvenance{epoch: 11, generation: 2, interfaceID: 0xCAFE}

	frame := make([]byte, 100)
	payload, env := captureAttachment(frame, gopacket.CaptureInfo{Length: 100}, 42, prov)
	if env.Completeness != PayloadComplete {
		t.Fatalf("complete frame: got completeness %d", env.Completeness)
	}
	if env.Flags&V3FlagPayloadPresent == 0 || env.Flags&V3FlagProvenanceValid == 0 {
		t.Fatalf("complete frame flags: %+v", env)
	}
	if env.PayloadLen != 100 || env.OriginalLen != 100 || env.PayloadCRC32 != crc32.ChecksumIEEE(frame) {
		t.Fatalf("complete frame envelope: %+v", env)
	}
	if len(payload) != 100 || env.CaptureSequence != 42 || env.InterfaceID != 0xCAFE {
		t.Fatalf("complete frame payload/provenance: %+v", env)
	}

	small := make([]byte, 64)
	_, env = captureAttachment(small, gopacket.CaptureInfo{Length: 1514}, 43, prov)
	if env.Completeness != PayloadTruncated || env.OriginalLen != 1514 || env.PayloadLen != 64 {
		t.Fatalf("truncated frame envelope: %+v", env)
	}

	payload, env = captureAttachment(nil, gopacket.CaptureInfo{Length: 60}, 44, prov)
	if env.Completeness != PayloadUnavailable || env.Flags&V3FlagPayloadPresent != 0 {
		t.Fatalf("absent frame envelope: %+v", env)
	}
	if len(payload) != 0 {
		t.Fatalf("absent frame must carry no payload")
	}

	big := make([]byte, EventV3MaxPayload+100)
	payload, env = captureAttachment(big, gopacket.CaptureInfo{Length: len(big)}, 45, prov)
	if env.Completeness != PayloadTruncated || len(payload) != EventV3MaxPayload {
		t.Fatalf("over-max frame must clamp and report truncated: env=%+v len=%d", env, len(payload))
	}
}
