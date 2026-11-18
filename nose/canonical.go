//! canonical.go - AEGIS NIDS Canonical Event (109-byte wire format)
//!
//! Defines the CanonicalEvent struct and serialization/deserialization
//! methods for all 5 supported languages. Wire format matches
//! canonical_event.zig and is 109 bytes long (WIRE_PAYLOAD_SIZE).
//!
//! Cross-language invariant: every language's Serialize/Deserialize must
//! produce byte-identical output for the same logical event.

package main

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// ── EventSource enum ──────────────────────────────────────────
// Ordinals MUST match src/contract/canonical_event.zig EventSource
// (VOL01-FOUNDATION-002: added the 6 missing sources; fixed names).
const (
	SourceZigCore        = 0
	SourceWfpSensor      = 1
	SourcePipeSensor     = 2
	SourceMinifilter     = 3
	SourcePipeMonitor    = 4
	SourcePythonBrain    = 5
	SourceCppBridge      = 6
	SourceRustShield     = 7
	SourceGoAggregator   = 8
	SourceNpcapSensor    = 9
	SourceHostTelemetry  = 10
	SourceMlDetector     = 11
	SourceClusterFed     = 12
	SourceProcessSensor  = 13
	SourceFileSensor     = 14
	SourceRegistrySensor = 15
	SourceReplaySensor   = 16
	SourceExternal       = 255

	// Deprecated alias: 0 is zig_core (matches Zig). Kept for compat.
	SourceUnknown = SourceZigCore

	// Descriptive alias retained for callers using the long name.
	SourceClusterFederation = SourceClusterFed
)

// String returns the human-readable name for each source value.
func (s Source) String() string {
	switch s {
	case SourceZigCore:
		return "zig_core"
	case SourceWfpSensor:
		return "wfp_sensor"
	case SourcePipeSensor:
		return "pipe_sensor"
	case SourceMinifilter:
		return "minifilter"
	case SourcePipeMonitor:
		return "pipe_monitor"
	case SourcePythonBrain:
		return "python_brain"
	case SourceCppBridge:
		return "cpp_bridge"
	case SourceRustShield:
		return "rust_shield"
	case SourceGoAggregator:
		return "go_aggregator"
	case SourceNpcapSensor:
		return "npcap_sensor"
	case SourceHostTelemetry:
		return "host_telemetry"
	case SourceMlDetector:
		return "ml_detector"
	case SourceClusterFed:
		return "cluster_federation"
	case SourceProcessSensor:
		return "process_sensor"
	case SourceFileSensor:
		return "file_sensor"
	case SourceRegistrySensor:
		return "registry_sensor"
	case SourceReplaySensor:
		return "replay_sensor"
	case SourceExternal:
		return "external"
	default:
		return "unknown"
	}
}

// classifyGo mirrors canonical_event.zig SourceKind.classify().
func classifyGo(src byte) byte {
	switch src {
	case SourceWfpSensor, SourceNpcapSensor:
		return 0
	case SourceHostTelemetry, SourceMinifilter, SourcePipeMonitor, SourcePipeSensor:
		return 1
	case SourceProcessSensor:
		return 2
	case SourceFileSensor:
		return 3
	case SourceRegistrySensor:
		return 4
	case SourceMlDetector:
		return 5
	case SourceClusterFed:
		return 6
	case SourceReplaySensor:
		return 7
	case SourceZigCore, SourceCppBridge, SourceGoAggregator, SourcePythonBrain, SourceRustShield:
		return 8
	case SourceExternal:
		return 255
	default:
		return 255
	}
}

// ── EventType enum ────────────────────────────────────────────
// Ordinals MUST match Zig EventType (VOL01-FOUNDATION-002: was iota-based
// and wrong for every value except block; now explicit).
const (
	EventBlock         EventType = 0
	EventMatch         EventType = 1
	EventForward       EventType = 2
	EventIpBlocked     EventType = 3
	EventRejected      EventType = 4
	EventSessionStart  EventType = 5
	EventSessionEnd    EventType = 6
	EventRulesetReload EventType = 7
	EventShutdown      EventType = 8
	EventStartup       EventType = 9
	EventCustom        EventType = 0xFFFFFFFF
)

// Compatibility names used by the capture path. Untyped so they assign to
// the uint32/byte wire fields; values are the frozen canonical ordinals.
const (
	TypeForward = 2
	TypeMatch   = 1
)

// String returns the human-readable name for each event type.
func (t EventType) String() string {
	switch t {
	case EventBlock:
		return "block"
	case EventMatch:
		return "match"
	case EventForward:
		return "forward"
	case EventIpBlocked:
		return "ip_blocked"
	case EventRejected:
		return "rejected"
	case EventSessionStart:
		return "session_start"
	case EventSessionEnd:
		return "session_end"
	case EventRulesetReload:
		return "ruleset_reload"
	case EventShutdown:
		return "shutdown"
	case EventStartup:
		return "startup"
	case EventCustom:
		return "custom"
	default:
		return "unknown"
	}
}

// ── PolicyAction enum ─────────────────────────────────────────
// Ordinals MUST match Zig PolicyAction (VOL01-FOUNDATION-002: was
// iota-based block=1/failed=2; now explicit allow=0..log_only=5).
const (
	PolicyAllow      PolicyAction = 0
	PolicyAlert      PolicyAction = 1
	PolicyBlock      PolicyAction = 2
	PolicyQuarantine PolicyAction = 3
	PolicyRateLimit  PolicyAction = 4
	PolicyLogOnly    PolicyAction = 5
)

const (
	ActionLogOnly = 5
	ActionAlert   = 1
)

// String returns the human-readable name for each policy action.
func (p PolicyAction) String() string {
	switch p {
	case PolicyAllow:
		return "allow"
	case PolicyAlert:
		return "alert"
	case PolicyBlock:
		return "block"
	case PolicyQuarantine:
		return "quarantine"
	case PolicyRateLimit:
		return "rate_limit"
	case PolicyLogOnly:
		return "log_only"
	default:
		return "unknown"
	}
}

// ── CanonicalEvent struct ─────────────────────────────────────
type CanonicalEvent struct {
	EventID, TimestampMS, MonotonicNS             uint64
	Source                                        byte
	SourceIP                                      uint32
	SourcePort                                    uint16
	DestIP                                        uint32
	DestPort                                      uint16
	SessionID                                     uint64
	Protocol, Direction, LayerID, IsPipe          byte
	EventType                                     uint32
	Severity                                      byte
	RuleID                                        uint32
	RulesetVersion                                uint64
	PayloadLength                                 uint32
	PayloadHash                                   uint64
	PolicyAction, EnforcementStatus, DefconImpact byte
	ContextFlags                                  uint32
	PID, PPID                                     uint32
	ProcType, Integrity, HidsFlag                 byte
	NodeID                                        uint32
	Confidence                                    byte
	// Full IPv6 identity (wire v2 only, T2-V6-022a). The u32 SourceIP/
	// DestIP fields always carry first-4-bytes (bit2 set); these hold
	// the complete 128-bit addresses in network order when a v2 frame
	// was decoded, zero otherwise. Never on the v1 wire.
	Src6, Dst6 [16]byte
	// Wire v3 bounded payload + provenance (PAYLOAD-ENVELOPE-V3-001).
	// Populated only by DeserializeV3/DeserializeDispatch for a v3 frame;
	// nil/empty for the frozen v1/v2 metadata-only compatibility paths.
	Envelope *V3Envelope
	Payload  []byte
}

// ── ContextFlags bits (frozen v1 vocabulary, all languages) ──
// bit0=threat_intel_match bit1=correlation_match bit2=ipv6_truncated.
// bit2 means SourceIP/DestIP carry only the first 4 bytes of each IPv6
// address: identity is degraded by construction (v1 wire has no v6 fields)
// and must never be treated as an IPv4 identity.
//
// Additive transport-metadata lane (RB-021-NOSE-FLAGS): bits 16..23 hold
// the raw TCP flags byte observed by Nose, and bit24 says the lane is
// valid. This is a semantic allocation of previously unused ContextFlags
// bits, not a wire-layout change: v1 stays 109 bytes and v2 stays 133.
// Existing allocations (RAG bits 0..3, L7 bits 8..13) do not overlap.
const (
	ContextThreatIntelMatch uint32 = 1 << 0
	ContextCorrelationMatch uint32 = 1 << 1
	ContextV6Truncated      uint32 = 1 << 2

	ContextTCPFlagsShift uint32 = 16
	ContextTCPFlagsMask  uint32 = 0xFF << ContextTCPFlagsShift
	ContextTCPFlagsValid uint32 = 1 << 24
)

// SetTCPFlags records the raw TCP flags byte (FIN=0x01 .. CWR=0x80) in the
// ContextFlags transport lane. Callers set this only when they actually
// observed a TCP header; absence is distinct from a zero flags byte.
func (e *CanonicalEvent) SetTCPFlags(flags uint8) {
	e.ContextFlags = (e.ContextFlags &^ (ContextTCPFlagsMask | ContextTCPFlagsValid)) |
		ContextTCPFlagsValid |
		(uint32(flags) << ContextTCPFlagsShift)
}

// TCPFlags returns the observed TCP flags and whether the lane is valid.
func (e *CanonicalEvent) TCPFlags() (uint8, bool) {
	if e.ContextFlags&ContextTCPFlagsValid == 0 {
		return 0, false
	}
	return uint8((e.ContextFlags & ContextTCPFlagsMask) >> ContextTCPFlagsShift), true
}

const (
	ResOffPid        = 0  // reserved[0..4]   = PID
	ResOffPpid       = 4  // reserved[4..8]   = PPID
	ResOffProcType   = 8  // reserved[8..9]   = ProcType
	ResOffIntegrity  = 9  // reserved[9..10]  = Integrity
	ResOffHidsFlag   = 10 // reserved[10..11] = HidsFlag
	ResOffNodeID     = 11 // reserved[11..15] = NodeID
	ResOffConfidence = 15 // frozen golden vector confidence offset
)

// EventWireSize is the canonical wire format size.
const EventWireSize = 109

// Wire v2 (T2-V6-022a, see shared/protocol/wire_v2.md): v1 109 bytes plus
// a 24-byte tail holding source bytes [4..16] then dest bytes [4..16] in
// network order. v1 is frozen; v2 is additive.
const EventV2WireSize = 133
const V6TailSize = 24

// EventMagic is the canonical magic number.
var EventMagic = uint32(0x41454731)

// EventSchemaVersion is the wire protocol version.
var EventSchemaVersion = uint16(1)

// EventSchemaVersionV2 marks frames carrying the 24-byte IPv6 tail.
var EventSchemaVersionV2 = uint16(2)

// ── Wire v3: bounded payload + capture provenance ─────────────────
// v3 = the frozen v2 133-byte base (zero tail when bit2 is clear) + a
// 32-byte envelope + 0..1024 payload bytes. v1/v2 remain byte-identical
// metadata-only compatibility frames. Zig owns the detection verdict;
// this envelope only reports captured evidence.
var EventSchemaVersionV3 = uint16(3)

const (
	EventV3BaseSize     = EventV2WireSize // 133
	EventV3EnvelopeSize = 32
	EventV3HeaderSize   = EventV3BaseSize + EventV3EnvelopeSize // 165
	EventV3MaxPayload   = 1024
	EventV3MaxWireSize  = EventV3HeaderSize + EventV3MaxPayload // 1189
)

// Payload completeness vocabulary. Absence is distinct from completeness.
const (
	PayloadUnavailable  byte = 0
	PayloadComplete     byte = 1
	PayloadTruncated    byte = 2
	PayloadMetadataOnly byte = 3
)

const (
	V3FlagPayloadPresent  uint16 = 1 << 0
	V3FlagProvenanceValid uint16 = 1 << 1
)

// V3Envelope is the v3 provenance/payload descriptor. OriginalLen is the
// producer's on-wire frame length; PayloadLen is the number of bytes that
// actually follow the envelope. PayloadCRC32 is CRC32 (IEEE) over exactly
// those PayloadLen bytes.
type V3Envelope struct {
	Flags              uint16
	Completeness       byte
	PayloadLen         uint16
	OriginalLen        uint16
	PayloadCRC32       uint32
	CaptureSequence    uint64
	ProducerEpoch      uint32
	ProducerGeneration uint32
	InterfaceID        uint32
}

// Validate checks an envelope against the payload bytes that will travel
// with it. Fail closed: no inferred acceptance, no silent truncation.
func (env *V3Envelope) Validate(payload []byte) error {
	if len(payload) > EventV3MaxPayload {
		return errors.New("canonical: v3 payload exceeds maximum")
	}
	if int(env.PayloadLen) != len(payload) {
		return errors.New("canonical: v3 payload length mismatch")
	}
	present := env.Flags&V3FlagPayloadPresent != 0
	switch env.Completeness {
	case PayloadUnavailable, PayloadMetadataOnly:
		if present || len(payload) != 0 || env.PayloadCRC32 != 0 {
			return errors.New("canonical: v3 metadata-only envelope carries payload")
		}
		if env.Completeness == PayloadMetadataOnly && env.OriginalLen != 0 {
			return errors.New("canonical: v3 metadata-only original length must be zero")
		}
	case PayloadComplete:
		if !present || len(payload) == 0 {
			return errors.New("canonical: v3 complete envelope requires payload")
		}
		if env.OriginalLen != env.PayloadLen {
			return errors.New("canonical: v3 complete original length mismatch")
		}
		if crc32.ChecksumIEEE(payload) != env.PayloadCRC32 {
			return errors.New("canonical: v3 payload crc mismatch")
		}
	case PayloadTruncated:
		if !present || len(payload) == 0 {
			return errors.New("canonical: v3 truncated envelope requires payload")
		}
		if env.OriginalLen <= env.PayloadLen {
			return errors.New("canonical: v3 truncated original length must exceed captured")
		}
		if crc32.ChecksumIEEE(payload) != env.PayloadCRC32 {
			return errors.New("canonical: v3 payload crc mismatch")
		}
	default:
		return errors.New("canonical: unknown v3 completeness")
	}
	if env.Flags&V3FlagProvenanceValid == 0 {
		if env.CaptureSequence != 0 || env.ProducerEpoch != 0 ||
			env.ProducerGeneration != 0 || env.InterfaceID != 0 {
			return errors.New("canonical: v3 provenance without valid flag")
		}
	}
	return nil
}

var DefaultDevStructSize = uint16(128) // used by Go; Zig uses @sizeOf

// validSource mirrors Zig deserializeFromBytes: 0-16 or 255.
func validSource(s byte) bool {
	return s <= SourceReplaySensor || s == SourceExternal
}

func validEventType(t uint32) bool {
	return t <= 9 || t == uint32(EventCustom)
}

func validPolicyAction(a byte) bool {
	return a <= byte(PolicyLogOnly)
}

// ── Serialize encodes the event to the frozen 109-byte wire format.
func (e *CanonicalEvent) Serialize() ([EventWireSize]byte, error) {
	var b [EventWireSize]byte
	if !validSource(e.Source) {
		return b, errors.New("canonical: invalid source")
	}
	if !validEventType(e.EventType) {
		return b, errors.New("canonical: invalid event_type")
	}
	if !validPolicyAction(e.PolicyAction) {
		return b, errors.New("canonical: invalid policy_action")
	}
	if e.Confidence > 100 {
		return b, errors.New("canonical: confidence must be 0-100")
	}
	binary.LittleEndian.PutUint32(b[0:4], EventMagic)
	binary.LittleEndian.PutUint16(b[4:6], EventSchemaVersion)
	binary.LittleEndian.PutUint16(b[6:8], DefaultDevStructSize)
	binary.LittleEndian.PutUint64(b[8:16], e.EventID)
	binary.LittleEndian.PutUint64(b[16:24], e.TimestampMS)
	binary.LittleEndian.PutUint64(b[24:32], e.MonotonicNS)
	b[32] = e.Source
	binary.LittleEndian.PutUint32(b[33:37], e.SourceIP)
	binary.LittleEndian.PutUint16(b[37:39], e.SourcePort)
	binary.LittleEndian.PutUint32(b[39:43], e.DestIP)
	binary.LittleEndian.PutUint16(b[43:45], e.DestPort)
	binary.LittleEndian.PutUint64(b[45:53], e.SessionID)
	b[53] = e.Protocol
	b[54] = e.Direction
	b[55] = e.LayerID
	b[56] = e.IsPipe
	binary.LittleEndian.PutUint32(b[57:61], e.EventType)
	b[61] = e.Severity
	binary.LittleEndian.PutUint32(b[62:66], e.RuleID)
	binary.LittleEndian.PutUint64(b[66:74], e.RulesetVersion)
	binary.LittleEndian.PutUint32(b[74:78], e.PayloadLength)
	binary.LittleEndian.PutUint64(b[78:86], e.PayloadHash)
	b[86] = e.PolicyAction
	b[87] = e.EnforcementStatus
	b[88] = e.DefconImpact
	binary.LittleEndian.PutUint32(b[89:93], e.ContextFlags)
	// reserved[0..4] = pid
	binary.LittleEndian.PutUint32(b[93+ResOffPid:93+ResOffPid+4], e.PID)
	// reserved[4..8] = ppid
	binary.LittleEndian.PutUint32(b[93+ResOffPpid:93+ResOffPpid+4], e.PPID)
	b[93+ResOffProcType] = e.ProcType
	b[93+ResOffIntegrity] = e.Integrity
	b[93+ResOffHidsFlag] = e.HidsFlag
	// reserved[11..15] = node_id
	binary.LittleEndian.PutUint32(b[93+ResOffNodeID:93+ResOffNodeID+4], e.NodeID)
	b[93+ResOffConfidence] = e.Confidence
	return b, nil
}

// Deserialize decodes a 109-byte wire format event into a CanonicalEvent.
// It mirrors Zig deserializeFromBytes: validates magic, version, enum
// ordinals and confidence, and reports false on any contract violation.
func (e *CanonicalEvent) Deserialize(b [EventWireSize]byte) bool {
	if binary.LittleEndian.Uint32(b[0:4]) != EventMagic {
		return false
	}
	if binary.LittleEndian.Uint16(b[4:6]) != EventSchemaVersion {
		return false
	}
	if binary.LittleEndian.Uint16(b[6:8]) != DefaultDevStructSize {
		return false
	}
	if !validSource(b[32]) {
		return false
	}
	if !validEventType(binary.LittleEndian.Uint32(b[57:61])) {
		return false
	}
	if !validPolicyAction(b[86]) {
		return false
	}
	if b[93+ResOffConfidence] > 100 {
		return false
	}
	*e = CanonicalEvent{
		// Header occupies bytes 0..7: magic (u32), schema (u16),
		// and struct-size marker (u16). EventID starts at byte 8.
		EventID:           binary.LittleEndian.Uint64(b[8:16]),
		TimestampMS:       binary.LittleEndian.Uint64(b[16:24]),
		MonotonicNS:       binary.LittleEndian.Uint64(b[24:32]),
		Source:            b[32],
		SourceIP:          binary.LittleEndian.Uint32(b[33:37]),
		SourcePort:        binary.LittleEndian.Uint16(b[37:39]),
		DestIP:            binary.LittleEndian.Uint32(b[39:43]),
		DestPort:          binary.LittleEndian.Uint16(b[43:45]),
		SessionID:         binary.LittleEndian.Uint64(b[45:53]),
		Protocol:          b[53],
		Direction:         b[54],
		LayerID:           b[55],
		IsPipe:            b[56],
		EventType:         binary.LittleEndian.Uint32(b[57:61]),
		Severity:          b[61],
		RuleID:            binary.LittleEndian.Uint32(b[62:66]),
		RulesetVersion:    binary.LittleEndian.Uint64(b[66:74]),
		PayloadLength:     binary.LittleEndian.Uint32(b[74:78]),
		PayloadHash:       binary.LittleEndian.Uint64(b[78:86]),
		PolicyAction:      b[86],
		EnforcementStatus: b[87],
		DefconImpact:      b[88],
		ContextFlags:      binary.LittleEndian.Uint32(b[89:93]),
		PID:               binary.LittleEndian.Uint32(b[93 : 93+ResOffPid+4]),
		PPID:              binary.LittleEndian.Uint32(b[93+ResOffPpid : 93+ResOffPpid+4]),
		ProcType:          b[93+ResOffProcType],
		Integrity:         b[93+ResOffIntegrity],
		HidsFlag:          b[93+ResOffHidsFlag],
		NodeID:            binary.LittleEndian.Uint32(b[93+ResOffNodeID : 93+ResOffNodeID+4]),
		Confidence:        b[93+ResOffConfidence],
	}
	return true
}

// SerializeV2 encodes the event as a 133-byte v2 frame: frozen v1 bytes
// with schema version 2 plus the IPv6 tail. Requires ContextV6Truncated
// (v2 is v6-identity only) and first-4-byte consistency between the u32
// fields (BigEndian.Uint32(addr[:4])) and the full addresses.
func (e *CanonicalEvent) SerializeV2() ([EventV2WireSize]byte, error) {
	var out [EventV2WireSize]byte
	if e.ContextFlags&ContextV6Truncated == 0 {
		return out, errors.New("canonical: v2 requires ContextV6Truncated")
	}
	if binary.BigEndian.Uint32(e.Src6[:4]) != e.SourceIP {
		return out, errors.New("canonical: src first-4 mismatch")
	}
	if binary.BigEndian.Uint32(e.Dst6[:4]) != e.DestIP {
		return out, errors.New("canonical: dst first-4 mismatch")
	}
	v1, err := e.Serialize()
	if err != nil {
		return out, err
	}
	copy(out[:], v1[:])
	binary.LittleEndian.PutUint16(out[4:6], EventSchemaVersionV2)
	copy(out[EventWireSize:EventWireSize+12], e.Src6[4:16])
	copy(out[EventWireSize+12:], e.Dst6[4:16])
	return out, nil
}

// IsV6 reports whether the event carries IPv6 identity (first-4-bytes in
// the u32 fields with ContextV6Truncated set). v6 events serialize as
// 133-byte v2 frames; everything else stays frozen v1.
func (e *CanonicalEvent) IsV6() bool {
	return e.ContextFlags&ContextV6Truncated != 0
}

// SerializeV3 encodes the event as a v3 frame: the frozen v2 base (a zero
// 24-byte tail when bit2 is clear) + 32-byte envelope + bounded payload.
// The envelope is validated against the payload before any byte is written.
func (e *CanonicalEvent) SerializeV3(env V3Envelope, payload []byte) ([]byte, error) {
	if err := env.Validate(payload); err != nil {
		return nil, err
	}
	base := make([]byte, EventV3BaseSize)
	if e.IsV6() {
		v2, err := e.SerializeV2()
		if err != nil {
			return nil, err
		}
		copy(base, v2[:])
	} else {
		v1, err := e.Serialize()
		if err != nil {
			return nil, err
		}
		copy(base, v1[:])
	}
	binary.LittleEndian.PutUint16(base[4:6], EventSchemaVersionV3)

	out := make([]byte, EventV3HeaderSize+len(payload))
	copy(out, base)
	off := EventV3BaseSize
	binary.LittleEndian.PutUint16(out[off:off+2], env.Flags)
	out[off+2] = env.Completeness
	out[off+3] = 0 // reserved
	binary.LittleEndian.PutUint16(out[off+4:off+6], env.PayloadLen)
	binary.LittleEndian.PutUint16(out[off+6:off+8], env.OriginalLen)
	binary.LittleEndian.PutUint32(out[off+8:off+12], env.PayloadCRC32)
	binary.LittleEndian.PutUint64(out[off+12:off+20], env.CaptureSequence)
	binary.LittleEndian.PutUint32(out[off+20:off+24], env.ProducerEpoch)
	binary.LittleEndian.PutUint32(out[off+24:off+28], env.ProducerGeneration)
	binary.LittleEndian.PutUint32(out[off+28:off+32], env.InterfaceID)
	copy(out[EventV3HeaderSize:], payload)
	return out, nil
}

// DeserializeV3 decodes a strict v3 frame. Payload aliases the input slice;
// callers must consume it before reusing the buffer. Encoding/size/crc/v6
// tail rules are all enforced (fail closed).
func DeserializeV3(b []byte) (*CanonicalEvent, error) {
	if len(b) < EventV3HeaderSize {
		return nil, errors.New("canonical: short v3 frame")
	}
	var prefix [EventWireSize]byte
	copy(prefix[:], b[:EventWireSize])
	binary.LittleEndian.PutUint16(prefix[4:6], EventSchemaVersion)
	ev := &CanonicalEvent{}
	if !ev.Deserialize(prefix) {
		return nil, errors.New("canonical: v3 prefix rejected")
	}
	isV6 := ev.ContextFlags&ContextV6Truncated != 0
	if isV6 {
		binary.BigEndian.PutUint32(ev.Src6[:4], ev.SourceIP)
		binary.BigEndian.PutUint32(ev.Dst6[:4], ev.DestIP)
		copy(ev.Src6[4:16], b[EventWireSize:EventWireSize+12])
		copy(ev.Dst6[4:16], b[EventWireSize+12:EventWireSize+24])
	} else {
		for _, x := range b[EventWireSize:EventV3BaseSize] {
			if x != 0 {
				return nil, errors.New("canonical: v3 non-v6 tail must be zero")
			}
		}
	}
	off := EventV3BaseSize
	// wire_v3.md: any non-zero reserved byte is rejected fail closed. The
	// encoder always writes 0, so a set byte is a corrupt or foreign frame.
	if b[off+3] != 0 {
		return nil, errors.New("canonical: v3 reserved byte must be zero")
	}
	env := V3Envelope{
		Flags:              binary.LittleEndian.Uint16(b[off : off+2]),
		Completeness:       b[off+2],
		PayloadLen:         binary.LittleEndian.Uint16(b[off+4 : off+6]),
		OriginalLen:        binary.LittleEndian.Uint16(b[off+6 : off+8]),
		PayloadCRC32:       binary.LittleEndian.Uint32(b[off+8 : off+12]),
		CaptureSequence:    binary.LittleEndian.Uint64(b[off+12 : off+20]),
		ProducerEpoch:      binary.LittleEndian.Uint32(b[off+20 : off+24]),
		ProducerGeneration: binary.LittleEndian.Uint32(b[off+24 : off+28]),
		InterfaceID:        binary.LittleEndian.Uint32(b[off+28 : off+32]),
	}
	if int(env.PayloadLen) > EventV3MaxPayload {
		return nil, errors.New("canonical: v3 payload length exceeds maximum")
	}
	if len(b) != EventV3HeaderSize+int(env.PayloadLen) {
		return nil, errors.New("canonical: v3 frame length mismatch")
	}
	payload := b[EventV3HeaderSize:]
	if err := env.Validate(payload); err != nil {
		return nil, err
	}
	ev.Envelope = &env
	ev.Payload = payload
	return ev, nil
}

// DeserializeDispatch decodes a length-delimited canonical payload of
// either version: 109-byte v1 (Src6/Dst6 left zero, truncated semantics
// unchanged) or 133-byte v2 (full addresses reconstructed). Anything
// else is rejected; version 2 with 109 bytes is malformed, never
// silently truncated.
func DeserializeDispatch(b []byte) (*CanonicalEvent, error) {
	if len(b) < EventWireSize {
		return nil, errors.New("canonical: short buffer")
	}
	ver := binary.LittleEndian.Uint16(b[4:6])
	if ver == EventSchemaVersion {
		var fixed [EventWireSize]byte
		copy(fixed[:], b[:EventWireSize])
		ev := &CanonicalEvent{}
		if !ev.Deserialize(fixed) {
			return nil, errors.New("canonical: v1 rejected")
		}
		return ev, nil
	}
	if ver == EventSchemaVersionV3 {
		return DeserializeV3(b)
	}
	if ver != EventSchemaVersionV2 {
		return nil, errors.New("canonical: unknown version")
	}
	if len(b) < EventV2WireSize {
		return nil, errors.New("canonical: truncated v2 frame")
	}
	var fixed [EventWireSize]byte
	copy(fixed[:], b[:EventWireSize])
	ev := &CanonicalEvent{}
	// Decode the v1 prefix with the frozen validator, then lift the
	// version gate: Deserialize demands schema 1, so patch a copy.
	binary.LittleEndian.PutUint16(fixed[4:6], EventSchemaVersion)
	if !ev.Deserialize(fixed) {
		return nil, errors.New("canonical: v2 prefix rejected")
	}
	// First-4 on the wire is LE(u32-BE-value); restore network order so
	// Src6/Dst6 hold canonical byte addresses (mirrors Zig sidecar).
	binary.BigEndian.PutUint32(ev.Src6[:4], ev.SourceIP)
	binary.BigEndian.PutUint32(ev.Dst6[:4], ev.DestIP)
	copy(ev.Src6[4:16], b[EventWireSize:EventWireSize+12])
	copy(ev.Dst6[4:16], b[EventWireSize+12:EventWireSize+24])
	return ev, nil
}

// ── SourceKind classification (cross-language T2 mapping) ───────
// These must match Zig's SourceKind.classify() ordinals for interop.

// ── Source type ────────────────────────────────────────────────
// The source constants are declared once above with the frozen wire ordinals.
type Source int

// ── EventType enumeration ─────────────────────────────────────
type EventType int

// ── PolicyAction enumeration ──────────────────────────────────
type PolicyAction int
