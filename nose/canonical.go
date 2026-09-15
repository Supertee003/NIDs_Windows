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
)

// ── EventSource enum ──────────────────────────────────────────
const (
	SourceUnknown        = 0
	SourceWfpSensor      = 1
	SourceMinifilter     = 3
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

	// Descriptive alias retained for callers using the long name.
	SourceClusterFederation = SourceClusterFed
)

// String returns the human-readable name for each source value.
func (s Source) String() string {
	switch s {
	case SourceUnknown:
		return "unknown"
	case SourceWfpSensor:
		return "wfp_sensor"
	case SourceMinifilter:
		return "minifilter"
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
	case SourceHostTelemetry, SourceMinifilter:
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
	case SourceGoAggregator:
		return 8
	case SourceExternal:
		return 255
	default:
		return 255
	}
}

// ── EventType enum ────────────────────────────────────────────
const (
	EventBlock EventType = iota
	EventForward
	EventAlert
	EventCustom
	EventSessionStart
)

// Compatibility names used by the capture path. Values remain the frozen
// canonical ordinals; aliases avoid a second competing event vocabulary.
const (
	TypeForward = 2
	TypeMatch   = 1
)

// String returns the human-readable name for each event type.
func (t EventType) String() string {
	names := [5]string{"block", "forward", "alert", "custom", "session_start"}
	if t >= 0 && t < 5 {
		return names[t]
	}
	return "unknown"
}

// ── PolicyAction enum ─────────────────────────────────────────
const (
	PolicyAllow PolicyAction = iota
	PolicyBlock
	PolicyFailed
)

const (
	ActionLogOnly = 5
	ActionAlert   = 1
)

// String returns the human-readable name for each policy action.
func (p PolicyAction) String() string {
	names := [3]string{"allow", "block", "failed"}
	if p >= 0 && p < 3 {
		return names[p]
	}
	return "unknown"
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
}

// Reserved offsets within the 109-byte wire format
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

// EventMagic is the canonical magic number.
var EventMagic = uint32(0x41454731)

// EventSchemaVersion is the wire protocol version.
var EventSchemaVersion = uint16(1)
var DefaultDevStructSize = uint16(128) // used by Go; Zig uses @sizeOf

// ── Serialize encodes the event to the frozen 109-byte wire format.
func (e *CanonicalEvent) Serialize() ([EventWireSize]byte, error) {
	var b [EventWireSize]byte
	if e.Source > SourceExternal && e.Source != SourceExternal {
		return b, errors.New("canonical: invalid source")
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
// The wire format matches the canonical_event.zig contract and
// the Go Serialize() output.
func (e *CanonicalEvent) Deserialize(b [EventWireSize]byte) {
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
