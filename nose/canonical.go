package main

// =====================================================================
// canonical.go — AEGIS Canonical Event v1, Go binding (nose → Zig core)
// =====================================================================
// The CanonicalEvent schema is OWNED by Zig (core/canonical_event.zig).
// This Go file is a read-only binding that MUST reproduce the frozen
// 109-byte wire encoding byte-for-byte. golden vector is
// docs/contracts/canonical-event-v1.md + the Zig golden-vector test.
//
// Wire layout (all little-endian), size 109 bytes:
//
//   off  size  field
//   ---  ----  -------------------------------------------------
//   0    4     magic              0x41454731  ("AEG1")
//   4    2     schema_version     1
//   6    2     struct_size        (Zig sizeof; 128 in dev — wire ignores)
//   8    8     event_id           unique id (atomic counter)
//   16   8     timestamp_ms       wall-clock ms
//   24   8     monotonic_ns       monotonic ns
//   32   1     source             EventSource (u8)
//   33   4     source_ip          host byte order (same as Zig wire)
//   37   2     source_port
//   39   4     dest_ip
//   43   2     dest_port
//   45   8     session_id         ← source_id (T2)
//   53   1     protocol           IPPROTO_TCP=6 ...
//   54   1     direction          0=inbound 1=outbound
//   55   1     layer_id           0=TCP 1=WFP 2=kernel 3=pipe
//   56   1     is_pipe
//   57   4     event_type         EventType (u32)
//   61   1     severity           0=Low 1=Med 2=High 3=Crit
//   62   4     rule_id
//   66   8     ruleset_version
//   74   4     payload_length
//   78   8     payload_hash
//   86   1     policy_action      PolicyAction
//   87   1     enforcement_status 0..3
//   88   1     defcon_impact      1-5
//   89   4     context_flags
//   93   16    reserved           pid(4) ppid(4) proc_type(1)
//                                integrity(1) hids_flag(1) node_id(4)
//                                confidence(1)
//   ============================================================
//
// No policy, no enforcement, no detection: this file ONLY encodes
// observed packets into the canonical event schema (ADR-0001:
// Go is acquisition-only).

import (
	"encoding/binary"
	"errors"
)

const (
	EventMagic               uint32 = 0x41454731 // "AEG1"
	EventSchemaVersion       uint16 = 1
	EventWireSize            int    = 109
	DefaultDevStructSize     uint16 = 128 // Zig @sizeOf(CanonicalEvent) on win64 dev
)

// EventSource — MUST match core/canonical_event.zig EventSource enum.
const (
	SourceZigCore          byte = 0
	SourceWfpSensor        byte = 1
	SourcePipeSensor       byte = 2
	SourceMinifilter       byte = 3
	SourcePipeMonitor      byte = 4
	SourcePythonBrain      byte = 5
	SourceCppBridge        byte = 6
	SourceRustShield       byte = 7
	SourceGoAggregator     byte = 8
	SourceNpcapSensor      byte = 9
	SourceHostTelemetry    byte = 10
	SourceMlDetector       byte = 11
	SourceClusterFed       byte = 12
	SourceProcessSensor    byte = 13
	SourceFileSensor       byte = 14
	SourceRegistrySensor   byte = 15
	SourceReplaySensor     byte = 16
	SourceExternal         byte = 255
)

// EventType — MUST match core/canonical_event.zig EventType enum.
const (
	TypeBlock    uint32 = 0
	TypeMatch    uint32 = 1
	TypeForward  uint32 = 2
	TypeIpBlock  uint32 = 3
	TypeRejected uint32 = 4
	// ... session_start 5, session_end 6, ruleset_reload 7, shutdown 8,
	// startup 9, custom 0xFFFFFFFF
	TypeCustom uint32 = 0xFFFFFFFF
)

// PolicyAction — MUST match core/canonical_event.zig PolicyAction enum.
const (
	ActionAllow      byte = 0
	ActionAlert      byte = 1
	ActionBlock      byte = 2
	ActionQuarantine byte = 3
	ActionRateLimit  byte = 4
	ActionLogOnly    byte = 5
)

// Reserved-area offsets (see core/canonical_event.zig RES_OFF_*).
const (
	ResOffPid        = 0
	ResOffPpid       = 4
	ResOffProcType   = 8
	ResOffIntegrity  = 9
	ResOffHidsFlag   = 10
	ResOffNodeID     = 11
	ResOffConfidence = 15
)

// CanonicalEvent is the Go-side view of the Zig-owned schema.
// It is NOT the wire layout — Serialize() writes the frozen format.
type CanonicalEvent struct {
	EventID           uint64
	TimestampMS       uint64
	MonotonicNS       uint64
	Source            byte // EventSource
	SourceIP          uint32
	SourcePort        uint16
	DestIP            uint32
	DestPort          uint16
	SessionID         uint64 // source_id (T2)
	Protocol          byte
	Direction         byte
	LayerID           byte
	IsPipe            byte
	EventType         uint32
	Severity          byte
	RuleID            uint32
	RulesetVersion    uint64
	PayloadLength     uint32
	PayloadHash       uint64
	PolicyAction      byte
	EnforcementStatus byte
	DefconImpact      byte
	ContextFlags      uint32
	PID               uint32
	PPID              uint32
	ProcType          byte
	Integrity         byte
	HidsFlag          byte
	NodeID            uint32 // host identity
	Confidence        byte
}

// classifyGo maps an EventSource to the canonical SourceKind enum order
// used by the Zig test (mirrors SourceKind.classify). Kind ordinal iota:
// network=0 host=1 process=2 file=3 registry=4 ml=5 federation=6
// replay=7 core=8 external=255.
func classifyGo(src byte) byte {
	switch src {
	case SourceWfpSensor, SourceNpcapSensor:
		return 0 // network
	case SourceHostTelemetry, SourceMinifilter, SourcePipeMonitor, SourcePipeSensor:
		return 1 // host
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
		return 8 // core
	default:
		return 255 // external
	}
}

// SourceKindName returns the canonical kind label (for logs/TUI).
func SourceKindName(src byte) string {
	names := []string{"network", "host", "process", "file", "registry", "ml", "federation", "replay", "core"}
	if k := classifyGo(src); int(k) < len(names) {
		return names[k]
	}
	return "external"
}

// Serialize encodes the event to the frozen 109-byte wire format.
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