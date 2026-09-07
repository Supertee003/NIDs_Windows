# AEGIS Canonical Event Contract v1

**Status:** FROZEN by ADR-0001  
**Date:** 2026-09-02  
**Owner:** core/canonical_event.zig  

## Schema

### Header (ABI-safe, fixed-width)

| Field | Type | Size | Description |
|---|---|---|---|
| magic | u32 | 4 | 0x41454731 ("AEG1") |
| version | u16 | 2 | 1 (current) |
| struct_size | u16 | 2 | sizeof(CanonicalEvent) for forward compat |
| event_id | u64 | 8 | Unique ID (atomic counter) |

### Timestamps (dual-clock)

| Field | Type | Size | Description |
|---|---|---|---|
| timestamp_ms | u64 | 8 | Wall-clock epoch milliseconds |
| monotonic_ns | u64 | 8 | Monotonic nanoseconds |

### Source Identification

| Field | Type | Size | Description |
|---|---|---|---|
| source | EventSource (u8) | 1 | Which subsystem produced this event |
| source_ip | u32 | 4 | Network byte order (0 = N/A) |
| source_port | u16 | 2 | Source port |
| dest_ip | u32 | 4 | Destination IP |
| dest_port | u16 | 2 | Destination port |
| session_id | u64 | 8 | Cross-tier correlation ID |

### Protocol/Transport

| Field | Type | Size | Description |
|---|---|---|---|
| protocol | u8 | 1 | IPPROTO_TCP=6, IPPROTO_UDP=17, etc. |
| direction | u8 | 1 | 0=inbound, 1=outbound |
| layer_id | u8 | 1 | 0=TCP, 1=WFP, 2=kernel, 3=pipe |
| is_pipe | u8 | 1 | 1 if from named pipe (host event) |

### Detection Results

| Field | Type | Size | Description |
|---|---|---|---|
| event_type | EventType (u32) | 4 | BLOCK/MATCH/FORWARD/IP_BLOCKED/REJECTED |
| severity | u8 | 1 | 0=Low, 1=Medium, 2=High, 3=Critical |
| rule_id | u32 | 4 | Rule hash (SipHash64) |
| ruleset_version | u64 | 8 | Which ruleset version matched |

### Payload Reference

| Field | Type | Size | Description |
|---|---|---|---|
| payload_length | u32 | 4 | Original payload size |
| payload_hash | u64 | 8 | SHA-256 prefix (first 8 bytes) for dedup |

### Policy/Enforcement

| Field | Type | Size | Description |
|---|---|---|---|
| policy_action | PolicyAction (u8) | 1 | ALLOW/ALERT/BLOCK/QUARANTINE |
| enforcement_status | u8 | 1 | 0=pending, 1=enforced, 2=failed, 3=rolled_back |

### Context/Intelligence

| Field | Type | Size | Description |
|---|---|---|---|
| defcon_impact | u8 | 1 | 1-5 (5=normal, 1=critical) |
| context_flags | u32 | 4 | Bitfield for enrichment flags |

### Reserved

| Field | Type | Size | Description |
|---|---|---|---|
| reserved | [16]u8 | 16 | Zero-filled, for v2 fields |

## Total Size: 109 bytes on the wire (packed, explicit field-by-field LE)

`struct_size` reports 128 on the win64 dev build (ab/alignment padding);
the WIRE size is always 109. Cross-language serializers (Zig, Go)
agree via a golden vector embedded in tests on both sides.

## Validated Identity Fields (T2, cross-language)

Each producing language MUST populate identity before handoff:

- **source_id** (u48 @ session_id) — session/capture-session identity.
  Go Nose derives it from the 5-tuple; Zig accessors: `getSourceId`/`setSourceId`.
- **host identity** — node_id in `reserved[11..15]`; accessors:
  `getHostIdentity`/`setHostIdentity`.
- **process identity** — pid/ppid in `reserved[0..7]`; accessors:
  `getProcessIdentity`.
- **network identity** — frozen 5-tuple (src ip/port, dst ip/port, protocol)
  in wire slots 33..53; `getNetworkIdentity` verifies the frozen layout.
- **provenance** — (source, layer_id, is_pipe); `getProvenance` returns it.

Mappings recorded in `docs/adr/0003-*` and mirrored in `nose/canonical.go`.

## Enums

### EventSource (u8)
```
zig_core = 0, wfp_sensor = 1, pipe_sensor = 2, minifilter = 3,
pipe_monitor = 4, python_brain = 5, cpp_bridge = 6, rust_shield = 7,
go_aggregator = 8, npcap_sensor = 9, host_telemetry = 10, ml_detector = 11,
cluster_federation = 12, process_sensor = 13, file_sensor = 14,
registry_sensor = 15, replay_sensor = 16, external = 255
```

### SourceKind (u8) — logical grouping of EventSource
```
network = 0, host = 1, process = 2, file = 3, registry = 4, ml = 5,
federation = 6, replay = 7, core = 8, external = 255
```
classify(source) maps EventSource → SourceKind. Shared across Zig
(`SourceKind` enum + `classify()`) and Go (`classifyGo`), tested against
each other and against the golden vector.

### EventType (u32)
```
block = 0, match_ = 1, forward = 2, ip_blocked = 3, rejected = 4,
session_start = 5, session_end = 6, flow_update = 7, ...
```

### PolicyAction (u8)
```
allow = 0, alert = 1, block = 2, quarantine = 3, rate_limit = 4
```

## Validation Rules

1. magic MUST be 0x41454731
2. version MUST be 1 (reject if > 1)
3. struct_size MUST match sizeof(CanonicalEvent)
4. event_id MUST be unique (monotonic counter)
5. timestamp_ms MUST be > 0
6. monotonic_ns MUST be > 0
7. severity MUST be in [0, 3]
8. protocol MUST be valid IPPROTO_* or 0
9. reserved MUST be all zeros
