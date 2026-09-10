# CONTRACT-01: Canonical Event Schema

**Contract ID:** CANONICAL_EVENT
**Version:** 1.0
**Status:** FROZEN
**Languages:** Zig, C, Rust, Go, Python

## Purpose

Single source of truth for event structure across all AEGIS subsystems.
Every sensor, detector, correlator, and policy engine MUST use this model.

## Schema

### Binary Layout (109 bytes, little-endian)

| Offset | Size | Type | Field | Description |
|--------|------|------|-------|-------------|
| 0 | 4 | u32 | magic | 0x41454731 ("AEG1") |
| 4 | 2 | u16 | version | 1 |
| 6 | 2 | u16 | struct_size | sizeof(CanonicalEvent) |
| 8 | 8 | u64 | event_id | Unique ID (atomic counter) |
| 16 | 8 | u64 | timestamp_ms | Wall-clock epoch ms |
| 24 | 8 | u64 | monotonic_ns | Monotonic ns (in-process ordering) |
| 32 | 1 | u8 | source | EventSource enum |
| 33 | 4 | u32 | source_ip | Network byte order (0 = N/A) |
| 37 | 2 | u16 | source_port | |
| 39 | 4 | u32 | dest_ip | |
| 43 | 2 | u16 | dest_port | |
| 45 | 8 | u64 | session_id | Cross-tier correlation ID |
| 53 | 1 | u8 | protocol | IPPROTO_TCP=6, IPPROTO_UDP=17 |
| 54 | 1 | u8 | direction | 0=inbound, 1=outbound |
| 55 | 1 | u8 | layer_id | 0=TCP, 1=WFP, 2=kernel, 3=pipe |
| 56 | 1 | u8 | is_pipe | 1 if from named pipe (host event) |
| 57 | 4 | u32 | event_type | EventType enum |
| 61 | 1 | u8 | severity | 0=Low, 1=Medium, 2=High, 3=Critical |
| 62 | 4 | u32 | rule_id | Rule hash (SipHash64) |
| 66 | 8 | u64 | ruleset_version | Which ruleset version matched |
| 74 | 4 | u32 | payload_length | Original payload size |
| 78 | 8 | u64 | payload_hash | SHA-256 prefix (first 8 bytes) |
| 86 | 1 | u8 | policy_action | PolicyAction enum |
| 87 | 1 | u8 | enforcement_status | 0=pending, 1=enforced, 2=failed, 3=rolled_back |
| 88 | 1 | u8 | defcon_impact | 1-5 (5=normal, 1=critical) |
| 89 | 4 | u32 | context_flags | Bitfield: bit0=threat_intel, bit1=correlation |
| 93 | 16 | u8[16] | reserved | v1 extension area (G2 frozen layout) |

### Enums

**EventSource (u8):**
- 0: Zig Core
- 1: WFP Sensor
- 2: Pipe Sensor
- 3: Minifilter
- 4: Pipe Monitor
- 5: Python Brain
- 6: C++ Bridge
- 7: Rust Shield
- 8: Go Aggregator
- 255: External

**EventType (u32):**
- 0: BLOCK
- 1: MATCH
- 2: FORWARD
- 3: IP_BLOCKED
- 4: REJECTED
- 5: SESSION_START
- 6: SESSION_END
- 7: RULESET_RELOAD
- 8: SHUTDOWN
- 9: STARTUP
- 0xFFFFFFFF: CUSTOM

**PolicyAction (u8):**
- 0: ALLOW
- 1: ALERT
- 2: BLOCK
- 3: QUARANTINE
- 4: RATE_LIMIT
- 5: LOG_ONLY

## Language Implementations

### Zig
File: `src/contract/canonical_event.zig`
- `CanonicalEvent` extern struct
- `serializeToBytes()` / `deserializeFromBytes()`

### C
File: `shared/schema/canonical_event_v1.h`
- `AegisCanonicalEvent` typedef struct
- `#pragma pack(push, 1)`

### Rust
File: `rust-src/canonical_event.rs` (TBD)
- `#[repr(C, packed)]`

### Go
File: `nose/canonical_event.go` (TBD)
- Struct with same field order

### Python
File: `brain/canonical_event.py` (TBD)
- Dataclass with same field names

## Invariants

- Magic MUST be 0x41454731 ("AEG1")
- Version MUST be 1
- Struct size MUST be 109 bytes
- All fields are fixed-width (no pointers, no padding dependency)
- No i128 (not portable across languages)
- Explicit field-by-field encoding (no memcpy of struct)
- Reserved area is G2 frozen (process identity, host identity, node identity, confidence)

## References

- `shared/schema/canonical_event_v1.h` - C header (authoritative)
- `src/contract/canonical_event.zig` - Zig implementation
- `src/contract/wire_event.zig` - Wire protocol wrapper
- `CONTRACT_MAP.json` - Contract registry
