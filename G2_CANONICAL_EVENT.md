# G2 — Canonical Event Contract

**Gate:** G2
**Status:** COMPLETE
**Date:** 2026-09-07

## Single Source of Truth

`bridge/aegis_ipc.hpp` → `struct IpcEvent` (72 bytes) is the canonical event definition.
All language bindings MUST derive from this header — no duplicate event struct definitions.

## Canonical Event Schema (v2)

```
Offset  Size  Field             Type      Description
------  ----  -----             ----      -----------
0       4     event_type         u32       EventType enum (0=network, 1=kernel_file, 2=kernel_process, 3=pipe)
4       4     source_ip          u32       IPv4 source (0 for host-only events)
8       4     dest_ip            u32       IPv4 destination (0 for host-only)
12      2     source_port        u16       Source port (0 for host-only)
14      2     dest_port          u16       Destination port (0 for host-only)
16      1     protocol           u8        6=TCP, 17=UDP, 1=ICMP (0 for host)
17      1     direction          u8        0=inbound, 1=outbound
18      1     layer_id           u8        WFP layer or source layer ID
19      1     tier_result        u8        0=NoMatch, 1=Tier1(Aho-Corasick), 2=Tier2(regex), 3=Tier3(behavioral)
20      4     payload_length     u32       Length of payload data following header
24      4     rule_id            u32       Matched rule ID (0 if none)
28      4     severity           u32       0=Low, 1=Medium, 2=High, 3=Critical
32      4     reserved           u32       Reserved (0)
36      8     timestamp          u64       Event timestamp (ms since epoch)
44      4     source_pid         u32       Process PID (0 if unknown)
48      4     defcon_impact      u32       DEFCON impact level (1-5)
--- G2 extension (bytes 52-71) ---
52      8     event_id           u64       Unique event identifier (monotonic or hash)
60      2     schema_version     u16       Schema version (currently 2)
62      1     confidence         u8        Detection confidence 0-100 (0=no detection, 100=certain)
63      1     provenance         u8        SubsystemId that produced this event
64      4     parent_pid         u32       Parent process PID (0 if unknown)
68      4     evidence_offset   u32       Offset to evidence data in payload (0 if none)
72      4     evidence_length   u32       Length of evidence data (0 if none)
------ ----
Total: 76 bytes (was 48 before G2)
```

Wait - let me recalculate. The struct is packed:
- Bytes 0-3: event_type (4)
- Bytes 4-7: source_ip (4)
- Bytes 8-11: dest_ip (4)
- Bytes 12-13: source_port (2)
- Bytes 14-15: dest_port (2)
- Byte 16: protocol (1)
- Byte 17: direction (1)
- Byte 18: layer_id (1)
- Byte 19: tier_result (1)
- Bytes 20-23: payload_length (4)
- Bytes 24-27: rule_id (4)
- Bytes 28-31: severity (4)
- Bytes 32-35: reserved (4)
- Bytes 36-43: timestamp (8)
- Bytes 44-47: source_pid (4)
- Bytes 48-51: defcon_impact (4)
- Bytes 52-59: event_id (8)
- Bytes 60-61: schema_version (2)
- Byte 62: confidence (1)
- Byte 63: provenance (1)
- Bytes 64-67: parent_pid (4)
- Bytes 68-71: evidence_offset (4)
- Bytes 72-75: evidence_length (4)
Total: 76 bytes

## Report v2.0 Compliance

| Required Field | IpcEvent Field | Status |
|---|---|---|
| Event ID | event_id (u64) | ✅ Added |
| Timestamp | timestamp (u64) | ✅ Existing |
| Source | provenance (u8 SubsystemId) | ✅ Added |
| Type | event_type (u32 EventType) | ✅ Existing |
| Host identity | source_pid + parent_pid | ✅ Added parent_pid |
| Process identity | source_pid, parent_pid | ✅ Added parent_pid |
| Network identity | source_ip, dest_ip, ports, protocol | ✅ Existing |
| Evidence | evidence_offset + evidence_length | ✅ Added |
| Risk/Confidence | confidence (u8 0-100) | ✅ Added |
| Provenance | provenance (u8 SubsystemId) | ✅ Added |
| Schema version | schema_version (u16) | ✅ Added |

## Language Bindings

| Language | File | Status |
|---|---|---|
| C++ (source of truth) | `bridge/aegis_ipc.hpp` | ✅ Updated (76 bytes) |
| Python | `bridge/aegis_bridge_ctypes.py` | ✅ Updated (ctypes fields match) |
| Zig | Uses DynLib runtime loading — no struct copy needed | ✅ No change needed |
| Rust | `src/lib.rs` — FFI to C++, no direct struct copy | ✅ No change needed |
| Kernel C | `drivers/wfp_callout/aegis_wfp.h` — AEGIS_EVENT_HEADER (40 bytes) maps to first 40 bytes | ✅ Compatible (subset) |

## Backward Compatibility

- First 48 bytes are identical to the pre-G2 IpcEvent struct
- Existing code that reads only the first 48 bytes continues to work
- New fields (bytes 48-75) default to 0 when not populated
- `schema_version` field allows future detection of old vs new events

## Exit Gate

> Network + Host + Federation events เข้า schema เดียวกันได้

✅ PASS — `IpcEvent` can represent:
- Network events: event_type=0, source_ip/dest_ip/ports/protocol populated
- Host events: event_type=1/2, source_pid/parent_pid populated, network fields=0
- Pipe events: event_type=3, payload contains pipe data
- Federation events (future): event_type can be extended; provenance identifies source node
