# AEGIS Wire Protocol v1 (Rewrite Phase 2)

## Status: FROZEN — Changes require protocol version bump

## Overview

All cross-language communication uses this wire protocol.
Every language (Zig, C++, Rust, Go, Python) MUST produce byte-identical output.

## Wire Frame Layout (125 bytes total)

```
Offset  Size  Field              Description
0       4     magic              0x57455631 ("WEV1")
4       2     protocol_version   1
6       2     payload_type       0=event, 1=command, 2=ack, 3=heartbeat
8       4     payload_length     109 (canonical event)
12      4     crc32              CRC32 of payload (IEEE 802.3)
--- Header: 16 bytes ---
16      109   payload            Canonical event (explicit field-by-field)
--- Total: 125 bytes ---
```

## Encoding Rules (MANDATORY)

### MUST:
- Fixed-width fields (u8, u16, u32, u64)
- Little-endian byte order (explicit)
- Explicit field-by-field encoding (NOT memcpy of struct)
- CRC32 integrity check on payload

### MUST NOT:
- `memcpy(struct)` — breaks across compilers/languages
- Pointer cast — not portable
- Implicit alignment — compiler-specific
- `i128` — not portable across languages
- Variable-width encoding — not deterministic

## Canonical Event Payload (109 bytes)

```
Offset  Size  Field
0       4     magic (0x41454731, "AEG1")
4       2     version (1)
6       2     struct_size
8       8     event_id
16      8     timestamp_ms (u64)
24      8     monotonic_ns (u64)
32      1     source
33      4     source_ip
37      2     source_port
39      4     dest_ip
43      2     dest_port
45      8     session_id
53      1     protocol
54      1     direction
55      1     layer_id
56      1     is_pipe
57      4     event_type
61      1     severity
62      4     rule_id
66      8     ruleset_version
74      4     payload_length
78      8     payload_hash
86      1     policy_action
87      1     enforcement_status
88      1     defcon_impact
89      4     context_flags
93      16    reserved (zero-filled)
Total:  109 bytes
```

## Reference Implementations

| Language | File | Functions |
|----------|------|-----------|
| C/C++ | `shared/protocol/wire_v1.h` | `aegis_wire_encode_header()`, `aegis_wire_decode_header()`, `aegis_wire_encode_event()`, `aegis_wire_encode_frame()` |
| Zig | `core/wire_event.zig` | `serializeHeader()`, `deserializeHeader()`, `serializeEvent()`, `deserializeEvent()` |
| Python | `shared/wire/wire_codec.py` | `WireCodec.encode_header()`, `decode_header()`, `encode_event()`, `decode_event()` |

## CRC32

- Polynomial: IEEE 802.3 (same as `std.hash.Crc32` in Zig, `zlib.crc32` in Python)
- Computed over payload bytes only (not header)
- Stored at header offset 12 (little-endian u32)

## Test Vectors

```
tests/contracts/event_vectors/event_v1_001.bin  — benign forward (109 bytes)
tests/contracts/event_vectors/event_v1_002.bin  — APT block (109 bytes)
tests/contracts/event_vectors/event_v1_003.bin  — host event (109 bytes)
tests/contracts/event_vectors/event_v1_004.bin  — edge case: zeros (109 bytes)
tests/contracts/event_vectors/event_v1_005.bin  — edge case: max (109 bytes)
```

All languages must produce bytes identical to these vectors for the same input.
