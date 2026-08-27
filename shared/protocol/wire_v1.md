# AEGIS Wire Protocol v1 (STEP 2 — Explicit Encoding, Complete)

## Status: FROZEN — Changes require protocol version bump

This document is the single source of truth for the AEGIS wire format.
All languages (Zig, C++, Rust, Go, Python) MUST produce byte-identical
output for the same logical input.

## Wire Frame Layout

A wire frame consists of a 16-byte header followed by a variable-length payload:

```
+----------------+----------------+----------------+----------------+
| magic (4)      | version (2)    | payload_type(2)| payload_len(4) |
+----------------+----------------+----------------+----------------+
| crc32 (4)                          |
+------------------------------------+
| payload (variable, e.g. 109 bytes for canonical event)        |
+----------------------------------------------------------------+
```

Total canonical event frame = 16 (header) + 109 (payload) = **125 bytes**.

## Wire Header (16 bytes, little-endian, explicit field-by-field encoding)

```
Offset  Size  Field              Description
0       4     magic              0x57455631 ("WEV1")
4       2     protocol_version   1
6       2     message_type       0=event, 1=command, 2=ack, 3=heartbeat
8       4     payload_length     Length of payload following header
12      4     crc32              CRC32 of payload
```

### STEP 2 MUST rules for header encoding:
- Use `writeInt(u32, ..., .little)` / `writeInt(u16, ..., .little)` (or equivalent in other languages)
- **NO** `memcpy(struct)` — breaks across compilers due to padding
- **NO** `@ptrCast` / pointer cast — not portable
- **NO** `#pragma pack(push, 1)` with raw struct cast — relies on compiler-specific behavior
- Fixed offsets: magic@0, version@4, payload_type@6, payload_length@8, crc32@12

### Reference encoders (STEP 2):
- Zig: `wire_event.zig::serializeHeader(buf, header)` / `deserializeHeader(bytes)`
- C++: `shared/wire/wire_codec.h::aegis_wire_encode_header()` / `aegis_wire_decode_header()`
- Python: `shared/wire/wire_codec.py::WireCodec.encode_header()` / `decode_header()`

## Payload Types

| Type | Value | Description |
|------|-------|-------------|
| Canonical Event | 0 | Serialized AegisCanonicalEvent (109 bytes) |
| Command | 1 | Control message (reload, shutdown) — 4-byte cmd_id + variable data |
| Ack | 2 | Acknowledgement |
| Heartbeat | 3 | Keepalive |

## Canonical Event Payload (109 bytes, explicit field-by-field encoding)

```
Offset  Size  Field
0       4     magic (0x41454731, "AEG1")
4       2     version (1)
6       2     struct_size
8       8     event_id
16      8     timestamp_ms (u64, was i64 in STEP 0)
24      8     monotonic_ns (u64, was i128 in STEP 0)
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

### STEP 2 MUST rules for payload encoding:
- Same explicit `writeInt` / `readInt` approach as header
- **NO** `memcpy(event_struct)` — even with `#pragma pack(push, 1)`, struct layout varies by language (Rust enum tags, Zig extern alignment, etc.)
- **NO** `i128` for `monotonic_ns` (STEP 1 fix — not portable across languages)
- **NO** `i64` for `timestamp_ms` (STEP 1 fix — negative timestamps make no sense and break ABI)

### Reference encoders (STEP 2):
- Zig: `canonical_event.zig::serializeToBytes(event, buf)` / `deserializeFromBytes(bytes)`
- C++: `shared/wire/wire_codec.h::aegis_wire_encode_event()` / `aegis_wire_decode_event()`
- Python: `shared/wire/wire_codec.py::WireCodec.encode_event()` / `decode_event()`

## CRC32

- Polynomial: IEEE 802.3 (same as `std.hash.Crc32` in Zig, `zlib.crc32` in Python, `crc32` in Go's `hash/crc32` package with `crc32.IEEETable`)
- Computed over the payload bytes only (not the header)
- Stored at header offset 12 (little-endian u32)

## Test Vectors

```
tests/contracts/canonical_event.bin  — Binary canonical event payload (109 bytes)
tests/contracts/wire_event.bin       — Wire-format frame (125 bytes = 16 header + 109 payload)
tests/contracts/test_vectors.json    — Human-readable expected field values
```

All languages must produce bytes identical to the test vectors for the same input.

## Cross-Language Verification

`tests/contracts/generate_test_vectors.py` generates the canonical test vectors.
Each language's wire codec must pass:

1. Encode a known event → bytes match `wire_event.bin` exactly
2. Decode `wire_event.bin` → all fields match expected values in `test_vectors.json`
3. Round-trip (encode → decode) preserves all fields
4. CRC32 mismatch → reject
5. Wrong magic → reject
6. Wrong version → reject
7. Short buffer → reject

## Versioning

- `EVENT_MAGIC` (0x41454731) and `WIRE_MAGIC` (0x57455631) are permanent identifiers — never change for v1 events
- `EVENT_VERSION` (1) and `WIRE_VERSION` (1) bump on schema-breaking changes
- Receivers MUST validate magic + version before reading any other field
- `struct_size` field (in canonical event) provides forward compatibility — receivers can skip unknown trailing fields if struct_size > expected
