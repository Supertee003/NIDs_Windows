# AEGIS Wire Protocol v1 (STEP 1 — Explicit Encoding)

## Status: FROZEN — Changes require protocol version bump

## Wire Header (16 bytes, little-endian)

```
Offset  Size  Field              Description
0       4     magic              0x57455631 ("WEV1")
4       2     protocol_version   1
6       2     message_type       0=event, 1=command, 2=ack, 3=heartbeat
8       4     payload_length     Length of payload following header
12      4     crc32              CRC32 of payload
```

## Encoding Rules (STEP 1)

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

## Payload Types

| Type | Value | Description |
|------|-------|-------------|
| Canonical Event | 0 | Serialized AegisCanonicalEvent |
| Command | 1 | Control message (reload, shutdown) |
| Ack | 2 | Acknowledgement |
| Heartbeat | 3 | Keepalive |

## Canonical Event Payload (STEP 1: field-by-field encoding)

```
Offset  Size  Field
0       4     magic (0x41454731)
4       2     version (1)
6       2     struct_size
8       8     event_id
16      8     timestamp_ms (u64, was i64)
24      8     monotonic_ns (u64, was i128 — STEP 1 fix)
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

## Test Vectors

```
tests/contracts/canonical_event.bin  — Binary test vector
tests/contracts/wire_event.bin       — Wire-format test vector
tests/contracts/policy_ir.json       — Policy IR test vector
```

All languages must produce identical bytes for the same input.
