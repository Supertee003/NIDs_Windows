# AEGIS Wire Canonical Event v3 — Bounded Payload + Capture Provenance

## Status: ACTIVE (v1 frozen, v2 unchanged — see `wire_v1.md`, `wire_v2.md`)

v3 is additive. It appends a fixed 32-byte envelope and `0..1024` bounded
payload bytes to the frozen v2 133-byte base. v1 and v2 frames, vectors, and
decoders stay byte-identical and remain explicit **metadata-only**
compatibility frames.

v3 reports captured evidence. It never carries a detection verdict. Zig
(`src/pipeline/event_processor.zig`) remains the sole detection authority;
the envelope does not authorize enforcement (`prevention_gate=closed`,
`host_effect_capable=false`).

## Delta vs v2 (additive only)

```
v1 payload:  109 bytes (frozen)
v2 payload:  133 bytes = v1 109 bytes ++ v6 tail 24 bytes
v3 payload:  165 + payload_len bytes
             = v2 133-byte base ++ 32-byte envelope ++ 0..1024 payload
```

The v3 base is exactly the v2 layout. When `ContextFlags` bit2 is clear the
24-byte v6 tail MUST be all zero. When bit2 is set the tail carries
source/dest bytes `[4..16]` exactly as v2.

## Envelope layout (offset from frame start)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 133 | v2 base | frozen v1 109 B + 24 B v6 tail |
| 133 | 2 | `flags` | bit0 = payload present, bit1 = provenance valid |
| 135 | 1 | `completeness` | 0 unavailable, 1 complete, 2 truncated, 3 metadata_only |
| 136 | 1 | `reserved` | MUST be 0 |
| 137 | 2 | `payload_len` | bytes actually following the envelope |
| 139 | 2 | `original_len` | producer's on-wire frame length (clamped to u16) |
| 141 | 4 | `payload_crc32` | CRC32 IEEE over exactly `payload_len` bytes |
| 145 | 8 | `capture_sequence` | producer capture counter |
| 153 | 4 | `producer_epoch` | producer process epoch (seconds) |
| 157 | 4 | `producer_generation` | producer restart generation |
| 161 | 4 | `interface_id` | opaque interface identity (FNV-1a of device name) |
| 165 | 0..1024 | payload | raw captured frame bytes prefix |

All fields little-endian. Envelope format string: `"<HBBHHIQIII"` (32 bytes).
Total frame size: `165 + payload_len`, maximum `1189` bytes.

## Completeness semantics

- `unavailable` (0): no payload was produced. `payload_len == 0`,
  `original_len` may be 0 or the on-wire length, `payload_crc32 == 0`,
  `flags` bit0 clear.
- `metadata_only` (3): v1/v2-equivalent compatibility frame. `payload_len == 0`,
  `original_len == 0`, `payload_crc32 == 0`, `flags` bit0 clear.
- `complete` (1): the captured bytes are the whole frame.
  `flags` bit0 set, `payload_len > 0`, `original_len == payload_len`,
  CRC over the payload.
- `truncated` (2): the attached bytes are a prefix.
  `flags` bit0 set, `payload_len > 0`, `original_len > payload_len`,
  CRC over the captured prefix only.

`payload_len` MUST equal the number of bytes physically present after the
envelope. Any mismatch, any CRC mismatch, any unknown completeness ordinal,
any non-zero reserved byte, and any `payload_len > 1024` is rejected fail
closed (no inferred acceptance, no silent truncation).

## Provenance rules

- `flags` bit1 set ⇒ `capture_sequence`, `producer_epoch`,
  `producer_generation`, `interface_id` are meaningful.
- `flags` bit1 clear ⇒ all four provenance fields MUST be zero.
- Provenance identifies the acquisition producer. It is not a trust
  signature and MUST NOT be used to authorize enforcement.

## Encoder rules

- Emit v3 only through the canonical codecs below; never hand-pack.
- Validate the envelope against the payload before emitting any byte.
- Preserve the frozen v2 base bytes exactly; only patch `version` to 3.
- Nose (`nose/capture.go::captureAttachment`) attaches the raw captured frame
  bytes prefix (max 1024) and reports `complete` only when the prefix is the
  whole frame; otherwise `truncated`. It emits no verdict, no `rule_id`, and
  no event-type reinterpretation.
- Enforce the 1024-byte payload cap at the producer; never rely on the
  transport to clamp.

## Decoder rules

- Dispatch on the `version` field.
- v1: 109+ bytes → frozen path (tail ignored, null sidecars).
- v2: 133+ bytes → full IPv6 reconstruction; `version == 2` with 109 bytes is
  malformed.
- v3: exact length `165 + payload_len` → strict envelope validation, then
  expose payload + envelope in the decode product.
- Anything else → reject. No version fallback, no silent truncation.
- `struct_size` stays the producer's in-memory layout tag (128) for every
  live producer, exactly as v2 pins it. It is never the wire length.

## Reference codecs (v3 entry points)

- Zig: `src/contract/canonical_event.zig::serializeV3` / `deserializeV3` /
  `deserializeDispatch` (returns `DecodedFrame` with `envelope` + `payload`)
- Go: `nose/canonical.go::SerializeV3` / `DeserializeV3` /
  `DeserializeDispatch` (`Envelope` + `Payload`)
- C++: `shared/wire/wire_codec.h::aegis_wire_encode_event_v3` /
  `aegis_wire_decode_event_v3`
- Python: `shared/wire/wire_codec.py::WireCodec.encode_event_v3` /
  `decode_event` (version-dispatched) and `brain/canonical_event.py`

## Queue acceptance (Zig pipeline gate)

`src/pipeline/event_queue.zig::pushDecodedFrame` accepts a v3 frame only when
`src/contract/canonical_event.zig::validateDecodedFrame` confirms the v3 shape
(`version == 3`, envelope present, payload bounded). The payload is capped at
`MAX_PAYLOAD_BYTES = 1500`; the v3 maximum (1024) is therefore never clamped
by the queue. Mixed shapes (v3 without envelope, v1/v2 with envelope) are
rejected fail closed.

### Ingress verdict strip (VERDICT-AUTH-001, #28)

Version dispatch gates *shape*; `sanitizeAcquisitionClaim` gates *authority*.
Every frame that reaches the queue — v1, v2 or v3 — has any producer-authored
`rule_id`, nonzero `severity`, and `.match_`/`.block`/`.ip_blocked` event type
cleared before the record becomes an `IpcEvent`, and demoted to a plain
`.forward` evidence row when it claimed a verdict. Consequences an implementer
must rely on:

- after ingress, `rule_id != 0` means Zig's own Aho-Corasick / L4 / L7 stage
  produced it, and nothing else;
- `queue.stats.ingress_authority.claims_stripped` counts the removal, per field;
  a nonzero counter on a stock host means a producer is still authoring
  verdicts and must be fixed;
- no byte of the frozen v1/v2 base or the v3 envelope changes, so vectors,
  codecs and `struct_size` are untouched by this rule.


## Golden vectors

`tests/contracts/event_vectors/generate_test_vectors.py` freezes:

| File | Size | Meaning |
|---|---|---|
| `event_v3_007.bin` | 197 | IPv6 complete payload (32 bytes, provenance valid) |
| `event_v3_008.bin` | 229 | IPv4 truncated payload (64 of 1514 bytes) |
| `event_v3_009.bin` | 165 | IPv4 metadata-only (no payload bytes) |

`event_v1_*.bin` and `event_v2_006.bin` are unchanged byte-for-byte. The v3
vectors are pinned by Zig (`canonical_event.zig`), Go (`payload_v3_test.go`),
both Python codecs (`tests/contracts/test_payload_envelope_v3.py`,
`tests/brain/test_canonical_event_v3.py`), and the compiled C++ harness
(`tests/contracts/wire_codec_v3_cpp_check.cpp`, which decodes, re-encodes and
strictly rejects tampered frames against the same vectors).
