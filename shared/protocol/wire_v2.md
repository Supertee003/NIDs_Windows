# AEGIS Wire Canonical Event v2 — Full IPv6 Identity (T2-V6-022a)

## Status: ACTIVE (v1 frozen — see `wire_v1.md`, never modified by v2)

v1 carries only the first 4 bytes of IPv6 addresses (`ContextFlags` bit2 =
"these 32-bit fields are NOT IPv4 identity"). v2 appends the remaining
bytes so a v2 reader reconstructs full 128-bit addresses. v1 producers,
frames, vectors, and decoders are byte-identical before and after v2.

## Delta vs v1 (additive only)

```
v1 payload: 109 bytes (frozen)
v2 payload: 133 bytes = v1 109 bytes ++ v6 tail 24 bytes
  tail[0..12]   = source IPv6 bytes [4..16] (bytes 0..4 already in source_ip)
  tail[12..24]  = dest IPv6 bytes [4..16] (bytes 0..4 already in dest_ip)
```

- `version` field: 1 (v1) or 2 (v2). `struct_size` keeps its v1 meaning:
  sender in-memory `CanonicalEvent` size (128). It is NOT the wire length;
  wire length is known from `version` (109 | 133).
- `ContextFlags` bit2 semantics are UNCHANGED: set whenever the 32-bit IP
  fields hold first-4-bytes-of-IPv6 (i.e. "not IPv4 identity") — in v1
  (truncated, tail absent) and in v2 (full bytes in tail) alike.
- A v2 frame MUST carry the full 24-byte tail. `version == 2` with length
  109 is malformed and must be rejected. Unknown versions are rejected
  (wire_v1.md rule 6 still holds).
- In-memory `CanonicalEvent` layout is UNCHANGED (128 bytes, version 1).
  Full addresses travel on the wire only; v2 decoders expose them as a
  sidecar (`src6`/`dst6`), never by widening the struct.

## Encoder rules

- Emit v1 for IPv4 (bit2 clear) — byte-identical to frozen v1.
- Emit v2 for IPv6 (bit2 set, first-4-bytes in v1 IP fields, full
  addresses in tail). Encoders MUST verify tail[0..4] == IP field.
- v1-only senders (old daemons, C++ adapters) keep emitting v1; v2
  readers must still accept v1 (truncated) frames.

## Decoder rules

- Version 1 with 109+ bytes → v1 path (first 109 bytes, tail ignored,
  frozen behavior). The version field is authoritative, not the length.
- Version 2 with 133+ bytes → v2 path (validate magic/version/struct_size,
  same enum gates as v1, reconstruct full addresses).
- Anything else → reject. No silent truncation, no version fallback.

## Reference codecs (v2 entry points)

- Zig: `src/contract/canonical_event.zig::serializeV2` /
  `deserializeDispatch` (returns `DecodedFrame`)
- Go: `nose/canonical.go::SerializeV2` / `DeserializeDispatch`
- C++: `shared/wire/wire_codec.h::aegis_wire_encode_event_v2` /
  `aegis_wire_decode_event_v2`
- Python: `shared/wire/wire_codec.py::WireCodec.encode_event_v2` /
  `decode_event` (version-dispatched)

## Out of scope (scheduled follow-ups, NOT this slice)

- ~~Nose emitting v2 on the live pipe (decode-ready first, emit second).~~
  DONE T2-V6-022b: `eventFromPacket` fills Src6/Dst6, `Send` dispatches
  to `SerializeV2` for bit2 events; Zig reader already accepts 133.
- Detection/flow/forensic plumbing of full addresses (u32 identity +
  bit2 guard unchanged; see UNWIRED_INVENTORY flow `is_ipv6` item).
