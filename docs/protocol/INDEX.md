# Canonical event / wire protocol — index and answer sheet

> This is an **index**, not a second specification. Authoritative text lives in
> `shared/event/canonical_event.md` (FROZEN schema) and `shared/protocol/wire_v1.md`,
> `wire_v2.md`, `wire_v3.md` (v3 ACTIVE). A wire change must update all codecs and the
> shared `event_v*` vectors in the same patch. This page reproduces no field table.

## Questions an auditor asks, answered from the current codec

| Question | Answer | Source |
|---|---|---|
| Header size? | Active Nose pipe framing has a **4-byte little-endian length prefix** before the raw frame. The legacy 16-byte WEV1 container is not the live pipe frame. | `shared/protocol/wire_v1.md:13-20`; `nose/pipe_writer.go:9-13` |
| Length prefix present? | Yes, 4-byte LE. On-pipe sizes: v1 **113**, v2 **137**, v3 **169..1193** bytes. | `shared/protocol/wire_v1.md:13-18` |
| Where is the version? | Raw frame bytes **4–5**, `u16` little-endian (`1`, `2`, `3`). Magic `AEG1` at bytes 0–3; `struct_size` at 6–7 is the in-memory tag (128), not the wire length. | `src/contract/canonical_event.zig:602,612-613`; `wire_v1.md:69-95` |
| Required vs optional fields? | v1/v2: all **109 / 133** bytes required. v3: the 133-byte base is required; the 32-byte envelope is present, with payload `0..1024` bytes. `flags` bit0 says payload present; bit1 says provenance fields are meaningful. `reserved` must be 0. | `wire_v3.md:28-46,48-65` |
| Endianness? | Codec fields little-endian. The first four source/destination address bytes are stored as a little-endian `u32` holding a big-endian value; the v6 tail bytes are written verbatim in network order. | `wire_v3.md:45`; `src/contract/canonical_event.zig:616-618` |
| Maximum size? | Raw v3 frame **1189** bytes (`165 + payload_len`, payload ≤ 1024); on-pipe **1193** with the length prefix. | `wire_v3.md:43-46`; `wire_v1.md:15-17` |
| Unknown version? | Rejected. `deserializeDispatch` returns `null` for anything other than v1/v2/v3. | `src/contract/canonical_event.zig:595-610` |
| Invalid frame rejection? | Exact per-version length required: v1 109, v2 133, v3 `165 + payload_len`. Trailing bytes, short frames, version/length disagreement, CRC mismatch, unknown completeness, non-zero reserved and `payload_len > 1024` are rejected and counted (`nose_frames_rejected`), never silently truncated. | `canonical_event.zig:595-604`; `wire_v3.md:62-65`; `src/capture/nose_pipe_reader.zig:452-456` |
| Golden vectors? | Shared `event_v*` vectors under `tests/contracts/event_vectors/`; Zig, Go, C and reference Python codecs are pinned to the same schema. Rust canonical codec is TBD; Python brain codec is not production-wired. | `tests/contracts/event_vectors/event_vectors/README.md`; `shared/protocol/wire_v1.md:5-9` |

## Source-of-truth order

1. Actual runtime behavior (current source at build source `aa3b7b0`; `7822f4c` and `43a8bcc` are HISTORICAL)
2. `src/contract/canonical_event.zig` — authoritative Zig codec
3. `shared/event/canonical_event.md` — frozen schema
4. `shared/protocol/wire_v3.md` — active framing
5. Shared golden vectors under `tests/contracts/event_vectors/`
6. This index

`docs/CANONICAL_EVENT_SCHEMA.md` and `docs/architecture/CONTRACTS.md` are historical
or superseded views; see `docs/architecture/DEPRECATION_MAP.md` and `CONTRACT_MAP.json`.
Current-source validation findings: [`CODEC-VALIDATION-E1-AUDIT`](../../analysis/current-head/CODEC-VALIDATION-E1-AUDIT-AA3B7B0-20261128.md)
and [`GOLDEN_VECTORS.md`](GOLDEN_VECTORS.md); source fixes remain an explicit
[`SOURCE-SLICE-DECISIONS`](../SOURCE-SLICE-DECISIONS.md) decision, not an implicit doc edit.

## Boundary reminder

The v3 envelope carries capture evidence, never a detection verdict. Encoding a frame
does not authorize policy or a host effect; production is detection-only with
`prevention_gate=closed` and `host_effect_capable=false` (`wire_v3.md:10-13`).

---

Related: [`docs/evidence/PROVENANCE.md`](../evidence/PROVENANCE.md) ·
[`docs/runtime/HEALTH_MODEL.md`](../runtime/HEALTH_MODEL.md)
