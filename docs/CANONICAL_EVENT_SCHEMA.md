# Canonical Event Schema — AEGIS NIDS Windows

> Source-of-truth document: [`shared/event/canonical_event.md`](../shared/event/canonical_event.md).
> Additive wire extensions: [`shared/protocol/wire_v2.md`](../shared/protocol/wire_v2.md) and
> [`shared/protocol/wire_v3.md`](../shared/protocol/wire_v3.md).
> This page is an **index with verified code references**, not a second schema. If it disagrees with
> the source documents, the source documents win.

## 1. Why a single schema exists

Every sensor produces a different native shape (packet, WFP row, file notification, registry
event). AEGIS normalizes all of them into one `CanonicalEvent`. One schema with N codecs is a
deliberate constraint: a wire change must update every language and the shared vector in the same
patch, so silent divergence becomes a test failure instead of a field bug.

Zig owns the ABI struct. The other languages are spokes with codecs, not schema authorities.

## 2. Frozen v1 layout

| Property | Value |
|---|---|
| Wire size | **109 bytes, little-endian** |
| Magic | `0x41454731` = `"AEG1"` |
| Version | `1` (v1 frozen); `2` and `3` are additive extensions |
| `struct_size` | Producer's **in-memory** struct size (Zig `@sizeOf` = 128 due to alignment) — **not** the wire length |
| Timestamp | `timestamp_ms`, wall-clock epoch milliseconds; `mono_ns` is monotonic |

Field order (from the Python codec reference in `brain/canonical_event.py:1-15`):

```text
magic(4) ver(2) struct_size(2) event_id(8) ts_ms(8) mono_ns(8)
source(1) src_ip(4) src_port(2) dst_ip(4) dst_port(2) session(8)
proto(1) dir(1) layer(1) is_pipe(1) evtype(4) sev(1) rule(4)
rsv_ver(8) pay_len(4) pay_hash(8) pol_act(1) enf(1) defcon(1)
ctx_flags(4) reserved(16)              = 109 bytes
```

`event_id` is a `u64` produced by an atomic counter (`shared/event/canonical_event.md:19-23`).
The reserved area is G2-frozen for process, host, and node identity plus confidence.

## 3. Wire versions

| Version | Wire size | Meaning |
|---|---|---|
| **v1** | 109 B | Frozen base. Metadata only. |
| **v2** | 133 B | v1 + 24-byte tail: full IPv6 source/destination identity. `struct_size` keeps its v1 meaning; wire length comes from `version`. |
| **v3** | 165 + `payload_len` B | v2 base + 32-byte envelope + 0..1024 bounded payload. Carries captured evidence, **never** a detection verdict. |

Receivers dispatch on `version` and reject unknown values — no silent truncation, no version
fallback. All fields are fixed-width: no pointers, no padding dependency, no `i128`, and explicit
field-by-field encoding (never `memcpy` of the in-memory struct).

## 4. Codec implementation status

| Language | File | Status |
|---|---|---|
| Zig | [`src/contract/canonical_event.zig`](../src/contract/canonical_event.zig) | Authoritative `extern struct`, `serializeToBytes()` / `deserializeFromBytes()` |
| C | `shared/schema/canonical_event_v1.h` | `AegisCanonicalEvent` typedef, `#pragma pack(push, 1)` |
| Go | `nose/canonical.go`, `nose/canonical_test.go`, `nose/golden_path_ffi.go` | 109-byte codec with golden-byte parity against Zig |
| Python | `brain/canonical_event.py` | Pure-Python 109-byte codec. **Not wired to the production entrypoint** (`brain/windows_brain.py`); exercised by brain tests only |
| Rust | `rust-src/canonical_event.rs` | **TBD — does not exist as an implemented codec** |

Zig validation (`src/contract/canonical_event.zig:348-355`) checks magic, version, and struct size
and returns `false` on ABI mismatch. The version-dispatch logic for v2/v3 lives in the wire
documents and their decoders.

## 5. Validation, deduplication, and invalid input

| Topic | Behavior supported by source |
|---|---|
| ABI mismatch | `validate()` returns `false`; endpoint creation / decoding fails closed |
| Unknown wire version | Rejected; no fallback |
| Missing / malformed field | Rejected at the codec boundary; contract tests pin decoder behavior |
| Duplicate / non-monotonic IDs | **Not deduplicated by the schema**. The runtime exposes diagnostic counters (`duplicate_event_ids`, `nose_non_monotonic_event_ids`) in health |
| Event ID generation | Atomic counter, not a content hash |
| Timestamp handling | Wall-clock `timestamp_ms` + monotonic `mono_ns`; the `capture_to_decode` stage counter on the current host has an implausible maximum consistent with a boot-time clock artifact — see [Observed performance](portfolio/OBSERVED_PERFORMANCE.md) |
| Privacy / redaction | **No explicit privacy/PII/redaction contract is documented** in `shared/event/**`. Do not claim redaction behavior |
| Rule-ID hash | Active implementation is **FNV-1a** over the rule-id string (`src/pipeline/rule_loader.zig:15-19`, pinned by `tests/security/test_detection_contract_pin.py`). A `SipHash64` comment in older schema text is stale |

## 6. Boundaries this schema does not cross

- A canonical event is **evidence**, not a verdict. Detection authority stays in Zig
  (`src/pipeline/event_processor.zig`); Python's `regex_pattern` is advisory Tier-2 analytics.
- The v3 envelope carries captured evidence and explicitly does not authorize enforcement
  (`prevention_gate=closed`, `host_effect_capable=false`).
- Ingress authority stripping is counted in health (`ingress_authority.claims_stripped`), so a
  sensor cannot inject its own severity, rule, or event type into the canonical stream.

## 7. Interview-ready answer

> "The schema is one frozen 109-byte v1 struct that every language encodes explicitly. Zig owns
> the struct; Go and Python have byte-exact codecs pinned by golden vectors, C has a packed
> struct, and the Rust codec is still a documented gap. Wire v2 and v3 are additive, so old frames
> stay decodable. The important design choice is that `struct_size` describes in-memory layout,
> not the wire — receivers validate the wire length from the version, which prevents an alignment
> difference between languages from becoming a memory-safety bug. I also track duplicate and
> non-monotonic event IDs as counters rather than silently deduplicating, because hiding that
> signal would hide a sensor bug."

---

*See also: [Security boundaries](architecture/SECURITY_BOUNDARIES.md) ·
[Detection catalog](portfolio/DETECTION_CATALOG.md) ·
[Technology decisions](TECHNOLOGY_DECISIONS.md)*
