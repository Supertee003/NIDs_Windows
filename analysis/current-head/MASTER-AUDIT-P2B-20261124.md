# Master Audit — Phase 2b (codec helper guards / vector metadata)

**Target HEAD:** `f3ae4321ebdfafba5110d0f8ed4f7f5d87712d83`
**Build source after this patch:** `661fb768dc1c8eeb0f79e4e437807f2eac08c9ff`
**Date:** 2026-11-24
**Patch ID:** `P2B-CODEC-GUARDS-20261124`
**Classification:** "ตรวจพบ" = confirmed in current source before this patch; all six items were confirmed read-only in the P2 audit and are closed here.

---

## 1. Scope and invariant

This patch closes carry-forward findings **B1–B6** from `analysis/current-head/MASTER-AUDIT-P2-20261124.md` §6b. Every change is a guard or a test: no canonical field, wire length, golden-vector byte, rule, authority or host effect is changed. Live codecs already failed closed on version/length mismatch; the gaps were in direct-call helpers, test helpers, a mislabeled Zig assertion and an unverified metadata file.

Verified source truth before editing:

- `src/contract/canonical_event.zig:600-655` — `deserializeDispatch` enforces exact length per declared version; `deserializeV3` additionally pins `event.version == EVENT_VERSION_V3`.
- `nose/canonical.go:612-621` — `DeserializeV3` copied the first 109 bytes and rewrote `prefix[4:6]` to version 1 **without checking the declared version**.
- `shared/wire/wire_codec.h:501-508` — same v1-prefix trick in `aegis_wire_decode_event_v3`, no version pin.
- `shared/wire/wire_codec.py:112,555` — `<` length checks, so a longer buffer was accepted.
- `shared/wire/wire_codec.h:597-617` — `aegis_wire_decode_frame` (legacy full WEV1 container) used `<` and handled only v1/v2; repo-wide grep found zero callers.
- `vectors_metadata.json` recorded 9 SHA256/size pairs but no test read them.

---

## 2. Findings and replacements

### B1 — Zig "extra trailing bytes" assertion actually tested a short frame · ตรวจพบ

- **Current:** `src/contract/canonical_event.zig:1624-1625`: comment "Extra trailing bytes are rejected: v3 length is exact." followed by `deserializeDispatch(buf[0 .. n - 1]) == null`.
- **Reason:** `n - 1` is one byte **short**, the opposite of the stated case. The live codec rejects both, but the test never proved the trailing case and there was no v3→v1/v2 downgrade case.
- **Replacement:** kept the short-frame case with its own comment; added `buf[0 .. n + 1]` for a real trailing byte; added a loop forging the declared version to v1 and v2 on a v3-sized frame and asserting rejection. `n + 1` is safely inside `[WIRE_V3_MAX_SIZE]u8`.
- **Acceptance:** fresh-cache Zig suite passes; the three new assertions only reject malformed inputs, no golden bytes changed.

### B2 — Go exported `DeserializeV3` accepted a forged declared version · ตรวจพบ

- **Current:** `nose/canonical.go:613-618`: length check, then `copy(prefix[:], b[:EventWireSize]); binary.LittleEndian.PutUint16(prefix[4:6], EventSchemaVersion)`.
- **Reason:** dispatch (`nose/canonical.go:690`) is safe, but direct callers of this exported function could pass a v1/v2 frame relabelled to v3 and have it decoded through the v1 prefix path. The prefix rewrite is intentional; the missing step is pinning the version first.
- **Replacement:** before copying, `if binary.LittleEndian.Uint16(b[4:6]) != EventSchemaVersionV3 { return nil, errors.New("canonical: v3 frame has wrong declared version") }`.
- **Acceptance:** new `TestDeserializeV3RejectsForgedVersion` (versions 1, 2, 4) fails before the fix and passes after; existing trailing/dirty-tail/short tests still pass.

### B3 — C++ direct v3 decoder had the same version-pin gap · ตรวจพบ

- **Current:** `shared/wire/wire_codec.h:504-508`: length check, `::memcpy(prefix, bytes, WIRE_PAYLOAD_SIZE)`, `write_u16_le(prefix + 4, EVENT_VERSION)`.
- **Reason:** identical relabeling risk for direct callers. Existing C++ test only covered forged versions **through dispatch**, which was already safe.
- **Replacement:** `if (read_u16_le(bytes + 4) != EVENT_VERSION_V3) return false;` before the copy. Added a direct-call assertion inside the existing forged-version loop in `tests/contracts/wire_codec_v3_cpp_check.cpp`.
- **Acceptance:** `g++ -std=c++17 -Wall -Wextra` harness prints `wire_codec_v3_cpp_check: PASS`.

### B4 — Python helper decoders used `<` instead of exact length · ตรวจพบ

- **Current:** `PayloadEnvelope.decode`: `if len(data) < V3_ENVELOPE_SIZE: raise ValueError("short v3 envelope")`; `WireCodec.decode_frame`: `if len(buf) < WIRE_HEADER_SIZE + header.payload_length: return None`.
- **Reason:** both helpers would parse a shorter prefix and silently ignore trailing bytes, contradicting the live exact-length rule used by `decode_event` / `_decode_v3`. All in-repo callers pass exact-length slices or complete frames, so tightening is safe.
- **Replacement:** `!=` in both places with explicit "length mismatch" diagnostics; new tests `test_frame_helper_rejects_trailing_byte` and `test_envelope_helper_rejects_trailing_byte` assert `None` / `ValueError` respectively.
- **Acceptance:** `tests/contracts` 80 passed; no vector fixture rewritten.

### B5 — legacy full-frame helper was looser and omitted v3 · ตรวจพบ (dead code)

- **Current:** `shared/wire/wire_codec.h:597-617`: accepted `buf_len >= WIRE_HEADER_SIZE + h.payload_length`, restricted `h.payload_length` to 109/133 and branched to v1/v2 only. Zero callers repo-wide.
- **Reason:** a test-only compatibility helper with weaker guards is a misleading coverage claim and a latent incorrect fallback if anyone later calls it.
- **Replacement:** kept the helper but labelled it LEGACY WEV1 / no production caller; `h.payload_length >= WIRE_PAYLOAD_SIZE`, `buf_len == WIRE_HEADER_SIZE + h.payload_length`, CRC over the declared payload, then delegate to `aegis_wire_decode_event_dispatch` (v1/v2/v3). Added `check_legacy_frame_helper` to the C++ harness (encode v1 frame, decode it, reject one trailing byte).
- **Acceptance:** helper is still not counted as live pipe coverage; harness passes. No caller was introduced.

### B6 — vector metadata digests were recorded but never verified · ตรวจพบ

- **Current:** `tests/contracts/event_vectors/event_vectors/vectors_metadata.json` lists 9 vectors with `sha256` and `size`; no test read those fields.
- **Reason:** a metadata file that is never compared to the bytes can drift unnoticed; the recorded digests matched the bytes at audit time but that was a manual check.
- **Replacement:** new read-only test `tests/contracts/test_vectors_metadata_digests.py` asserts 9 entries and checks each file's byte length and `hashlib.sha256` against the metadata. It never regenerates or writes vectors (test hygiene).
- **Acceptance:** test passes against all nine committed bins; no tracked fixture touched.

### B7 (consistency, same file) — C++ harness called itself the byte-identity authority · ตรวจพบ

- **Current:** `tests/contracts/wire_codec_v3_cpp_check.cpp:6-7`: "The C++ reference header is the byte-identity authority every other codec is written against".
- **Reason:** contradicts the corrected protocol docs and `CONTRACT_MAP` (P2a): Zig is authoritative, Go is the Nose producer, C/C++ is a test/reference codec.
- **Replacement:** header comment now states the actual status while keeping the harness purpose unchanged.
- **Acceptance:** no "C++ is authority" claim remains in the file.

---

## 3. Flow / contract impact

```
OLD  direct v3 helper (Go/C++)  -> patch version to 1 without pin -> forged frame accepted
NEW  direct v3 helper           -> pin declared version 3, then patch -> forged frame rejected
OLD  Python frame/envelope      -> '<' length check -> trailing bytes ignored
NEW  Python frame/envelope      -> exact length -> trailing bytes rejected
OLD  Zig trailing test           -> asserted short frame -> claim unproven
NEW  Zig trailing test           -> short + overlong + v1/v2 relabel cases all rejected
OLD  vectors_metadata.json       -> digests recorded, unverified
NEW  vectors_metadata.json       -> 9/9 bytes checked against sha256 + size in a test
```

- **Wire/ABI:** none. Golden vectors 109/133/197/229/165 bytes are unchanged and still byte-identical across codecs.
- **Authority:** none. All changes reject malformed input earlier; no host effect and no policy decision added.
- **State:** none.
- **Tests:** Zig 3367/3377 passed / 10 skipped (fresh caches; same total because assertions were added inside an existing test); Go targeted `ok`; C++ harness `PASS`; Python contracts 80 passed.
- **Evidence:** E2 for helper guards and digest verification (executable tests). No E4/E5, no soak, no Windows host run.

---

## 4. Completion gate

**PASS (E2).** Build source = `661fb76` (source-file changes). Machine maps restamped and digests refreshed in follow-up records commits; final verification must show `TRUTH_VALID @ 661fb76`, 674/674 digests and no bad links. Issue #44 counter-delta follow-ups were open at recorded source `661fb76`; they were closed by the P8-I44 slices and re-proved at current source `a26c573` in `analysis/current-head/MASTER-AUDIT-P8-I44-CURRENT-SOURCE-20261125.md`.
