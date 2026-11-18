# PAYLOAD-ENVELOPE-V3-001 — wire v3 bounded payload + capture provenance

**Status:** E2 (all codecs) — no live capture-path claim
**Code commit:** `a1024f2` (feat(wire): carry bounded capture payload in an additive v3 frame)
**Target HEAD:** `9494c63a633eaec985cad280c45eb2ef4af4c087`
**Build source:** recorded by `tools/truth.py verify` after the rebuild

## Patch contract

- **PATCH-ID:** PAYLOAD-ENVELOPE-V3-001
- **FLOW-ID:** Nose capture → `\\.\pipe\aegis_nose` → Zig nose pipe reader → canonical decode → queue → detection
- **TARGET FILES:** `shared/protocol/wire_v3.md`, `shared/wire/wire_codec.h`,
  `shared/wire/wire_codec.py`, `brain/canonical_event.py`,
  `nose/canonical.go`, `nose/capture.go`, `nose/pipe_writer.go`,
  `src/contract/canonical_event.zig`, `src/capture/nose_pipe_reader.zig`,
  `src/pipeline/event_queue.zig`, `src/pipeline/event_processor.zig`,
  `tests/contracts/*`, `tests/brain/test_canonical_event_v3.py`
- **IN SCOPE:** Additive v3 frame (frozen v2 133-byte base + 32-byte envelope +
  `0..1024` bounded payload), strict fail-closed decode in every codec, and
  transport of captured bytes to the Zig queue.
- **OUT OF SCOPE:** Any detection verdict in the acquisition tier; any host
  effect. v3 carries evidence only.
- **CONTRACT IMPACT:** New v3 wire version. v1/v2 frames, vectors and decoders
  stay byte-identical and metadata-only.
- **ABI IMPACT:** None. `struct_size` stays the producer's in-memory layout tag
  (128); the wire length is never derived from it.
- **AUTHORITY IMPACT:** None. Zig remains the sole detection authority and
  `rust_pep` the sole enforcement authority. The envelope carries acquisition
  provenance, which is explicitly not a trust signature.
- **STATE IMPACT:** Live capture now emits v3 frames; the queue carries the
  bounded payload behind `qe.payload_len` while `ev.payload_len` keeps the
  producer's full wire claim (two-length rule preserved).
- **TEST IMPACT:** Golden vectors 007/008/009 pinned in four codecs plus a new
  compiled C++ harness; v1/v2 vectors still decode byte-identically.
- **EVIDENCE IMPACT:** New E2 entry. No E5 claim: no capture run was performed
  against this revision.

## Findings this slice had to close

The slice arrived uncommitted, with no evidence entry and no gap record. Four
defects were found while verifying it:

1. **Reserved-byte enforcement was missing in every decoder.** `wire_v3.md`
   states any non-zero reserved byte is rejected fail closed, but Zig, Go,
   C++ and the reference Python decoder all skipped the byte, and the brain
   decoder never even unpacked it. All five now reject it, and each codec has
   a test. The spec and the implementations now agree.
2. **`brain/canonical_event.py` v3 was broken outright.** The envelope struct
   (`<HBBHHIQIII`, 10 fields / 32 bytes) was unpacked into nine names and
   packed from nine values, so every valid v3 frame raised `ValueError` and
   `encode_v3` raised `struct.error`. The brain codec is not on the live path,
   which is why nothing caught it. It now round-trips all three vectors, is
   pinned against the reference codec, and is covered by
   `tests/brain/test_canonical_event_v3.py`.
3. **The C++ leg was never compiled.** `shared/wire/wire_codec.h` is header
   only and no translation unit included it, so the "compiled against the C++
   reference header" claim was unproven. `tests/contracts/wire_codec_v3_cpp_check.cpp`
   now compiles with `g++ -std=c++17 -Wall -Wextra` and decodes, re-encodes
   and strictly rejects tampered frames against the committed vectors.
4. **Detection promotion from upstream producers was removed.** The pipeline
   no longer lifts an upstream `signature_match` + `rule_id` into
   `matched_rule_id`; detections come only from the Zig Aho-Corasick/L4/L7
   stages. This matches ADR-0001 (Zig is the sole detection authority) and
   `nose/signature_classifier.go` has no production caller, so no live
   producer loses identity today. It is a semantic change, recorded here so it
   cannot be mistaken for an accident later.

## Evidence

Executed on the Windows host at `9494c63` + this working tree:

| Check | Command | Result |
|---|---|---|
| C++ codec (compile + vectors + guards) | `g++ -std=c++17 -Wall -Wextra -I. tests/contracts/wire_codec_v3_cpp_check.cpp` → run | `PASS` |
| Reference Python codec | `python -m pytest tests/contracts -q` | 60 passed |
| Brain codec | `python -m pytest tests/brain/test_canonical_event_v3.py -q` | 9 passed |
| Go Nose (vectors, decode, capture attachment) | `go test -count=1 ./...` (in `nose/`) | ok, 9.6s |
| Zig contract + queue + pipeline | `zig build test` | exit 0 |
| Canonical build | `zig build` | exit 0 |
| Native adapters | `cmake --build build` | exit 0 |

`aegisctl forensic verify` remains `verified true`; the running service and
the running Nose (pid 10680, VMnet1) are unchanged by this slice — no live
capture was run against the v3 producer.

## Deployment note (ordering matters)

The live capture loop calls `SendWithPayload` unconditionally, so a rebuilt
Nose emits v3 frames. A daemon built before this slice rejects those frames.
Deploy the daemon first, then Nose; never the reverse. This is the only
silent-loss risk in the slice, and it is a rollout ordering constraint, not a
contract ambiguity.

## Limitations

- E2 only: the v3 producer and reader have unit and golden-vector proof, not a
  live capture proof at this revision.
- The v3 payload is capped at 1024 bytes at the producer; longer frames are
  reported `truncated`, never clamped silently by the transport.
- `queue_dropped_total` on the running service is cumulative and unaffected by
  this slice; `readiness` still reports `degraded true` for that accumulated
  shed count.
