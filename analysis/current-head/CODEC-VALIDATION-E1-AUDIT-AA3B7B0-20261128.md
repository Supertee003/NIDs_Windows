# Canonical event / wire codec validation — E1 source audit

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (unchanged — records-only)  
**RECORDS TIP WHEN WRITTEN:** `61be9bc51ba95ce8499a67a6eb7bf373e887062d`  
**SCOPE:** AEGIS-004. Read-only source inspection; no build, host, finalizer or
soak action. This is a **finding map, not new proof**. No gate, verdict or
evidence level changed.

## 1. What the live paths already enforce

| Path | Current behavior | Evidence in source |
|---|---|---|
| Zig canonical dispatch | v1 exactly 109 bytes, v2 exactly 133, v3 strict delegate, unknown version rejected | `src/contract/canonical_event.zig:601-631`; tests `:1286-1301`, `:1468-1481` |
| Zig v3 decoder | version, struct-size, reserved byte, zero tail, exact `header + payload_len`, envelope/payload validation | `canonical_event.zig:633-683`; tests `:1603-1649` |
| Zig provenance | when flag set requires **all four** tuple fields nonzero | `canonical_event.zig:498-535`; test `:1671-1689`; producer guard `src/capture/producer_identity.zig:140-153` |
| Live pipe framing | 4-byte LE prefix, allowed lengths 109/133/165..1189, garbage drain, reject counters | `src/capture/nose_pipe_reader.zig:85-109`, `:388-461`; counters `:539-555` |
| Go dispatch / v3 | exact v1/v2/v3 lengths, unknown version rejected, CRC/completeness checked | `nose/canonical.go:675-721`, `:609-673`, `:355-403`; tests `canonical_test.go:399-428`, `payload_v3_test.go:281-314` |
| Go framing | oversize rejection with `dropped++`, LE u32 prefix, `writeAll`, close on write error | `nose/pipe_writer.go:55-68`, `:149-195` |
| C++ exact lengths | v1/v2/v3 and legacy helper exactness, no trailing bytes | `shared/wire/wire_codec.h:313-358`, `:394-411`, `:500-545`, `:598-621` |
| Python reference codec | exact v1/v2/v3 lengths and frame length | `shared/wire/wire_codec.py:356-381`, `:452-485`, `:537-563` |
| Brain Tier-2 codec | exact lengths, struct-size and confidence gates | `brain/canonical_event.py:130-153`, `:247-279`, `:305-344` |
| Golden vectors | 5 v1 + 1 v2 + 3 v3 positive vectors, complete provenance tuples for v3 | `tests/contracts/event_vectors/generate_test_vectors.py:327-378`; `event_vectors/event_vectors/README.md:5-64` |

**Conclusion:** the *live* decode paths do not accept trailing bytes and do not
silently drop malformed frames. Earlier articles that called this "documented,
not re-run" were conservative; this audit pins it to current source lines.

## 2. Concrete divergences found

1. **Zig legacy WEV1 helper accepts trailing bytes** —
   `src/contract/wire_event.zig:117-143` uses
   `buf.len < WIRE_HEADER_SIZE + payload_length` instead of exact equality.
   `submitWireEvent` at `src/capture/nose_contract.zig:151-163` consumes this
   helper, but no in-tree production caller of `submitWireEvent` was found.
   Existing oversize-buffer tests (`:343-393`) do not pin rejection.
   Spec: `shared/protocol/wire_v3.md:62-73` — no ignored tail.
2. **Partial provenance tuple passes Go/C++/Python/brain when the flag is set** —
   Go `nose/canonical.go:355-403`, C++ `shared/wire/wire_codec.h:442-465`,
   reference Python `shared/wire/wire_codec.py:133-164`, brain
   `brain/canonical_event.py:275-278` lack the positive "all four nonzero"
   branch that Zig enforces. Live Nose always builds a complete tuple
   (`nose/capture.go:272-304`) and Zig ingress rejects partial ones, so this
   is a **codec-divergence risk**, not a live bypass.
3. **C++ / shared Python v1 decoders omit strict field gates** —
   `shared/wire/wire_codec.h:313-358` and `wire_codec.py:383-413` check
   magic/version but not `struct_size`, enum ordinals or confidence, unlike
   Zig/Go/brain.
4. **Unpinned test seams** — Go `writeAll` short-write continuation
   (`nose/pipe_writer_test.go:3-6`) and the CLI `frames_rejected` delta for a
   valid-length bad frame (`src/tests/cli/nose_pipe_e2e_cli.zig:172-231`).

All four are validation/test changes with **no wire layout, struct field or ABI
change**.

## 3. Proposed patch transaction — NOT APPLIED

```
PATCH-ID:      AEGIS-004-CODEC-STRICT-01
FLOW-ID:       canonical frame -> decode/validate -> reject counter -> evidence
TARGET HEAD:   aa3b7b0161e425e54155d5767737bffcde7939b5
TARGET FILES:  src/contract/wire_event.zig
               src/capture/nose_contract.zig (tests only if needed)
               nose/canonical.go, nose/canonical_test.go
               shared/wire/wire_codec.h, shared/wire/wire_codec.py,
               tests/contracts/wire_codec_v3_cpp_check.cpp
               tests/contracts/test_payload_envelope_v3.py
               brain/canonical_event.py, tests/brain/test_canonical_event_v3.py
               src/tests/cli/nose_pipe_e2e_cli.zig
TARGET SYMBOLS:deserializeEvent, aegis_v3_envelope_valid, validate_v3_envelope,
               Validate, writeAll, frames_rejected
IN SCOPE:      exact-length legacy helper, complete provenance tuple in every
               codec, v1 field gates, short-write and reject-counter tests
OUT OF SCOPE:  wire layout, struct fields, ABI, policy bytes, authority, verdicts,
               host action, soak, gate thresholds
CONTRACT IMPACT:none (validation aligned to existing wire_v3.md)
ABI IMPACT:      none
AUTHORITY IMPACT:none
STATE IMPACT:    none
TEST IMPACT:     zig build test; go test ./...; C++ wire check; pytest contracts/brain
EVIDENCE IMPACT: E2 only; no E3/E4/E5/E6/E7 promotion
```

**Why it was not applied in this records patch:** every target file is under a
`SOURCE_PATHS` entry (`src`, `nose`, `shared`, `brain`) in `tools/truth.py:44-66`.
A source commit would move the build source off `aa3b7b0`, require full
machine-map rebaselining and make signed tree `6c94b47` no longer contain the
runtime — turning `release_signature` OPEN. That is a gate regression and an
explicit owner decision (Card B), not a silent documentation fix.

## 4. Recorded boundary

- No codec was edited; no golden vector was regenerated; no test was skipped.
- `docs/protocol/INDEX.md` remains the answer sheet; authoritative text remains
  `shared/protocol/wire_v1.md`/`v2.md`/`v3.md` and `shared/event/canonical_event.md`.
- This audit does not close AEGIS-004; it converts a vague "documented" claim
  into exact current-source findings and a ready patch transaction.
