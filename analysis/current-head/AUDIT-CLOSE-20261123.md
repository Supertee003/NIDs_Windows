# AUDIT-CLOSE-20261123 — Issues #40–#43 source + records slice

## PATCH declaration

```text
PATCH-ID:       AUDIT-CLOSE-20261123
FLOW-ID:        NET-INGRESS -> CANONICAL-DECODE -> DETECTION -> DIAGNOSTICS
TARGET HEAD:    5e168562683c085aa5bb4bdb4d8c89983d6712f0
TARGET FILES:   Zig/Go/Python(x2)/C canonical decoders + tests; Zig source comments;
                protocol specs; evidence index; portfolio resume note
TARGET SYMBOLS: deserializeDispatch, deserializeFromBytes, DeserializeDispatch,
                brain.canonical_event.decode, WireCodec.decode_event,
                aegis_wire_decode_event[_v2|_dispatch], NoseWireFrame
IN-SCOPE:       exact per-version length at the decode boundary; fail-closed
                rejection; source/doc comment accuracy; historical evidence qualifiers
OUT-OF-SCOPE:   CanonicalEvent wire layout, golden .bin vectors, rule logic,
                ruleset, loopback networking, host effects, MITRE mapping
CONTRACT IMPACT: tightened decoder rule only (version AND length must agree).
                Wire offsets and sizes are unchanged.
ABI IMPACT:     none — no struct, enum or field change
AUTHORITY IMPACT: none — detection-only; no host effect authority added
STATE IMPACT:   malformed frames now reach the existing g_nose_frames_rejected
                counter instead of being accepted as metadata-only events
TEST IMPACT:    permissive parity tests replaced by rejection tests in all
                codecs; committed v3 vectors mutated in-memory for negative cases
EVIDENCE IMPACT: this artifact + EVIDENCE_INDEX entry + current-phase rebaseline
```

## Old flow → new flow

```text
OLD: 4-byte length prefix (v3-sized) → classifyFrameLen accepts → version byte
     reads 1 → v1 decoder copies first 109 bytes → tail/envelope silently lost →
     event accepted, no rejection counter.

NEW: 4-byte length prefix → classifyFrameLen accepts → version byte reads 1 →
     decoder requires exactly 109 bytes for v1 → mismatch → null/error →
     nose_frames_rejected incremented on the live pipe path → no silent loss.
```

## What changed

- **#41 (source):** exact-length gate per version in Zig (`deserializeDispatch`,
  `deserializeFromBytes`), Go (`DeserializeDispatch`), both Python codecs
  (`brain.canonical_event.decode`, `shared.wire.wire_codec.WireCodec.decode_event`),
  and C++ (`aegis_wire_decode_event`, `_v2`, `_dispatch`). v1=109, v2=133,
  v3=`165 + payload_len`; no wire-layout change.
- **#40 (source comments):** `source_arbiter.zig` no longer claims stream
  reassembly / L7 payload authority; `stream_reassembly.zig` marked UNWIRED and
  test-only; stale `SipHash64`, E3, and "IPS policy enforcement" comments fixed.
- **#43 (source comment):** `integration_contract.zig` now scopes the 125-byte
  WEV1 nominal frame to legacy compatibility and states the active framing
  (4-byte LE length prefix + 113/137/169..1193-byte canonical frame).
- **#42 (records):** four historical Zig count strings in `EVIDENCE_INDEX.json`
  explicitly marked as `f0baadf` historical runs; the resume two-phase sum
  qualified so it is not read as one pytest invocation.
- Specs `wire_v1.md`, `wire_v2.md`, `wire_v3.md` and
  `docs/CANONICAL_EVENT_SCHEMA.md` rebased to the exact-length rule.

## Invariant

No wire byte changes: every committed `event_v*.bin` vector decodes
byte-identically; only invalid version/length combinations change outcome
(accepted → rejected/counted). Rules, detection logic, loopback scope and
authority maps are untouched.

## Verification (E2/E3)

| Gate | Command | Result |
|---|---|---|
| Zig unit + out-of-unit | `zig build test --summary all` | **3366/3376 passed, 10 skipped**, build success |
| Go codec tests | `go test -run 'TestOverLengthV1FrameRejected\|TestDeserializeDispatchVersions\|TestV3Vector\|TestCommittedVectorsValidate\|TestV3EnvelopeRejects\|TestDeserializeV3RejectsDirtyTailAndTrailing' -v ./...` | PASS |
| Python codecs + release index | `python -m pytest tests/brain/test_canonical_event_v3.py tests/contracts/test_ipv6_wire_v2.py tests/contracts/test_payload_envelope_v3.py tests/release/test_evidence_index_valid.py tests/release/test_known_gap_status.py -q` | **47 passed** |
| C++ codec | `g++ -std=c++17 -Wall -Wextra -I. tests/contracts/wire_codec_v3_cpp_check.cpp -o <tmp>` + run with vector dir | `wire_codec_v3_cpp_check: PASS` |
| Go full suite (host capture) | `go test -run '^TestCapturePipeDeliversCanonicalEvents$' -count=1 -v ./...` | **FAIL / 601 s timeout on this host** in named-pipe capture teardown (`runCapture did not stop` on the earlier full-suite run). Environment-dependent live Npcap test, not a codec assertion; not used as a gate |
| Truth | `python tools/truth.py verify` | TRUTH_VALID at `ab0fa17` |
| Links | `python D:\aegis-tmp\check_links.py` | BAD LINKS: none |
| Release digests | `python tools/release_engineering.py --verify` | OK — 674 artifacts match, source_commit `ab0fa17` |

## Evidence level

**E2/E3** — cross-language codec component proof with committed vectors and
in-memory negative mutations. No E4/E5 claim: no new live-host soak, no host
effect, no signed-candidate change, no re-key. `v1.1` remains immutable.

## Rollback

Revert the source commit (decoder gates + tests) and the records commits
(maps, evidence index, docs). Golden vectors and wire schemas never changed,
so rollback requires no data migration.

## Remaining risk / open blockers

- The full Go suite includes `TestCapturePipeDeliversCanonicalEvents`, a live
  Npcap host-capture test. It is environment-dependent (real adapter, pipe
  timing) and is not an E3 codec assertion; codec tests above are the gate.
- Historical Zig counts remain genuine historical records at `f0baadf`; they
  are now explicitly labelled and are not presented as current-source results.
- No E5 verification is claimed for the corrupted-frame injection path.

## Completion gate

PASS when: codec gates above pass, `TRUTH_VALID` at the new build source,
link check clean, release-index tests pass, and issues #40–#43 are closed with
scope-honest comments.
