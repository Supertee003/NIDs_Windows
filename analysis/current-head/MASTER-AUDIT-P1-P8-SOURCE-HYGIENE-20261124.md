# MASTER AUDIT — P1/P8 source hygiene: stale production label and oversize wire guard (2026-11-24)

**SOURCE COMMIT:** `a26c5731afe154890e4f3d205d9736a5e1ead78a` (last commit touching `src/`, `nose/` or `build.zig`)
**PREVIOUS BUILD SOURCE:** `03bb86d98ea5925170157b6d0f9b63ed12f4c858`
**STATUS:** PASS_E2 — source-level honesty and defense-in-depth guard; no host re-measurement claimed.

## PATCH DECLARATION

```
PATCH-ID:             P1-P8-SOURCE-HYGIENE-CARRY
FLOW-ID:              Go Nose writer -> length-prefixed frame -> Zig pipe reader
TARGET FILES:         src/windows/ips_simulation.zig, nose/pipe_writer.go, nose/pipe_writer_test.go
IN-SCOPE:             comment truth (RETIRE-HOST-EFFECT-001), fail-closed oversize-wire guard + unit pin
OUT-OF-SCOPE:         wire layout, CanonicalEvent schema, golden vectors, rules, authority, host effects,
                      release identity, E3/E4/E5 re-run, host verification
CONTRACT IMPACT:      NONE (guard rejects; no frame is emitted)
ABI IMPACT:           NONE
AUTHORITY IMPACT:     NONE
STATE IMPACT:         NONE (an oversize wire is dropped and counted, same as any other failed send)
TEST IMPACT:          new Go unit test TestSendWireRejectsOversizeFrame; existing Zig/Go tests unchanged
EVIDENCE IMPACT:      one E2 entry; build source advanced 03bb86d -> a26c573; maps/digests re-stamped
```

## FINDING / OLD FLOW → NEW FLOW

1. `src/windows/ips_simulation.zig:44` said `isProduction()` returns true for a
   "production-ready" mode. Current truth is RETIRE-HOST-EFFECT-001 / issue #25:
   no component authorizes a host effect. The label is HISTORICAL lab-stage
   vocabulary.
   - `OLD`: terminal ENFORCE stage labelled "production-ready".
   - `NEW`: `/// Returns true for the terminal ENFORCE stage (HISTORICAL lab mode; no live host-effect authority).`
   - The boolean (`self == .enforce`) and its Zig unit test are unchanged.

2. `nose/pipe_writer.go:150` copied `wire` into a fixed
   `[4 + EventV3MaxWireSize]byte` frame and sliced `frame[:4+len(wire)]`
   without checking `len(wire)`. A direct caller supplying more than
   `EventV3MaxWireSize` (1189) bytes would panic and, if truncation happened
   first, would desynchronise the u32 length prefix from the bytes written.
   `SerializeV3` already bounds normal producers; this is defense in depth.
   - `OLD`: any `wire` length accepted -> silent truncation / possible slice panic.
   - `NEW`: `len(wire) > EventV3MaxWireSize` -> `w.dropped++`, first-drop stderr
     diagnostic, `return false`. No bytes written; the length prefix stays in
     sync with the bytes actually emitted.
   - `writeAll(frame[:4+len(wire)])` is intentionally unchanged: the exact string
     is pinned by `tests/e2e/test_t14_windows_golden_path.py:53`.

`nose/pipe_writer_test.go` gains `TestSendWireRejectsOversizeFrame`: with a live
temp-file `pipeConn`, an oversize wire returns false, `Stats()` is `(0,1)` and
the file stays empty. This pins fail-closed behavior at E2.

## INVARIANT

No wire-layout, schema, golden-vector, rule, authority, host-effect or release
change. Frame range stays `165..1189` v3 bytes with a u32 LE length prefix.
Release identity stays `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS (0 open).

## VERIFICATION (all run at source `a26c573`)

```
gofmt -l nose/pipe_writer.go nose/pipe_writer_test.go -> no output
cd nose && go test ./...                 -> ok aegis-nose 10.109s
cd nose && go build -o aegis-nose.exe .  -> exit 0
zig build test --cache-dir D:\aegis-tmp\zig-local --global-cache-dir D:\aegis-tmp\zig-global -> exit 0
zig build     --cache-dir D:\aegis-tmp\zig-local --global-cache-dir D:\aegis-tmp\zig-global -> exit 0
python -m pytest -q -m "not host_live"   -> 1486 passed, 1 skipped, 18 deselected, 27 subtests passed
python tools/rebuild_truth.py             -> TRUTH_VALID @ a26c573, maps re-stamped
python scripts/check_summary.py           -> SUMMARY_VALID
python scripts/doc_checker.py             -> 0 FAIL, 0 WARN
bad-link check                            -> none
python tools/release_engineering.py --refresh-digests / --verify -> digest set refreshed and verified
```

Zig caches were redirected to `D:\aegis-tmp\zig-local` / `zig-global` because the
`C:` drive was full; no source path or tracked artifact was affected.

## LIMITS / HISTORICAL EVIDENCE

- No host effect, no WFP mutation, no Signed-IR/HLK/Microsoft attestation.
- No E3/E4/E5 re-run at `a26c573`: the `-inject` exact-delta proof remains
  CLOSED_AT_RECORDED_HEAD at `03bb86d` and is not claimed at the new source.
- No soak, loss-rate, install, signing, production simulation, E6/E7 or
  zero-loss claim. The 36.52 h soak remains HISTORICAL at `a53eda8`.
- Records-only E2 rebaseline (maps, docs, digests) follows this source commit;
  no new host measurement is implied by the re-stamped source SHA.

## ROLLBACK / GATE

Revert source commit `a26c573` and its rebaseline/digest/evidence records to
restore the prior label and writer. **Completion gate: PASS_E2** when Zig/Go
tests, non-host pytest, truth, summary, docs, links and digests are green at
build source `a26c573`.
