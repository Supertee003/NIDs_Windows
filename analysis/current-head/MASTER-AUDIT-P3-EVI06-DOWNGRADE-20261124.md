# MASTER AUDIT — P3 EVI-06 carry-forward executed: four source-pointer E5 entries downgraded to E2 (2026-11-24)

**TARGET HEAD:** `c7c1662bf1aea4474aaa7d7122032336d7df5d25` (records-only; build source stays `03bb86d98ea5925170157b6d0f9b63ed12f4c858`)
**STATUS:** PASS_E2 — honest records correction, no source/build/wire/rule/authority/host-effect/release change.

## PATCH DECLARATION

```
PATCH-ID:             P3-EVI06-DOWNGRADE-CARRY
FLOW-ID:              evidence registry -> level counts -> honesty markers -> validators -> docs
TARGET FILES:         EVIDENCE_INDEX.json, analysis/current-head/MASTER-AUDIT-P3-20261124.md,
                      analysis/current-head/MASTER-AUDIT-P3-EVI06-DOWNGRADE-20261124.md (new)
IN-SCOPE:             level correction for four entries whose primary artifact is source/test code
OUT-OF-SCOPE:         source code, wire, rules, authority, host effects, release identity, new E5 claim
CONTRACT/ABI/AUTHORITY: NONE
STATE IMPACT:         NONE (records only)
EVIDENCE IMPACT:      E2_count 153->157; E5_count 123->119; E5_with_artifact 73->69;
                      E5_with_resolvable_artifact 41->37; unresolvable counts unchanged
```

## FINDING AND REPLACEMENT

P3 audit (`MASTER-AUDIT-P3-20261124.md:58-65`) classified four 2026-11-18 entries as
**ต้องตรวจ Source**: each narrates a host measurement with an installed sha256,
but its primary `evidence_artifact` is only source/test code
(`tests/forensics/test_forensic_payload_filter.py`,
`src/pipeline/event_processor.zig`, `src/pipeline/telemetry_threads.zig`).
P3 added `artifact_status: historical`, `artifact_locator` and an operator-attested
basis but explicitly left the recommendation unexecuted: obtain operator
install/health output **or** downgrade after source+artifact review.

Search of the worktree, `D:\aegis-tmp` and the visible
`D:\AEGIS_archive\admin-evidence-20261106\` found **no** install/health capture for
those four windows or their four build hashes. A records-only slice cannot
manufacture one. Per the user's instruction to finish all remaining honest work,
the four levels were reduced E5 → E2 after source/test-pointer review. The IDs
keep their historical `E5` substring (they are referenced elsewhere), and the
narratives were **not** deleted or falsified; `artifact_status_basis` now states
the downgrade explicitly.

| ID | Old level | New level | Primary pointer |
|---|---|---|---|
| `FORENSIC-CONTAINS-001-E5-20261118` | E5 | E2 | `tests/forensics/test_forensic_payload_filter.py` |
| `PROC-LAYER-001-E5-20261118` | E5 | E2 | `src/pipeline/event_processor.zig` |
| `QLOSS-DELFILTER-001-E5-20261118` | E5 | E2 | `src/pipeline/telemetry_threads.zig` |
| `QLOSS-DELAGG-001-E5-20261118` | E5 | E2 | `src/pipeline/telemetry_threads.zig` |

The 48 unresolvable artifact pointers were checked separately: 18 already carry
`historical` + `artifact_locator`, 30 carry `missing` + `artifact_status_basis`,
and `check_summary.py` reports `SUMMARY_VALID`. No change was needed there; no
artifact was invented.

## INVARIANT / OLD FLOW → NEW FLOW

```
OLD: host narrative + source/test pointer -> "level": "E5" -> counted as Windows host verification
NEW: host narrative + source/test pointer -> "level": "E2" + explicit carry-forward basis
     -> counted as source/test evidence only; operator attestation remains disclosed, never promoted
```

## VERIFICATION

```
python scripts/check_summary.py                       -> SUMMARY_VALID (recomputed counts match)
python -m pytest tests/release/test_evidence_index_valid.py -q -> PASS (live count validators)
python -m pytest tests/security/test_evidence_index_integrity.py -q -> PASS
python scripts/doc_checker.py                         -> 0 FAIL, 0 WARN
bad-link check                                        -> none
python tools/truth.py verify                          -> TRUTH_VALID @ 03bb86d
python tools/release_engineering.py --verify          -> 674/674 digests
```

Full non-host pytest, `zig build test`, `zig build` and both CI workflows are
re-run for the enclosing records transaction; this slice itself changes no
source/build tree.

## LIMITS / ROLLBACK / GATE

Records-only E2 correction. No new E4/E5 claim, no host artifact recovered, no
falsification of the operator narratives, no change to release identity
`v1.1` / `466a226` / `a53eda8` (6/6 gates PASS, 0 open). Revert the records
commit to restore the four E5 levels and counts. **Completion gate: PASS_E2**
when validators, truth, digests, docs and links are green at unchanged build
source `03bb86d`.
