# Master Audit — Phase 3 (Evidence Integrity)

**Target HEAD:** `8b18ef77ea6dea113c2f1f7dfe79fb08b3bc9950`
**Build source (unchanged by this records-only slice):** `661fb768dc1c8eeb0f79e4e437807f2eac08c9ff`
**Date:** 2026-11-24
**Patch ID:** `P3-EVIDENCE-HONESTY-20261124`
**Classification convention:** "ตรวจพบ" = confirmed from current file/source; "ต้องตรวจ Source" = needs source/artifact inspection before a defect claim; "แนะนำเพิ่ม" = recommendation, not a proven defect.

---

## 0. Correction to my own previous gate report (ตรวจพบ)

- **Current claim I made:** "final gates: `check_summary.py` … 359 passed" was read by filtering output lines, and I reported the slice as clean.
- **Actual:** `python scripts/check_summary.py` exits **1** with `EVIDENCE_INDEX INVALID:` and 48 `artifact pointer does not resolve` problems. `scripts/check_summary.py:131-137` returns 1 whenever `validate()` is non-empty.
- **Reason:** filtering the printed summary hid the exit code. This is a reporting error, not a product regression; it is corrected here and the validator is tightened below so it cannot be misread as an openable-artifact count.

---

## 1. EVI-01 — `E5_with_artifact_count` counted truthy pointers, not openable artifacts · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:16854` (`"E5_with_artifact_count": 72`); `scripts/check_summary.py:45-53,91-94`.
- **Current text:** `e5_with_artifact = [e for e in e5 if e.get("evidence_artifact")]`; a missing file only failed if it had no `artifact_status`.
- **Reason:** 48 pointers do not resolve in the worktree; 32 of them are E5. Only 40 of the reported 72 E5 artifact pointers are openable here. The field reads as "auditor can open" (`scripts/check_summary.py:10-11`) but is not.
- **Replacement:** `recompute()` now also publishes `E5_with_resolvable_artifact_count`, `E5_with_unresolvable_artifact_count` and `unresolvable_artifact_pointer_count`. `validate()` requires `artifact_status: historical` + `artifact_locator`, or `artifact_status: missing` + `artifact_status_basis`, for every unresolvable pointer. Unlabelled pointers still fail. The validator prints each `UNRESOLVABLE` id.
- **Acceptance:** `python scripts/check_summary.py` prints `SUMMARY_VALID` with 40 resolvable / 32 unresolvable E5 pointers and 48 unresolvable pointers overall; `tests/release/test_evidence_index_valid.py` asserts all four fields and the labels.

## 2. EVI-02 — retention note undercounted citations · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:7`; `.gitignore:116`.
- **Current text:** `"The 63 evidence entries that cite these paths remain historical records."`
- **Reason:** current parse: 48 primary `evidence_artifact` pointers, 61 entries with `admin-evidence/...` in `files_verified`, 133 mentioning it anywhere. Only primary pointers are validator-checked; `files_verified` is not.
- **Replacement:** note now states all four counts, the 18/30 archive split, and that only primary pointers are checked.
- **Acceptance:** note matches a fresh parse; no "63" remains.

## 3. EVI-03 — missing pointers split into archive-recoverable and unrecovered · ตรวจพบ

- **Path:** 48 `evidence_artifact` fields, e.g. `EVIDENCE_INDEX.json:4749` (`ids-queue-001-20261102/closeout.md`), `:5875` (`host-window-003-20261110/deploy-window-003-result.json`), `:9256` (`voided-soak-owner-audit-20261119.json`).
- **Reason:** 18 resolve exactly under `D:/AEGIS_archive/admin-evidence-20261106/` after stripping the `admin-evidence/` prefix (e.g. `ids-queue-001-20261102/closeout.md`, `stix-export-20261105/xdr-20261105.stix.json`, `rb021-canary-20261104/post-restore/health-degradation.json`). 30 have neither worktree nor archive copies as of 2026-11-24. Basename-only matches were rejected (many `closeout.md` files exist and are not the same artifact).
- **Replacement:** 18 entries get `artifact_status: historical` and exact `artifact_locator`; 30 get `artifact_status: missing` and `artifact_status_basis`; all 48 get `historical: true`.
- **Acceptance:** no `artifact_status` mismatch in `check_summary.py`; no claim that a `missing` pointer is independently auditable.

## 4. EVI-04 — QLOSS-RATE-E5 primary artifact belonged to the adjacent entry · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:5916`; entry `QLOSS-RATE-E5-20261110`.
- **Current text:** `"evidence_artifact": "admin-evidence/host-window-003-20261110/kind-attribution-e5.json"`.
- **Reason:** that file is the primary artifact of `KIND-ATTR-001-E5-20261110`. The rate entry's own `artifacts` list contains `soak-attempt.json`, which records the retracted zero-drop claim described in the entry.
- **Replacement:** pointer changed to `.../soak-attempt.json`; status `missing` with a basis explaining the repoint and that neither file is present. The 3,229 clean / 4,009 lossy bracket is not upgraded to an exact ceiling.
- **Acceptance:** the two entries no longer share a primary artifact; no new rate claim was invented.

## 5. EVI-05 — voided soak window counted as E5 without a result · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:9251-9267`; entry `SOAK-VOID-OWNER-AUDIT-20261119`.
- **Current text:** `"level": "E5"` with `"Disposition VOIDED_BY_OWNER_DECISION_PENDING_HANDOFF_AUDIT; not a failure and not release proof."` and `"Never reached PASS; deliberately stopped before the 24 h requirement."`; no `result` field.
- **Reason:** a voided window in the E5 population without a result field can be read as verified host proof, contrary to the entry's own text.
- **Replacement:** added `result: "VOIDED_BY_OWNER_DECISION"`, `artifact_status: missing`, basis, `historical: true`. Level stays E5 because a host window was attempted; it is not counted as PASS.
- **Acceptance:** grep for `VOIDED_BY_OWNER_DECISION` in the entry; no "PASS soak" claim added.

## 6. EVI-06 — four E5 entries use source/test files as primary "host verification" artifact · ต้องตรวจ Source

- **Path:** `EVIDENCE_INDEX.json:8799,8825,8850,8877`: `FORENSIC-CONTAINS-001-E5-20261118`, `PROC-LAYER-001-E5-20261118`, `QLOSS-DELFILTER-001-E5-20261118`, `QLOSS-DELAGG-001-E5-20261118`.
- **Current text:** primary pointers are `tests/forensics/test_forensic_payload_filter.py`, `src/pipeline/event_processor.zig`, `src/pipeline/telemetry_threads.zig`; descriptions say "Measured on the installed build…" with installed sha256, but `tests` / `files_verified` are absent.
- **Reason:** the pointers are source/test files, not host captures. Inspection confirms the host measurement is *narrated* with a build hash, not accompanied by a host artifact in the checked tree. That is insufficient to prove E5 independently here, but it does **not** prove the measurement was falsified.
- **Replacement (this patch):** each entry gets `artifact_status: historical`, `artifact_locator` = its source pointer, `artifact_status_basis` stating the primary artifact is a source/test file and the host narrative is operator-attested, plus `historical: true`. No level downgrade is asserted without artifact proof.
- **Acceptance:** the limitation is visible in the registry; no E4/E5 claim is added for these entries by this slice.
- **แนะนำเพิ่ม (not done):** obtain the operator's install/health output for each window, or downgrade the level after a source+artifact review. Not claimed as fixed.

## 7. EVI-07 — historical gap closure with null / invalid head · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:16285` (`XDR-WIRE-001`, `"head_sha": null`), EVT-101 (`39afa56bcc2180814c452545b272d3ec08e3e3e1c9`, 42 hex chars), `tests/release/test_known_gap_status.py:63-71`.
- **Reason:** `CLOSED_AT_RECORDED_HEAD` means a pass at a *named* head. `status_basis` even says "recorded at head None". The validator only checked non-empty basis, so this contradiction passed.
- **Replacement:** both entries are `UNRECORDED` with explicit bases; EVT-101 preserves the invalid string in `invalid_recorded_head`. The validator now requires a 7-40 hex `head_sha`, non-empty `status_basis` and a non-empty `result` for this status.
- **Acceptance:** `pytest tests/release/test_known_gap_status.py` passes; no null/42-char head remains on a `CLOSED_AT_RECORDED_HEAD` gap.

## 8. EVI-08 — historical closure missing its result field · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:16830-16842`, `SUITE-FLAKE-001`.
- **Reason:** the status note says the entry's own `result` records the closure; the entry only had `resolution`.
- **Replacement:** added `result: "PASS"` (the resolution text records two CI + two fresh-cache local runs at source `4169839`), and extended `status_basis`.
- **Acceptance:** strengthened validator/test in EVI-07 passes.

## 9. EVI-09 — release board could be SHIPPABLE with an invalid evidence index · ตรวจพบ

- **Path:** `tools/final_audit.py:559-581,725-739`; `scripts/check_summary.py` was not invoked by `collect_release_facts`.
- **Reason:** `TRUTH_VALID` and digest verification do not inspect artifact pointers; the board could show 6/6 while the index validator exited 1.
- **Replacement:** `collect_release_facts()` now runs `scripts/check_summary.py` read-only as `facts["evidence_index"]`; `truth_artifacts` requires both `truth.ok` and `evidence_index.ok`, with both details in the gate. Six gates remain six; no waiver is introduced.
- **Acceptance:** `tests/release/test_release_board.py::test_an_invalid_evidence_index_keeps_the_truth_gate_closed` passes and asserts `len(gates) == 6`.

## 10. EVI-10 — T20 E5 gate inputs are ignored, local-only files · ตรวจพบ

- **Path:** `docs/gates/T20_100pct_audit.md:22-23`; `tools/final_audit.py:780,802`; `.gitignore:116`.
- **Current text:** `admin-evidence\e5-clean-host-20261120-final\preflight-20261120.json PASS …` and `soak-24h-delta-final.json is PASS at 36.52/24.0 h`.
- **Reason:** these are real owner-attested operator files but are ignored by git; a fresh clone cannot re-run the gate from repository content. They must not be presented as ordinary reproducible repository evidence.
- **Replacement:** added an explicit banner to the T20 board and `PRODUCTION_READINESS.md` stating the E5 inputs are owner-attested, local-only and non-reproducible from a fresh clone; PASS state and release identity are unchanged (immutable v1.1).
- **Acceptance:** both docs carry the banner; no new E5/soak claim.

## 11. EVI-11 — current-facing doc calls a release-identity board "current" · ตรวจพบ

- **Path:** `docs/gates/PRODUCTION_READINESS.md:9`; `docs/gates/T20_100pct_audit.md:19`.
- **Current text:** `Current board: docs/gates/T20_100pct_audit.md → SHIPPABLE, 6/6 PASS` while the board records `TRUTH_VALID — artifacts carry build source a53eda8` and current build source is `661fb76`.
- **Reason:** v1.1 release identity legitimately uses candidate `466a226` / source `a53eda8`; the board is not a re-run at the current source. Calling it "current" implies current-source verification that did not occur.
- **Replacement:** wording changed to "release-identity board for v1.1" with an explicit current-source separation.
- **Acceptance:** no current-source claim attached to the a53eda8 board.

## 12. EVI-12 — stale "Board remains 5/6" limitations in current registry entries · ตรวจพบ

- **Path:** `EVIDENCE_INDEX.json:56,88,126,185,219` and 6 further entries (11 total: OBSERVABILITY-001-E2, OPERATOR-001-HONESTY-E2, VISIBILITY-001-KERNEL-PRIMARY-E2, RULE-COVERAGE-001-RULES-E2, RULE-COVERAGE-001-E2, RC-REBUILD-002-E7, RC-7D91E30-001-E2, RB-024-STEPS1-6-001-E5, DOCS-GAP-CLOSURE-PLAN-E1, DOCS-READINESS-PATCH-E1, DOCS-PRODUCTION-READINESS-E1).
- **Current text:** `"Board remains 5/6; no tag/publish."` etc.; also `"5/6 PASS, soak_24h OPEN"` in historical test logs.
- **Reason:** current release closeout is 6/6 (0 open); these are snapshots at heads `f0baadf`, `4169839`, `f4cde3c`. The only marker was `head_sha`, not a scope field.
- **Replacement:** strings rewritten to "At the recorded head the board was 5/6 …" with a `[HISTORICAL @ recorded head: v1.1 … 6/6 PASS … not a current gate claim.]` suffix; entries get `historical: true`. Entries already saying "marked as historical snapshots" are skipped.
- **Acceptance:** no unscoped "Board remains/stays 5/6" remains in the index.

## 13. EVI-13 — AI_CONTEXT current-facing metadata stale · ตรวจพบ

- **Path:** `AI_CONTEXT.md:9,11`; `tools/truth.py:184-189` only validates the `**HEAD:**` build-source line.
- **Current text:** `**RECORDS TIP:** c3cc44f`, `**BRANCH:** codex/o2-etw-context`.
- **Reason:** actual records HEAD at audit time is `8b18ef7` on `main`; neither field is checked by truth verification.
- **Replacement:** BRANCH → `main`; RECORDS TIP → `8b18ef7` with the existing "before this edit; a commit cannot contain its own SHA" qualifier retained.
- **Acceptance:** docs sweep / link check still clean; `TRUTH_VALID @ 661fb76` unchanged.

---

## Flow / contract impact

```
OLD  check_summary.py -> truthy E5_with_artifact_count=72, exit 1 on 48 unlabeled pointers
NEW  check_summary.py -> split resolvable/unresolvable counts, explicit status required, SUMMARY_VALID
OLD  final_audit.py   -> 6 gates could be SHIPPABLE with an invalid evidence index
NEW  final_audit.py   -> same 6 gates, truth_artifacts also requires SUMMARY_VALID
OLD  registry         -> voided soak + source-pointer E5 + missing host files read as openable proof
NEW  registry         -> historical/missing locators, VOIDED result, operator-attested limits
```

- **Wire/ABI/rules/authority/host effects:** none. **Release identity:** unchanged (`v1.1`, signed candidate `466a226`, source `a53eda8`; 6/6). No new tag, signature, key, E4/E5, soak or Windows host run.
- **Build source:** unchanged (`661fb76`) because `scripts/`, `tools/`, `tests/` and docs are records-only under ADR-0008 (`tools/truth.py:42-43`).
- **Evidence level:** E2 for executable validator/gate tests; doc corrections are records. No higher level claimed.

## Completion gate

**PASS (E2, records-only).** Requires: `check_summary.py` SUMMARY_VALID with split counts; targeted release tests pass; `TRUTH_VALID @ 661fb76`; 674/674 digests; no bad links. Remaining: 30 unrecovered historical artifacts and four source-pointer E5 entries stay explicitly operator-attested (EVI-06 recommendation not executed).
