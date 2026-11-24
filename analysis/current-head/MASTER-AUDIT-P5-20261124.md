# Master Audit — Phase 5 (Detection)

**Target HEAD:** `7979735caa19f0dca10256a61efd28be0aec29af`
**Build source (unchanged by this records-only slice):** `661fb768dc1c8eeb0f79e4e437807f2eac08c9ff`
**Date:** 2026-11-24
**Patch ID:** `P5-DETECTION-TRUTH-20261124`
**Classification convention:** "ตรวจพบ" = confirmed from current file/source; "ต้องตรวจ Source" = needs source/artifact inspection before a defect claim; "แนะนำเพิ่ม" = recommendation, not a proven defect.
**Evidence level:** E1/E2 static pins only. No new E4/E5, host, soak or rule change claimed.

---

## STOP-THE-LINE watch

DET-01 is the same silent detector degradation already recorded as F6 in `MASTER-AUDIT-P4-20261124.md`. It remains **deferred**: the event is not dropped, so "silent event loss" is not proven; the named condition is silent *detection* degradation. It must be fixed in a source slice with a forced-failure test before any detection-claim refresh. It is not silently closed here.

---

## 1. DET-01 — detector errors swallowed by `catch null` · ตรวจพบ · DEFERRED (P4 F6)

- **Path:** `src/pipeline/event_processor.zig:452,474,489`; outer catch `:1258-1263`.
- **Current text/code:** `if (corr.observe(ev) catch null) |corr_rule_id| {`, `ad.observe(...) catch null`, `tt.observeFlowThreat(ev, 10) catch null`; outer catch comment says the counter is defensive and stays at 0.
- **Reason:** callees propagate allocation errors (`src/detection/correlator.zig:83`, `anomaly_detector.zig:89`, `threat_tracker.zig:137` all use `try ...getOrPut`). Three call sites discard them with no counter and no diagnostic. The event continues, so this is silent detection degradation, not proven event loss.
- **Replacement direction:** per-detector named counters (or the existing processing-error counter plus a diagnostic) at each catch; a forced-allocation-failure test must increment the named counter and surface it in health; then update control/maps in the same vertical slice.
- **Acceptance criteria:** no unaccounted `catch null` on an error-returning detector call; forced failure visible in health; full source rebuild.
- **Disposition:** already tracked with identical proof in the P4 artifact. Not re-fixed by this records-only patch.

## 2. DET-02 — "evaluable coverage 23/23" contradicted by FN-1 · ตรวจพบ · FIXED

- **Path:** `docs/portfolio/DETECTION_CATALOG.md:16` (old), `:69,73-76`; `analysis/current-head/RULE-COVERAGE-001-MATRIX.md:18`.
- **Current text:** `| **Evaluable coverage** | the runtime has a code path that can evaluate the rule from evidence it can actually receive | **23/23** |` while the same document says R2003 is inert on host because ProcessStart v0–v4 carry no `CommandLine` and no producer exists.
- **Reason:** by the term's own definition, R2003 cannot be evaluated from evidence the runtime can actually receive. "Code path exists" was reported as "host-evaluable".
- **Replacement:** split the row into **Code-path coverage 23/23** and **Host-evaluable coverage 22/23 — R2003 blocked by FN-1**; explain FN-1 under the table. The historical matrix row now records the original 23/23 as its definition at `f4cde3c` and points at the current split.
- **Acceptance:** pin `test_catalog_separates_code_path_from_host_evaluable_coverage` passes; no bare "Evaluable coverage … 23/23" row remains.

## 3. DET-03 — ML drawn as a live pipeline input; stale `core/` paths · ตรวจพบ · FIXED (docs)

- **Path:** `docs/ARCHITECTURE.md:36` (diagram), `:48,55` (paths), `:82`; imports `src/all_tests.zig:155`, `src/tests/cli/ml_test_cli.zig:22`.
- **Current text:** `ML flow detector ─────────────┘        → incidents → ClusterCoord → XdrEngine (CEF→SIEM)` while the same doc says "ยัง**ไม่ได้ wire** เข้า pipeline" and source imports are test/CLI only.
- **Reason:** the diagram asserts a third active input to the production pipeline that does not exist. The component table also names `core/*.zig` files that do not exist (see SL-2, P4).
- **Replacement:** diagram now reads `ML flow detector (NOT WIRED - test/CLI only) - - ┘ ...`; section 3 gained a path-convention banner: no `core/` directory exists, those are phase-era aliases, current sources under `src/`, table is a historical phase ledger.
- **Acceptance:** pin asserts both markers; no production import of `ml_detector` was added.

## 4. DET-04 — injection detector header claims real-time detection with no producer · ตรวจพบ · DEFERRED (source slice)

- **Path:** `src/detection/injection_detector.zig:1-12`; `src/daemon.zig:43-50`; `src/contract/runtime_manifest.zig:109-117`; `docs/ARCHITECTURE.md:55`.
- **Current text:** `Phase 37 Ext 7: Full T1055 Process Injection Detection` / `Real-time detection of process injection techniques using ETW Thread provider`; daemon says `// S2-03: no injection-detector import here on purpose.` and manifest sets `c.has_injection_detector = false;`.
- **Reason:** source itself documents no `InjectionEvent` producer and no `ingest()` call site. The header reads as live capability.
- **Replacement direction:** prefix the header `HISTORICAL / NOT WIRED — unit-tested logic only; no InjectionEvent producer`, mirroring the manifest comment. No behavior change.
- **Acceptance criteria:** header marker present; production import graph unchanged; no capability claim in current docs.
- **Why deferred:** `src/` is a build-source path under ADR-0008; a header edit requires a full rebuild and rebaseline. The current docs already state NOT WIRED, so no current-facing document overclaims remain.

## 5. DET-05 — MITRE "only occurrence" statement false · ตรวจพบ · FIXED

- **Path:** `docs/portfolio/DETECTION_CATALOG.md:101-107` (old); `src/detection/injection_detector.zig:7-12`; `docs/portfolio/APPLY_NOW.md:88-91`; `docs/ARCHITECTURE.md:51`.
- **Current text:** `the only occurrence is an ATS keyword in APPLY_NOW.md`.
- **Reason:** the injection detector contains T1055, T1055.001/.002/.003/.004/.012 as comments; `APPLY_NOW.md` has ATS keywords but no MITRE/T1055; `ARCHITECTURE.md` names a MITRE scenario library. Both the "only occurrence" claim and its citation were wrong.
- **Replacement:** "no reviewed, authoritative mapping; no technique IDs in Rules.json or DETECTION_VALIDATION.md; IDs exist only as comments in the NOT-WIRED injection detector and a test-only scenario library; APPLY_NOW mentions ATT&CK only as an ATS keyword."
- **Acceptance:** pin asserts the stale phrase is gone and the real occurrences are named. No mapping was invented.

## 6. DET-06 — pre-change E5/E6 matrix presented as current · ต้องตรวจ Source · FIXED (provenance only)

- **Path:** `docs/DETECTION_VALIDATION.md:1-8`; `docs/portfolio/DETECTION_CATALOG.md:1-5,32,40-41,112-114`; `analysis/current-head/RULE-COVERAGE-001-MATRIX.md:5-7`.
- **Current text:** matrix measured at `f4cde3c`, validation doc written for `a53eda8`, catalog calls it "the authoritative coverage matrix" with no provenance caveat; current build source is `661fb76`.
- **Reason:** under AGENTS.md a report tied to a non-current source commit is HISTORICAL, not current truth. `git show 9105ff5 -- src/pipeline/event_processor.zig` shows the detection path did change (counter addition). The delta appears observability-only, so E5 claims may survive — but inheritance is not verification.
- **Replacement (this patch):** provenance banners added to catalog, validation doc and the historical matrix: measured at `f4cde3c`, release identity `a53eda8`, current source `661fb76`, not re-measured, every E5/E6 row HISTORICAL. No E5 claim was upgraded or downgraded without a host run.
- **Acceptance:** pin asserts all three carry current-source provenance; no new E5 claim added.

## 7. DET-07 — language-count convention broken in first-read doc · ตรวจพบ · FIXED

- **Path:** `AI_CONTEXT.md:62`; canonical form `README.md:34-36`, `docs/portfolio/RESUME_PROJECT.md:11`.
- **Current text:** `seven-language architecture`.
- **Reason:** AGENTS.md makes AI_CONTEXT the first document an agent reads; it used a different count and omitted TypeScript's advisory-only qualifier.
- **Replacement:** `six language families (seven toolchains; TypeScript advisory-only, no production artifact)`.
- **Acceptance:** pin asserts no "seven-language architecture" string remains.

## 8. DET-08 — golden-path generator emits removed paths · ตรวจพบ · FIXED (declaration label)

- **Path:** `tools/golden_path_evidence.py:43-48,143,170,188,196,226-238,251-259`; admitted at `docs/DETECTION_VALIDATION.md:92-95`.
- **Current text:** `ZIG_GATES` lists `core/canonical_event.zig`, `core/flow_engine.zig`, … and step descriptions name `shield/src/pep.rs` / `core/forensics_engine.zig`; none exist in this tree.
- **Reason:** the tool emits a bundle called "Final Golden Path evidence" that names absent files. The validation doc already says treat it as declaration, not verification, but the emitted record carried no such marker.
- **Replacement:** docstring now says HISTORICAL declaration package; `collect()` stamps `declaration_only: true` and a `declaration_note` into every emitted record. Paths were not silently rewritten to guessed current locations; that would fabricate a mapping.
- **Acceptance:** pin asserts both markers; `tests/security/test_single_rule_authority.py::test_golden_path_evidence_hashes_the_file_it_claims` still passes (it checks the canonical Rules.json path logic, unchanged).

## 9. DET-09 — policy boundary intact; production seam unproven · แนะนำเพิ่ม · NOT A DEFECT

- **Path:** `brain/policy_decision.py:1-8,32-42,49-73`; `analysis/current-head/detection-only-baseline.json:3-10`.
- **Verified:** actions limited to ALLOW/ALERT; `enforcement_requested` rejected; Block/Drop documented as intent only. No contradiction found.
- **Limitation:** `brain/policy_decision.py:8` says `SEAM-STATUS: not wired to the production entrypoint (brain/windows_brain.py)`, so this safe adapter is not the production path.
- **Recommendation (not executed):** add a production-path assertion that no Python/TS/Cython decision can set `matched_rule_id`, mint a receipt or request a host effect. Do not present the safe adapter as proof of the production seam.

---

## Verified-negative areas (no finding)

- No zero-day / AI-overclaim / prevention-overclaim in current docs; docs actively forbid them.
- Loopback consistently caveated as self-test only, never production binding.
- DEGRADED reported honestly, not repainted.
- All 23 rule IDs have fixtures under `tests/vectors/rules22/`; `tests/security/test_detection_contract_pin.py:146-232` pins catalog consistency (AC1–AC4). That pin does **not** prove per-rule host reachability — see DET-02.

## Flow / contract impact

```
OLD  DETECTION_CATALOG: Evaluable coverage 23/23 (contradicted by FN-1)
NEW  Code-path 23/23 + Host-evaluable 22/23 (R2003 blocked by FN-1)
OLD  architecture diagram: ML is a live pipeline input
NEW  ML marked NOT WIRED; core/* table labelled historical aliases
OLD  golden-path bundle: "Final evidence" naming absent core/* files
NEW  every emitted record stamped declaration_only: true
```

- **Rules/wire/ABI/authority/host effects:** none changed. No rule added, removed or re-scored; no MITRE mapping invented.
- **Build source:** unchanged (`661fb76`) — all edited paths are records-only docs, tools or analysis under ADR-0008.
- **Evidence level:** E1/E2 static pins; existing E5/E6 rows explicitly labelled HISTORICAL at `f4cde3c`.

## Completion gate

**PASS (E1/E2, records-only).** Requires: new doc pins pass; `TRUTH_VALID @ 661fb76`; 674/674 digests; BAD LINKS none; `SUMMARY_VALID`; CI-equivalent pytest green. Remaining at the recorded source: DET-01/F6, DET-04 and the earlier P4 source findings were documented deferred source/design slices — not fixed, not claimed as fixed by this slice. DET-01/F6 was subsequently covered by the P8-I44 counters and exact-delta pipe proof at current source `a26c573`; DET-04 and the remaining source/design findings stay explicitly deferred.
