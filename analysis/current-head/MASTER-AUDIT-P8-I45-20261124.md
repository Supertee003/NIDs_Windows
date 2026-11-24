# MASTER AUDIT — P8 / issue #45 source-truth slice (2026-11-24)

**PATCH-ID:** `P8-I45-SOURCE-TRUTH`
**FLOW-ID:** authority disclosure / capture-provenance disclosure (CONTRACT-02, DET-04, F4, F5, F10)
**TARGET HEAD (build source before patch):** `661fb768dc1c8eeb0f79e4e437807f2eac08c9ff`
**SOURCE COMMIT AFTER PATCH:** `2129dcd7a166ef47226a9ae4afd8144d787ebbf0`
**RECORDS COMMITS:** truth rebaseline `2eaeb11`, digest refresh `7b89f74`, doc-checker fix `2ddc9f5`, digest refresh `0c1a413`; final records HEAD is the commit that lands this addendum (read with `git rev-parse HEAD`).

## 0. Why this is a source patch

P6 record-only closeout labelled `shared/abi/pep_abi.md` as HISTORICAL from the
records surfaces and deferred the source-path edit to issue #45. P4/P5 audits
also left source-level findings F4, F5, F10 and DET-04 open with exact
replacement directions. This slice edits those source/build-tree files in one
patch transaction. It changes **comments and test pins only**; no ABI byte,
struct layout, ordinal, FFI signature, rule, wire codec, authority behavior or
runtime branch was changed.

---

## 1. Findings and replacements

### 1.1 P6-DOC-TRUTH — `shared/abi/pep_abi.md` still read as current enforcement truth

- **Current text before patch:** `Rust is the FINAL security authority - no bypass allowed.`; `Action Dispatcher (block via WFP, quarantine, escalate, etc.)`; `- Rust PEP is the ONLY final enforcement authority`.
- **Reason:** the file is a build-source contract, but its authority narrative predates `RETIRE-HOST-EFFECT-001`. A reader following the source would infer live WFP enforcement and a final authority that `AUTHORITY_MAP.json` explicitly denies.
- **Replacement:** a banner marks the narrative **HISTORICAL (P6-DOC-TRUTH / issue #45)** and names current authority: Rust PEP is a detection-only policy/evidence authority, `is_final_enforcement: false`, no host-effect authority. Each stale line carries an inline HISTORICAL qualifier. The frozen ABI bytes, sizes and FFI signatures are explicitly UNAFFECTED.
- **Acceptance:** `tests/docs/test_doc_truth_labels.py::test_pep_abi_narrative_is_historical_but_abi_bytes_frozen` requires the banner, current-authority wording, HISTORICAL qualifiers on each stale marker, and the unchanged frozen size/signature tokens.

### 1.2 `nose/pipe_writer.go` — stale `core/` paths and a TCP fallback that is not implemented

- **Current text before patch:** `that the Zig core consumes (core/nose_pipe_reader.zig)`; `non-Windows falls back to a TCP loopback socket so the capture path is still testable/functional on dev boxes`; `Frame protocol (shared with core/nose_pipe_reader.zig)`.
- **Reason:** no `core/` filesystem tree exists; those names are module-ID aliases. `dialPipe` uses `os.OpenFile` only, so no TCP fallback exists to make the path testable.
- **Replacement:** paths become `src/capture/nose_pipe_reader.zig` with an explicit note that `core/*` names in manifests are aliases; the TCP sentence becomes `no TCP fallback is implemented (dialPipe uses os.OpenFile only)`.
- **Acceptance:** `test_source_comments_no_longer_claim_removed_core_paths_or_tcp_fallback` pins the new strings and forbids both old strings.

### 1.3 `src/tests/cli/nose_pipe_e2e_cli.zig` — non-runnable usage line

- **Current text before patch:** `zig run core/nose_pipe_e2e_cli.zig -- [-seconds N]`.
- **Reason:** the file lives at `src/tests/cli/`; the documented command would not run.
- **Replacement:** `zig run src/tests/cli/nose_pipe_e2e_cli.zig -- [-seconds N]`.
- **Acceptance:** the same pin asserts the corrected path and forbids the old one.

### 1.4 F4 — `src/capture/source_arbiter.zig` / `wfp_telemetry.zig` hid a real dual-submitter window

- **Current text before patch:** `kernel_fallback`/`nose_stalled` returned `packet_may_submit=true, kernel_may_submit=true`, while surrounding comments claimed "one authority at a time, no duplicated flow accounting".
- **Reason:** two detection-ingress producers are admitted during bounded stall recovery. Overlap can duplicate flow rows; the mode/reason pair is published, but the source comments denied the exception. Gating Nose off would risk silent event loss when it resumes and would break the existing E2 pin (`tests/wfp/test_capture_source_arbitration.py`, `tests/host_telemetry/test_t11_single_convention_ingress.py`).
- **Replacement:** the arbiter header and the `stalled` branch call this a deliberate `TWO-SUBMITTER` exception and say a resumed Nose must be admitted on the next `evaluate()`. The telemetry doc names the same `DOCUMENTED EXCEPTION (F4)`, warns duplicate flow rows are possible in that window, and keeps `nose_absent` kernel-only.
- **Acceptance:** `test_dual_submit_exception_is_disclosed_not_hidden` requires the disclosure and still requires the exact dual-submit return; no behavior changed.

### 1.5 F5 — `src/capture/windows_capture.zig` read like a live WFP block path

- **Current text before patch:** header called it a WFP kernel traffic reader and documented `rust_pep.block_ip()` installing a kernel block filter for severity >= 2.
- **Reason:** `build.zig:30` roots the daemon at `src/main.zig`; this module is referenced only by the orphaned `src/core/nids_main.zig` and `src/all_tests.zig`. `src/core/rust_pep.zig:291-295` fails closed (`false`, "receipt API required"). Production uses `src/capture/wfp_telemetry.zig`, submit-only. A reader could mistake quarantined code for a host effect.
- **Replacement:** a `HISTORICAL — QUARANTINED, NEVER IMPORTED BY PRODUCTION (F5 / REBUILD-004)` banner cites the roots, the fail-closed shim and the P0-class risk of wiring it back. The severity>=2 doc comment is labelled historical; the call site says it always returns false and is never a host effect.
- **Acceptance:** `test_quarantined_reader_is_labeled_and_stays_out_of_production` pins the banner, fail-closed text, daemon exclusion, telemetry "must stay retired" marker, and the old behavior is not claimed as current.

### 1.6 F10 — `src/control/defcon.zig` implied production-reachable confirmed-effect rungs

- **Current text before patch:** `confirmed >= 5` and `confirmed >= 3` were presented as ordinary ladder rungs.
- **Reason:** `confirmed` is incremented only by `ActionDispatcher.dispatchWithReceipt`, reached solely through the lab prevention gate (`build.zig:21-25`, default false; `runtime_manifest.json` says no receipt can now be minted). Presenting those rungs as production truth would imply a host effect.
- **Replacement:** module header and `level()` doc state they are lab-only and NOT production-reachable; production escalation uses only `total`/`critical`.
- **Acceptance:** `test_confirmed_effect_rungs_are_labeled_lab_only` pins both comments and the manifest receipt note. Ladder numbers and inputs are unchanged.

### 1.7 DET-04 — `src/detection/injection_detector.zig` advertised live T1055 detection

- **Current text before patch:** "Full T1055 Process Injection Detection", "Real-time detection ... Replaces the heuristic-based approach", "actual event-driven detection".
- **Reason:** no production component constructs an `InjectionEvent` or calls `InjectionDetector.ingest()`. `src/contract/runtime_manifest.zig:109-117` reports `has_injection_detector = false`; `src/daemon.zig:43-50` records why; call sites are unit tests and a test-only CLI. Existing `tests/security/test_capability_claims.py` pins the capability as not claimed.
- **Replacement:** a `HISTORICAL / NOT WIRED — unit-tested logic only (DET-04 / S2-03)` banner names the real call sites and forbids treating its alerts as live detection evidence until an E5-gated producer exists.
- **Acceptance:** `test_injection_module_header_says_not_wired` pins banner, "unit-tested logic only", `has_injection_detector = false` and "NO production component".

### 1.8 Records-only result: `scripts/doc_checker.py` false FAIL on a valid command

- **Current text before patch:** `AEGISCTL_USE_RE` and `parse_aegisctl_commands()` used `[a-z_0-9]+`, truncating `mark-fp` to `mark` and reporting `doc-cmd-unknown`; a naive `[a-z_0-9-]+` fix then misread `-v`/`-` as commands.
- **Reason:** `tools/aegisctl.py:2755-2761` registers `sub.add_parser("mark-fp", ...)`, and `docs/CLI_COMMANDS.md:37` documents it. The checker contradicted both.
- **Replacement:** both regexes use `[a-z_0-9][a-z_0-9-]*` (first character cannot be a hyphen). The self-test fixture now contains a hyphenated command and uses it in the good doc.
- **Acceptance:** `python scripts/doc_checker.py --self-test` -> ALL PASS, repo check -> `Summary: 0 FAIL, 0 WARN`, and `test_doc_checker_accepts_hyphenated_aegisctl_commands` pins the regex and command.

---

## 2. Patch transaction / flow impact

```text
OLD  pep_abi.md                -> final enforcement + WFP action dispatcher read as current
NEW  pep_abi.md                -> HISTORICAL narrative; frozen ABI bytes unchanged

OLD  Go writer / CLI usage      -> non-existent core/ paths + non-existent TCP fallback
NEW  Go writer / CLI usage      -> real src/capture paths; no TCP fallback stated

OLD  F4 comments                -> dual submit hidden behind "one authority at a time"
NEW  F4 comments                -> documented TWO-SUBMITTER stall-recovery exception

OLD  F5 / F10 / DET-04 source   -> quarantined/lab/unwired code read as live capability
NEW  F5 / F10 / DET-04 source   -> explicit HISTORICAL / QUARANTINED / lab-only / NOT WIRED

OLD  doc_checker                -> valid `mark-fp` reported as unknown command
NEW  doc_checker                -> hyphenated commands parsed; options not treated as commands
```

**INVARIANT:** no runtime behavior, ABI byte, wire layout, rule, release identity,
gate count or authority changed. All changes are disclosure comments, corrected
documentation strings and E1 test pins.

**CONTRACT IMPACT:** `CONTRACT_MAP.json:historical_source_note` now has a matching
source banner in `shared/abi/pep_abi.md`. No contract ID, version, size or FFI
signature changed.

**ABI IMPACT:** none. `PepRequest=64`, `PepResponse=24`,
`PepAssessmentResponse=16`, `PepContext=24`, `PepFilterState=20`, and
`aegis_pep_read_events` are unchanged and re-pinned.

**AUTHORITY IMPACT:** none at runtime. Current authority remains detection-only
policy/evidence with no host effect. Historical enforcement vocabulary is
labelled, not promoted.

**STATE IMPACT:** none. No counter, lifecycle field, queue, timer or persistent
state changed.

**TEST IMPACT:** 41 targeted pins passed before the rebaseline; 1483 passed,
1 skipped, 18 deselected, 27 subtests passed in the final CI-equivalent run.

**EVIDENCE IMPACT:** one E2 entry added; build source advanced from `661fb76` to
`2129dcd`; 674 digests refreshed; all truth maps restamped; frozen historical
records left untouched.

---

## 3. Verification proof

- `zig build test` using `D:\aegis-tmp\zig-cache-i45` -> exit 0.
- `zig build` -> `D:\aegis-tmp\zig-out-i45\bin\aegis_nids.exe` present.
- `cd nose && go build -o D:\aegis-tmp\aegis-nose-i45.exe .` -> artifact present.
- Targeted Pin Set A (doc truth, capture arbitration, T11 ingress, DEFCON, capability claims) -> `41 passed`.
- `python -m pytest -q -m "not host_live"` -> `1483 passed, 1 skipped, 18 deselected, 27 subtests passed`.
- `python scripts/check_summary.py` -> `SUMMARY_VALID`.
- `python scripts/doc_checker.py --self-test` -> `Self-test: ALL PASS`; repo check -> `0 FAIL, 0 WARN`.
- `python D:\aegis-tmp\check_links.py` -> `BAD LINKS: none`.
- `python tools/truth.py verify` -> `TRUTH_VALID @ 2129dcd`.
- `python tools/release_engineering.py --verify` -> `674 artifacts ... OK`.

**WINDOWS RESULT:** not run at this source. No E5, E4, soak, host install or
production simulation is claimed.

**EVIDENCE LEVEL:** E1 (source/document inspection) + E2 (unit/pin proof).
No higher level is claimed.

**EVIDENCE ARTIFACTS:** this file; `EVIDENCE_INDEX.json` entry
`P8-I45-SOURCE-TRUTH-E2`; `D:\aegis-tmp\i45_targeted3.txt`,
`D:\aegis-tmp\i45_full_pytest2.txt`, `D:\aegis-tmp\i45_zig_exit.txt`,
`D:\aegis-tmp\i45_artifacts.txt`, `D:\aegis-tmp\i45_truth4.txt`,
`D:\aegis-tmp\i45_verify4.txt`, `D:\aegis-tmp\i45_docselftest2.txt`,
`D:\aegis-tmp\i45_doccheck3.txt`, `D:\aegis-tmp\i45_links2.txt`.

**ROLLBACK:** revert source commit `2129dcd` and its rebaseline/digest records
commits; frozen `v1.1` release identity is untouched. No config, key, tag or
signature rollback is required.

**REMAINING RISK:** issue #44 was closed at current build source `a26c573` with
E3 private-pipe and E4/E5 canonical-pipe `-inject` exact-delta proof; see
`analysis/current-head/MASTER-AUDIT-P8-I44-CURRENT-SOURCE-20261125.md`. The
earlier "still open" wording in this record was true at its recorded source
`2129dcd` and is SUPERSEDED, not a current status. The F4 dual-submitter overlap
remains disclosed but deliberately retained to avoid silent event loss. Lab-only
F10 rungs remain in the pure ladder for the lab gate.

**OPEN BLOCKERS:** none for this slice. These E1/E2 results close no E4/E5/soak
gate; the narrow current-source pipe/lifecycle E4/E5 proof is recorded separately
and adds no soak, install, signing, rule-matrix, E6/E7 or zero-loss claim.

**COMPLETION GATE:** PASS (E1/E2). Build 0, targeted pins 41/41, CI-equivalent
1483/1483, docs 0 FAIL, links none, TRUTH_VALID @ 2129dcd, 674/674 digests.
Release identity remains `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS, no new
tag/signature/key and no current-source E4/E5/soak claim.
