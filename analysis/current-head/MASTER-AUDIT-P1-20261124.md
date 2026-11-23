# Master Audit — Phase 1: Release Truth & README Consistency (2026-11-24)

**Records HEAD at read time:** `00e8d522149de5b2ac47e09433a9f953c17e663a`
**Build source HEAD:** `ab0fa171eb89cecaa826c9256ecc90eb4e2a3bfd` (ADR-0008; unchanged by this records-only patch)
**Classification:** `CONFIRMED` = contradiction against source or self-contradiction · `SOURCE-CHECK` = suspicion resolved against source/test · `RECOMMENDED` = ambiguity reduction, not a defect

This patch changes documentation only. No release status, gate count, rule, wire layout,
authority map, signature, tag or key was changed. The v1.1 release identity (`466a226` /
build source `a53eda8`) and the current build source (`ab0fa17`) remain distinct and intact.

---

## Findings and dispositions

### P1-1 — `README.md:316` · CONFIRMED
- **Current:** `### The five-question model: who, what, where, how, and why`
- **Reason:** the table at :320–327 has six rows including `**When?**` at :326; the examples at :332–353 also use six. The heading omitted `When` and contradicted its own body.
- **Replacement:** `### The six-question model: who, what, where, how, when, and why`
- **Also:** `docs/portfolio/INTERVIEW_PREP.md:36` → `Five interview questions...` (that section is a different Q1–Q5 interview set, not the operational six-question model).
- **Acceptance:** `five-question model` → 0 hits; table row count = 6; no stale anchor (grep found none).

### P1-2 — `README.md:20-22, 109-114`, `docs/OPERATIONAL_FAILURE_MATRIX.md:41-47` · CONFIRMED (doc ↔ source)
- **Current:** `The DEGRADED badge is the host's current control-pipe responder detail` / `because of a control-pipe responder detail while all subsystems report RUNNING`
- **Reason:** `tools/aegisctl/api/control_api.py:974-980` builds `"detail": "responder state %s" % health.get("state")`. The detail *renders* the daemon health state; it is not an independent cause. Actual demotion inputs live in `src/control/state_machine.zig:407-434` and `src/daemon.zig:935-944`.
- **Replacement:** state that the detail is the control API echoing `system.health.state`; keep the `DEGRADED` badge visible and unchanged; disclose that the specific demotion counter for that snapshot was not preserved and must not be inferred; keep prevention gate closed / `host_effect_capable=false`.
- **Acceptance:** `because of a control-pipe responder detail` → 0 hits; screenshot caption still shows `runtime=DEGRADED`; no invented root cause.

### P1-3 — `docs/ARCHITECTURE-TRUTH.md` (root) · CONFIRMED
- **Current:** no HISTORICAL banner; `:62` `- main.zig status: degraded → false (...)`
- **Reason:** the README links the `docs/architecture/` copy, which *is* bannered; the root copy is an unlinked stale Step 39–46 record. Its hard-coded `degraded → false` contradicts `src/control/state_machine.zig:407-434`; `src/main.zig:85,109` only registers the `health.check` alias.
- **Replacement:** HISTORICAL banner before the status line + inline **HISTORICAL** annotation on `:62` pointing at the current health computation.
- **Acceptance:** banner within first 6 lines; `degraded → false` appears only on the annotated line; link checker clean; README:752 still points to the `docs/architecture/` copy.

### P1-4 — `docs/runtime/LOCAL_RUNBOOK.md:500` · CONFIRMED
- **Current:** ``- `docs/architecture/DEPLOYMENT.md` — production deployment guide.``
- **Reason:** path does not exist (actual file `docs/DEPLOYMENT.md`); "production deployment guide" conflicts with detection-only / observe-only scope.
- **Replacement:** ``- `docs/DEPLOYMENT.md` — lab/qualification deployment and observe-only host setup; production blocking deployment is out of scope.``
- **Acceptance:** `Test-Path docs/DEPLOYMENT.md` = True; `production deployment guide` → 0 hits; BAD LINKS: none.

### P1-5 — `docs/gates/PRODUCTION_READINESS.md`, `docs/runbooks/RB-024-final-release-window.md` · RECOMMENDED
- **Current:** `gate 3 ... **FAIL / NOT closed**` / `**No tag and no GitHub Release until gate 3 and the board are 6/6.**` / `turns release: 5/6 gates into a shippable release` / `the board stays at 5/6`
- **Reason:** correct HISTORICAL banners already exist (:3-6 and :3-14), but the stale bodies read as current if opened by line number. Current board is `docs/gates/T20_100pct_audit.md` → SHIPPABLE 6/6.
- **Replacement:** added a **Reading rule** pointing to the current board, a **Historical snapshot values** marker at the gate-3 paragraph, and **Historical procedure value / retired candidate** markers in RB-024. Stale values retained for provenance.
- **Acceptance:** every 5/6 and soak-FAIL statement carries a marker; no historical record deleted; current board untouched.

### P1-6 — language count across README and portfolio · CONFIRMED ambiguity + SOURCE-CHECK
- **Current:** `six languages` / `six-language hub-and-spoke runtime` / `One schema across six languages`
- **Reason:** literal count is seven toolchains (Zig, Go, C, C++, Rust, Python, TypeScript); "six" only works if C/C++ is one family, and TypeScript is advisory with no runtime artifact. `INTERVIEW_PREP.md:19` was factually wrong: codecs exist in Zig/Go/C/Python + golden tuple map; Rust codec is TBD (`ARCHITECTURE_EN.md:103-104`, `INTERVIEW_PREP.md:97,113`).
- **Decision (owner):** standardise on **six language families**, with an explicit counting convention at first use and `seven toolchains` in parentheses.
- **Replacement:** README:27-28 + convention footnote after the summary table; `RESUME_PROJECT.md:11,28`; `ARCHITECTURE_EN.md:74`; `INTERVIEW_PREP.md:19,36,38,Q1 answer`; `APPLY_NOW.md:39,45,67`; codec line corrected to the four live codecs + golden tuple map.
- **Acceptance:** `six languages` → 0 hits; `six-language runtime` → 0 hits; `One schema across six languages` → 0 hits; no claim that Rust is a canonical codec; resume headline and prose use one convention.

### P1-7 — `docs/portfolio/INTERVIEW_PREP.md:112`, `docs/portfolio/ARCHITECTURE_EN.md:167` · RECOMMENDED
- **Current:** `a 36.5-hour zero-loss soak` / `36.52 / 24.0 h PASS ... counters all 0`
- **Reason:** standalone sentences lacked the recorded-window qualifier present elsewhere (`README.md:719`, `OBSERVED_PERFORMANCE.md:70`, `APPLY_NOW.md:53`).
- **Replacement:** `... owner-run soak PASS with zero loss during that recorded 36.52 h window` in both places.
- **Acceptance:** `36.5-hour zero-loss soak` → 0 hits; no "zero loss ever" claim.

---

## Checked and intentionally unchanged

| Item | Evidence |
|---|---|
| SHIPPABLE `0/6 open` ≡ `6/6 PASS` | `tools/final_audit.py:641-654,948`; `docs/gates/T20_100pct_audit.{md,json}`; `analysis/current-head/V1.1-RELEASE-CLOSEOUT-20261122.md:3,16` |
| Detection-only authority | `README.md:99-105`; `AI_CONTEXT.md:34`; `src/pipeline/runtime_state.zig:45-62`; `src/control/handler_registry.zig:1960-1989` |
| 23 rules, no "all live-proven" | `README.md:47,56-60`; `docs/portfolio/DETECTION_CATALOG.md:15-17`; R2003 FN-1 disclosed at `docs/DETECTION_VALIDATION.md:61` |
| 1,471 / 3366 / 674 / 36.52 h | commit-and-scope-qualified at `README.md:30,713` and `EVIDENCE_INDEX.json:9998-10032` |
| Backpressure semantics | `README.md:174`, `docs/SECURITY_THREAT_MODEL.md:46` match `src/pipeline/event_queue.zig:199-277` (drop-on-full, bounded ≤5 ms pace, not blocking producer) |
| Capability matrix | `README.md:42-60,375-385` separates implemented / verified / active runtime / observe / host-effect |
| `shippable_with_waiver: true` with empty `waived` | derived `not unwaived` at `tools/final_audit.py:649`; generated board must not be hand-edited (`:1034`) |

## Carry-forward (later phases, not in this patch)

- **Phase 2 / Protocol:** `shared/wire/wire_codec.h:597-606` helper accepts only v1/v2 and has no caller; `src/contract/canonical_event.zig:1624-1625` comment says "Extra trailing bytes" but asserts a short frame (live exact-length gate at `:653` is correct).
- **Phase 3 / Evidence:** per-entry `head_sha` vs ad-hoc `source_commit`; inconsistent historical labels; legacy `100% PRODUCTION VERIFIED` strings at `EVIDENCE_INDEX.json:10642,10654` lack an inline "removed" qualifier; no `docs/evidence/`.
- **Phase 4 / Runtime:** `docs/architecture/FAILURE_MODEL.md:3,191-200` is labelled AUTHORITATIVE but describes a fill-percent priority-drop model absent from `src/pipeline/event_queue.zig`; legacy `core/event_fabric.zig` references in `RUNTIME_SPINE.md:98-99`, `data-flow.md:120-123`, `LANGUAGE_OWNERSHIP.md:12`; `src/windows/ips_simulation.zig:44` "production-ready" comment.
- **Phase 5 / Detection:** R2003 FN-1 is a real capability gap (no `CommandLine` in ProcessStart v0–v4); disclose, do not fabricate a fix.

---

## Patch transaction record

```
PATCH-ID: MASTER-AUDIT-P1-20261124
FLOW-ID: N/A (truth/documentation; no runtime flow)
TARGET HEAD: 00e8d52
FILES CHANGED: README.md, docs/OPERATIONAL_FAILURE_MATRIX.md, docs/ARCHITECTURE-TRUTH.md,
  docs/runtime/LOCAL_RUNBOOK.md, docs/gates/PRODUCTION_READINESS.md,
  docs/runbooks/RB-024-final-release-window.md,
  docs/portfolio/{INTERVIEW_PREP,ARCHITECTURE_EN,RESUME_PROJECT,APPLY_NOW}.md,
  EVIDENCE_INDEX.json, analysis/current-head/MASTER-AUDIT-P1-20261124.md
OLD FLOW → NEW FLOW: ambiguous language/status/DEGRADED wording → single explicit convention,
  historical markers, source-accurate health reporting
INVARIANT: release identity, 6/6 board, 674 digests, 23 rules, wire/rule/authority maps unchanged;
  DEGRADED badge remains visible and truthful
CONTRACT / ABI / AUTHORITY / STATE IMPACT: none
BUILD RESULT: not required (records-only; build source remains ab0fa17)
TEST RESULT: python tools/truth.py verify -> TRUTH_VALID @ ab0fa17;
  python tools/release_engineering.py --verify -> OK - 674 artifacts match recorded digests;
  check_links.py -> BAD LINKS: none; python -m pytest tests/release -q -> 207 passed
WINDOWS RESULT: not applicable (no source or host change)
EVIDENCE LEVEL: E1 (static documentation reconciliation against current source and generated board)
EVIDENCE ARTIFACTS: this file; EVIDENCE_INDEX.json entry MASTER-AUDIT-P1-20261124-E1
ROLLBACK: git revert the records commit(s); build source unaffected
REMAINING RISK: carry-forward items above; no new E4/E5 verification in this slice
OPEN BLOCKERS: none
COMPLETION GATE: PASS (E1); Phase 2 may start
```
