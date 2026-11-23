# Master Audit — Phase 6 (Documentation)

**Target HEAD:** `20102d41c9bf97a80745b32090a0a0678d95f1ca`
**Build source (unchanged by this records-only slice):** `661fb768dc1c8eeb0f79e4e437807f2eac08c9ff`
**Date:** 2026-11-24
**Patch ID:** `P6-DOC-TRUTH-20261124`
**Classification convention:** "ตรวจพบ" = confirmed from current file/source; "ต้องตรวจ Source" = needs source/artifact inspection before a defect claim; "แนะนำเพิ่ม" = recommendation, not a proven defect.
**Evidence level:** E1/E2 static pins only. No new E4/E5, host, soak, Windows or release verification is claimed for this slice.

---

## STOP-THE-LINE disposition

**DOC-AUDIT-01 is a confirmed contradictory-source-of-truth trigger** (`AGENTS.md` STOP-THE-LINE list). Current machine truth (`AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `runtime_manifest.json`) says Rust PEP is detection-only with `is_final_enforcement: false` and no host-effect authority, while multiple current-facing docs still said "final/sole enforcement authority", "Privileged action authorization", "block via WFP" and "all enforcement goes through the Rust PEP".

All **records-path** occurrences were corrected or explicitly scoped in this patch. One occurrence remains in `shared/abi/pep_abi.md`; `shared/` is a build-source path under ADR-0008 (`tools/truth.py:52`), so an in-file banner would move the source commit and force a full rebuild. It is labelled HISTORICAL from `AI_CONTEXT.md` and `CONTRACT_MAP.json`, and tracked with the other deferred source/design findings in **issue #45**: https://github.com/Supertee003/NIDs_Windows/issues/45 . This is disclosure, not a silent workaround.

No new enforcement claim was introduced. No wire, ABI bytes, rule, authority behavior, host effect, release tag, signature or key changed.

---

## 1. DOC-AUDIT-01 — enforcement-authority vocabulary in current docs · ตรวจพบ · FIXED (records paths) / DEFERRED (source path)

- **Paths / current text (before patch):**
  - `AI_CONTEXT.md:291` — `- **Final enforcement authority:** Rust PEP (\`rust-src/lib.rs\`)`; `:305` — `Never create a second enforcement authority`; `:843` — `Final enforcement authority: PEP, Ed25519, TLS, authorization`; `:917` — `- Privileged action authorization`.
  - `CONTRIBUTING.md:50-51` — `Changes that touch the WFP path outside \`rust-src/\` (the Rust PEP is the sole enforcement authority).`
  - `docs/ai-context/02-runtime-spine.md:18` — `11. Rust PEP (ENFORCE) - Rust - validate + execute + defer`.
  - `docs/ai-context/03-language-ownership.md:9,14` — `Rust | Security boundary, policy verification, PEP, enforcement, privileged state, rollback`; `No language can bypass Rust PEP for enforcement.`
  - `docs/ai-context/05-data-lifecycle.md:6` — `... Policy -> EnforcementPlan -> Rust PEP -> Action -> Forensics -> Replay`.
  - `docs/ai-context/governance.md:43-44` — `all enforcement goes through the Rust PEP`.
  - `docs/ai-context/01-semantic-map.md:18` — `| ENFORCE | PEP and privileged actions |`.
  - `docs/ai-context/10-current-phase.md:599` — `  -> ONE ENFORCEMENT AUTHORITY`.
  - `docs/architecture/authority-map.md:37,87-90` — `Final enforcement; validates + executes`; `[Windows Enforcement] (WFP IOCTL, netsh, etc.)`.
  - `docs/architecture/MULTI_PROCESS_ARCHITECTURE.md:132,150-152,175`, `docs/architecture/RUNTIME_SPINE.md:3,207`, `docs/ARCHITECTURE_BOUNDARY.md:45-47,109`, `docs/architecture/data-flow.md:61-63,152`, and nine dated root handoff/plan docs.
  - Source path (deferred): `shared/abi/pep_abi.md:12,179,188-189`.
- **Reason:** `AUTHORITY_MAP.json:177,196,321,425-432` and `CONTRACT_MAP.json:82-84` define detection-only policy/evidence authority, `is_final_enforcement: false`, and no host-effect authority. The live control API was already corrected in P4 (F9); these documents were not rebased.
- **Replacement applied:** all records-path occurrences now say detection-only policy/evidence authority, authorization evidence (no host effect), ESCALATE reason 8 / `filter_id=0`, or are explicitly marked HISTORICAL with current truth pointed at `AUTHORITY_MAP.json`. `shared/abi/pep_abi.md` is labelled a historical source-path ABI snapshot in `AI_CONTEXT.md` and `CONTRACT_MAP.json`; in-file banner deferred to issue #45.
- **Acceptance:** pins in `tests/docs/test_doc_truth_labels.py` assert the stale phrases are absent or scoped in current records docs and that the historical ABI note names issue #45. No current doc claims a host-effect authority.

## 2. DOC-AUDIT-02 — AI_CONTEXT mixes v1.1 identity with v2.0.0 "current" language · ตรวจพบ · FIXED

- **Path / current text:** `AI_CONTEXT.md:38` — `Current evidence establishes Windows E5 for the shipped detection-only release \`v2.0.0\` (build source \`7c604d5\`)`; `:357` — `Current source/build slice (2026-11-03; source commit \`f7c626d...\`)`; `docs/ai-context/10-current-phase.md:7` still named `ab0fa17` as current.
- **Reason:** the same first-read document declares v2.0.0 release statements HISTORICAL at lines 17–22, then calls v2.0.0 the shipped release and an old commit the current slice. Current release record is `V1.1-RELEASE-CLOSEOUT-20261122.md` (`466a226` / `a53eda8`); current build source is `661fb76`.
- **Replacement:** line 38 now records E5 as historical at `7c604d5` and states v1.1 / `466a226` / `a53eda8` / current `661fb76`; line 357 is `HISTORICAL @ 2026-11-03 ...`; the phase-doc banner now says the current build source is `661fb76`.
- **Acceptance:** pins assert no "Current evidence establishes ... v2.0.0" or "Current source/build slice (2026-11-03" survives, and `661fb76` is present.

## 3. DOC-AUDIT-03 — trust anchor named superseded b597e71 as current · ตรวจพบ · FIXED

- **Path / current text:** `docs/gates/RELEASE_TRUST_ANCHOR.md:23` — `| Current candidate signed with this key | \`release/T20-final/b597e71\` |`; `:34` — `python tools\sign_release.py --verify --dir release\T20-final\b597e71`.
- **Reason:** `docs/gates/T20_100pct_audit.md:7-9,28` and `V1.1-RELEASE-CLOSEOUT-20261122.md:12` identify the active signed candidate as `466a226`. `b597e71` is superseded. No new key or signature is implied.
- **Replacement:** current candidate row and operator command now point to `release/T20-final/466a226`; `b597e71` moved into the superseded row.
- **Acceptance:** pin asserts both row and command use `466a226` and no current-candidate `b597e71` remains. `Test-Path release/T20-final/466a226` was verified true before the edit.

## 4. DOC-AUDIT-04 — "evaluable 23/23" survived P5 · ตรวจพบ · FIXED

- **Path / current text:** `README.md:62` — `| Evaluable in the runtime | 23/23 |`; `docs/portfolio/INTERVIEW_PREP.md:51` — `23/23 catalog and evaluable coverage`; `:102` — `Catalog/evaluable 23/23`.
- **Reason:** P5 split the claim into **code-path 23/23** and **host-evaluable 22/23 (R2003/FN-1)**. The README and interview doc still used the retired unsplit term.
- **Replacement:** README now has separate `Code-path evaluable 23/23` and `Host-evaluable 22/23` rows; interview answers use "catalog and code-path 23/23, 22/23 host-evaluable". The stale APPLY_NOW/ATS sentence was removed from the catalog's MITRE section.
- **Acceptance:** pins assert the old row/phrases are absent and the 22/23 split is present in README, interview doc and catalog.

## 5. DOC-AUDIT-05 — zero-loss caveat dropped in role variant · ตรวจพบ · FIXED

- **Path / current text:** `docs/portfolio/RESUME_PROJECT.md:62` — `- Shipped a signed release with verified artifacts, a 36.52 h soak PASS, and zero-loss counters.`
- **Reason:** the same file at `:17` and `README.md:728` scope zero loss to the recorded 36.52 h window; current lab counters are nonzero. The shorter variant read as an unlimited claim.
- **Replacement:** `... zero loss/shed counters were measured only in that recorded window, and later lab snapshots show nonzero ring/alert-write counters.`
- **Acceptance:** pin asserts both the recorded-window scope and the later-nonzero disclosure.

## 6. DOC-AUDIT-06 — CONTRACT_MAP claimed unimplemented TCP fallback · ตรวจพบ · FIXED

- **Path / current text:** `CONTRACT_MAP.json:29` — `non-Windows development uses a loopback TCP fallback.`
- **Reason:** `nose/pipe_writer.go:103-111` only calls `os.OpenFile(path, os.O_WRONLY, 0)`; there is no `net` import or socket. P4 already corrected `FLOW_MAP.json`; this map was missed.
- **Replacement:** `Windows named pipe ... only; no TCP fallback is implemented ... Loopback capture is a labelled self-test, not a production or fallback adapter.`
- **Acceptance:** pin asserts the fallback clause is gone and the explicit no-fallback note is present. No wire layout changed.

## 7. DOC-AUDIT-07 — ADR-0001 declared deleted `core/` files canonical · ตรวจพบ · FIXED

- **Path / current text:** `docs/adr/0001-architecture-lock.md:3` — `**Status:** Accepted`; `:23-32` list `core/*.zig` owners; `:45` — `core/dispatcher.zig is the ONLY production runtime orchestrator.`
- **Reason:** `build.zig:28-30` roots production at `src/main.zig`; `ADR-CORE-LEGACY-CLASSIFICATION.md:31-35` says `src/` is canonical; `AI_CONTEXT.md:861` says `core/` does not exist.
- **Replacement:** status is `Accepted — HISTORICAL in part (P6-DOC-TRUTH)` with a current-state note pointing at `src/main.zig`, `AUTHORITY_MAP.json` and `FLOW_MAP.json`. The historical table is retained, not silently rewritten.
- **Acceptance:** pin asserts the status and current-state note.

## 8. DOC-AUDIT-08 — lifecycle diagram showed removed Rust :8080 dashboard · ตรวจพบ · FIXED

- **Path / current text:** `docs/runtime/LIFECYCLE.md:3-6` — `This document is the **state-machine authority**`; `:282` — `└──► dashboard (Rust) ──► :8080`.
- **Reason:** `aegis_dashboard/Cargo.toml:14-15` records axum/tokio removal; the current operator view is `python -m tools.aegisctl.web_dashboard.app` on `127.0.0.1:5000` (`DEMO.md:114-118`). The doc claimed normative authority over a topology it no longer describes.
- **Replacement:** authority is assigned to `src/control/state_machine.zig` + `FLOW_MAP.json`; diagram now names the read-only Python dashboard on `127.0.0.1:5000`.
- **Acceptance:** pin asserts no `dashboard (Rust)` or `:8080` and the Python endpoint is present.

## 9. DOC-AUDIT-09 — standing exclusion: application/outreach content in current docs · ตรวจพบ · FIXED

- **Path / current text:** `README.md:736` — `**For recruiters and job applications**`; `:739` — `[Ready-to-use job application kit]`; `docs/portfolio/APPLY_NOW.md:1` — `# Apply now — ready-to-use job application kit`; `:59-78` recruiter cold-email/DM template; `:114-121` application tracker and 10–15-per-week cadence; `INTERVIEW_PREP.md:121` — `[Apply now]`; `ARCHITECTURE_EN.md:3` — `for recruiters, interviewers, and engineers`; `DEMO.md:73` — `--label recruiter-demo`.
- **Reason:** standing exclusion is no job applications or emails. These are current-facing outreach/application artifacts, not technical documentation. No new application or email content was created by this audit or patch.
- **Replacement:** `APPLY_NOW.md` is rewritten in place as `# Technical evidence quick reference` (stable link target preserved) with only links, a technical summary, technical Q&A and a claims guardrail. README heading/link, interview link, architecture audience line and demo label were neutralized. The catalog's ATS-keyword sentence was removed.
- **Acceptance:** pin asserts the outreach/application strings are absent from the rewritten file and current docs, and that the technical markers remain.

---

## Additional current-facing corrections made during verification

- `docs/architecture/RUNTIME_SPINE.md` still had `**Status**: AUTHORITATIVE` and `ONE ENFORCEMENT AUTHORITY`; now scoped HISTORICAL in part and detection-only.
- `docs/ARCHITECTURE_BOUNDARY.md` and `docs/architecture/data-flow.md` carried unscoped WFP-block language; both now carry HISTORICAL banners pointing at `AUTHORITY_MAP.json` / `FLOW_MAP.json`.
- All nine dated root `AEGIS_*2026-09*.md` handoff/plan/status docs now carry a `HISTORICAL (P6-DOC-TRUTH)` banner; previously only two did. Frozen `release/T20-final/**`, `docs/historical/**`, `docs/gates/T20_golden_path_evidence/**` and historical `EVIDENCE_INDEX.json` quotes were deliberately not rewritten.

## Checked and consistent (no finding)

- Gate identity in `docs/gates/T20_100pct_audit.md` and `PRODUCTION_READINESS.md` is already scoped to `466a226` / `a53eda8`; 6/6 PASS (0 open) unchanged.
- P5 detection provenance banners in `DETECTION_CATALOG.md` and `DETECTION_VALIDATION.md` remain; this patch only removed the superseded ATS sentence and added README/interview parity.
- Loopback self-test caveats in `README.md`, `DEMO.md`, `ARCHITECTURE_EN.md` and `OBSERVED_PERFORMANCE.md` remain; only `CONTRACT_MAP.json` had the false fallback claim.
- DEGRADED remains honestly reported; no repainting.

## Flow / contract impact

```
OLD  current docs: Rust PEP = final/sole enforcement authority, WFP block
NEW  current docs: Rust PEP = detection-only policy/evidence authority, no host effect
OLD  RELEASE_TRUST_ANCHOR current candidate = b597e71
NEW  current candidate = 466a226 (same key, no re-key)
OLD  CONTRACT_MAP: loopback TCP fallback
NEW  named pipe only; loopback is self-test only
OLD  APPLY_NOW.md = application/email kit
NEW  APPLY_NOW.md = technical evidence quick reference
```

- **Wire/ABI bytes/rules/authority behavior/host effects:** none changed. **Release identity:** unchanged (`v1.1`, `466a226`, `a53eda8`, 6/6). No new tag, signature, key, E4/E5 or soak claim.
- **Build source:** unchanged (`661fb76`) — every edited path is records-only (docs, root historical docs, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, tests). `shared/abi/pep_abi.md` was not edited; issue #45 tracks the source slice.
- **Evidence level:** E1/E2 static pins only.

## Completion gate

**PASS (E1/E2, records-only).** Requires: new doc pins pass; `TRUTH_VALID @ 661fb76`; 674/674 digests; BAD LINKS none; `SUMMARY_VALID`; CI-equivalent pytest green. Remaining source/design findings are explicitly listed in issue #45 and in the P4/P5 audit artifacts; none are claimed fixed by this records-only slice.
