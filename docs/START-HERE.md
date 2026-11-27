# Start here — AEGIS NIDS Windows

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (ADR-0008; records-only commits do not move it)  
**RECORDS TIP:** read `git rev-parse HEAD` for the live value (the 2026-11-27 reconciliation began at `c7603f7`)  
**BOARD:** **5/6 PASS — `soak_24h` OPEN — NOT SHIPPABLE.** No E7 claim.  
**AUTHORITY:** detection-only. Rust PEP is a detection/evidence authority; no component authorizes a host effect.

This page is an onboarding index, not a new proof. It points to the current truth surfaces and to the exact order in which work may resume. It changes no evidence level, gate verdict or authority.

## 1. Read in this order

1. `AGENTS.md` — control loop, STOP-THE-LINE triggers, patch transaction fields, test matrix.
2. `AI_CONTEXT.md` plus `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json` — machine-readable truth. Verify their build-source stamp before relying on them.
3. `analysis/current-head/CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md` — the one-page combined view of what is proven, documented or open at this source.
4. `docs/gates/PRODUCTION_READINESS.md` and `tools/final_audit.py` — the gate board and the rules that evaluate it.
5. `analysis/current-head/REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md` — separates physical proof from `CLOSED as documented gap`.
6. `docs/DOCS_LIFECYCLE.md` and `analysis/historical/HISTORICAL-NAMESPACE.md` — what is frozen, archived or historical.
7. `docs/PATH-TO-COMPLETE.md` — what remains, the three owner inputs required, and the exact closeout sequence. It is a plan, not new proof.
8. `analysis/current-head/SOAK-225843-FINALIZER-FAIL-AA3B7B0-20261127.md` and `SOAK-VOID-LATE-FINALIZER-GAPS-FIRST-AA3B7B0-20261127.md` — the real finalizer verdicts (`FAIL`) and the STOP-THE-LINE runtime swap. Neither closes a gate.
9. `docs/OWNER-ACTIONS.md` — the short card separating what still needs owner input from what the agent can do immediately.

## 2. Where development actually starts

| Issue | Disposition at this records tip |
|---|---|
| #47 P0 | Items 4 (PEP ABI) and 5 (status source-of-truth) reconciled records-only. Items 1–3 (minifilter UAF/close API/persistent block filters) and 6 (release-gate per-file checks) remain frozen pending owner disposition. |
| #48, #49 | Records reconciliation complete and pushed; no source moved. |
| #50, #51 | Kernel/WFP and network source work frozen. The real finalizer verdict was `FAIL` and the window was VOID for a runtime swap; no product patch without a separate owner rebaseline decision. |
| #52 | Evidence provenance sidecars, E6/E7 historical labels and logical namespace done. Gate-depth and policy-boundary items are owner decisions, not silent changes. |
| #53 | Testing-maturity items are source/CI/test changes; remain frozen. `NOT_RUN` stays `NOT_RUN`. |
| #54 | Real SYSTEM finalizer result consumed: `verdict=FAIL`, window VOID (#55). Gate stays OPEN; rebaseline only after an owner-authorized clean window. |
| #55 | STOP-THE-LINE: a stale finalizer swapped the runtime of the live `225843` window; verbatim FAIL artifacts are tracked. Owner must serialize finalizers and re-arm one clean window. |

## 3. Truth commands (records-only, no host effect)

- `python tools/truth.py verify` → `TRUTH_VALID @ aa3b7b0`.
- `python scripts/check_summary.py` → `SUMMARY_VALID` (the 48 unresolvable pointers are explicitly marked, not PASS evidence).
- `python scripts/doc_checker.py` → `0 FAIL, 0 WARN, 23 total`.
- `python tools/release_engineering.py --verify` → `OK - 691 artifacts ... source_commit=aa3b7b0`.
- `python -m pytest -q tests/ --ignore=tests/test_e2e.py -m "not host_live"` → last full run `1513 passed, 1 skipped, 18 deselected, 27 subtests`.
- `python tools/final_audit.py --check` with the owner anchor → `NOT SHIPPABLE (1/6 gates open)`; T20 drift is reverted after every check.

## 4. Hard rules until a valid current-source soak PASS exists

- Do not touch the host, binaries, service, drivers, soak window or finalizer.
- Do not start product source fixes without an explicit owner disposition; STOP-THE-LINE is still in force for #47.
- Do not relax, skip, xfail or edit a guard, gate, verdict or test to hide a failure.
- Accept a soak only with `verdict=PASS`, `elapsed_hours>=24`, `problems=[]`, `restore.verified=true` and counter deltas consistent with the raw transcript. A VOID/FAIL is recorded honestly.
- `docs/gates/T20_100pct_audit.{json,md}` stay at their historical `8f01825` stamp. The real artifact is in place but is `FAIL`; `final_audit.py --check` rewrites those files on every run, so that drift is reverted before each commit.
- A soak PASS alone does not create E7, a new release identity or production qualification.

## 5. Do not infer

- Narrow E5/E6 proofs at `aa3b7b0` are not the full 23-rule host matrix, a full Windows E5 or kernel IDS qualification.
- The Ed25519 record signature is not Authenticode and is not a driver-load claim.
- Published `v1.1` / `466a226` / `a53eda8` evidence is HISTORICAL relative to this build source.
- A documented gap with `CLOSED as documented gap` is still `NOT_RUN` / `NOT_PROVEN` underneath.
