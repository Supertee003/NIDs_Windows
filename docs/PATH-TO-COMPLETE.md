# Path to complete — remaining work and who can close it

**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (ADR-0008; unchanged by records commits)  
**RECORDS TIP:** read `git rev-parse HEAD` for the live value (written at `43fd6612f26f44e1d065cc6d7e4196dad59a0d4c`)  
**BOARD:** **5/6 PASS — `soak_24h` OPEN — NOT SHIPPABLE**  
**FINALIZER:** `D:\aegis-tmp\owner-soak-aa3b7b0-20261126-225843\result.json` was still absent at `2026-11-27T04:12:04+07:00`

This page is a **plan and an owner-input checklist, not evidence**. It does not close a gate, create a signature, add E7, or change a verdict. It exists so that "make everything complete" has one unambiguous meaning: every item the repository side can do is already done; the remaining items require inputs that only the owner or the external SYSTEM finalizer can supply.

## 1. Already complete on the repository side

| Area | State |
|---|---|
| Machine-map and status reconciliation (#48/#49) | `5c69b6b`, `a77d1e0`, `f9783fd`, `512b3e7`; `TRUTH_VALID`, `SUMMARY_VALID`, `0 FAIL/0 WARN/23 total` |
| Evidence provenance (#52) | `b08ca80`: `build_source`/`historical`/`evidence_namespace` on all seven E6/E7 entries; ten transcode sidecars; logical historical namespace. 48 unresolvable pointers already carry explicit markers; none promoted to PASS |
| Documentation lifecycle / archive declarations | `dfc7822`, `1df890a`, `43fd661`: frozen signed records, root handoffs, case-only doc aliases, post-audit disposition §11 |
| Onboarding | `410aa6f`: `docs/START-HERE.md` is the single developer index |
| Issue hygiene | #47–#54 all have explicit status comments; no skip/xfail/relaxation added |
| Verification at the current tip | `OK - 691 artifacts ... source_commit=aa3b7b0`; full non-host pytest `1513 passed, 1 skipped, 18 deselected, 27 subtests`; `final_audit.py --check` with owner anchor = `NOT SHIPPABLE (1/6 gates open)`, only `soak_24h` OPEN; both CI workflows `success`; pre-commit hygiene checks pass; tree clean |

The full non-host pytest is **E2** only. It excludes `host_live` tests (18 deselected) and `tests/test_e2e.py`; it is not a host, soak, signature or E7 proof.

## 2. The three inputs that are not in the agent's authority

| Owner input | Closes / enables | Why the agent cannot supply it |
|---|---|---|
| **1. Real finalizer verdict** at the path above | `soak_24h` gate | The window runs under SYSTEM task `AegisNidsSoakFinalize_20261126-225843`. The result file does not exist yet; touching the host, service, driver, binaries or finalizer during the window is prohibited. Accept only `verdict=PASS`, `elapsed_hours>=24`, `problems=[]`, `restore.verified=true` and counter deltas consistent with the raw transcript; otherwise record VOID/FAIL honestly. |
| **2. Rebaseline decision + later authorized host window** | #47 P0 items 1–3 and 6, #50, #51, #53 source/CI/test work | These are SOURCE_PATHS and STOP-THE-LINE items. Changing them now would move the build source and invalidate the running soak and all current-source evidence. Each fix needs a PATCH-ID / FLOW-ID / IN-SCOPE / OUT-OF-SCOPE / CONTRACT / ABI / AUTHORITY / STATE / TEST / EVIDENCE transaction per `AGENTS.md`. |
| **3. Owner private key and real E7 / signed-driver evidence** | new Ed25519 signature, E7, Authenticode/catalog signing | The private key is owner-held (`D:\aegis-tmp\keys\...`) and is not in the tree; the existing `94F65BCC…` signature covers `SHA256SUMS` of the historical release identity, not driver bytes. `tools/final_audit.py` has no HLK/E7 gate. A soak PASS does not create E7, a new release identity or driver signing. |

No combination of passing tests, documentation edits or static review substitutes for any of these three inputs.

## 3. Exact sequence once those inputs exist

1. Read the finalizer result and evaluated soak JSON from their actual paths. Validate the four criteria and counter deltas; do not reuse `soak-24h-f4cde3c-final.json` and do not add `loss_budget=3500`.
2. If accepted, copy result and raw traces into tracked `admin-evidence/` and raw artifacts with hashes; do not transcode or edit values silently. If VOID/FAIL, record that verdict and keep the gate OPEN.
3. Re-run `python tools/final_audit.py --check` with the owner anchor. Revert generated `docs/gates/T20_100pct_audit.{json,md}` drift before any interim commit; regenerate deliberately only with the new artifact in place.
4. Re-run `python tools/truth.py verify`, `python scripts/check_summary.py`, `python scripts/doc_checker.py`, `python tools/release_engineering.py --verify`, and the targeted doc-truth/release tests. Record exact outputs.
5. Rebaseline machine maps, `CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md`, `release/release-status.json`, `docs/gates/PRODUCTION_READINESS.md` and the deep audit report with the real verdict and final records HEAD.
6. Only after that, take owner decisions on #47/#50/#51/#52/#53 as separate patch transactions. Product fixes require a new build source and fresh verification; they do not inherit the soak result.
7. Schedule a new authorized host window for any driver-load/cleanup or full-matrix claim. Do not infer it from static review or from the previous narrow proofs.
8. Treat E7, a new signature and signed drivers as **separate work items** backed by owner-held key material and real HLK/catalog evidence. None is created by step 1–7 automatically.
9. Commit/push records-only changes, confirm a clean tree and `origin/main == HEAD`, and watch both CI workflows to completion.

## 4. Invariants that must not be traded to reach "complete"

- Exact strings stay untouched: `| Host-evaluable | 22/23 |`, `**22/23** — R2003 blocked by FN-1`, `host-evaluable coverage (R2003/FN-1)`.
- No guard, test, skip, xfail, waiver, threshold, gate or verdict is relaxed or edited to hide a failure.
- No fabricated `PASS`, `E5`, `E6`, `E7`, signature, soak result, driver load or release identity.
- Published identity remains `v1.1` / `466a226` / `a53eda8` with anchor `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=`; no private key in the tree.
- `CLOSED as documented gap` remains `NOT_RUN` / `NOT_PROVEN` underneath; narrow E5/E6 proofs are not the full 23-rule host matrix.

## 5. What "complete" looks like

- A real finalizer artifact has been consumed and honestly recorded (PASS or VOID/FAIL).
- The board is 6/6 **only if** a valid PASS artifact exists and the rebaselined checks pass; otherwise it stays 5/6 NOT SHIPPABLE.
- Every issue #47–#54 has either an owner-authorized patch transaction with evidence or an explicit accepted-limitation disposition.
- E7, signed-driver and reproducible-build claims exist only with their own real evidence — or remain explicitly `NOT_PROVEN` / `NOT_RUN`.
- `docs/START-HERE.md` and this page are updated to the final records tip; CI is green; the tree is clean.

Until input 1 exists, the honest answer to "is it complete?" is **no** — not because repository work is missing, but because the evidence and authority are external.
