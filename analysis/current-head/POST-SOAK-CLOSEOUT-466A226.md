# POST-SOAK-CLOSEOUT-466A226 — the exact path from a real PASS to a finished release

**Status: PLAN ONLY. Nothing here is a PASS and nothing here has been executed.**
This document exists so that no record work is left after the final soak: once the
owner's `-Mode final` returns a genuine PASS, the remaining steps are mechanical.

## State at the time this plan was written (2026-11-21)

| Surface | State |
|---|---|
| Release gates | **5/6 PASS**, only `soak_24h` OPEN → `NOT SHIPPABLE` |
| `truth_artifacts` | PASS — `TRUTH_VALID`, build source `a53eda8` |
| `component_audit` | PASS — 66/66 modules, 0 prod failures, part_ii 5/5 |
| `release_signature` | PASS — `466a226` signs `A053C048C8B373CF...` with the pinned key |
| `clean_host_e5` | PASS — preflight `2026-11-20T05:04:22`, 16 checks, hash binding |
| `evidence_debt` | PASS — unnamed product files 0 <= baseline 0 |
| Known gaps | 287 total, **1 OPEN**: `GAP-QLOSS-ISOLATION-002` — `next_step` says *"Only the 24 h soak remains"* |
| Full pytest | 1456 passed / 14 skipped / 1 xfailed / 1 xpassed / 26 subtests |
| Manifest | 674/674 artifacts match digest, source `a53eda8` |
| Waivers | 0 active — no gate is waived |

No source change, rebuild, re-sign, installer change, or new candidate is needed.
The signed candidate `466a226` (runtime `a53eda8`) is the release.

### Non-blocking known condition (do not discover it after PASS)

`python scripts\check_summary.py` still exits 1 because **48 historical
EVIDENCE_INDEX entries point at `admin-evidence/*` paths that are local-only
after the 2026-11-06 history rewrite**. All 48 belong to old head commits; none
belongs to `a53eda8` or to this release. `final_audit.py` does **not** use this
check — its `evidence_debt` gate uses `tools/evidence_debt.py` — so this does not
block SHIPPABLE. It is listed here for honesty, not as work to do in the release
window. Adding honest `artifact_status: historical` markers to those 48 rows is
a separate records-only patch, never a release-gate change.

## Owner steps (elevated; agent cannot run these)

Use the existing helper, which already requires elevation:
`C:\Users\User\.local\share\opencode\worktree\a6f58a\rule-coverage-20261119\analysis\current-head\soak-466a226.ps1`

1. **Quiet the host first.** No gaming, browser sessions, OneDrive sync,
   installs, service restarts or adversarial load for the whole 24 h. Pause
   TeamViewer / Edge / Copilot updaters so no pending reboot can void the window.
2. `...\reset-soak-baseline-466a226.ps1` → must print `BASELINE CLEAN`
   (image hashes OK, AC/DC standby/hibernate 0, four services in clean order).
3. `...\soak-466a226.ps1 -Mode start` → `IN_PROGRESS`, `0.0/24.0`,
   `problems=[]`, all loss counters 0, record the new
   `process_generation_ms`.
4. Stay quiet for **24 real hours**. Do not shorten it to 12 h:
   `final_audit.py:335` hard-codes `SOAK_HOURS = 24.0`.
5. At/after `start + 24 h`: `...\soak-466a226.ps1 -Mode final` → must print
   `== 24 h SOAK PASS ==`.

If any counter grows past 3500 / 20000, the daemon goes `DEGRADED`, or the
generation changes, the window is void — see `SOAK-VOID-466A226-20261121.md`.
Do not finalize a FAIL window.

## Agent steps after a genuine PASS (records only; no host writes)

1. Read `admin-evidence\e5-clean-host-20261120-final\soak-24h-delta-final.json`
   and assert: `verdict=PASS`, `elapsed_hours >= 24`, `required_hours=24`,
   `problems=[]`, `scm_restarts=[]`, four services `RUNNING`,
   `process_generation_ms` equals the start artifact, all loss/shed deltas
   within 3500/20000.
2. `$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY='txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='`
   then `python tools\final_audit.py --release-check` → must print
   `SHIPPABLE (6/6 gates closed)`; it regenerates
   `docs/gates/T20_100pct_audit.{json,md}`.
3. In `EVIDENCE_INDEX.json`:
   - add the final soak PASS entry (E5, `head_sha=a53eda8`, artifact pointer to
     the final JSON, `result=PASS`);
   - close `GAP-QLOSS-ISOLATION-002`: `status=CLOSED`, `closed_at=<actual date>`,
     `closed_by=<soak artifact>`, `closure_evidence` citing the genuine 24 h
     PASS plus the already-recorded ETW/FIM storm measurements, and mark the
     three `required_evidence` rows DONE only where the E5 records actually
     support them. If any row is not supported, leave the gap OPEN and report it
     — do **not** close a gap to make a board pretty.
   - set `evidence_level_summary` via `python scripts\check_summary.py --write`
     (then re-check the 48 historical pointers are still the only INVALID rows).
4. Re-verify, in this order:
   `python tools\truth.py verify`,
   `python tools\release_engineering.py --verify`,
   `python tools\sign_release.py --verify --dir release\T20-final\466a226`,
   full `python -m pytest`, and `final_audit.py --release-check` again.
5. Commit the records patch (ADR-0008: build source stays `a53eda8`; the board
   records the parent HEAD, as on `3caad73`). Re-run `truth.py verify` after the
   commit.
6. **Only then**, with your explicit go-ahead, tag `v1.1` (annotated, at the
   final records commit; `466a226` remains an ancestor) and push the branch and
   tag to `origin` (`https://github.com/Supertee003/NIDs_Windows.git`). Publish
   `dist\aegis_setup_6.0.0_trial.exe` (`D2267E72...`) and the signed bundle from
   `release\T20-final\466a226` — never the retired `360B9C06...` installer.

## Hard limits (unchanged)

- No gate, budget, `SOAK_HOURS`, checker or artifact is edited to produce PASS.
- No tagged/pushed/published artifact before a real `== 24 h SOAK PASS ==`.
- No fake E5, no re-key, no Signed-IR promotion, no EV/HLK attestation claim.
- Detection-only: no WFP mutation, no host effect, no enforcement claim.
