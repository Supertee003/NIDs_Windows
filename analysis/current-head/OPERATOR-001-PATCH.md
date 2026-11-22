# OPERATOR-001 — alert + management: honest closure, no new authority

**PATCH-ID:** OPERATOR-001
**FLOW-ID:** OPERATOR-VIEW, CONTROL-AUTHORITY, SIEM-OBSERVE
**TARGET HEAD:** `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40` (detached worktree)
**BUILD SOURCE BEFORE PATCH:** `f4cde3c503fd8b696183751a608b999768caa769`
**STATUS:** code + E2 COMPLETE. Not E5. No host effect, no egress, no new authority.

---

## Declaration

- **TARGET FILES**
  - `tools/aegisctl/web_dashboard/app.py` — per-threat banner in `renderBanner()`
  - `tools/aegisctl.py` — `policy reload/enable/disable` help text states fail-closed truth
  - `docs/OPERATOR_COMMAND_MAP.md` — stale `.operate` → `.privileged`
  - `docs/runbooks/RB-011-policy-ir-mirror-workflow.md` — stale `NOT_IMPLEMENTED` → read-only verify
  - `tests/tools/test_web_dashboard.py`, `tests/tools/test_operator_honesty.py` — new pins
- **TARGET SYMBOLS:** `renderBanner`, `_threat_posture`, `cmd_policy` argparse setup,
  `COMPONENT_MATRIX` notifier row (unchanged, pinned).
- **IN-SCOPE:** operator-visible truth; a real per-threat banner from existing snapshot data;
  documentation reconciliation.
- **OUT-OF-SCOPE:** revive SMTP/webhook/syslog notifier; new network egress; secrets;
  managed runner; rule mutation endpoint; policy apply commands; signed IR promotion;
  any change to Zig authority, detection verdicts, WFP/PEP, host, wire layout.
- **CONTRACT IMPACT:** none. No control command, no JSON field, no config schema change.
- **ABI IMPACT:** none.
- **AUTHORITY IMPACT:** **none by design.** No new mutation path; `rules_reload` stays
  `.privileged`; every policy mutation verb stays fail-closed (exit 4); the IR mirror
  stays verify-only and `g_policy_ir_verified` stays an observe-only metric.
- **STATE IMPACT:** none (banner is pure view state from the existing snapshot).
- **TEST IMPACT:** 4 new Python tests (banner fields, banner precedence, CLI help,
  docs/notifier honesty); existing gate-E and stale-doc-sweep suites remain green.
- **EVIDENCE IMPACT:** one new E2 entry; no E5 claim.

---

## Item-by-item disposition (the honest part)

| Plan item | Decision | Why |
|---|---|---|
| 1. Re-enable notifier transport (webhook/syslog) | **NOT DONE — keep RETIRED (EVT-152)** | The script is fully coded but unowned: no runner, no secrets, no config read. Reviving it requires egress and secret custody, which violate detection-only and need an owner decision. Existing pins (`test_notifier_retired.py`, `test_notifier_failclosed.py`) prove retirement and fail-closed webhook. No network code was added. |
| 2. SIEM opt-in + per-threat banner | **DONE (banner); SIEM already real** | `AEGIS_SIEM=1` is the only real switch (`daemon.zig:146-179`); `configs/siem_config.json` is a pinned contract, not a runtime read. Added exactly one branch to `renderBanner()` using `snap.threat` (DEFCON 2/1 etc.), which the daemon owns. No new control call, no enforcement claim. |
| 3. Authenticated rule mutation | **ALREADY REAL — no change** | `rules_reload` is `.privileged` with postcondition (`protocol.zig`, `authorization.zig`), gated by impersonated-token role on the pipe; CLI `rules add/update/delete` is a local atomic file write needing explicit `rules.reload`. Fixed one stale doc line that said `.operate`. Quarantined legacy helpers were NOT re-wired. |
| 4. `policy reload/enable/disable` real or remove | **KEPT FAIL-CLOSED; help corrected** | Real apply would create duplicate authority with no postcondition. The verbs must remain registered so `test_gate_e.py` can exercise the gate, so instead `--help` now says UNAVAILABLE (exit 4) and names the real path (`configs/disabled_rules.json` + `rules reload`). `cmd_policy` still returns `available:false` / `UNAVAILABLE_NOT_IMPLEMENTED` on stderr with exit 4. |
| 5. Signed `ts_policy` IR promotion | **NOT DONE — keep verify-only** | Promotion into enforcement would make advisory TS policy an authority and bypass Zig. Kept `g_policy_ir_verified` as an observe-only metric and the IR mirror read-only. Fixed the stale runbook that claimed `policy.verify` was `NOT_IMPLEMENTED` (it is a read-only signed-envelope report since BE-RCPT-091). |

A "gap" that is a deliberate safety boundary is closed by **stating the decision**,
not by implementing the unsafe feature and calling it coverage.

---

## Result

PATCH-ID: OPERATOR-001
FLOW-ID: OPERATOR-VIEW, CONTROL-AUTHORITY, SIEM-OBSERVE
TARGET HEAD: `f0baadf9205a69ea0fc3e27a26eb7968e71cbb40`
FINAL HEAD: unchanged (worktree, uncommitted)
FILES CHANGED: 6 (2 code/help, 2 docs, 2 test files)

OLD FLOW:
```
dashboard banner: control / forensic / no-feed only; no threat state
policy --help: "reload / enable / enable --id" advertised as if actionable
docs: notifier row correct, but .operate and NOT_IMPLEMENTED claims stale
```

NEW FLOW:
```
snapshot.snap.threat (daemon-owned DEFCON) -> renderBanner last branch
  -> "Threat posture SEVERE (DEFCON 2) — N critical, M high ... Detection-only"
  -> SAFE (DEFCON 5) shows nothing; fail-closed branches keep precedence
policy --help -> "UNAVAILABLE (fail-closed, exit 4) — use disabled_rules.json + rules reload"
docs -> .privileged / read-only verify / mirror never touches PolicySet
```

INVARIANT: no operator surface may advertise an apply step, egress path or trust
promotion that the runtime does not perform. Zig remains the only detection and
policy authority; Python/TS stay advisory.

BUILD RESULT: n/a (Python/docs only). Full worktree `zig build` still PASS from Slice 2.

TEST RESULT (2026-11-19):
```
pytest tests/tools/test_operator_honesty.py tests/tools/test_web_dashboard.py
       tests/runtime/test_gate_e.py tests/docs/test_stale_doc_sweep.py
       -> 48 passed, 9 subtests passed
full worktree suite before this patch -> 1394 passed, 35 skipped, 1 xfailed,
       1 xpassed, 23 subtests passed
```

WINDOWS RESULT: not E5; no host access, no egress, no service change.

EVIDENCE LEVEL: E2 (unit + CLI invocation) + E1 (static pins/docs). Not E3/E5.

EVIDENCE ARTIFACTS:
- `analysis/current-head/OPERATOR-001-PATCH.md`
- `tests/tools/test_operator_honesty.py`
- `tests/tools/test_web_dashboard.py`

ROLLBACK: revert the 6 files. No state, config, host or authority change to undo.

REMAINING RISK:
- Push alerting remains unavailable by decision; a future owner who wants it must
  bring secrets management, a managed runner and lab E5 proof.
- `configs/siem_config.json` is a contract document, not a runtime config; operators
  must use `AEGIS_SIEM=1` + `AEGIS_SIEM_*` env vars (documented in RB-015).
- The banner is presentation-only: the daemon DEFCON counter remains the authority.

OPEN BLOCKERS: owner authorisation to commit source (truth rebaseline gated);
fresh soak for the final candidate after Slice 4.

COMPLETION GATE: Slice 3 COMPLETE at E2 with no new authority and no host effect.
Board remains 5/6; no tag/publish.

TRUTH STATE: TRUTH_INVALID in this worktree is expected while source is uncommitted.
