# READINESS-CAUSE-002 — name data-integrity loss, fix the cross-surface test helper

**PATCH-ID:** `READINESS-CAUSE-002`
**FLOW-ID:** operator control / readiness gate (`CLI-STATE-001`, `READINESS-CAUSE-001`)
**TARGET HEAD:** `0952fe6`
**Build source:** `a53eda8` (unchanged — `tools/` and `tests/` are outside `SOURCE_PATHS`)

## Why this patch exists

The two live-daemon E4 tests were classified in `SIGNED-RC-A53EDA8-20261120.md` as
"host state only, not fixable without an elevated install." Re-reading the actual
payload and test bodies showed that classification was incomplete: both failures
had a genuine, records-only cause that could be fixed without touching the host.

Live health payload (installed daemon, read-only probe 2026-11-20):

```
state = DEGRADED
degraded_components = []                      # no subsystem marked DEGRADED
data_integrity.queue_dropped_total = 5177
data_integrity.loss_budget          = 3500    # 5177 > 3500 -> the real cause
workers                            = all ready, failure_reasons = []
state_machine_disagrees            = false
```

`build_readiness` only looked at `subsystems` for a named cause. The queue-loss
cause was present in the payload but ignored, so readiness answered with the
anonymous `degraded_without_named_component` marker. That violates the spirit of
`READINESS-CAUSE-001` ("every refusal must name a cause an operator can act on").

Test 1 (`test_every_surface_agrees_about_health`) failed in the generic `_json`
helper, which asserts exit code 0. `readiness` is a gate: exit 1 on a not-ready
verdict is legitimate, so the helper aborted before the test could compare the
three degraded flags (which do in fact agree — all `True`).

## Patch declaration

| Field | Value |
|---|---|
| TARGET FILES | `tools/aegisctl.py`, `tests/integration/test_e4_live_pipeline.py`, `tests/tools/test_readiness_cause.py` |
| TARGET SYMBOLS | `build_readiness`, `test_every_surface_agrees_about_health`, `test_queue_loss_over_budget_is_named_not_anonymous` |
| IN-SCOPE | readiness cause naming from `data_integrity`; test helper parses gate JSON regardless of exit verdict; E2 unit proof |
| OUT-OF-SCOPE | daemon Zig source, wire/codecs, host install, services, soak, signed candidate tree |
| CONTRACT IMPACT | `failure_reasons` gains a named `data_integrity` component when queue loss exceeds budget; no wire change |
| ABI IMPACT | none |
| AUTHORITY IMPACT | none — readiness remains advisory control; no detection or enforcement change |
| STATE IMPACT | none — pure read of published counters |
| TEST IMPACT | new E2 unit test; E4 helper corrected; full suite below |
| EVIDENCE IMPACT | this record + full-suite result; no E5/E6 claim |
| OLD FLOW | degraded daemon -> anonymous `degraded_without_named_component` -> E4 test 2 fails; E4 test 1 aborts in helper |
| NEW FLOW | degraded daemon -> named `data_integrity queue_dropped_total>loss_budget` -> both E4 tests assert their real invariant |
| INVARIANT | a not-ready verdict still returns `ready: false` and exit 1; only the *reason* becomes specific |

## Verification (real, this head)

- `tests/tools/test_readiness_cause.py` + `tests/tools/test_readiness_state_machine.py`
  + `tests/integration/test_e4_live_pipeline.py`: **30 passed**.
- Full suite: **1455 passed, 14 skipped, 1 xfailed, 1 xpassed, 26 subtests passed,
  0 failed** in 344.20 s (`FULL_EXIT=0`).
- `python tools\\truth.py verify` -> `TRUTH_VALID` at build source `a53eda8`.
- `python tools\\sign_release.py --verify --dir release\\T20-final\\466a226` -> PASS,
  digest `A053C048C8B373CF...` unchanged.
- `final_audit --release-check`: component audit COMPLETE, `release_signature` PASS;
  `clean_host_e5` and `soak_24h` remain OPEN (owner/time gates).
- The signed candidate tree is intentionally left as the point-in-time snapshot at
  commit `466a226` (ADR-0008): a records-only change after that snapshot does not
  invalidate its signature, and no test or gate compares candidate files to the
  current worktree. No re-sign was performed.

## Why the release is still NOT SHIPPABLE

This patch closes the E4 test failures honestly, but it does **not** install the new
candidate. The release gates `clean_host_e5` and `soak_24h` still require the
elevated RB-024 window described in `SOAK-WINDOW-466A226-20261120.md`. That window
remains the final step and is untouched here.
