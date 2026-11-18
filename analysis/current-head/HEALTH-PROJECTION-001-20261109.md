# HEALTH-PROJECTION-001 — preserve degraded state in control API

**Status:** E2 + bounded E5 PASS
**Code commit:** `13f72b72519c2a1b13065c17453d1977be514840`
**Target HEAD:** `86b0b0862bc4a0d2a45dc890b66225995585a4b1`
**Build source:** `318a10a95b7922851562aad27f389c2ab9f4fdac` (unchanged; tools/tests are records-only per `tools/truth.py`)

## Patch contract

- **PATCH-ID:** HEALTH-PROJECTION-001
- **FLOW-ID:** Runtime health control API → CLI/dashboard health state
- **TARGET FILES:** `tools/aegisctl/api/control_api.py`, `tests/runtime/test_health.py`
- **TARGET SYMBOLS:** `get_health_payload`, `TestControlApiHealthPayload`
- **IN SCOPE:** Prevent `runtime_state=RUNNING` from promoting an operationally degraded response to `state=RUNNING`; preserve FAILED as the strongest failure state.
- **OUT OF SCOPE:** Daemon lifecycle, event queue policies, provider readiness, detector/capture behavior, prevention.
- **CONTRACT IMPACT:** `state` is DEGRADED whenever daemon health is DEGRADED or `degraded=true`; the `degraded` boolean and state no longer contradict each other.
- **ABI IMPACT:** None.
- **AUTHORITY IMPACT:** None; Rust PEP remains sole authority, detection-only posture unchanged.
- **STATE IMPACT:** CLI/API now reports the daemon's operational health even when daemon lifecycle remains RUNNING.
- **TEST IMPACT:** Regression test first failed (`RUNNING != DEGRADED`), then passed after fix; the complete `tests.runtime.test_health` suite passed 36/36.
- **EVIDENCE IMPACT:** E2 deterministic regression plus E5 live Windows CLI projection observation.

## Evidence

Before the patch, the live current-source service produced `runtime_state=RUNNING`, daemon health `state=DEGRADED`, and `degraded=true`; the Python API returned `state=RUNNING`. The deterministic mocked daemon response reproduced exactly that mismatch.

The API now prioritizes FAILED, keeps explicit lifecycle states (STOPPED/STOPPING/STARTING), and projects DEGRADED if either daemon health state is DEGRADED or its degraded bit is true. The queue's attributed source-quota sheds remain visible and continue to keep the CLI health DEGRADED.

- Red test before fix: `python -m unittest tests.runtime.test_health.TestControlApiHealthPayload.test_degraded_daemon_health_cannot_be_promoted_by_running_runtime_state` failed with `RUNNING != DEGRADED`.
- Green regression after fix: same command passed.
- Full health suite: `python -m unittest tests.runtime.test_health` — 36 passed.
- Live Windows CLI assertion after fix: health `state=DEGRADED`, `degraded=true`, `capabilities.wfp=true`.
- Prevention gate remained closed; no canary traffic or host effect was attempted.

## Patch completion record

- **FINAL HEAD:** `13f72b72519c2a1b13065c17453d1977be514840`
- **FILES CHANGED:** 2
- **OLD FLOW → NEW FLOW:** compatibility calculator could promote from RUNNING lifecycle despite degraded daemon health → daemon state/degraded contract constrains API health projection
- **INVARIANT:** `degraded=true` cannot be returned with `state=RUNNING`.
- **BUILD RESULT:** No binary build input changed; `python tools/truth.py verify` remains TRUTH_VALID.
- **TEST RESULT:** PASS, 36/36.
- **WINDOWS RESULT:** PASS for the live CLI projection on the installed current-source service.
- **EVIDENCE LEVEL:** E2 + bounded E5.
- **EVIDENCE ARTIFACTS:** this report; local-only `admin-evidence/wfp-readiness-refresh-001-20261109/postinstall-verification-e5.json`.
- **ROLLBACK:** `git revert 13f72b7`.
- **REMAINING RISK:** Source quota shedding and minifilter ring loss remain; the API truthfully reports DEGRADED.
- **OPEN BLOCKERS:** #25 authority reconciliation, #29 event-loss reduction, #30 service lifecycle, RB-021 canary, Phase 6–9 gates.
- **COMPLETION GATE:** PASS for control API health projection; overall backend/runtime acceptance remains OPEN.
