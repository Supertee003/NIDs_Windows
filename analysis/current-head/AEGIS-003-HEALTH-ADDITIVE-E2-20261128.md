# AEGIS-003 — additive runtime health diagnostics (E2)

**PATCH-ID:** `AEGIS-003-HEALTH-ADDITIVE-01`  
**FLOW-ID:** health fact → state machine → JSON → operator display  
**TARGET HEAD:** `6de0184c968571daf6321da3cc31f47d7d02bc2f`  
**FINAL SOURCE COMMIT:** `c01e8091995e3afb9e93e48ea3bd1d7cb6ae5cce`  
**RECORDS HEAD:** see `git rev-parse HEAD` (records-only commits after the source commit)  
**OWNER DECISION:** option B in `docs/SOURCE-SLICE-DECISIONS.md` — execute on main with full rebaseline.

## 1. Patch declaration

| Field | Value |
|---|---|
| Target files | `src/control/state_machine.zig`; `tests/runtime/test_health.py`; `tests/contracts/test_contract_fixtures.py`; `contracts/fixtures/control/runtime_health_response.json`; `contracts/fixtures/health/degraded_core.json` |
| Target symbols | `RuntimeState.last_transition_ms`; `RuntimeState.transition`; `RuntimeState.recomputeHealth`; `RuntimeState.reconcileLifecycle`; `RuntimeState.healthJson`; `validate_health_response`; fixture validators |
| In scope | additive JSON keys `last_transition_ms`, `reason`, `impact`, `recovery_state`; deterministic tokens from already-observable readiness, bridge, loss and lifecycle facts; updated contract/fixture/schema tests |
| Out of scope | `UNKNOWN`, state vocabulary changes, canonical event wire, IOCTL structs, gate thresholds, verdicts, host effects, service/driver/soak action |
| Contract impact | additive health JSON keys only (`RUNTIME_CONTRACT.md` §4.1); older readers ignore unknown keys |
| ABI impact | none — no canonical wire bytes, control command frames or IOCTL structs changed |
| Authority impact | none — Zig remains the health authority; Python only validates the emitted shape |
| State impact | one in-memory epoch-ms transition timestamp in `RuntimeState`; no persisted state |
| Test impact | Zig unit tests, Python health-schema and contract-fixture tests |
| Evidence impact | E2 serialization/contract proof only; no E3/E4/E5 claim |

## 2. Old flow → new flow

- **Transition:** the state machine changed `system_state` but kept no timestamp → `transition`, `recomputeHealth` and `reconcileLifecycle` now stamp `last_transition_ms` at the point of change. For `reconcileLifecycle` the supplied deterministic `now_ms` is used, so the value is testable without wall-clock dependence.
- **Health payload:** `workers.failure_reason` was worker-scoped and there were no component-level `reason`, `impact` or `recovery_state` keys → `healthJson` now emits controlled diagnostic tokens derived from the same facts that already decide `state`/`degraded`. `reason` is a fixed-priority first-cause token; `impact` is a diagnostic scope token; `recovery_state` projects the existing `RECOVERING` state as `RECOVERING` or `NOT_RECOVERING`.
- **Contracts/fixtures:** the health schema example and two fixtures did not carry the new keys → the contract document, validator and fixtures now pin them together. Unknown tokens such as `UNKNOWN` are explicitly rejected by the validator.

**Invariant:** `state`, `degraded`, DEFCON, drop/loss decisions and the lifecycle transition graph are unchanged. No new state value, host effect, policy decision or gate input was introduced. `UNKNOWN` remains unimplemented by explicit owner-level boundary.

## 3. Real verification

| Check | Result |
|---|---|
| `zig fmt src/control/state_machine.zig` then `zig build test` (fresh cache) | exit 0; **2159 passed, 10 skipped** in the main test binary and **1235 passed** in the out-of-unit binary (overall `3394/3404`, 10 skipped) |
| `python -m pytest -q tests/runtime/test_health.py tests/contracts/test_contract_fixtures.py` | **58 passed** |
| Full non-host pytest `python -m pytest -q tests/ --ignore=tests/test_e2e.py -m "not host_live"` | `1519 passed, 1 skipped, 18 deselected, 27 subtests passed in 181.42s (0:03:01)` |
| `python tools/rebuild_truth.py` | `valid: true`, source commit `c01e809` |
| `python tools/release_engineering.py --refresh-digests` + `--verify` | 691 artifacts kept, 2 digests updated, verify OK at `c01e809` |
| `python tools/truth.py verify` / `python scripts/check_summary.py` | `TRUTH_VALID` and `SUMMARY_VALID` at build source `c01e809` |
| `python tools/final_audit.py --check` with owner key `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=` | `NOT SHIPPABLE (2/6 gates open: release_signature, soak_24h)` |

The Zig tests pin exact token strings, the healthy/degraded/no-bridge cases, the `RECOVERING` projection, and deterministic transition timestamps through two lifecycle samples. The Python tests pin token vocabularies and reject `UNKNOWN`; the fixture tests require the same keys and values in both health fixtures.

No service, daemon, driver, finalizer or soak process was touched. No live host probe was run. E2 serialization/contract proof is not E3, E4, E5, E6 or E7.

## 4. Honest gate consequence (owner option B)

Moving the build source from `473b3fe` to `c01e809` keeps the board at **4/6 PASS, NOT SHIPPABLE**. The immutable release identity remains `v1.1` / `466a226` / `a53eda8`; the signed tree `6c94b47` still verifies with public key `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=` but predates this runtime, so `release_signature` stays OPEN. `soak_24h` stays OPEN: no clean serialized current-source 24 h SYSTEM window exists. The 36.52 h PASS is HISTORICAL at `a53eda8`; `aa3b7b0`, `3e7e591`, `3c78c96` and `473b3fe` host/proof records are HISTORICAL at `c01e809`.

AEGIS-003 is still **PARTIAL**, not DONE: this transaction proves serialization and contract shape at E2 only. Fresh E3/E4/E5 evidence would still be required before a DONE claim. No waiver, gate threshold, verdict rule, new release identity or owner key was created.

## 5. Rollback / remaining risk / open blockers

- **Rollback:** revert source commit `c01e809`, then re-run `tools/rebuild_truth.py` and `tools/release_engineering.py --refresh-digests` to return the build source to `473b3fe`.
- **Remaining risk:** `reason`/`impact` are diagnostic projections, not root-cause analysis; a worker-reported token remains whatever the daemon supplied, bounded by the controlled token vocabulary in the Python validator. Historical health screenshots do not show the new keys and must remain labelled with their own source commits.
- **Open blockers:** owner re-signature; fresh serialized current-source soak; frozen #47/#50 kernel work; E3/E4/E5 proof for a DONE health claim. Full current-source Windows E5/kernel IDS qualification, signed-driver/HLK/catalog/Authenticode evidence and E7 remain NOT_PROVEN.
- **Completion gate:** E2 additive health serialization and contract proof for this transaction only. Not a release, not E5/E6/E7, not shippable.
