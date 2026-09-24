# AEGIS NIDS — Pre-Attack Readiness Gap Scan for 22 Rules

**Scan date:** 2026-09-23  
**Scope:** all 22 configured rules, synthetic detection fixtures, qualification matrix, observe-only matching report, and controlled attack-test readiness gates  
**Mode:** read-only analysis; no network transmission, process creation, file mutation, named-pipe creation, enforcement request, or host mutation

## Executive finding

The 22-rule detection contract is complete at the synthetic matching layer: all **22 of 22 rules matched**, all fixture records are present, and the latest run reports zero synthetic failures. However, the system has **0 of 22 sensor proofs** and **0 of 22 host-effect proofs**. The prevention gate remains closed. Consequently, the project is ready for synthetic/replay and sensor-adapter validation, but it is not yet ready for real attack traffic or adversarial host actions.

A configured action such as `Block` or `Drop` is not evidence that enforcement works. The qualification matrix correctly keeps every rule unpromoted until sensor evidence, policy trace, forensic linkage, receipt validation, host postcondition, cleanup proof, and stale-filter checks are complete.

## Current totals

| Dimension | Result | Interpretation |
|---|---:|---|
| Configured rules | 22/22 | Rule source is complete for this scope |
| Synthetic observe-only matches | 22/22 | Fast and regex matching work against fixture markers |
| Synthetic failures | 0 | No fixture-level matching failure reported |
| Fixture records | 22/22 | Every rule has a fixture record |
| Fixture status | 22 `READY_FOR_SENSOR_ADAPTER` | None is yet sensor-proven |
| Sensor proof | 0/22 | No real or sensor-adapter event path has been proven for these records |
| Host-effect proof | 0/22 | No host block, file, process, pipe, or network effect is claimed |
| Prevention gate | Closed | Correct and required at this stage |

## Qualification blockers

| Blocker | Rules | Count | Missing capability |
|---|---|---:|---|
| `L7_SENSOR_MAPPING` | R0056, R9064, R9059, R0088 | 4 | Application/proxy payload sensor; WFP 5-tuple telemetry cannot prove L7 payload matches |
| `KERNEL_WFP_E2E` | R9002, R9006, R9007 | 3 | Provider-backed Windows sensor, canonical event, policy/forensic chain, and controlled end-to-end evidence |
| `FILE_RULE_PROOF` | R1001–R1005 | 5 | FIM trigger and benign file-event simulation/replay with per-rule proof; no destructive file action is justified |
| `PROCESS_SENSOR_PROOF` | R2001–R2005 | 5 | ETW/process sensor mapping and benign process-event fixture; no credential theft or process hollowing payload is justified |
| `PIPE_RULE_PROOF` | R3001–R3005 | 5 | Named-pipe sensor mapping and replay fixture; no external or destructive pipe activity is justified |

## Action distribution

| Configured action | Count | Current meaning |
|---|---:|---|
| `Alert` | 4 | Detection-only expectation; still needs sensor and forensic evidence |
| `Block` | 8 | Candidate action only; not authorized as a proven host effect |
| `Drop` | 10 | Candidate action only; not evidence of a working enforcement path |

## What is ready now

The project can proceed with a **synthetic/replay readiness run** for all 22 rules. Each fixture must produce a matched rule ID, canonical event, forensic record, and stable identity chain without any host effect. The required identity chain is:

```text
event_id -> trace_id -> audit_id -> policy/request id -> forensic id
```

The project can also proceed with **sensor-adapter tests** by layer, provided the adapter accepts synthetic events and does not create processes, mutate files, transmit network traffic, create named pipes, or call `enforcement.block`.

The three L4 rules are candidates for a later isolated network-sensor test, but only after the controlled readiness gates R1–R6 have evidence from the rebuilt Windows binaries. They must not be treated as ready for blocking merely because WFP compilation passed.

## What is missing before controlled attack traffic

The following evidence is absent or not proven by the current 22-rule artifacts:

1. **R1 process lifecycle:** current artifacts do not establish a fresh, stale-free runtime baseline for the exact binary build used in the upcoming test.
2. **R2 sensor transport:** every adapter must show accepted event transport with `1 sent, 0 failed` or an equivalent recorded result.
3. **R3 canonical queue:** each event must produce canonical queue evidence and increment processing counters.
4. **R4 sensor-backed detection:** the current `matched_count=22` is synthetic matching, not sensor proof.
5. **R5 policy/PEP trace:** candidate Block/Drop rules need a traceable policy decision; no configured action may be interpreted as enforcement success.
6. **R6 forensics:** event, trace, audit, policy/request, and forensic IDs must be linked and replayable.
7. **R7 safety:** isolated lab boundary, rollback plan, stale-filter scan, and operator record must be captured before any host-affecting test.
8. **R8 evidence:** build hash, configuration hash, logs, counters, and gate results must be stored for the exact run.

## Recommended execution order

| Phase | Scope | Allowed activity | Exit criterion |
|---|---|---|---|
| A | All 22 rules | Synthetic fixtures/replay only | 22/22 matched, zero failures, identity and forensic chain complete |
| B | Per-layer adapters | Synthetic sensor events only | R2–R6 evidence for each layer; no host effect |
| C | L4 network sensor | Benign isolated lab traffic only | Provider-backed sensor evidence and explicit non-enforcement result |
| D | Approved adversarial scenarios | Only individually approved scenarios with rollback | Complete receipt/postcondition/cleanup evidence per scenario |

No rule should enter Phase D solely because it has `configured_action=Block` or `Drop`. L7, file, process, and pipe rules should remain in synthetic/replay or sensor-adapter phases until their specific blocker is cleared.

## Stop conditions

Stop the run if any event is accepted but lacks canonical queue evidence, if counters reset or become non-monotonic, if policy/PEP lacks trace linkage, if a WFP or driver state changes without an operator record, if a destination leaves the lab boundary, or if rollback/stale-filter proof is unavailable.

## Decision

**Pre-attack status: PARTIALLY READY.** The system is ready to continue synthetic and sensor-adapter validation for all 22 rules. It is **not ready for real attack traffic or host-affecting adversarial tests** until the missing R1–R8 evidence is collected and the per-layer qualification blockers are cleared.

## Source artifacts

- `configs/Rules.json`
- `analysis/RULE_22_QUALIFICATION_MATRIX.json`
- `analysis/RULE_22_DETECTION_FIXTURE_MANIFEST.json`
- `analysis/RULE_22_OBSERVE_ONLY_MATCHING.json`
- `analysis/rules-22-run-20260923_000110_940/summary.json`
- `docs/runtime/CONTROLLED_ATTACK_TEST_READINESS.md`
