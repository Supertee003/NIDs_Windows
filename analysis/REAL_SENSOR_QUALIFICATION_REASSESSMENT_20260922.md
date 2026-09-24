# Real Sensor Qualification Reassessment — 2026-09-22

## Executive result

The Host run passed the safe, observe-only device and fixture checks. It did **not** yet prove that a configured rule matched in a real sensor path, nor that the daemon emitted a canonical event and forensic record for the generated stimulus.

## L4/WFP evidence

The WFP proof established:

- `AegisWfp` was present and `Running`.
- `\\.\AegisWfpDevice` opened with `GENERIC_READ`.
- Only `GET_STATS` and `READ_EVENTS` were requested.
- No `BLOCK_FLOW` or `UNBLOCK_FLOW` was called.
- 407,264 bytes were read as 9,256 complete 44-byte frames with no trailing bytes.
- The prevention gate remained closed and host effect was `none`.

The result is therefore valid as `L4_WFP_DEVICE_RING_READBACK_PASS`.

It is not yet `L4_RULE_SENSOR_PROOF`, for these reasons:

1. The baseline ring was not drained before the benign probe. The 9,256 frames therefore include pre-existing traffic.
2. The proof did not require or identify the ephemeral localhost listener port. `expected_flow.required` was `false` and `matches` counted every frame.
3. The sampled frames had `rule_id=0`, `severity=0`, `payload_length=0`, and `layer_id=0`. This is consistent with telemetry readback, not a configured rule match.
4. The current driver statistics report only `currentUsedBytes`; event and drop counters are explicitly unimplemented.

The next L4 proof must drain the ring before the probe, capture the dynamically assigned listener port, require a matching localhost TCP frame after the probe, and report pre-probe/post-probe frame counts separately.

## FIM evidence

The FIM proof established:

- A disposable proof root was created.
- A benign marker file was created and remained present.
- A SHA-256 hash was calculated.
- The script requested no WFP block and no PEP operation.
- The prevention gate remained closed and host effect was `none`.

The result is valid as `FIM_FIXTURE_SAFETY_PASS`.

It is not yet `FIM_REAL_SENSOR_PROOF`, because the script itself states that daemon FIM counters, canonical provenance, and forensic record must be confirmed separately. The output contains `event_expected=fim_change` but no observed daemon event, matched rule ID, canonical event ID, or forensic record ID.

## Promotion decision

```text
Rules-22 synthetic qualification       = PASS (22/22)
L4 device/ring readback                 = PASS
L4 real rule match                      = PENDING
FIM fixture safety                      = PASS
FIM daemon event/canonical evidence    = PENDING
prevention_gate                         = CLOSED
host_effect_capable                     = FALSE
```

No rule is promoted to `BLOCK_PROVEN` from this run. No enforcement test should be started yet.
