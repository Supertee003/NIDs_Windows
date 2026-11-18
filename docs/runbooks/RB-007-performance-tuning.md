# RB-007: Performance Tuning (Queue Depth + Batching)

## Objective

Diagnose a slow system with live numbers, then change only knobs that
exist. Several knobs in the old revision (worker count, queue capacity
at runtime) have no live command on this host -- this runbook says
which, instead of printing Zig structs.

## Prerequisites

- System running. Reads need no elevation.

## Steps

1. **Capture the baseline (live)**
   ```bat
   python tools\aegisctl.py metrics
   python tools\aegisctl.py queue
   ```
   - Record: queue `depth`/`queue_size`, `dropped_total`,
     `shed_overload`, per-stage p50/p95/max, nose frames rate.

2. **Diagnose from numbers, not guesses**
   - `dropped_total`/`shed_overload` climbing: pipe is saturated --
     stop heavy scans first (full pytest, forensics verify loops,
     extra dashboards). Re-measure quiet before touching config.
   - Per-stage p95 dominated by one stage: that stage is the
     bottleneck; note it for engineering (no live per-stage knob).
   - Queue depth pinned near capacity with drops: backpressure is
     working as designed (better slow than OOM).

3. **Knobs that exist**
   - `configs/runtime.json`: validated by
     `python tools/config_validator.py --config configs/runtime.json`.
     Change ONLY documented keys; re-validate; restart the service
     (admin) to apply. There is no live thread-pool/queue-resize
     command -- any doc claiming one is stale.
   - Ruleset weight: fewer/heavier rules via RB-005 + `rules reload`.

4. **Apply + compare**
   - One change at a time; re-run step 1; compare drops/latency.
   - Expect DEFCON to follow load down, not instantly.

5. **Record**: before/after metrics output + config diff + HEAD.

## Verification

- Drops stop climbing; p95 back under the stage budget; DEFCON sane.
- `forensic verify` still true (perf work must never break the ring).

## Rollback

- Revert the config edit, re-validate, restart, re-measure.

## Notes

- Observer effect (EVT-148): measuring IS load. One heavy scan at a
  time; never tune against numbers taken during a suite.
- Backpressure dropping beats OOM crashing -- drops are a signal,
  not a bug, until they climb without load explanation.

## References

- RB-006 (health baseline), RB-005 (config mechanics), EVT-148
