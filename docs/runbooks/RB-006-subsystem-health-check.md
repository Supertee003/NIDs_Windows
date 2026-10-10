# RB-006: Subsystem Health Check

## Objective

Verify the whole system is alive and honest in under a minute: service,
daemon, nose, brain, workers, queue, DEFCON. Everything here is
read-only and safe to run anytime, on any state.

## Prerequisites

- Shell in `D:\NIDs_Windows` (repo root; commands below assume it).
- No elevation needed (all reads).

## Steps

1. **Liveness (processes + listeners)**
   ```bat
   python scripts\aegis_open.py status
   ```
   - 4 rows: service / daemon / nose / brain. OK = alive.
   - Exit code is information, not just pass/fail: **0** all green,
     **1** something failed, **2** something is unknown/skipped
     (unknown is an answer, not a failure -- see EVT-147).

2. **Readiness (workers + gate)**
   ```bat
   python tools\aegisctl.py readiness
   python tools\aegisctl.py components
   ```
   - `readiness` lists `degraded_components` (empty = ready).
   - `components` shows the five concepts (Core/Brain/Nose/Mouth/Bridge)
     with best-available status; Mouth `stopped` is normal (optional
     display), anything else `stopped` is not.

3. **Metrics snapshot (queue + flow)**
   ```bat
   python tools\aegisctl.py metrics
   python tools\aegisctl.py queue
   ```
   - Watch `depth` vs `queue_size`, `dropped_total`, `shed_overload`.
   - Nose frames must advance between two reads minutes apart
     (`frames_read` is per-daemon-lifetime: a reset means the daemon
     restarted, not that data was lost).

4. **DEFCON (daemon is the authority)**
   - Read `defcon_level`/`defcon_label` from step 1-2 output
     (1 MAXIMUM .. 5 SAFE). The file-tail ladder in dashboards is a
     labeled fallback only -- never the authority.

5. **Degraded drill-down (only if something is not OK)**
   ```bat
   python tools\aegisctl.py diagnose
   python tools\aegisctl.py bridge
   python tools\aegisctl.py forensic verify
   ```
   - `diagnose` for the structured picture, `bridge` for the
     brain-channel listener honesty, `forensic verify` for ring
     integrity (~5s).

6. **Corrective action (only if needed)**
   - Anything down: `python scripts\aegis_open.py keep` (converges;
     the AegisKeeper task already does this every 5 minutes).
   - DEFCON 1 with cause found: see RB-004 (restore from snapshot).
   - Config suspect: see RB-005. Slow: see RB-007 (performance tuning).

7. **Record the check**
   - Note date, HEAD (`git rev-parse --short HEAD`), and the four
     status rows in your change/incident record. No tree writes.

## Verification

- `status` exit 0 (or 2 with an understood unknown, never 1 unexplained).
- `readiness`: `degraded_components` empty, `over` field sane.
- `forensic verify`: `verified: true` when run.
- DEFCON matches the operator's expectation for current activity
  (quiet host is normally 5 SAFE; live detection raises it).

## Rollback

None -- health checks are read-only.

## Notes

- Exit 2 (`unknown`) during load spikes is normal observer effect: the
  single control pipe contends (full-ring verify holds it for seconds).
  Re-run after the load passes instead of treating it as failure.
- Nose `frames_read=0` with the process up means no flow, not health;
  process down is the failure signal.

## References

- `python tools\aegisctl.py health` (single-shot daemon health)
- EVT-147 (unknown is a first-class answer), EVT-148 (observer effect),
  EVT-150 (keeper), EVT-157 (brain posture)
