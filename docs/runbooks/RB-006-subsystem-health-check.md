# RB-006: Subsystem Health Check

## Objective
Perform a comprehensive health check of all AEGIS NIDS subsystems. This runbook covers verifying system readiness, detecting degraded components, and computing the current DEFCON level.

## Prerequisites
- AEGIS NIDS running (at least partially)
- Access to health monitoring API
- No active incidents (run during maintenance window if possible)

## Steps

1. **Check liveness (process heartbeat)**
   ```
   liveness = LivenessState.init(pid, now_ms)
   liveness.isAlive(now_ms)  # true if within 5s threshold
   ```
   - Verify the main process is sending heartbeats
   - Threshold: 5 seconds (LIVENESS_STALE_THRESHOLD_MS)
   - If stale: process may be deadlocked or hung

2. **Check subsystem readiness (5 subsystems)**
   ```
   statuses = [
       .nose,       # Sensor ingestion
       .flow,       # Flow tracking
       .detection,  # Rule matching
       .policy,     # Decision making
       .pep,        # Enforcement
   ]
   report = ReadinessReport.fromStatuses(statuses)
   ```
   - Each subsystem reports: ready, starting, degraded, or down
   - System ready only when ALL 5 are ready
   - Any `down` status fails the readiness check

3. **Capture metrics snapshot**
   ```
   metrics = MetricsSnapshot{
       .total_events = ...,
       .total_blocks = ...,
       .total_alerts = ...,
       .queue_depth = ...,
       .max_queue_depth = ...,
       .latency_samples_us = ...,
       .latency_sample_count = ...,
   }
   ```
   - EPS rate: `metrics.epsRate(window_start_ms)`
   - p50/p95/p99 latency: `metrics.p50LatencyUs()`, etc.
   - Block rate: `metrics.blockRate()`

4. **Compute DEFCON level**
   ```
   defcon = computeDefcon(readiness, metrics)
   ```
   - DEFCON 1 (critical): any subsystem DOWN -> fail-closed mode
   - DEFCON 2 (severe): 2+ subsystems degraded
   - DEFCON 3 (elevated): 1 subsystem degraded
   - DEFCON 4 (guarded): all ready but queue > 80% full
   - DEFCON 5 (normal): all healthy, low queue

5. **Identify degraded subsystems**
   - For each degraded subsystem, investigate:
     - Check recent audit records for errors
     - Check forensic log for subsystem-specific events
     - Check subsystem logs (if available)

6. **Take corrective action based on DEFCON**
   - DEFCON 1: System in fail-closed. Investigate immediately. Consider restore from snapshot (RB-004).
   - DEFCON 2: Multiple failures. Check for systemic issues (config, network, resources).
   - DEFCON 3: Single degraded. Monitor closely. May self-recover.
   - DEFCON 4: Queue pressure. Check for event spikes or slow processing.
   - DEFCON 5: Normal operation. No action needed.

7. **Record health check in audit trail**
   - Audit trail records: action=health_check, outcome=success/failed
   - Include DEFCON level in the detail field

## Verification
- Liveness: `isAlive(now_ms) == true`
- Readiness: `system_ready == true` (all 5 subsystems ready)
- Metrics: EPS, p99 latency, block rate within expected ranges
- DEFCON: level 5 (normal) for healthy system

## Rollback
No rollback needed - health checks are read-only. If issues are found, follow the appropriate runbook:
- Subsystem down: RB-004 (restore from snapshot)
- Config issues: RB-005 (config rollback)
- Performance issues: RB-007 (performance tuning)

## Notes
- Liveness threshold: 5 seconds (5 missed heartbeats)
- 5 subsystems: Nose, Flow, Detection, Policy, PEP
- 4 subsystem statuses: ready, starting, degraded, down
- 5 DEFCON levels: 1 (critical) to 5 (normal)
- DEFCON rollup: failed_count + degraded_count + queue_depth

## References
- G13: `core/health_monitoring_proof.zig` - Health monitoring proof
- G18: `core/performance_tuning_proof.zig` - Performance metrics
- G14: `core/audit_trail_proof.zig` - Audit trail (records health checks)
