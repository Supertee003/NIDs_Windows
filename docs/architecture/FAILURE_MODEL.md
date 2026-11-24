# Failure Model

**Status**: HISTORICAL in part — fail-soft model current; backpressure table superseded by `src/pipeline/event_queue.zig` (2026-11-24, P1 carry-forward)
**Source**: `docs/architecture/ARCHITECTURE_CANONICAL.md` Section 8

---

## Fail-Soft Model

When a subsystem is unavailable, the system continues with reduced capability.

| Subsystem Down | Impact | System Continues? | Fallback |
|----------------|--------|-------------------|----------|
| Brain | Verdict defaults to "suspicious" (no advisory) | YES | BrainAdvice{kind=insufficient_data} |
| PEP | No enforcement (forensic still records) | YES | EnforcementResult{status=deferred} |
| Detection | No evidence (verdict stays "unknown") | YES | Empty evidence list |
| RAG | No context enrichment (detection + policy work) | YES | ThreatContext empty |
| Threat Intel | No IOC matches (reputation unknown) | YES | ThreatIntelMatch null |
| Correlation | No alerts (entities not tracked) | YES | CorrelationAlert empty |
| Forensic | No recording (CRITICAL - data loss) | NO | Stop-the-line |
| Audit | No operator trail (compliance impact) | NO | Stop-the-line |
| Event Fabric | No event processing (system halt) | NO | Stop-the-line |
| Lifecycle | No init/shutdown (system down) | NO | Stop-the-line |

---

## Stop-the-Line Conditions

These errors require immediate halt:

- Memory corruption
- ABI mismatch
- Event loss (fabric failure)
- Race/deadlock
- Policy bypass
- Unauthorized enforcement
- Forensic inconsistency (hash chain broken)

---

## Error Classes

| Class | Description | Handling |
|-------|-------------|----------|
| BUILD | Build system failure | Fix build config, retry |
| COMPILE | Compilation error | Fix code, retry |
| RUNTIME | Runtime crash | Restart subsystem, log |
| CONCURRENCY | Race/deadlock | Stop-the-line, investigate |
| ABI | Cross-language mismatch | Stop-the-line, fix contract |
| SECURITY | Policy bypass/unauthorized enforcement | Stop-the-line, security review |
| SEMANTIC | Logic error | Fix logic, add test |

---

## Error Handling Procedure

```
ERROR
  |
CLASSIFY
  |
LOCALIZE (find root cause)
  |
MINIMAL FIX (smallest change that fixes root cause)
  |
TARGETED TEST (test the specific fix)
  |
REGRESSION (run full test suite)
  |
CONTINUE
```

---

## Fail-Soft Implementation

### Brain Down (G8 Exit Gate)

```
When Brain unavailable:
  -> brain_integration.advise() returns
     BrainAdvice{
       kind = .insufficient_data,
       threat_score = 0,
       recommended_verdict = (event.event_type == .block) ? .malicious : .unknown,
       confidence = 0,
       explanation = "brain unavailable"
     }
  -> Policy uses insufficient_data advice (reduced context)
  -> System continues (capture + detect + correlate + policy + forensic work)
```

### PEP Down (G10 Exit Gate)

```
When PEP unavailable:
  -> rust_pep_integration.execute() returns
     EnforcementResult{
       status = .no_op,
       reason = .none,
       requested_action = decision.action,
       actual_action = .allow,
       message = "PEP not initialized"
     }
  -> No enforcement occurs
  -> Forensic records the no-op result
  -> System continues (next events still process)
```

### RAG Down (G7 Exit Gate)

```
When RAG unavailable:
  -> rag_engine.query() returns empty context
  -> Detection + Policy still work (no context enrichment)
  -> System continues
```

### Detection Down

```
When Detection rules not loaded:
  -> detection_engine.analyze() returns empty evidence
  -> Verdict stays "unknown"
  -> Policy makes decision with unknown verdict
  -> System continues
```

---

## Recovery Procedure

### Subsystem Recovery

When a subsystem comes back online:

1. Subsystem initializes (via lifecycle)
2. Health monitoring detects status change (degraded -> ready)
3. DEFCON level recomputed (may de-escalate)
4. Audit trail records the recovery
5. System resumes full capability

### System Recovery (from snapshot)

See `docs/runbooks/RB-004-restore-from-snapshot.md`:

1. Verify snapshot integrity (content_hash)
2. Restore SystemState (8 fields)
3. Verify DEFCON level restored
4. Resume event processing
5. Audit trail records the restore

---

## RPO/RTO Bounds

| Metric | Default | Description |
|--------|---------|-------------|
| RPO | 5 minutes | Max data loss (snapshot interval) |
| RTO | 30 seconds | Max recovery time (restore + verify) |

**RPO check**: `time_since_last_snapshot <= rpo_ms`
**RTO check**: `last_restore_duration <= rto_ms`

**No snapshot**: RPO always violated (no recovery point exists).

---

## Deferred Enforcement

When PEP cannot execute immediately (e.g., quarantine not implemented):

```
EnforcementResult{
  status = .deferred,
  reason = .unsupported_action,
  requested_action = .quarantine,
  actual_action = .allow,
  message = "quarantine deferred (not yet supported)"
}
```

**Deferred queue** (G10):
- Max 64 entries
- Max 3 retries per entry
- Drops after max retry count
- Full queue rejects new enqueues

---

## Backpressure Model (current source: `src/pipeline/event_queue.zig:220-299`)

Admission is binary; there are no fill-percent tiers and no priority-drop by
occupancy. The former NORMAL/ELEVATED/HIGH/CRITICAL table above is HISTORICAL and
must not be used as current truth:

- Queue full (`depth >= PIPELINE_QUEUE_SIZE`, 16384): refuse and count
  `g_queue_drops` (plus per-source/per-kind counters).
- Host telemetry beyond the working tail (`WORKING_HOST_TAIL`, 14336): refuse and
  count `g_reserved_tail_shed`.
- One host source beyond `SOURCE_OCCUPANCY_CAP` (7168): refuse and count
  `g_source_quota_shed`.
- `RESERVED_NETWORK_SLOTS` (1024) and `CRITICAL_SLOTS` (1024) are reservations,
  not occupancy levels; protected System32/SysWOW64 FIM writes use the full host
  tail.
- Oversize payloads truncate to a `MAX_PAYLOAD_BYTES` (1500) prefix; the wire
  claim is kept verbatim and no priority-drop branch exists.

**Rule**: Queue count never exceeds capacity (bounded, no OOM); producers are
refused/drop-counted, never blocked.

---

## DEFCON Rollup

| DEFCON | Condition | Action |
|--------|-----------|--------|
| 1 (Critical) | Any subsystem DOWN | Fail-closed mode |
| 2 (Severe) | 2+ subsystems degraded | Investigate immediately |
| 3 (Elevated) | 1 subsystem degraded | Monitor closely |
| 4 (Guarded) | All ready, queue > 80% | Check for event spikes |
| 5 (Normal) | All healthy, low queue | No action needed |
