# RB-002: Forensic Query for Incident Reconstruction

## Objective
Query the forensic log to reconstruct a security incident. This runbook covers querying events by event_id, source IP, time range, or severity for incident response and post-incident analysis.

## Prerequisites
- AEGIS NIDS running with forensic logging enabled
- Incident details (event_id, IP, or approximate time)
- Operator access to forensic query API

## Steps

1. **Identify the incident scope**
   - Determine the key parameter for the query:
     - event_id (if known)
     - source IP (if investigating a specific host)
     - time range (if investigating a time window)
     - minimum severity (to filter noise)

2. **Query by event_id (most precise)**
   ```
   query ForensicLog by event_id=<incident_event_id>
   ```
   - Returns the specific event with full details
   - Includes: timestamp, level, event type, rule, src_ip, verdict, action

3. **Query by source IP (host investigation)**
   ```
   query ForensicLog by src_ip=<malicious_ip>
   ```
   - Returns ALL events from that IP
   - Useful for identifying attack patterns and timeline

4. **Query by time range (window investigation)**
   ```
   query ForensicLog by start_ms=<start>, end_ms=<end>
   ```
   - Returns events within the time window
   - Use for "what happened between X and Y" investigations

5. **Query by minimum severity (filter noise)**
   ```
   query ForensicLog by min_level=.critical
   ```
   - Returns only critical+ events
   - Useful for post-incident review of high-severity events

6. **Redact PII for export**
   ```
   redactInto(record, &redacted)
   ```
   - Source IP last octet masked (10.0.0.123 -> 10.0.0.X)
   - Source port dropped
   - Payload content dropped (length preserved)
   - Use redacted records for external sharing

7. **Replay through pipeline (regression test)**
   ```
   replayRecord(record)
   ```
   - Re-runs the event through the pipeline
   - Verifies detection still produces the same verdict
   - Useful for validating rule changes didn't break detection

## Verification
- Query returns expected records (count > 0 for valid queries)
- Each record has: record_id, timestamp, level, event, verdict, action
- Redacted records have masked IPs (end with ".X")
- Replay produces matching verdict (deterministic)

## Rollback
No rollback needed - forensic queries are read-only. The forensic log is append-only and immutable.

## Notes
- Forensic log is append-only (no edit/delete API)
- Hash chain verifies integrity: `forensic_log.verifyHashChain()`
- Empty filter returns ALL records (use carefully)
- Max capacity: 1024 records per in-memory log (production uses file rotation)

## References
- G11: `core/forensic_replay_proof.zig` - Forensic replay + redaction proof
- G14: `core/audit_trail_proof.zig` - Audit trail (operator actions)
- `core/forensic_log.zig` - NDJSON append-only logger
