# RB-003: Audit Trail Tamper Investigation

## Objective
Investigate suspected tampering of the audit trail. This runbook covers detecting and responding to modifications of historical audit records using the hash chain verification.

## Prerequisites
- AEGIS NIDS running with audit trail enabled
- Suspicion of tampering (e.g., unexpected behavior, missing records)
- Operator access to audit trail API

## Steps

1. **Run hash chain verification**
   ```
   audit_trail.verifyChain()
   ```
   - Returns `true` if chain is intact
   - Returns `false` if any record was tampered with

2. **If verification FAILS, identify the tampered record**
   - Walk the chain manually to find the break point:
     ```
     for each record in audit_trail:
         if record.prev_hash != expected_prev_hash:
             # This record's prev_hash link is broken
         if record.record_hash != computeRecordHash(record):
             # This record's content was modified
     ```

3. **Classify the tampering type**
   - **record_hash tampering**: The stored hash doesn't match recomputed hash
     - Indicates: record content was modified after creation
   - **prev_hash tampering**: The prev_hash link doesn't match previous record
     - Indicates: record was inserted, deleted, or reordered
   - **field tampering**: Recomputed hash differs (e.g., timestamp changed)
     - Indicates: a field was modified, breaking the hash

4. **Preserve evidence**
   - Do NOT modify the tampered audit trail
   - Export a copy of the current state for forensic analysis
   - Record the tampering in a SEPARATE audit trail (if available)

5. **Determine scope of tampering**
   - Check if multiple records are affected
   - Identify the earliest tampered record (chain breaks cascade forward)
   - Check if the tampering affects operator actions or system events

6. **Report and escalate**
   - Document: which records were tampered, what fields were changed
   - Escalate to security team (potential insider threat or compromise)
   - Consider restoring from backup (see RB-004: Restore from snapshot)

## Verification
- `verifyChain()` returns `true` for intact chains
- `verifyChain()` returns `false` for tampered chains
- Three tamper types are detectable: record_hash, prev_hash, field modification
- Genesis hash (0xA171BAC5) seeds the first record's prev_hash

## Rollback
- **DO NOT** attempt to "fix" the tampered records manually
- The hash chain is append-only; modifications break the chain by design
- To restore integrity: restore from a known-good snapshot (see RB-004)

## Notes
- Audit trail is append-only (no edit/delete API by design)
- Hash chain uses FNV-1a over: record_id, timestamp, action, outcome, operator_id, target, detail, prev_hash
- Genesis hash: 0xA171BAC5 (constant seed for first record)
- Tamper detection is cryptographically sound (modifying any field breaks the chain)

## References
- G14: `core/audit_trail_proof.zig` - Audit trail proof (chain of custody, tamper-evident)
- G17: `core/backup_recovery_proof.zig` - Backup & recovery (for restore from snapshot)
- `core/audit_trail_proof.zig:computeRecordHash()` - FNV-1a hash computation
