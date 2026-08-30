# RB-004: Restore from Snapshot

## Objective
Restore the AEGIS NIDS system state from a previously captured snapshot. This runbook covers the recovery procedure when the system needs to be rolled back to a known-good state.

## Prerequisites
- AEGIS NIDS running with SnapshotManager initialized
- At least one snapshot captured previously
- Operator access to restore API
- Estimated restore time: < 30 seconds (RTO bound)

## Steps

1. **List available snapshots**
   ```
   snapshot_manager.len()  # count of stored snapshots
   snapshot_manager.latest()  # most recent snapshot
   ```
   - Verify snapshots exist before proceeding
   - Note the snapshot_id of the target snapshot

2. **Select the target snapshot**
   - Choose based on the incident timeline:
     - Latest snapshot: for recent known-good state
     - Earlier snapshot: for deeper rollback
   - Get the snapshot details: `snapshot_manager.getById(snapshot_id)`

3. **Verify snapshot integrity**
   ```
   snapshot = snapshot_manager.getById(target_id)
   expected_hash = computeStateHash(snapshot.state)
   if snapshot.content_hash != expected_hash:
       # SNAPSHOT IS CORRUPTED - do not use
   ```
   - The restore API automatically verifies content_hash
   - If verification fails, restore returns null

4. **Initiate the restore**
   ```
   restored_state = snapshot_manager.restore(snapshot_id, now_ms)
   ```
   - Restore is idempotent (same snapshot -> same state)
   - Returns the SystemState (8 fields: ruleset_version, rule_count, total_events, etc.)
   - Returns null if snapshot_id invalid or content_hash mismatch

5. **Verify the restored state**
   - Check ruleset_version matches expected
   - Check total_events count is correct
   - Check defcon_level is restored
   - Verify config_mtime_ms matches the snapshot time

6. **Monitor system after restore**
   - Watch health monitoring for stability
   - Check DEFCON level (should match restored state)
   - Verify event processing resumes normally

7. **Record the restore in audit trail**
   - Audit trail automatically records: action=system_restart, outcome=success
   - Verify audit record created with restore timestamp

## Verification
- `restore()` returns non-null SystemState
- Restored state matches snapshot (all 8 fields)
- Restore is idempotent (3 restores of same snapshot -> same state)
- RTO satisfied: restore completes within 30 seconds

## Rollback
If the restore itself fails or produces unexpected state:
1. Do NOT attempt to re-restore immediately
2. Check snapshot integrity: `verifyChain()` on audit trail
3. If audit trail is intact, capture a new snapshot of current (broken) state
4. Try restoring from an earlier snapshot
5. If all snapshots fail, contact engineering (possible database corruption)

## Notes
- RPO (Recovery Point Objective): 5 minutes (default snapshot interval)
- RTO (Recovery Time Objective): 30 seconds (restore + verify)
- Max snapshots stored: 32 (oldest evicted when full)
- Snapshot is content-addressed (FNV-1a hash over 8 state fields + seed 0xA171BAC5)
- Restore does NOT modify the snapshot store (snapshots are immutable)

## References
- G17: `core/backup_recovery_proof.zig` - Backup & recovery proof
- G13: `core/health_monitoring_proof.zig` - Health monitoring (post-restore verification)
- G14: `core/audit_trail_proof.zig` - Audit trail (records restore action)
