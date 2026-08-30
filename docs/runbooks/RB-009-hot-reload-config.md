# RB-009: Hot Reload Config (No Restart)

## Objective
Reload the AEGIS NIDS configuration without restarting the process. This runbook covers the hot reload procedure using the mtime watchdog and atomic swap mechanism.

## Prerequisites
- AEGIS NIDS running with config reload enabled
- Updated `config/Rules.json` file ready to deploy
- Operator access to the config directory
- Estimated reload time: < 5 seconds (detection + validation + swap)

## Steps

1. **Prepare the new configuration**
   - Edit `config/Rules.json` with the new ruleset
   - Verify the JSON is valid (no syntax errors)
   - Verify all rules have required fields: rule_id, name, severity, action
   - Verify no duplicate rule_ids
   - Verify no rule_id == 0 (reserved for "no rule matched")

2. **Deploy the new config file**
   ```
   copy config/Rules.json config/Rules.json.bak  # backup current
   copy config/Rules.new.json config/Rules.json  # deploy new
   ```
   - The mtime of Rules.json changes
   - The watchdog will detect this within 5 seconds

3. **Wait for watchdog detection**
   - Watchdog checks mtime every 5 seconds (WATCHDOG_INTERVAL_MS)
   - Detection latency: <= 5 seconds
   - The watchdog triggers a reload when mtime changes

4. **Monitor validation**
   - ConfigStore validates the new ruleset BEFORE swap:
     - No empty rulesets (rule_count > 0)
     - No duplicate rule_ids
     - No rule_id == 0
     - No exceeding MAX_RULES_PER_RULESET (256)
   - If validation FAILS: live config preserved, reload aborted
   - Check logs for validation errors

5. **Verify atomic swap**
   ```
   store.currentVersion()  # should be incremented
   store.getActive().ruleCount()  # should match new ruleset
   ```
   - The swap is atomic (RCU pattern: prepare -> validate -> swap -> retire)
   - Concurrent readers see consistent state (old or new, never torn)
   - No events are lost during the swap

6. **Verify event processing uses new version**
   - Process a test event:
     ```
     processEventWithVersion(store, test_event_id, test_rule_id)
     ```
   - Verify the event records the new ruleset_version
   - Check forensic log for the version change

7. **Record in audit trail**
   - Audit trail automatically records: action=config_reload, outcome=success
   - Verify audit record created with detail "ruleset v<old> -> v<new>"

8. **Monitor for issues post-reload**
   - Watch health monitoring for stability
   - Check DEFCON level (should remain normal)
   - Verify event processing continues without interruption

## Verification
- `currentVersion()` returns the new version number
- `getActive().ruleCount()` matches expected
- Events processed after reload record the new version
- Audit trail contains config_reload action with success outcome
- No events lost during the swap (queue depth stable)
- DEFCON level remains normal (5)

## Rollback
If the new config causes issues:
1. Restore the previous Rules.json:
   ```
   copy config/Rules.json.bak config/Rules.json
   ```
2. The watchdog will detect the mtime change and reload
3. The system will roll back to the previous version automatically
4. See RB-005 (Config Rollback) for detailed rollback procedure

## Notes
- Hot reload is NON-BLOCKING (no process restart)
- Detection: mtime watchdog, 5-second interval
- Validation: 6 rules (empty, too_many, rule_id_zero, duplicate_id, invalid_action, invalid_severity)
- Swap: atomic RCU (Read-Copy-Update) pattern
- Every event records ruleset_version at decision time (audit trail)
- Max rules per ruleset: 256 (MAX_RULES_PER_RULESET)

## References
- G12: `core/config_reload_proof.zig` - Config reload proof
- G14: `core/audit_trail_proof.zig` - Audit trail (records config changes)
- G13: `core/health_monitoring_proof.zig` - Health monitoring (post-reload verification)
- `config/Rules.json` - Detection rules file
