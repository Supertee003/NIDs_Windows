# RB-005: Config Rollback

## Objective
Roll back the AEGIS NIDS configuration to a previous version. This runbook covers reverting a failed config reload or undoing policy changes using the atomic swap mechanism.

## Prerequisites
- AEGIS NIDS running with ConfigStore initialized
- Previous ruleset version available (version history maintained)
- Operator access to config reload API
- Estimated rollback time: < 5 seconds (atomic swap)

## Steps

1. **Identify the current (broken) config version**
   ```
   store.currentVersion()  # current ruleset version
   ```
   - Note the current version number
   - Identify the target version to roll back to (usually current - 1)

2. **Prepare the previous ruleset**
   - The previous ruleset must be available (stored in version history)
   - If using file-based config, restore the previous Rules.json:
     ```
     copy config/Rules.json.v<current> config/Rules.json.bak
     copy config/Rules.json.v<target> config/Rules.json
     ```

3. **Trigger hot reload (mtime watchdog)**
   - The config reload watchdog detects Rules.json mtime changes within 5 seconds
   - Wait for the watchdog to detect the change:
     ```
     # Watchdog checks every 5 seconds (WATCHDOG_INTERVAL_MS)
     # Detection latency: <= 5 seconds
     ```

4. **Verify validation passes**
   - The ConfigStore validates the new ruleset BEFORE swap:
     - No empty rulesets
     - No duplicate rule_ids
     - No rule_id == 0 (reserved)
     - No exceeding MAX_RULES_PER_RULESET (256)
   - If validation FAILS, the live config is preserved (no swap occurs)

5. **Verify atomic swap succeeded**
   ```
   store.currentVersion()  # should be the target version
   store.getActive().ruleCount()  # should match expected rule count
   ```
   - The swap is atomic (RCU pattern: prepare -> validate -> swap -> retire)
   - Concurrent readers see consistent state (old or new, never torn)

6. **Verify event processing uses new version**
   - Process a test event:
     ```
     processEventWithVersion(store, test_event_id, test_rule_id)
     ```
   - Verify the event records the new ruleset_version

7. **Record in audit trail**
   - Audit trail automatically records: action=config_reload, outcome=success
   - Verify audit record created with the version change detail

## Verification
- `currentVersion()` returns the target version
- `getActive().ruleCount()` matches expected
- Events processed after rollback record the new version
- Audit trail contains config_reload action

## Rollback of the Rollback
If the rollback itself causes issues:
1. The previous (broken) config is still available in version history
2. Repeat this procedure to roll forward to the broken version
3. If validation fails on rollback, live config is preserved (no swap)

## Notes
- Config reload is HOT (no process restart needed)
- Atomic swap uses RCU (Read-Copy-Update) pattern
- Validation happens BEFORE swap (invalid ruleset rejected, live config preserved)
- Mtime watchdog: 5-second detection interval (Phase 14 P-11 pattern)
- Every event records ruleset_version at decision time (audit trail)

## References
- G12: `core/config_reload_proof.zig` - Config reload proof (hot reload, atomic swap)
- G14: `core/audit_trail_proof.zig` - Audit trail (records config changes)
- `config/Rules.json` - Detection rules file
- `config/aegis.conf` - System configuration
