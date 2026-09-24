# AEGIS T20 Release Candidate - Upgrade / Rollback

- Snapshot:   python tools/upgrade_rollback.py snapshot
- Inspect:    python tools/upgrade_rollback.py report --json
- Revert:     python tools/upgrade_rollback.py rollback --snapshot <id>
- Runbook:    docs/runbooks/RB-005-config-rollback.md
- Paired registry + config rollback coordinated through control-plane IPC
  (core/control_ipc.zig) with audit trail in logs/control_audit.ndjson.
