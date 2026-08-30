# AEGIS NIDS Runbooks

This directory contains operational runbooks for the AEGIS NIDS system.

## Runbook Index

| ID | Type | Title | Module |
|----|------|-------|--------|
| [RB-001](RB-001-block-ip-via-pep.md) | Incident Response | Block IP via PEP | pep_enforcement_proof |
| [RB-002](RB-002-forensic-query.md) | Incident Response | Forensic query for incident reconstruction | forensic_replay_proof |
| [RB-003](RB-003-audit-tamper-investigation.md) | Incident Response | Audit trail tamper investigation | audit_trail_proof |
| [RB-004](RB-004-restore-from-snapshot.md) | Recovery | Restore from snapshot | backup_recovery_proof |
| [RB-005](RB-005-config-rollback.md) | Recovery | Config rollback | config_reload_proof |
| [RB-006](RB-006-subsystem-health-check.md) | Troubleshooting | Subsystem health check | health_monitoring_proof |
| [RB-007](RB-007-performance-tuning.md) | Troubleshooting | Performance tuning (queue depth + batching) | performance_tuning_proof |
| [RB-008](RB-008-siem-ingestion-debug.md) | Troubleshooting | SIEM ingestion debugging | siem_integration_proof |
| [RB-009](RB-009-hot-reload-config.md) | Deployment | Hot reload config (no restart) | config_reload_proof |
| [RB-010](RB-010-telemetry-export-setup.md) | Deployment | Telemetry export setup | telemetry_export_proof |

## Runbook Types

- **Incident Response** -- Security incident handling (block, query, investigate)
- **Recovery** -- System recovery (restore, rollback)
- **Troubleshooting** -- Debug and diagnose issues
- **Deployment** -- Install, upgrade, configure

## Using Runbooks

Each runbook follows this structure:

1. **Objective** -- What this runbook accomplishes
2. **Prerequisites** -- What you need before starting
3. **Steps** -- Numbered, actionable steps
4. **Verification** -- How to confirm success
5. **Rollback** -- How to undo if something goes wrong

## Contributing

When adding a new runbook:
1. Use the next available RB-XXX ID
2. Follow the standard structure
3. Test the procedure before committing
4. Update this index file
