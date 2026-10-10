# AEGIS NIDS Runbooks

This directory contains operational runbooks for the AEGIS NIDS system.

## Runbook Index

| ID | Type | Title | Module | Status |
|----|------|-------|--------|--------|
| [RB-001](RB-001-block-ip-via-pep.md) | Incident Response | Block IP via PEP | pep_enforcement_proof | procedure |
| [RB-002](RB-002-forensic-query.md) | Incident Response | Forensic query for incident reconstruction | forensic_replay_proof | procedure |
| [RB-003](RB-003-audit-tamper-investigation.md) | Incident Response | Audit trail tamper investigation | audit_trail_proof | procedure |
| [RB-004](RB-004-restore-from-snapshot.md) | Recovery | Restore from snapshot | backup_recovery_proof | procedure |
| [RB-005](RB-005-config-rollback.md) | Recovery | Config rollback | config_reload_proof | procedure |
| [RB-006](RB-006-subsystem-health-check.md) | Troubleshooting | Subsystem health check | health_monitoring_proof | procedure |
| [RB-007](RB-007-performance-tuning.md) | Troubleshooting | Performance tuning (queue depth + batching) | performance_tuning_proof | procedure |
| [RB-008](RB-008-siem-ingestion-debug.md) | Troubleshooting | SIEM ingestion debugging | siem_integration_proof | procedure |
| [RB-009](RB-009-hot-reload-config.md) | Deployment | Hot reload config (no restart) | config_reload_proof | procedure |
| [RB-010](RB-010-telemetry-export-setup.md) | Deployment | Telemetry export setup | telemetry_export_proof | procedure |
| [RB-011](RB-011-policy-ir-mirror-workflow.md) | Deployment | Author, seal, export, verify TS policy IR mirror | policy_ir_proof | procedure |
| [RB-012](RB-012-wfp-block-lab-proof.md) | Lab Proof | WFP BLOCK live proof (isolated lab VM only) | enforcement_proof | NOT YET EXECUTED |
| [RB-013](RB-013-quarantine-lab-proof.md) | Lab Proof | Quarantine positive-path proof (isolated lab VM only) | enforcement_proof | NOT YET EXECUTED |
| [RB-014](RB-014-federation-lab-proof.md) | Lab Proof | Federation live cluster verification (lab) | federation_proof | NOT YET EXECUTED |
| [RB-015](RB-015-siem-delivery-proof.md) | Lab Proof | SIEM delivery proof (lab) | siem_proof | NOT YET EXECUTED |
| [RB-016](RB-016-production-trust-checklist.md) | Deployment | Production trust (signed policy, secrets, gates) | policy_signing | OPERATOR ACTION |
| [RB-017](RB-017-brain-bring-up.md) | Deployment | Brain Tier-2 supervised bring-up | brain_channel | OPERATOR ACTION |
| [RB-018](RB-018-hostonly-observe-only-qualification.md) | Lab Proof | Host-only observe-only qualification (Kali VM) | wfp_telemetry | NOT YET EXECUTED |
| [RB-019](RB-019-attack-visibility-demo.md) | Troubleshooting | Attack-visibility demo (marked canary end to end) | detection_chain | procedure |

## Runbook Types

- **Incident Response** -- Security incident handling (block, query, investigate)
- **Recovery** -- System recovery (restore, rollback)
- **Troubleshooting** -- Debug and diagnose issues
- **Deployment** -- Install, upgrade, configure
- **Lab Proof** -- Isolated-lab verification procedures with exact postconditions (never production)

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
