# AEGIS NIDS Blueprint Status

## Current State: G1-G21 Rewrite COMPLETE

**Last Updated**: 2026-08-30
**Status**: All 21 proof modules deployed and tested (84 test targets in build.zig)

---

## G1-G21 Proof Module Status

The rewrite introduced 21 self-contained proof modules that verify the architecture's contracts end-to-end. Each module is tested with 15-30 unit tests.

### Foundation Gates (G1-G3)

| Gate | Module | Lines | Tests | Status |
|------|--------|-------|-------|--------|
| G1 | `contract_freeze.zig` | 582 | 25 | [DONE] COMPLETE |
| G2 | `fabric_accounting.zig` | 719 | 28 | [DONE] COMPLETE |
| G3 | `runtime_spine.zig` | 596 | 22 | [DONE] COMPLETE |

**G1 Exit Gate**: Contract frozen (no breaking changes after release).
**G2 Exit Gate**: input = processed + dropped + rejected (all 7 stress scenarios balanced).
**G3 Exit Gate**: One event traced through 12-stage golden path.

### Core Pipeline Gates (G4-G10)

| Gate | Module | Lines | Tests | Status |
|------|--------|-------|-------|--------|
| G4 | `flow_state_proof.zig` | 622 | 18 | [DONE] COMPLETE |
| G5 | `detection_fabric_proof.zig` | 567 | 15 | [DONE] COMPLETE |
| G6 | `correlation_proof.zig` | 428 | 15 | [DONE] COMPLETE |
| G7 | `intelligence_proof.zig` | 371 | 14 | [DONE] COMPLETE |
| G8 | `brain_proof.zig` | 414 | 14 | [DONE] COMPLETE |
| G9 | `policy_plane_proof.zig` | 684 | 18 | [DONE] COMPLETE |
| G10 | `pep_enforcement_proof.zig` | 1222 | 30 | [DONE] COMPLETE |

**G4 Exit Gate**: 10K flows x 10 packets = 110K operations, no duplicates, no dangling pointers.
**G5 Exit Gate**: Add detector without changing Fabric/Dispatcher/Policy.
**G6 Exit Gate**: Process + File + Flow + IOC combined into one incident.
**G7 Exit Gate**: RAG down -> system continues (Detection + Policy work).
**G8 Exit Gate**: If Brain gone, system still: capture, detect, correlate, policy, forensic.
**G9 Exit Gate**: Highest-priority enabled rule wins, deterministic, disabled skipped.
**G10 Exit Gate**: Deferred enforcement queued (max 64), retried (max 3), bounded.

### Operations Gates (G11-G18)

| Gate | Module | Lines | Tests | Status |
|------|--------|-------|-------|--------|
| G11 | `forensic_replay_proof.zig` | 1366 | 25 | [DONE] COMPLETE |
| G12 | `config_reload_proof.zig` | 1241 | 30 | [DONE] COMPLETE |
| G13 | `health_monitoring_proof.zig` | 1017 | 30 | [DONE] COMPLETE |
| G14 | `audit_trail_proof.zig` | 943 | 25 | [DONE] COMPLETE |
| G15 | `telemetry_export_proof.zig` | 983 | 25 | [DONE] COMPLETE |
| G16 | `siem_integration_proof.zig` | 797 | 25 | [DONE] COMPLETE |
| G17 | `backup_recovery_proof.zig` | 957 | 25 | [DONE] COMPLETE |
| G18 | `performance_tuning_proof.zig` | 952 | 30 | [DONE] COMPLETE |

**G11 Exit Gate**: Forensic records replayable through pipeline (deterministic match + regression).
**G12 Exit Gate**: Every event records ruleset_version (audit trail across version swaps).
**G13 Exit Gate**: DEFCON level rolls up from subsystem health (1=critical to 5=normal).
**G14 Exit Gate**: Audit log is tamper-evident (any modification breaks hash chain).
**G15 Exit Gate**: Single source of truth -- same event exported to 3 formats (no data drift).
**G16 Exit Gate**: All 3 SIEM formats (CEF, LEEF, KEYVAL) normalize to NormalizedEvent.
**G17 Exit Gate**: RPO and RTO are bounded (default 5min / 30s).
**G18 Exit Gate**: p99 latency bounded while sustaining high EPS.

### Compliance & Documentation (G19-G21)

| Gate | Module | Lines | Tests | Status |
|------|--------|-------|-------|--------|
| G19 | `compliance_proof.zig` | 813 | 22 | [DONE] COMPLETE |
| G20 | `documentation_proof.zig` | 633 | 25 | [DONE] COMPLETE |
| G21 | `final_integration_proof.zig` | 781 | 18 | [DONE] COMPLETE |

**G19 Exit Gate**: Single AEGIS feature set maps to all 3 compliance frameworks.
**G20 Exit Gate**: No module without docs (no orphaned code) -- all 23 modules documented.
**G21 Exit Gate (CAPSTONE)**: End-to-end flow satisfies SOC 2 + ISO 27001 + NIST CSF.

---

## Compliance Coverage

### SOC 2 (Trust Services Criteria)

| Control | Category | Satisfied By |
|---------|----------|--------------|
| CC6.1 | Security | PEP enforcement (G10) |
| CC6.6 | Security | Audit trail (G14) |
| CC7.1 | Security | Brain advisory (G8) |
| CC7.2 | Security | SIEM integration (G16) |
| A1.1 | Availability | Health monitoring (G13) |
| A1.2 | Availability | Health monitoring (G13) |
| A1.3 | Availability | Backup & recovery (G17) |
| C1.1 | Confidentiality | Policy signing (G9) |
| C1.2 | Confidentiality | Forensic redaction (G11) |

### ISO 27001 (Annex A)

| Control | Section | Satisfied By |
|---------|---------|-------------|
| A.5.9 | Inventory of assets | Config validation (G12) |
| A.5.24 | Incident management | SIEM integration (G16) |
| A.5.30 | Business continuity | Backup & recovery (G17) |
| A.8.12 | Data leakage prevention | Forensic redaction (G11) |
| A.8.15 | Logging | Audit trail (G14) |
| A.8.16 | Monitoring activities | Health monitoring (G13) |
| A.8.23 | Web filtering | PEP enforcement (G10) |
| A.8.24 | Cryptography | Policy signing (G9) |

### NIST CSF (5 Functions)

| Function | Category | Satisfied By |
|----------|----------|--------------|
| Identify | ID.AM | Config validation (G12) |
| Protect | PR.AC | PEP enforcement (G10) |
| Protect | PR.DS | Policy signing (G9) |
| Detect | DE.CM | Brain advisory (G8) |
| Respond | RS.AN | SIEM integration (G16) |
| Respond | RS.MI | PEP enforcement (G10) |
| Recover | RC.RP | Backup & recovery (G17) |
| Recover | RC.CO | Telemetry export (G15) |

---

## Pipeline Architecture (G21 Capstone)

The 8-stage pipeline processes each event in strict order:

```
Event -> [Nose] -> [Flow] -> [Detection] -> [Verdict] -> [Policy] -> [PEP] -> [Forensic] -> [Audit]
                    |          |              |           |          |          |           |
                    v          v              v           v          v          v           v
               FlowState   Evidence      Verdict      Decision   Enforcement  Record      Trail
                             (G5)        (Brain)     (Policy)    (G10)       (G11)       (G14)
```

**Resilience**: Brain down -> system continues (fail-soft, default verdict). PEP down -> system continues (fail-soft, no enforcement). Forensic + Audit ALWAYS record.

---

## Remaining Items (P2)

| Item | Priority | Status |
|------|----------|--------|
| PEP quarantine implementation | P2 | DEFERRED (currently returns "deferred" status) |
| wfp_ioctl unblock-flow handler | P3 | Tracking-only mode (documented) |
| nids_analyze.zig stub removal | P1 | REPLACED with dispatcher route (G22) |

---

## Historical Phase Status (Pre-Rewrite)

The original phased development (Phase 1-27) is preserved. The G1-G21 rewrite layers proof modules on top of the existing runtime.

- Phase 1-14: Initial pipeline (canonical events, flow, detection, verdict, policy, PEP, forensic)
- Phase 15-27: Tools and integration (replay, e2e, performance, canary, xdr, release, legacy, rag, hids, concurrency, fault injection, ips simulation, policy plane)
- **G1-G21**: Rewrite proofs (contract verification, compliance, documentation)

---

**End of Blueprint Status**
