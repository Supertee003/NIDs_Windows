# AEGIS NIDs Windows -- Component Inventory

**Generated:** 2026-09-02  
**Method:** Automated scan of core/*.zig (89 files)

## Summary

| Category | Count | Total Lines |
|---|---|---|
| Production modules | 45 | ~15,000 |
| Integration modules | 18 | ~4,000 |
| Proof/test modules | 26 | ~22,000 |
| **Total** | **89** | **~41,000** |

## Production Modules (used in runtime path)

| Module | Lines | In Dispatcher | In Lifecycle | Role |
|---|---|---|---|---|
| canonical_event | 462 | yes | yes | Schema authority |
| event_fabric | 520 | yes | yes | Queue authority |
| event_queue | 234 | no | no | Legacy queue (candidate for removal) |
| flow_engine | 552 | no | no | Flow state authority |
| flow_types | 193 | yes | no | Flow type definitions |
| detection_engine | 735 | no | no | Evidence producer |
| detection_interface | 331 | no | no | Detection interface contract |
| verdict_aggregator | 724 | yes | no | Verdict aggregation |
| correlation_engine | 970 | yes | no | Correlation |
| threat_intel | 587 | yes | yes | Threat intelligence |
| rag_engine | 695 | no | no | RAG (P0.1: not in dispatcher) |
| rag_intelligence | 351 | no | no | RAG intelligence layer |
| brain_engine | 843 | yes | no | Brain advisory |
| policy_engine | 827 | yes | no | Policy decision |
| policy_contract | 378 | no | no | Policy contract |
| policy_ir | 306 | no | no | Policy IR |
| policy_plane | 727 | no | yes | Policy plane |
| rust_pep | 886 | yes | yes | PEP enforcement |
| forensics_engine | 941 | no | no | Forensic record |
| forensic_log | 439 | no | yes | Forensic logger |
| dispatcher | 404 | self | yes | Orchestrator |
| lifecycle | 356 | yes | self | Lifecycle manager |
| nids_main | 426 | no | no | Entry point |
| nids_analyze | 2237 | yes | no | LEGACY (P0.6: audit) |
| nids_capture | 248 | no | no | Pipe sensor |
| nose_contract | 259 | yes | yes | Nose contract |
| bridge_init | 621 | no | no | Bridge init |
| wfp_ioctl | 585 | no | no | WFP IOCTL |
| win32_io | 166 | no | no | Win32 I/O helpers |
| windows_capture | 179 | no | no | WFP capture |
| minifilter_reader | 326 | no | no | Minifilter reader |
| pipe_monitor | 224 | no | no | Pipe monitor |
| priority_queue | 290 | no | no | Priority queue |
| wire_event | 462 | no | no | Wire event codec |
| fabric_accounting | 719 | no | no | Fabric accounting |
| contract_freeze | 582 | no | no | Contract freeze |
| runtime_spine | 596 | no | no | Runtime spine proof |
| legacy_removal | 246 | no | no | Legacy removal |
| xdr_correlator | 373 | no | no | XDR correlator |
| xdr_harden | 662 | no | yes | XDR hardening |
| hids_engine | 899 | no | no | HIDS engine |
| hids_process_monitor | 250 | no | no | HIDS process monitor |
| replay_engine | 527 | no | no | Replay engine |
| concurrency_harden | 601 | no | yes | Concurrency hardening |
| release_engineering | 466 | no | yes | Release engineering |

## Integration Modules (glue code)

| Module | Lines | Connects |
|---|---|---|
| brain_integration | 304 | brain_engine -> dispatcher |
| correlation_integration | 241 | correlation_engine -> dispatcher |
| detection_integration | 222 | detection_engine -> dispatcher |
| flow_integration | 257 | flow_engine -> dispatcher |
| forensics_integration | 276 | forensics_engine -> dispatcher |
| hids_integration | 216 | hids_engine -> lifecycle |
| ips_canary_integration | 272 | ips_canary -> lifecycle |
| nose_integration | 492 | nose_contract -> lifecycle |
| performance_integration | 245 | performance_harness -> lifecycle |
| policy_integration | 281 | policy_engine -> dispatcher |
| policy_plane_integration | 149 | policy_plane -> lifecycle |
| rag_integration | 186 | rag_engine -> lifecycle (P0.1: NOT in dispatcher) |
| release_engineering_integration | 139 | release_engineering -> lifecycle |
| replay_integration | 235 | replay_engine -> lifecycle |
| rust_pep_integration | 290 | rust_pep -> dispatcher/lifecycle |
| threat_intel_integration | 271 | threat_intel -> dispatcher |
| concurrency_harden_integration | 120 | concurrency_harden -> lifecycle |
| fault_injection_integration | 150 | fault_injection -> lifecycle |

## Proof/Test Modules (NOT in production path)

| Module | Lines | Purpose |
|---|---|---|
| audit_trail_proof | 943 | Audit trail verification |
| backup_recovery_proof | 957 | Backup/recovery proof |
| brain_proof | 414 | Brain advisory proof |
| compliance_proof | 813 | Compliance mapping proof |
| config_reload_proof | 1241 | Config reload proof |
| correlation_proof | 438 | Correlation proof |
| detection_fabric_proof | 567 | Detection fabric proof |
| documentation_proof | 633 | Documentation proof |
| e2e_harness | 656 | E2E test harness |
| e2e_harness_integration | 228 | E2E harness integration |
| final_integration_proof | 781 | Final integration proof |
| flow_state_proof | 622 | Flow state proof |
| forensic_replay_proof | 1366 | Forensic replay proof |
| health_monitoring_proof | 1017 | Health monitoring proof |
| intelligence_proof | 371 | Intelligence proof |
| ips_simulation | 650 | IPS simulation |
| ips_simulation_integration | 186 | IPS simulation integration |
| pep_enforcement_proof | 1222 | PEP enforcement proof |
| performance_harness | 820 | Performance harness |
| performance_tuning_proof | 952 | Performance tuning proof |
| policy_plane_proof | 684 | Policy plane proof |
| siem_integration_proof | 797 | SIEM integration proof |
| telemetry_export_proof | 983 | Telemetry export proof |

## P0 Issues Identified

### P0.1 RAG Runtime Gap
- rag_engine.zig (695 lines) exists but is NOT imported by dispatcher.zig
- rag_integration.zig is initialized in lifecycle.zig but NOT called in dispatcher
- README claims RAG is a runtime capability -- code does not match

### P0.2 Policy Signing Placeholder
- policy_plane.zig line 267: uses "simplified FNV-1a" hash
- policy_plane.zig line 277: signature = hash ^ 0x41454731 (placeholder)
- Needs real SHA-256 + Ed25519

### P0.3 PEP Bypass in aegisctl
- aegisctl.py _block_add() directly writes to blocked_ips.json
- aegisctl.py _signal_core_block() sends SIGUSR1 to core (bypasses PEP)
- Must route through Rust PEP

### P0.5 Production/Test Lifecycle Mixed
- lifecycle.zig initializes 20+ subsystems including test/proof modules
- Needs ProductionProfile vs TestProfile separation

### P0.6 Legacy nids_analyze.zig
- 2,237 lines -- largest file in core/
- Competes with dispatcher.zig as runtime path
- Must be audited and migrated or removed
