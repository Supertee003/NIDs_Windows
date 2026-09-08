# AEGIS Final Golden Path - Evidence Package (T20 AC2)

- Commit: `39fb44a`
- OS / platform: Windows-11-10.0.26200-SP0
- Generated: 2026-09-08T06:44:50.659595+00:00

## Evidence inventory

- **event_trace**: canonical event schema + captured sample (logs/runtime/audit.ndjson)
- **decision_trace**: mandated 8-link decision trace (action -> pep_request -> policy -> verdict -> evidence -> correlation -> event -> source)
- **policy_artifact**: config/Rules.json (digest-verified) + core/policy_signing.zig (ed25519)
- **signature_proof**: core/policy_signing.zig (ed25519 signing + TrustStore) gate
- **pep_result**: shield/src/pep.rs (Rust PEP, sole enforcement authority) + tests/pep
- **wfp_result**: drivers/wfp_callout/*.sys kernel enforcement + core/wfp_production.zig + tests/wfp
- **windows_evidence**: ETW/FIM helpers, win32 modules, real telemetry sources (npcap)
- **forensic_record**: logs/runtime/audit.ndjson (append-only) + core/forensics_engine.zig
- **replay_result**: core/replayable_security.zig (rules/policy/context atom replay) + core/replay_engine.zig
- **metrics**: docs/gates/T17_benchmark_results.md + perf gates
- **logs**: git log + audit/forensic NDJSON
- **environment**: OS / machine / python / zig / rustc / go / node
- **commit_sha**: git HEAD (short)

## Golden path chain (Step 61)

1. real event
2. go/c++ acquisition
3. canonical_event
4. event_fabric
5. flow
6. detection (evidence)
7. verdict
8. correlation
9. threat_intel
10. rag (context)
11. brain (advisory)
12. policy (decision)
13. policy signing (ed25519)
14. rust pep (enforcement authority)
15. wfp (windows enforcement)
16. federation (cross-node incident)
17. federation TLS (mTLS transport)
18. forensics (immutable trace)
19. replay

Golden-path modules exercised: core/npcap_capture.zig, nose/capture.go, windows_capture.zig, brain/windows_brain.py, brain/cython/cython_regex_scan.pyx, bridge/aegis_adapter.cpp + aegis_adapter.hpp, core/flow_types.zig, core/flow_engine.zig, core/detection_engine.zig, core/correlation_engine.zig, core/rag_intelligence.zig, core/brain_engine.zig, core/policy_engine.zig, core/policy_signing.zig, shield/src/pep.rs, core/wfp_production.zig, core/forensics_engine.zig, core/replay_engine.zig.

## Gate results

- Zig module gates: 12 pass, 0 fail
  - `core/canonical_event.zig` PASS
  - `core/flow_engine.zig` PASS
  - `core/detection_engine.zig` PASS
  - `core/correlation_engine.zig` PASS
  - `core/policy_engine.zig` PASS
  - `core/policy_signing.zig` PASS
  - `core/wfp_production.zig` PASS
  - `core/forensics_engine.zig` PASS
  - `core/replay_engine.zig` PASS
  - `core/decision_trace.zig` PASS
  - `core/replayable_security.zig` PASS
  - `core/authority_review.zig` PASS
- Pytest scopes (forensics/pep/wfp/policy_signing/ips_xdr): 5 pass, 0 fail
  - forensics PASS
  - pep PASS
  - wfp PASS
  - policy_signing PASS
  - ips_xdr PASS
