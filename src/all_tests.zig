// Aggregator for all unit tests in src/
// Run: `zig build test`

const std = @import("std");

comptime {
    _ = @import("tests/contract/event.zig");
    _ = @import("tests/contract/runtime_manifest.zig");
    _ = @import("contract/abi_manifest.zig");
    _ = @import("tests/core/memory_pool.zig");
    _ = @import("tests/core/diagnostics.zig");
    // Service-cwd bundle resolution: the installed layout must win over cwd.
    _ = @import("core/runtime_paths.zig");
    // EVT-156: bridge_init carries inline unit tests (HMAC goldens + spool
    // join ownership) that never ran -- the module was never imported here.
    _ = @import("core/bridge_init.zig");
    // RB013-LOG: the daemon's diagnostic file-sink install is unit-pinned;
    // pull the runtime spine into the test graph.
    _ = @import("daemon.zig");
    _ = @import("tests/capture/npcap_adapter.zig");
    _ = @import("tests/capture/packet_decoder.zig");
    _ = @import("tests/capture/flow_table.zig");
    _ = @import("tests/capture/proto/parsers.zig");
    _ = @import("tests/capture/stream_reassembly.zig");
    _ = @import("pipeline/data_plane_contract.zig");
    _ = @import("tests/detection/signature_engine.zig");
    _ = @import("tests/detection/anomaly_detector.zig");
    _ = @import("tests/detection/proto_anomaly.zig");
    _ = @import("tests/detection/correlator.zig");
    _ = @import("tests/detection/threat_tracker.zig");
    _ = @import("detection/detection_result.zig");
    _ = @import("tests/policy/policy_ir.zig");
    _ = @import("policy/policy_contract.zig");
    _ = @import("tests/policy/trust_store.zig");
    _ = @import("tests/policy/policy_signing.zig");
    _ = @import("tests/policy/pep_bindings.zig");
    _ = @import("tests/policy/action_dispatcher.zig");
    _ = @import("tests/policy/ts_ir_loader.zig");
    _ = @import("policy/policy_plane.zig");
    _ = @import("policy/enforcement_receipt.zig");
    _ = @import("policy/rule_action.zig");
    _ = @import("tests/forensic/forensic_pipeline.zig");
    // EVT-166: siem_forwarder carries 24 inline CEF tests that never ran.
    _ = @import("forensic/siem_forwarder.zig");
    _ = @import("tests/forensic/decision_trace.zig");
    _ = @import("tests/forensic/evidence_record.zig");
    _ = @import("tests/forensic/provenance.zig");
    _ = @import("tests/forensic/replay_integrity.zig");
    _ = @import("tests/forensic/replay_verifier.zig");
    _ = @import("tests/forensic/abi_contract.zig");
    _ = @import("tests/forensic/integration_contract.zig");
    _ = @import("tests/forensic/python_contract.zig");
    _ = @import("tests/forensic/policy_contract.zig");
    _ = @import("tests/forensic/test_unit.zig");
    _ = @import("tests/forensic/test_integration.zig");
    _ = @import("tests/forensic/test_fault.zig");
    _ = @import("tests/forensic/test_release.zig");
    _ = @import("forensic/forensic_log.zig");
    _ = @import("tests/forensic/release_manifest.zig");
    _ = @import("tests/forensic/installer.zig");
    _ = @import("tests/forensic/release_gate.zig");
    _ = @import("tests/forensic/replay_engine.zig");
    _ = @import("tests/forensic/siem_forwarder.zig");
    _ = @import("forensic/replay_contract.zig");
    _ = @import("tests/windows/etw_realtime.zig");
    _ = @import("tests/windows/fim.zig");
    _ = @import("tests/windows/registry_monitor.zig");
    _ = @import("tests/windows/injection_detector.zig");
    _ = @import("tests/windows/host_telemetry.zig");
    _ = @import("windows/adapter_contract.zig");
    _ = @import("operator/recovery_contract.zig");
    _ = @import("lab/scenario_contract.zig");
    _ = @import("release/artifact_contract.zig");
    _ = @import("tests/reliability/watchdog.zig");
    _ = @import("tests/reliability/security_check.zig");
    _ = @import("tests/reliability/latency_histogram.zig");
    _ = @import("tests/reliability/fault_injection.zig");
    _ = @import("tests/federation/cluster_coord.zig");
    _ = @import("tests/federation/node_registry.zig");
    _ = @import("tests/federation/aggregator.zig");
    _ = @import("tests/federation/federation_tcp.zig");
    _ = @import("tests/federation/federation_rust_tls.zig");
    _ = @import("tests/xdr/xdr_engine.zig");
    // TEST-SCOPE-085: every test-bearing module below runs here. Files
    // that must NOT execute in the unit binary are listed with reasons
    // in tests/security/test_zig_test_scope.py — adding tests to a new
    // file wires them in automatically; moving a file OUT requires
    // updating that registry (conscious, reviewed).
    _ = @import("contract/event_fabric.zig");
    _ = @import("contract/runtime_spine.zig");
    _ = @import("detection/rag_intelligence.zig");
    _ = @import("forensic/replayable_security.zig");
    _ = @import("platform/win32_pipe.zig");
    _ = @import("policy/control_ipc.zig");
    _ = @import("policy/wfp_production.zig");
    _ = @import("reliability/fault_matrix.zig");
    _ = @import("reliability/release_engineering.zig");
    _ = @import("reliability/release_provenance.zig");
    _ = @import("xdr/xdr_correlator.zig");
    _ = @import("xdr/xdr_harden.zig");
    _ = @import("xdr/xdr_incident_fabric.zig");
    _ = @import("xdr/xdr_evidence_flow.zig");
    _ = @import("xdr/xdr_incident_graph.zig");
    _ = @import("windows/cpp_adapter.zig");
    _ = @import("windows/hids_engine.zig");
    _ = @import("windows/hids_process_monitor.zig");
    _ = @import("windows/ips_canary.zig");
    _ = @import("windows/ips_canary_order.zig");
    _ = @import("windows/ips_simulation.zig");
    _ = @import("capture/npcap_capture.zig");
    _ = @import("main.zig");
    _ = @import("policy/shadow_decision.zig");
    // Pipeline hook tests (T1-SIEM-022 SIEM forwarding pin executes here).
    _ = @import("pipeline/event_processor.zig");
    // LEN-CLAIM-100: direct edge — transitive-only files' tests do NOT
    // execute in this toolchain's test binary (silent death found live).
    _ = @import("pipeline/event_queue.zig");
    // BYTE-ORDER-096: capture-path ground-truth pins (parse gates +
    // anti-spoofing gate + fail-closed defaults). Direct edges: the scope
    // pin requires proven execution, transitive reachability is not enough.
    _ = @import("capture/windows_capture.zig");
    _ = @import("pipeline/packet_callback.zig");
    _ = @import("pipeline/runtime_state.zig");
    // ETW-GUID-180: classifier ground-truth pins live here; a direct edge
    // is the only proven execution guarantee (scope pin enforces it).
    _ = @import("pipeline/telemetry_threads.zig");
    // SCOPE-101: binary scan proved ~175 tests dead across these 15
    // non-exempt files (transitive reachability != execution — the
    // TEST-SCOPE-085 pin measured the wrong property). Direct edges wire
    // them; rotted ones are scoped in test_zig_test_scope.py with reason.
    _ = @import("capture/l7_classifier.zig");
    _ = @import("capture/minifilter_reader.zig");
    _ = @import("capture/nose_pipe_reader.zig");
    _ = @import("capture/source_arbiter.zig");
    _ = @import("capture/wfp_telemetry.zig");
    _ = @import("capture/pipe_monitor.zig");
    _ = @import("control/audit.zig");
    _ = @import("control/authorization.zig");
    _ = @import("control/state_machine.zig");
    _ = @import("detection/injection_detector.zig");
    _ = @import("detection/ml_detector.zig");
    _ = @import("federation/cluster_uplink.zig");
    _ = @import("policy/tier3_state.zig");
    _ = @import("policy/shield_screen.zig");
    _ = @import("windows/registry_trie.zig");
    _ = @import("windows/win32_io.zig");
    _ = @import("windows/windows_adapters.zig");
    // SCOPE-101 (hardening): these files' tests execute today only via
    // incidental paths (test-body imports, comptime wrappers) — a silent
    // refactor away from those paths would kill them without tripping any
    // pin. Direct edges make the execution guarantee explicit and
    // permanent. Zero behavior change: every one of these already runs.
    _ = @import("pipeline/l4_matcher.zig");
    _ = @import("pipeline/rule_loader.zig");
    _ = @import("detection/threat_tracker.zig");
    _ = @import("detection/correlator.zig");
    _ = @import("detection/signature_engine.zig");
    _ = @import("capture/flow_table.zig");
    _ = @import("forensic/forensic_pipeline.zig");
    _ = @import("forensic/siem_forwarder.zig");
    _ = @import("contract/canonical_event.zig");
    _ = @import("contract/wire_event.zig");
    _ = @import("control/audit.zig");
    _ = @import("control/authorization.zig");
    _ = @import("control/state_machine.zig");
    _ = @import("policy/pep_bindings.zig");
    _ = @import("policy/policy_ir.zig");
    // SCOPE-102 batch 2: grandfathered production files with pure/model
    // tests (verified executing + green below; rotted ones would be
    // scoped, not silently skipped).
    _ = @import("contract/event_queue.zig");
    _ = @import("core/authority_review.zig");
    _ = @import("core/brain_engine.zig");
    _ = @import("core/canary_progression.zig");
    _ = @import("core/concurrency_harden.zig");
    _ = @import("core/compliance_reporter.zig");
    _ = @import("core/contract_freeze.zig");
    _ = @import("core/fabric_accounting.zig");
    _ = @import("core/legacy_removal.zig");
    _ = @import("core/nids_analyze.zig");
    _ = @import("core/nids_capture.zig");
    _ = @import("core/priority_queue.zig");
    _ = @import("core/real_ips_path.zig");
    _ = @import("core/rust_pep.zig");
    _ = @import("tests/core/core_configs.zig");
    // SCOPE-102 batch 1: migrate grandfathered production files to direct
    // edges (each proven by binary presence + green suite, or scoped with
    // reason on rot — never silent).
    _ = @import("capture/flow_engine.zig");
    _ = @import("capture/nose_contract.zig");
    _ = @import("capture/proto/parsers.zig");
    _ = @import("contract/event_queue.zig");
    _ = @import("detection/correlation_engine.zig");
    _ = @import("detection/detection_engine.zig");
    _ = @import("detection/detection_interface.zig");
    _ = @import("detection/rag_engine.zig");
    _ = @import("detection/threat_intel.zig");
    _ = @import("detection/verdict_aggregator.zig");
    _ = @import("federation/federation_codec.zig");
    _ = @import("forensic/forensics_engine.zig");
    _ = @import("policy/policy_engine.zig");
    _ = @import("policy/wfp_ioctl.zig");
    _ = @import("windows/host_telemetry_detectors.zig");
    _ = @import("windows/host_telemetry_mock.zig");
    _ = @import("windows/host_telemetry_scenarios.zig");
    // Control plane contract + handlers (T3-TWOP-023 pins execute here).
    _ = @import("control/protocol.zig");
    _ = @import("control/handler_registry.zig");
    _ = @import("control/defcon.zig");
    // IDS-COV-001: direct edges ensure these inline tests execute in zig build test.
    _ = @import("capture/proto/l7_payload.zig");
    _ = @import("forensic/ids_evidence_receipt.zig");
}

test "all modules imported successfully" {
    try std.testing.expect(true);
}
