// Aggregator for all unit tests in src/
// Run: `zig build test`

const std = @import("std");

comptime {
    _ = @import("tests/contract/event.zig");
    _ = @import("tests/contract/runtime_manifest.zig");
    _ = @import("contract/abi_manifest.zig");
    _ = @import("tests/core/memory_pool.zig");
    _ = @import("tests/core/diagnostics.zig");
    // REBUILD-002: pull every orphaned src/core module into the test graph
    _ = @import("tests/core/core_modules.zig");
    // Service-cwd bundle resolution: the installed layout must win over cwd.
    _ = @import("core/runtime_paths.zig");
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
    _ = @import("tests/cli_imports.zig");
    // Pipeline hook tests (T1-SIEM-022 SIEM forwarding pin executes here).
    _ = @import("pipeline/event_processor.zig");
    // Control plane contract + handlers (T3-TWOP-023 pins execute here).
    _ = @import("control/protocol.zig");
    _ = @import("control/handler_registry.zig");
    _ = @import("control/defcon.zig");
}

test "all modules imported successfully" {
    try std.testing.expect(true);
}
