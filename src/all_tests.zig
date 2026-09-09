// Aggregator for all unit tests in src/
// Run: `zig build test`

const std = @import("std");

comptime {
    _ = @import("tests/contract/event.zig");
    _ = @import("tests/contract/runtime_manifest.zig");
    _ = @import("tests/core/memory_pool.zig");
    _ = @import("tests/core/diagnostics.zig");
    _ = @import("tests/capture/npcap_adapter.zig");
    _ = @import("tests/capture/packet_decoder.zig");
    _ = @import("tests/capture/flow_table.zig");
    _ = @import("tests/capture/proto/parsers.zig");
    _ = @import("tests/capture/stream_reassembly.zig");
    _ = @import("tests/detection/signature_engine.zig");
    _ = @import("tests/detection/anomaly_detector.zig");
    _ = @import("tests/detection/proto_anomaly.zig");
    _ = @import("tests/detection/correlator.zig");
    _ = @import("tests/detection/threat_tracker.zig");
    _ = @import("tests/policy/policy_ir.zig");
    _ = @import("tests/policy/trust_store.zig");
    _ = @import("tests/policy/pep_bindings.zig");
    _ = @import("tests/policy/action_dispatcher.zig");
    _ = @import("tests/forensic/forensic_pipeline.zig");
    _ = @import("tests/forensic/evidence_record.zig");
    _ = @import("tests/forensic/provenance.zig");
    _ = @import("tests/forensic/replay_integrity.zig");
    _ = @import("tests/forensic/replay_engine.zig");
    _ = @import("tests/windows/etw_realtime.zig");
    _ = @import("tests/windows/fim.zig");
    _ = @import("tests/windows/registry_monitor.zig");
    _ = @import("tests/windows/injection_detector.zig");
    _ = @import("tests/windows/host_telemetry.zig");
    _ = @import("tests/reliability/watchdog.zig");
    _ = @import("tests/reliability/security_check.zig");
    _ = @import("tests/reliability/latency_histogram.zig");
    _ = @import("tests/reliability/fault_injection.zig");
    _ = @import("tests/federation/cluster_coord.zig");
    _ = @import("tests/federation/node_registry.zig");
    _ = @import("tests/federation/aggregator.zig");
    _ = @import("tests/xdr/xdr_engine.zig");
}

test "all modules imported successfully" {
    try std.testing.expect(true);
}