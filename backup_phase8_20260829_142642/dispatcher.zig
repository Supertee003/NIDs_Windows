//! runtime/dispatcher.zig - AEGIS Runtime Dispatcher (Rewrite Phase 7)
//!
//! Pops events from Event Fabric and routes through the pipeline.
//! Replaces the old eventFabricDrain() in nids_analyze.zig.
//!
//! Pipeline (current):
//!   Event Fabric -> Flow Engine (Phase 6) -> Detection Engine (Phase 7)
//!   -> [Phase 9+: Correlation]
//!   -> [Phase 12+: Policy]
//!   -> [Phase 14+: Forensics]
//!
//! main() no longer knows pipeline details — Runtime owns lifecycle.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const flow_int = @import("flow_integration.zig");
const detection_int = @import("detection_integration.zig");

// ============================================================
// Pipeline stages
// ============================================================

/// Process a single event through the pipeline.
/// Phase 6: routes through Flow Engine.
/// Phase 7: routes through Detection Engine (evidence producer).
/// Future phases add: correlation -> policy -> forensics.
pub fn processEvent(event: canonical.CanonicalEvent) void {
    // Phase 6: route through Flow Engine
    var flow_update_opt: ?@import("flow_engine.zig").FlowUpdate = null;

    if (flow_int.isInitialized()) {
        flow_update_opt = flow_int.processEvent(event);

        if (flow_update_opt) |update| {
            // Log flow updates (forensics will replace this in Phase 14)
            switch (update.kind) {
                .flow_created => {
                    std.log.info("[DISPATCHER] Flow created: ip_a=0x{x} port_a={d} ip_b=0x{x} port_b={d} proto={d}", .{
                        update.key.ip_a, update.key.port_a,
                        update.key.ip_b, update.key.port_b,
                        update.key.protocol,
                    });
                },
                .flow_state_changed => {
                    std.log.debug("[DISPATCHER] Flow state changed: {s} (event_id={d})", .{
                        update.flow.state.toString(),
                        event.event_id,
                    });
                },
                .flow_expired => {
                    std.log.info("[DISPATCHER] Flow expired: packets={d} bytes={d}", .{
                        update.flow.packet_count,
                        update.flow.byte_count,
                    });
                },
                .flow_ended, .flow_updated => {
                    // Quietly track - logged at debug level only
                    std.log.debug("[DISPATCHER] Flow {s}: packets={d} bytes={d}", .{
                        update.flow.state.toString(),
                        update.flow.packet_count,
                        update.flow.byte_count,
                    });
                },
            }
        }
    } else {
        std.log.debug("[DISPATCHER] Flow not initialized, skipping event_id={d}", .{event.event_id});
    }

    // Phase 7: route through Detection Engine (evidence producer)
    if (detection_int.isInitialized()) {
        const evidence_list = detection_int.analyze(event, flow_update_opt);

        if (evidence_list.count > 0) {
            const max_verdict = evidence_list.maxVerdict();
            if (max_verdict.isThreat()) {
                std.log.info("[DISPATCHER] Detection verdict={s} for event_id={d} ({d} evidence)", .{
                    max_verdict.toString(),
                    event.event_id,
                    evidence_list.count,
                });

                // Log each threat evidence at info level
                for (evidence_list.slice()) |e| {
                    if (e.verdict.isThreat()) {
                        std.log.info("[DETECTION] detector={d} verdict={s} rule=0x{x} confidence={d} desc={s}", .{
                            e.detector_id,
                            e.verdict.toString(),
                            e.rule_id,
                            e.confidence,
                            e.description,
                        });
                    }
                }
            } else {
                std.log.debug("[DISPATCHER] Detection verdict={s} for event_id={d}", .{
                    max_verdict.toString(),
                    event.event_id,
                });
            }
        }
    }

    // Phase 9+: correlation_int.submitEvidence(evidence_list)
    // Phase 12+: policy_int.evaluateAndEnforce(event, evidence_list)
    // Phase 14+: forensics_int.logPipelineResult(event, evidence_list)
}

/// Drain the event fabric queue — pops all pending events and processes them.
/// Called by worker threads.
pub fn drainQueue(max_events: u32) u32 {
    if (!fabric.isInitialized()) return 0;

    var processed: u32 = 0;
    while (processed < max_events) {
        const event = fabric.popEvent() orelse break;
        processEvent(event);
        processed += 1;
    }
    return processed;
}

// ============================================================
// Tests
// ============================================================

test "drainQueue returns 0 when fabric not initialized" {
    if (fabric.isInitialized()) {
        const nose = @import("nose_contract.zig");
        nose.shutdownFabric(std.testing.allocator);
    }
    try std.testing.expect(drainQueue(100) == 0);
}

test "drainQueue processes events from fabric" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // Submit some events
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = fabric.submitEvent(event);
    }

    // Drain
    const processed = drainQueue(100);
    try std.testing.expect(processed == 5);
}

test "drainQueue respects max_events limit" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = fabric.submitEvent(event);
    }

    const processed = drainQueue(3);
    try std.testing.expect(processed == 3);
}

test "processEvent doesn't crash for valid event" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    processEvent(event);
    try std.testing.expect(true);
}

test "processEvent routes through Flow Engine when initialized" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // Initialize Flow Engine (idempotent - safe if already initialized by another test)
    if (!flow_int.isInitialized()) {
        flow_int.init(std.testing.allocator);
    }
    defer flow_int.shutdown();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;

    processEvent(event);

    // Verify the specific flow was created (robust against parallel test interference).
    // Checking flow_int.count() would be flaky if another test also created a flow.
    const flow_engine = @import("flow_engine.zig");
    const key = flow_engine.FlowKey.fromEvent(event);
    const retrieved = flow_int.getFlow(key);
    try std.testing.expect(retrieved != null);
    try std.testing.expect(retrieved.?.byte_count == 100);
    try std.testing.expect(retrieved.?.packet_count == 1);
}

test "processEvent routes through Detection Engine when initialized" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // Initialize Flow + Detection
    if (!flow_int.isInitialized()) {
        flow_int.init(std.testing.allocator);
    }
    defer flow_int.shutdown();

    if (!detection_int.isInitialized()) {
        detection_int.init();
    }
    defer detection_int.shutdown();

    // Event with rule match -> should produce suspicious evidence
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xDEAD;
    event.severity = 2;

    processEvent(event);

    // Verify detection stats accumulated
    const stats = detection_int.getStats();
    try std.testing.expect(stats.total_analyzed >= 1);
    try std.testing.expect(stats.total_threats >= 1);
}
