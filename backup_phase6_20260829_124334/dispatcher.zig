//! runtime/dispatcher.zig - AEGIS Runtime Dispatcher (Rewrite Phase 5)
//!
//! Pops events from Event Fabric and routes through the pipeline.
//! Replaces the old eventFabricDrain() in nids_analyze.zig.
//!
//! main() no longer knows pipeline details — Runtime owns lifecycle.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");

// ============================================================
// Pipeline stages (will be expanded in later phases)
// ============================================================

/// Process a single event through the pipeline.
/// Currently: pop -> log (Phase 5 minimal).
/// Future phases add: flow -> detection -> correlation -> policy -> forensics.
pub fn processEvent(event: canonical.CanonicalEvent) void {
    // Phase 5: minimal processing (just log)
    // Phase 6+: flow_int.processEvent(event)
    // Phase 7+: detection_int.processEvent(event)
    // Phase 9+: correlation_int.submitDetectionContext(...)
    // Phase 12+: policy_int.evaluateAndEnforce(...)
    // Phase 14+: forensics_int.logPipelineResult(...)

    std.log.debug("[DISPATCHER] Processing event_id={d}", .{event.event_id});
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
