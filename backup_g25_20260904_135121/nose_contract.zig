//! nose_contract.zig - AEGIS Nose -> Event Fabric Contract (Rewrite Phase 3)
//!
//! REWRITE v3.0 Phase 3: Updated to import event_fabric.zig (newly created).
//!
//! This is a thin facade over event_fabric.zig.
//! Legacy API preserved for backward compatibility with sensors.
//!
//! Contract:
//!   1. Sensor creates CanonicalEvent via createEvent()
//!   2. Sensor fills in detection-specific fields
//!   3. Sensor calls submitEvent() — validates and enqueues
//!   4. Event Fabric routes to appropriate priority queue
//!   5. Detection layer pops from queue and processes

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");

// Re-export priority_queue for backward compat
pub const pq = @import("priority_queue.zig");

// ============================================================
// Submit result (legacy enum)
// ============================================================

pub const SubmitResult = enum {
    accepted,
    rejected,
    dropped,
    not_initialized,
};

// ============================================================
// Legacy config (delegates to event_fabric.FabricConfig)
// ============================================================

pub const FabricConfig = struct {
    capacity_per_priority: usize = 256,
    validate_on_submit: bool = true,
    enforce_wire_format: bool = false,
};

// ============================================================
// Legacy stats (subset of FabricMetrics)
// ============================================================

pub const FabricStats = struct {
    initialized: bool,
    pending: usize,
    accepted: u64,
    rejected: u64,
    dropped: u64,
    high_pending: usize = 0,
    normal_pending: usize = 0,
    low_pending: usize = 0,
};

// ============================================================
// Initialization (delegates to event_fabric)
// ============================================================

pub fn initFabric(allocator: std.mem.Allocator, config: FabricConfig) !void {
    const new_config = fabric.FabricConfig{
        .capacity_per_priority = config.capacity_per_priority,
        .validate_on_submit = config.validate_on_submit,
        .medium_threshold = 0.50,
        .high_threshold = 0.80,
        .drop_policy = .block_new,
    };
    try fabric.initFabric(allocator, new_config);
}

pub fn shutdownFabric(allocator: std.mem.Allocator) void {
    fabric.shutdownFabric(allocator);
}

// ============================================================
// Sensor Interface
// ============================================================

pub fn createEvent(source: canonical.EventSource) canonical.CanonicalEvent {
    return canonical.create(source);
}

pub fn submitEvent(event: canonical.CanonicalEvent) SubmitResult {
    if (!fabric.isInitialized()) return .not_initialized;

    const result = fabric.submitWithBackpressure(event);
    if (result.accepted) return .accepted;
    if (result.pressure == .saturated) return .dropped;
    return .rejected;
}

pub fn submitWireEvent(wire_bytes: []const u8) SubmitResult {
    if (!fabric.isInitialized()) return .not_initialized;
    const ok = fabric.submitWireEvent(wire_bytes);
    if (ok) return .accepted;
    if (fabric.currentPressure() == .saturated) return .dropped;
    return .rejected;
}

pub fn popEvent() ?canonical.CanonicalEvent {
    return fabric.popEvent();
}

pub fn hasEvents() bool {
    return fabric.hasEvents();
}

pub fn pendingCount() usize {
    return fabric.pendingCount();
}

// ============================================================
// Backpressure-aware API (new in Phase 3)
// ============================================================

pub fn currentPressure() fabric.Pressure {
    return fabric.currentPressure();
}

pub fn submitWithBackpressure(event: canonical.CanonicalEvent) fabric.SubmitWithPressure {
    return fabric.submitWithBackpressure(event);
}

pub fn getMetrics() fabric.FabricMetrics {
    return fabric.getMetrics();
}

pub fn getStats() FabricStats {
    const m = fabric.getMetrics();
    return .{
        .initialized = m.initialized,
        .pending = m.pending,
        .accepted = m.total_accepted,
        .rejected = m.total_rejected,
        .dropped = m.total_dropped,
        .high_pending = m.high_pending,
        .normal_pending = m.normal_pending,
        .low_pending = m.low_pending,
    };
}

// ============================================================
// Tests
// ============================================================

test "createEvent returns valid CanonicalEvent" {
    const event = createEvent(.zig_core);
    try std.testing.expect(canonical.validate(&event));
    try std.testing.expect(event.source == .zig_core);
}

test "submitEvent before init returns not_initialized" {
    if (fabric.isInitialized()) shutdownFabric(std.testing.allocator);
    const event = createEvent(.zig_core);
    try std.testing.expect(submitEvent(event) == .not_initialized);
}

test "submitEvent accepts valid event" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();

    var event = createEvent(.wfp_sensor);
    event.event_type = .block;
    try std.testing.expect(submitEvent(event) == .accepted);
}

test "submitEvent rejects invalid event" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();

    var event = createEvent(.zig_core);
    event.magic = 0xDEADBEEF;
    try std.testing.expect(submitEvent(event) == .rejected);
}

test "submitEvent drops on overflow" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 2 });
    defer shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();

    var event = createEvent(.zig_core);
    event.event_type = .block;

    try std.testing.expect(submitEvent(event) == .accepted);
    try std.testing.expect(submitEvent(event) == .accepted);
    try std.testing.expect(submitEvent(event) == .dropped);
}

test "popEvent returns null when empty" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    try std.testing.expect(popEvent() == null);
}

test "popEvent returns highest priority first" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();

    var low_e = createEvent(.pipe_sensor);
    low_e.event_type = .forward;
    low_e.event_id = 100;
    _ = submitEvent(low_e);

    var high_e = createEvent(.wfp_sensor);
    high_e.event_type = .block;
    high_e.event_id = 200;
    _ = submitEvent(high_e);

    const popped = popEvent().?;
    try std.testing.expect(popped.event_id == 200);
}

test "hasEvents and pendingCount" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();

    try std.testing.expect(!hasEvents());
    try std.testing.expect(pendingCount() == 0);

    var event = createEvent(.zig_core);
    event.event_type = .match_;
    _ = submitEvent(event);

    try std.testing.expect(hasEvents());
    try std.testing.expect(pendingCount() == 1);
}

test "getStats tracks all counters" {
    try initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 });
    defer shutdownFabric(std.testing.allocator);
    fabric.resetMetrics();

    var e1 = createEvent(.zig_core);
    e1.event_type = .block;
    _ = submitEvent(e1);

    var e2 = createEvent(.zig_core);
    e2.event_type = .forward;
    _ = submitEvent(e2);

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.pending == 2);
    try std.testing.expect(stats.accepted == 2);
    try std.testing.expect(stats.high_pending == 1);
    try std.testing.expect(stats.low_pending == 1);
}

test "FabricConfig defaults" {
    const config = FabricConfig{};
    try std.testing.expect(config.capacity_per_priority == 256);
    try std.testing.expect(config.validate_on_submit == true);
}
