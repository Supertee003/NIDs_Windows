//! nose_integration.zig - AEGIS Nose Integration (Phase 5)
//!
//! Sampling policy facade over nose_contract.zig. The actual Event Fabric
//! is initialized by lifecycle.zig (step 2: nose.initFabric). This module
//! just holds the active SamplingPolicy for downstream queries.
//!
//! Contract (consumed by lifecycle.zig):
//!   SamplingPolicy: enum (default, high_throughput, paranoid)
//!   init(policy)   -> set active policy
//!   isInitialized() -> bool
//!   shutdown()      -> clear policy
//!   resetStats()   -> no-op (forensic_log style)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const nose = @import("nose_contract.zig");

var g_initialized: bool = false;
var g_policy: SamplingPolicy = .default;

pub const SamplingPolicy = enum {
    default,
    high_throughput,
    paranoid,

    pub fn toString(self: SamplingPolicy) []const u8 {
        return switch (self) {
            .default => "DEFAULT",
            .high_throughput => "HIGH_THROUGHPUT",
            .paranoid => "PARANOID",
        };
    }
};

pub fn init(policy: SamplingPolicy) void {
    g_policy = policy;
    g_initialized = true;
    std.log.info("[NOSE] Nose integration initialized (policy={s})", .{policy.toString()});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    g_initialized = false;
    std.log.info("[NOSE] Nose integration shutdown", .{});
}

pub fn activePolicy() SamplingPolicy {
    return g_policy;
}

pub fn submitEvent(event: canonical.CanonicalEvent) nose.SubmitResult {
    return nose.submitEvent(event);
}

pub fn popEvent() ?canonical.CanonicalEvent {
    return nose.popEvent();
}

pub fn resetStats() void {
    std.log.debug("[NOSE] resetStats called (no-op)", .{});
}

// ============================================================
// Tests
// ============================================================

test "SamplingPolicy.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, SamplingPolicy.default.toString(), "DEFAULT"));
    try std.testing.expect(std.mem.eql(u8, SamplingPolicy.high_throughput.toString(), "HIGH_THROUGHPUT"));
    try std.testing.expect(std.mem.eql(u8, SamplingPolicy.paranoid.toString(), "PARANOID"));
}

test "nose_integration: init and shutdown" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init(.default);
    try std.testing.expect(isInitialized());
    try std.testing.expect(activePolicy() == .default);

    init(.paranoid);
    try std.testing.expect(activePolicy() == .paranoid);

    shutdown();
    try std.testing.expect(!isInitialized());
}

test "nose_integration: submitEvent and popEvent round-trip" {
    // Need to init the fabric first
    if (nose.isFabricInitialized()) nose.shutdownFabric(std.testing.allocator);
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    init(.default);
    defer shutdown();

    var event = canonical.create(.zig_core);
    event.event_id = 42;
    event.event_type = .block;

    const result = submitEvent(event);
    try std.testing.expect(result == .accepted);

    const popped = popEvent() orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(popped.event_id == 42);
    try std.testing.expect(popped.event_type == .block);
}

test "nose_integration: popEvent returns null on empty queue" {
    if (nose.isFabricInitialized()) nose.shutdownFabric(std.testing.allocator);
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    init(.default);
    defer shutdown();

    try std.testing.expect(popEvent() == null);
}

test "nose_integration: resetStats is no-op" {
    init(.default);
    defer shutdown();
    resetStats();
    try std.testing.expect(isInitialized());
}
