//! lifecycle.zig - AEGIS Runtime Lifecycle (Rewrite Phase 10)
//!
//! Manages init/shutdown of all subsystems in correct order.
//! main() calls runtime.start() and runtime.shutdown() - nothing else.
//!
//! Phase 10 changes (on top of Phase 9):
//!   - Added Threat Intel to start()/shutdown() sequence.
//!   - Threat Intel is initialized AFTER Correlation (it provides enrichment context).

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const nose = @import("nose_contract.zig");
const nose_int = @import("nose_integration.zig");
const flow_int = @import("flow_integration.zig");
const detection_int = @import("detection_integration.zig");
const correlation_int = @import("correlation_integration.zig");
const threat_intel_int = @import("threat_intel_integration.zig");
const forensic_log = @import("forensic_log.zig");

// Forward declaration of dispatcher's aggregator init/shutdown functions.
// We import dispatcher at call site (lazy import) to avoid circular dependency:
// dispatcher.zig imports flow_int + detection_int, but lifecycle imports dispatcher.

// ============================================================
// Lifecycle states
// ============================================================

pub const State = enum(u8) {
    init = 0,
    starting = 1,
    running = 2,
    draining = 3,
    stopped = 4,

    pub fn toString(self: State) []const u8 {
        return switch (self) {
            .init => "INIT",
            .starting => "STARTING",
            .running => "RUNNING",
            .draining => "DRAINING",
            .stopped => "STOPPED",
        };
    }
};

var g_state: State = .init;
var g_allocator: ?std.mem.Allocator = null;

// ============================================================
// Start (init all subsystems in order)
// ============================================================

pub fn start(allocator: std.mem.Allocator) !void {
    switch (g_state) {
        .starting, .running => return,
        .init, .stopped, .draining => {},
    }
    g_state = .starting;
    g_allocator = allocator;

    // 1. Forensic logger (needs to log everything from start)
    forensic_log.init();
    defer if (g_state != .running) forensic_log.shutdown();

    // 2. Event Fabric (queue must be ready before sensors)
    try nose.initFabric(allocator, .{ .capacity_per_priority = 256 });
    defer if (g_state != .running) nose.shutdownFabric(allocator);

    // 3. Nose Contract (validation must be ready before events)
    // (nose_contract delegates to event_fabric, already initialized)

    // 4. Nose Integration (pressure-aware sampling)
    nose_int.init(nose_int.SamplingPolicy.default);

    // 5. Flow Engine (Phase 6) - tracks connections, emits FlowUpdate
    flow_int.init(allocator);
    defer if (g_state != .running) flow_int.shutdown();

    // 6. Detection Engine (Phase 7) - evidence producer
    // Needs FlowUpdate as input, so must init AFTER Flow.
    detection_int.init();
    defer if (g_state != .running) detection_int.shutdown();

    // 7. Verdict Aggregator (Phase 8) - consumes evidence from Detection
    // Owned by dispatcher module (lazy import to avoid circular dependency).
    const dispatcher = @import("dispatcher.zig");
    dispatcher.initAggregator();
    defer if (g_state != .running) dispatcher.shutdownAggregator();

    // 8. Correlation Engine (Phase 9) - entity tracking across flows
    // Consumes AggregatedVerdict, produces CorrelationAlerts.
    correlation_int.init(allocator);
    defer if (g_state != .running) correlation_int.shutdown();

    // 9. Threat Intel (Phase 10) - IP blocklist + enrichment
    // Advisor: provides context to correlation/policy, does not enforce.
    threat_intel_int.init(allocator);
    defer if (g_state != .running) threat_intel_int.shutdown();

    // Phase 11+: Brain
    // Phase 12+: Policy
    // Phase 13+: Rust PEP

    g_state = .running;
    std.log.info("[RUNTIME] Started (state={s})", .{g_state.toString()});
}

// ============================================================
// Shutdown (reverse order)
// ============================================================

pub fn shutdown() void {
    if (g_state == .stopped) return;
    if (g_state == .init) return;
    g_state = .draining;

    const allocator = g_allocator orelse {
        g_state = .init;
        return;
    };

    // Drain queue (process remaining events)
    const dispatcher = @import("dispatcher.zig");
    _ = dispatcher.drainQueue(1000);

    // Shutdown in reverse order:
    // 9. Threat Intel (Phase 10)
    threat_intel_int.shutdown();
    // 8. Correlation Engine (Phase 9)
    correlation_int.shutdown();
    // 7. Verdict Aggregator (Phase 8)
    dispatcher.shutdownAggregator();
    // 6. Detection Engine (Phase 7)
    detection_int.shutdown();
    // 5. Flow Engine (Phase 6)
    flow_int.shutdown();
    // 4. nose_integration has no shutdown() - just reset stats
    nose_int.resetStats();
    // 2. Event Fabric
    nose.shutdownFabric(allocator);
    // 1. Forensic logger
    forensic_log.shutdown();

    g_state = .init;
    g_allocator = null;
    std.log.info("[RUNTIME] Stopped", .{});
}

// ============================================================
// State queries
// ============================================================

pub fn getState() State {
    return g_state;
}

pub fn isRunning() bool {
    return g_state == .running;
}

pub fn getAllocator() ?std.mem.Allocator {
    return g_allocator;
}

// ============================================================
// Tests (all stateful tests merged into ONE serial test)
// ============================================================

test "State.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, State.init.toString(), "INIT"));
    try std.testing.expect(std.mem.eql(u8, State.running.toString(), "RUNNING"));
    try std.testing.expect(std.mem.eql(u8, State.stopped.toString(), "STOPPED"));
    try std.testing.expect(std.mem.eql(u8, State.draining.toString(), "DRAINING"));
    try std.testing.expect(std.mem.eql(u8, State.starting.toString(), "STARTING"));
}

test "lifecycle: full sequence (start, double-start, shutdown, double-shutdown)" {
    if (fabric.isInitialized()) {
        shutdown();
    }

    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    try std.testing.expect(getState() == .running);

    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    try std.testing.expect(getState() == .running);

    shutdown();
    try std.testing.expect(!isRunning());
    try std.testing.expect(getState() == .init);

    shutdown();
    shutdown();
    try std.testing.expect(getState() == .init);
    try std.testing.expect(!isRunning());

    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    shutdown();
    try std.testing.expect(getState() == .init);
}

test "lifecycle: all subsystems initialized after start" {
    if (fabric.isInitialized()) {
        shutdown();
    }

    try start(std.testing.allocator);
    try std.testing.expect(flow_int.isInitialized());
    try std.testing.expect(detection_int.isInitialized());
    try std.testing.expect(correlation_int.isInitialized());
    try std.testing.expect(threat_intel_int.isInitialized());

    const dispatcher = @import("dispatcher.zig");
    try std.testing.expect(dispatcher.isAggregatorInitialized());

    shutdown();
    try std.testing.expect(!flow_int.isInitialized());
    try std.testing.expect(!detection_int.isInitialized());
    try std.testing.expect(!correlation_int.isInitialized());
    try std.testing.expect(!threat_intel_int.isInitialized());
    try std.testing.expect(!dispatcher.isAggregatorInitialized());
}
