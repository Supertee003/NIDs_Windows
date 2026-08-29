//! lifecycle.zig - AEGIS Runtime Lifecycle (Rewrite Phase 5, Hotfix 6)
//!
//! Manages init/shutdown of all subsystems in correct order.
//! main() calls runtime.start() and runtime.shutdown() - nothing else.
//!
//! Hotfix 6 changes (on top of Hotfix 5):
//!   1. Merge "double start is no-op" + "double shutdown is no-op" into a single
//!      serial test "lifecycle: full sequence". This avoids Zig's default parallel
//!      test execution within the same file racing on shared global state.
//!   2. Fix deploy path: deploy to core/lifecycle.zig (NOT core/runtime/lifecycle.zig)
//!      because hotfix2 moved runtime files to core/ to fix `zig test` direct
//!      invocation path resolution.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const nose = @import("nose_contract.zig");
const nose_int = @import("nose_integration.zig");
const forensic_log = @import("forensic_log.zig");

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
    // Allow start() to proceed from .init, .stopped, or .draining.
    // Only bail if we are already .starting or .running (true no-op).
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
    nose_int.init(.default);

    // Phase 6+: Flow engine
    // Phase 7+: Detection
    // Phase 9+: Correlation
    // Phase 10+: Threat intel
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

    // Shutdown in reverse order
    // nose_integration has no shutdown() - just reset stats
    nose_int.resetStats();
    nose.shutdownFabric(allocator);
    forensic_log.shutdown();

    // Reset to .init so tests can re-run
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
// Tests
// ============================================================
// Hotfix 6: Merged the parallel-unsafe tests into ONE serial test.
// Zig 0.13 runs tests within a single file in parallel by default,
// which races on g_state (shared global). Combining all lifecycle
// state transitions into one test eliminates the race.

test "State.toString returns readable names" {
    // Pure function, no shared state, safe to run in parallel.
    try std.testing.expect(std.mem.eql(u8, State.init.toString(), "INIT"));
    try std.testing.expect(std.mem.eql(u8, State.running.toString(), "RUNNING"));
    try std.testing.expect(std.mem.eql(u8, State.stopped.toString(), "STOPPED"));
    try std.testing.expect(std.mem.eql(u8, State.draining.toString(), "DRAINING"));
    try std.testing.expect(std.mem.eql(u8, State.starting.toString(), "STARTING"));
}

test "lifecycle: full sequence (start, double-start, shutdown, double-shutdown)" {
    // Clean slate: shutdown if anything is running.
    if (fabric.isInitialized()) {
        shutdown();
    }

    // --- Phase A: first start ---
    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    try std.testing.expect(getState() == .running);

    // --- Phase B: double-start is no-op ---
    // State is .running, so second start() must bail early without error.
    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    try std.testing.expect(getState() == .running);

    // --- Phase C: first shutdown ---
    shutdown();
    try std.testing.expect(!isRunning());
    try std.testing.expect(getState() == .init);

    // --- Phase D: double-shutdown is no-op ---
    // State is .init, so second shutdown() must bail early without error.
    shutdown();
    shutdown();
    try std.testing.expect(getState() == .init);
    try std.testing.expect(!isRunning());

    // --- Phase E: restart from .init (proves shutdown reset state) ---
    try start(std.testing.allocator);
    try std.testing.expect(isRunning());
    shutdown();
    try std.testing.expect(getState() == .init);
}
