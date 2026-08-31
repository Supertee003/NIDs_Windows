//! flow_integration.zig - AEGIS Flow Integration (Rewrite Phase 6)
//!
//! Thin facade over flow_engine.zig that owns a singleton FlowEngine.
//! Mirrors the pattern of nose_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()    -> create FlowEngine with default config
//!   processEvent(event) -> returns FlowUpdate
//!   sweepExpired(now_ns) -> evict idle flows
//!   shutdown() -> deinit FlowEngine
//!
//! Pressure-aware: when fabric is saturated, can defer flow updates
//! (skip non-critical updates to keep hot path fast).

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow_engine = @import("flow_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?flow_engine.FlowEngine = null;
var g_initialized: bool = false;
var g_allocator: ?std.mem.Allocator = null;

// Lifetime stats (independent of FlowEngine instance)
var g_total_flow_updates: u64 = 0;
var g_total_flow_created: u64 = 0;
var g_total_flow_expired: u64 = 0;
var g_total_flow_ended: u64 = 0;

// ============================================================
// Initialization
// ============================================================

/// Initialize the Flow Engine with default configuration.
/// Idle timeout: 60 seconds, max flows: 65536.
pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_engine = flow_engine.FlowEngine.init(allocator);
    g_allocator = allocator;
    g_initialized = true;
    g_total_flow_updates = 0;
    g_total_flow_created = 0;
    g_total_flow_expired = 0;
    g_total_flow_ended = 0;
    std.log.info("[FLOW] Flow integration initialized", .{});
}

/// Configure the Flow Engine (must be called after init).
pub fn configure(idle_timeout_ns: i128, max_flows: usize) void {
    if (g_engine) |*engine| {
        engine.configure(idle_timeout_ns, max_flows);
    }
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_flow_updates = 0;
    g_total_flow_created = 0;
    g_total_flow_expired = 0;
    g_total_flow_ended = 0;
    if (g_engine) |*engine| {
        engine.total_created = 0;
        engine.total_expired = 0;
        engine.total_ended = 0;
        engine.total_packets = 0;
        engine.total_bytes = 0;
    }
}

// ============================================================
// Event Processing
// ============================================================

/// Process a CanonicalEvent and return a FlowUpdate.
/// This is the main entry point — dispatcher calls this for every event.
/// Returns null if not initialized.
pub fn processEvent(event: canonical.CanonicalEvent) ?flow_engine.FlowUpdate {
    if (!g_initialized) return null;
    if (g_engine) |*engine| {
        const update = engine.processEvent(event);
        g_total_flow_updates += 1;
        switch (update.kind) {
            .flow_created => g_total_flow_created += 1,
            .flow_expired => g_total_flow_expired += 1,
            .flow_ended => g_total_flow_ended += 1,
            .flow_updated, .flow_state_changed => {},
        }
        return update;
    }
    return null;
}

/// Sweep expired flows. Returns count evicted.
pub fn sweepExpired(now_ns: i128) usize {
    if (!g_initialized) return 0;
    if (g_engine) |*engine| {
        const n = engine.sweepExpired(now_ns);
        g_total_flow_expired += n;
        return n;
    }
    return 0;
}

/// Get a flow by key (read-only).
pub fn getFlow(key: flow_engine.FlowKey) ?flow_engine.Flow {
    if (g_engine) |*engine| {
        return engine.getFlow(key);
    }
    return null;
}

/// Current number of tracked flows.
pub fn count() usize {
    if (g_engine) |*engine| {
        return engine.count();
    }
    return 0;
}

// ============================================================
// Stats
// ============================================================

pub const FlowStats = struct {
    total_updates: u64,
    total_created: u64,
    total_expired: u64,
    total_ended: u64,
    current_flows: usize,
    engine_packets: u64,
    engine_bytes: u64,
};

pub fn getStats() FlowStats {
    var stats = FlowStats{
        .total_updates = g_total_flow_updates,
        .total_created = g_total_flow_created,
        .total_expired = g_total_flow_expired,
        .total_ended = g_total_flow_ended,
        .current_flows = 0,
        .engine_packets = 0,
        .engine_bytes = 0,
    };
    if (g_engine) |*engine| {
        stats.current_flows = engine.count();
        stats.engine_packets = engine.total_packets;
        stats.engine_bytes = engine.total_bytes;
    }
    return stats;
}

// ============================================================
// Shutdown
// ============================================================

/// Shutdown the Flow Engine and release resources.
pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_engine) |*engine| {
        engine.deinit();
    }
    g_engine = null;
    g_allocator = null;
    g_initialized = false;
    std.log.info("[FLOW] Flow integration shutdown", .{});
}

// ============================================================
// Tests
// ============================================================
// All tests merged into ONE serial test to avoid Zig 0.13's
// default parallel test execution racing on g_engine (shared global).
// Pattern proven in lifecycle.zig (Phase 5 Hotfix 6).

test "flow integration: full lifecycle (init, process, sweep, configure, reset, get, null-when-uninitialized)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: processEvent returns null when not initialized ---
    var event = canonical.create(.wfp_sensor);
    const null_update = processEvent(event);
    try std.testing.expect(null_update == null);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init(std.testing.allocator);
    try std.testing.expect(isInitialized());
    try std.testing.expect(count() == 0);

    // --- Phase C: configure ---
    configure(5 * std.time.ns_per_s, 2000);
    if (g_engine) |engine| {
        try std.testing.expect(engine.idle_timeout_ns == 5 * std.time.ns_per_s);
        try std.testing.expect(engine.max_flows == 2000);
    }

    // --- Phase D: processEvent creates a flow ---
    event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;

    const update = processEvent(event);
    try std.testing.expect(update != null);
    try std.testing.expect(update.?.kind == .flow_created);

    const stats_after_create = getStats();
    try std.testing.expect(stats_after_create.total_created == 1);
    try std.testing.expect(stats_after_create.total_updates == 1);

    // --- Phase E: getFlow retrieves the flow by key ---
    const key = flow_engine.FlowKey.fromEvent(event);
    const retrieved = getFlow(key);
    try std.testing.expect(retrieved != null);
    try std.testing.expect(retrieved.?.byte_count == 100);
    try std.testing.expect(retrieved.?.packet_count == 1);

    // --- Phase F: reconfigure to short timeout, test sweepExpired ---
    configure(100 * std.time.ns_per_ms, 1000);

    // Create a flow with monotonic_ns = 0
    event.monotonic_ns = 0;
    _ = processEvent(event);

    // Sweep at t=50ms - should not evict (idle < 100ms)
    var n = sweepExpired(50 * std.time.ns_per_ms);
    try std.testing.expect(n == 0);

    // Sweep at t=200ms - should evict (idle > 100ms)
    n = sweepExpired(200 * std.time.ns_per_ms);
    try std.testing.expect(n >= 1);

    // --- Phase G: resetStats zeroes counters ---
    resetStats();
    try std.testing.expect(getStats().total_updates == 0);

    // --- Phase H: double-init is no-op, double-shutdown is no-op ---
    init(std.testing.allocator); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase I: after shutdown, processEvent returns null again ---
    const null_update2 = processEvent(event);
    try std.testing.expect(null_update2 == null);
}
