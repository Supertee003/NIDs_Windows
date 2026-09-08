//! flow_integration.zig - AEGIS Flow Integration (Rewrite Phase 6)
//!
//! Thin facade over flow_engine.zig that owns a singleton FlowEngine.
//! Provides the per-event API consumed by the dispatcher.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()                -> create FlowEngine
//!   processEvent(event)   -> ?FlowUpdate  (null if engine not initialized)
//!   shutdown()            -> release engine

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?flow.FlowEngine = null;
var g_allocator: std.mem.Allocator = std.heap.page_allocator;
var g_initialized: bool = false;

// Lifetime stats
var g_total_events: u64 = 0;
var g_total_flows_created: u64 = 0;
var g_total_packets: u64 = 0;
var g_total_bytes: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_engine = flow.FlowEngine.init(allocator);
    g_allocator = allocator;
    g_initialized = true;
    g_total_events = 0;
    g_total_flows_created = 0;
    g_total_packets = 0;
    g_total_bytes = 0;
    std.log.info("[FLOW] Flow integration initialized", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_engine) |*engine| {
        engine.deinit();
    }
    g_engine = null;
    g_initialized = false;
    std.log.info("[FLOW] Flow integration shutdown", .{});
}

// ============================================================
// Event Processing
// ============================================================

/// Process a CanonicalEvent. Returns a FlowUpdate if a flow was touched,
/// null otherwise (e.g., non-network events).
pub fn processEvent(event: canonical.CanonicalEvent) ?flow.FlowUpdate {
    if (!g_initialized) return null;
    if (g_engine) |*engine| {
        g_total_events += 1;

        // Skip events that have no network 5-tuple
        if (event.source_ip == 0 and event.dest_ip == 0) return null;

        const key = flow.FlowKey{
            .ip_a = event.source_ip,
            .port_a = event.source_port,
            .ip_b = event.dest_ip,
            .port_b = event.dest_port,
            .protocol = event.protocol,
        };

        const bytes = if (event.payload_length > 0) event.payload_length else 64;
        const sev = event.severity;
        const rule_id = event.rule_id;

        const upd = engine.processPacket(key, bytes, sev, rule_id) catch return null;
        if (upd.isCreated()) g_total_flows_created += 1;
        g_total_packets += 1;
        g_total_bytes += bytes;
        return upd;
    }
    return null;
}

// ============================================================
// Stats
// ============================================================

pub const FlowIntegrationStats = struct {
    total_events: u64,
    total_flows_created: u64,
    total_packets: u64,
    total_bytes: u64,
};

pub fn getStats() FlowIntegrationStats {
    if (g_initialized) {
        return .{
            .total_events = g_total_events,
            .total_flows_created = g_total_flows_created,
            .total_packets = g_total_packets,
            .total_bytes = g_total_bytes,
        };
    }
    return .{
        .total_events = 0,
        .total_flows_created = 0,
        .total_packets = 0,
        .total_bytes = 0,
    };
}

pub fn resetStats() void {
    g_total_events = 0;
    g_total_flows_created = 0;
    g_total_packets = 0;
    g_total_bytes = 0;
}

/// Active flow count (forwarded to engine).
pub fn activeFlowCount() usize {
    if (g_engine) |*engine| return engine.count();
    return 0;
}

// ============================================================
// Tests (serial - singleton state)
// ============================================================

test "flow_integration: full lifecycle" {
    // Start clean
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init(std.testing.allocator);
    try std.testing.expect(isInitialized());

    // Process a network event
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 256;

    const upd = processEvent(event);
    try std.testing.expect(upd != null);
    try std.testing.expect(upd.?.isCreated());

    // Process same flow again - should be update not create
    const upd2 = processEvent(event);
    try std.testing.expect(upd2 != null);
    try std.testing.expect(!upd2.?.isCreated());

    const stats = getStats();
    try std.testing.expect(stats.total_events == 2);
    try std.testing.expect(stats.total_flows_created == 1);
    try std.testing.expect(stats.total_packets == 2);
    try std.testing.expect(stats.total_bytes == 512);

    try std.testing.expect(activeFlowCount() == 1);

    shutdown();
    try std.testing.expect(!isInitialized());
}

test "flow_integration: processEvent returns null when not initialized" {
    if (isInitialized()) shutdown();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    try std.testing.expect(processEvent(event) == null);
}

test "flow_integration: processEvent returns null for non-network events" {
    if (isInitialized()) shutdown();
    init(std.testing.allocator);
    defer shutdown();

    var event = canonical.create(.zig_core);
    event.source_ip = 0;
    event.dest_ip = 0;
    try std.testing.expect(processEvent(event) == null);
}
