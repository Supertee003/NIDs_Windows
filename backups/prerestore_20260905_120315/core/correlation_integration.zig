//! correlation_integration.zig - AEGIS Correlation Integration (Phase 9)
//!
//! Thin facade over correlation_engine.zig that owns a singleton
//! CorrelationEngine. Provides processVerdict() API consumed by dispatcher.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const detection = @import("detection_engine.zig");
const correlation = @import("correlation_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");

var g_engine: ?correlation.CorrelationEngine = null;
var g_initialized: bool = false;
var g_allocator: std.mem.Allocator = std.heap.page_allocator;
var g_total_verdicts: u64 = 0;
var g_total_alerts: u64 = 0;

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_engine = correlation.CorrelationEngine.init(allocator);
    g_allocator = allocator;
    g_initialized = true;
    g_total_verdicts = 0;
    g_total_alerts = 0;
    std.log.info("[CORRELATION] Correlation integration initialized", .{});
}

pub fn isInitialized() bool { return g_initialized; }

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_engine) |*engine| engine.deinit();
    g_engine = null;
    g_initialized = false;
    std.log.info("[CORRELATION] Correlation integration shutdown", .{});
}

pub fn processVerdict(
    event: canonical.CanonicalEvent,
    flow_update: ?flow.FlowUpdate,
    av: verdict_agg.AggregatedVerdict,
) [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert {
    g_total_verdicts += 1;
    if (!g_initialized) return .{null} ** 3;
    if (g_engine) |*engine| {
        const alerts = engine.processVerdict(event, flow_update, av.verdict, av.confidence);
        for (alerts) |a| {
            if (a != null) g_total_alerts += 1;
        }
        return alerts;
    }
    return .{null} ** 3;
}

pub fn getStats() struct { total_verdicts: u64, total_alerts: u64 } {
    return .{ .total_verdicts = g_total_verdicts, .total_alerts = g_total_alerts };
}

pub fn resetStats() void {
    g_total_verdicts = 0;
    g_total_alerts = 0;
    if (g_engine) |*engine| engine.resetStats();
}

test "correlation_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init(std.testing.allocator);
    defer shutdown();
    try std.testing.expect(isInitialized());

    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.severity = 2;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .malicious,
        .original_verdict = .malicious,
        .confidence = 80,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = event.event_id,
    };

    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        const alerts = processVerdict(event, null, av);
        _ = alerts;
    }

    const stats = getStats();
    try std.testing.expect(stats.total_verdicts == 3);
}

test "correlation_integration: returns empty when not initialized" {
    if (isInitialized()) shutdown();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .benign,
        .original_verdict = .benign,
        .confidence = 30,
        .agreeing_count = 0,
        .detector_count = 0,
        .escalated = false,
        .event_id = 0,
    };
    const alerts = processVerdict(event, null, av);
    for (alerts) |a| try std.testing.expect(a == null);
}
