//! correlation_integration.zig - AEGIS Correlation Integration (Rewrite Phase 9)
//!
//! Thin facade over correlation_engine.zig that owns a singleton CorrelationEngine.
//! Mirrors the pattern of detection_integration.zig and flow_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init(allocator)              -> create CorrelationEngine
//!   processVerdict(event, flow_update, av) -> returns [3]?CorrelationAlert
//!   shutdown()                   -> deinit CorrelationEngine

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?correlation.CorrelationEngine = null;
var g_initialized: bool = false;
var g_allocator: ?std.mem.Allocator = null;

// Lifetime stats
var g_total_verdicts: u64 = 0;
var g_total_threat_verdicts: u64 = 0;
var g_total_alerts: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_engine = correlation.CorrelationEngine.init(allocator);
    g_allocator = allocator;
    g_initialized = true;
    g_total_verdicts = 0;
    g_total_threat_verdicts = 0;
    g_total_alerts = 0;
    std.log.info("[CORRELATION] Correlation integration initialized", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_verdicts = 0;
    g_total_threat_verdicts = 0;
    g_total_alerts = 0;
    if (g_engine) |*engine| {
        engine.total_events_processed = 0;
        engine.total_threat_events = 0;
        engine.total_alerts = 0;
        engine.alerts_repeated_threats = 0;
        engine.alerts_port_scan = 0;
        engine.alerts_target_repeated = 0;
    }
}

// ============================================================
// Verdict Processing
// ============================================================

/// Process an aggregated verdict. Returns up to 3 correlation alerts.
/// Returns empty array (all null) if not initialized.
pub fn processVerdict(
    event: canonical.CanonicalEvent,
    flow_update: ?flow.FlowUpdate,
    av: verdict_agg.AggregatedVerdict,
) [3]?correlation.CorrelationAlert {
    if (!g_initialized) return .{ null, null, null };
    if (g_engine) |*engine| {
        const alerts = engine.processVerdict(event, flow_update, av);
        g_total_verdicts += 1;
        if (av.isThreat()) {
            g_total_threat_verdicts += 1;
        }
        for (alerts) |a| {
            if (a != null) {
                g_total_alerts += 1;
            }
        }
        return alerts;
    }
    return .{ null, null, null };
}

// ============================================================
// Stats
// ============================================================

pub const CorrelationStats = struct {
    total_verdicts: u64,
    total_threat_verdicts: u64,
    total_alerts: u64,
    entity_count: usize,
    alerts_repeated_threats: u64,
    alerts_port_scan: u64,
    alerts_target_repeated: u64,
};

pub fn getStats() CorrelationStats {
    if (g_engine) |*engine| {
        return .{
            .total_verdicts = g_total_verdicts,
            .total_threat_verdicts = g_total_threat_verdicts,
            .total_alerts = g_total_alerts,
            .entity_count = engine.entityCount(),
            .alerts_repeated_threats = engine.alerts_repeated_threats,
            .alerts_port_scan = engine.alerts_port_scan,
            .alerts_target_repeated = engine.alerts_target_repeated,
        };
    }
    return .{
        .total_verdicts = 0,
        .total_threat_verdicts = 0,
        .total_alerts = 0,
        .entity_count = 0,
        .alerts_repeated_threats = 0,
        .alerts_port_scan = 0,
        .alerts_target_repeated = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_engine) |*engine| {
        engine.deinit();
    }
    g_engine = null;
    g_allocator = null;
    g_initialized = false;
    std.log.info("[CORRELATION] Correlation integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "correlation integration: full lifecycle (init, process, alerts, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: processVerdict returns empty when not initialized ---
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.monotonic_ns = 1000;
    event.severity = 2;

    const av_threat = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 70,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = @import("detection_engine.zig").Indicator.RULE_MATCH,
        .event_id = event.event_id,
    };

    const empty_alerts = processVerdict(event, null, av_threat);
    try std.testing.expect(empty_alerts[0] == null);
    try std.testing.expect(empty_alerts[1] == null);
    try std.testing.expect(empty_alerts[2] == null);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init(std.testing.allocator);
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_verdicts == 0);
    try std.testing.expect(stats_init.entity_count == 0);

    // --- Phase C: send 3 threats from same src_ip (triggers repeated_threats) ---
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var ev = canonical.create(.wfp_sensor);
        ev.source_ip = 0x0A000001;
        ev.dest_ip = 0x0A000002;
        ev.dest_port = @intCast(80 + i);
        ev.monotonic_ns = @intCast(i * 1000);
        ev.severity = 2;

        const alerts = processVerdict(ev, null, av_threat);

        if (i < 2) {
            // First 2 threats: no alert (below threshold)
            try std.testing.expect(alerts[0] == null);
        } else {
            // 3rd threat: alert triggered
            var found_alert = false;
            for (alerts) |a| {
                if (a) |alert| {
                    if (alert.rule == .repeated_threats) {
                        found_alert = true;
                        try std.testing.expect(alert.threat_count >= 3);
                    }
                }
            }
            try std.testing.expect(found_alert);
        }
    }

    const stats_after = getStats();
    try std.testing.expect(stats_after.total_verdicts == 3);
    try std.testing.expect(stats_after.total_threat_verdicts == 3);
    try std.testing.expect(stats_after.total_alerts == 1);
    try std.testing.expect(stats_after.alerts_repeated_threats == 1);
    try std.testing.expect(stats_after.entity_count >= 2); // src_ip + dst_ip entities

    // --- Phase D: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_verdicts == 0);
    try std.testing.expect(stats_reset.total_alerts == 0);

    // --- Phase E: double-init is no-op, double-shutdown is no-op ---
    init(std.testing.allocator); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase F: after shutdown, processVerdict returns empty ---
    const empty_alerts2 = processVerdict(event, null, av_threat);
    try std.testing.expect(empty_alerts2[0] == null);
}
