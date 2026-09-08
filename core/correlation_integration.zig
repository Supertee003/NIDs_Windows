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
var g_total_evidence: u64 = 0;
var g_total_incidents: u64 = 0;

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_engine = correlation.CorrelationEngine.init(allocator);
    g_allocator = allocator;
    g_initialized = true;
    g_total_verdicts = 0;
    g_total_alerts = 0;
    g_total_evidence = 0;
    g_total_incidents = 0;
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

/// T4: feed detection evidence into correlation. Returns the emitted incident
/// (if any). Evidence flows in, an incident with evidence graph comes out.
pub fn processEvidence(
    event: canonical.CanonicalEvent,
    list: detection.EvidenceList,
) ?correlation.Incident {
    g_total_evidence += list.count;
    if (!g_initialized) return null;
    if (g_engine) |*engine| {
        const inc = engine.processEvidence(event, list);
        if (inc != null) g_total_incidents += 1;
        return inc;
    }
    return null;
}

pub fn getStats() struct {
    total_verdicts: u64,
    total_alerts: u64,
    total_evidence: u64,
    total_incidents: u64,
} {
    return .{
        .total_verdicts = g_total_verdicts,
        .total_alerts = g_total_alerts,
        .total_evidence = g_total_evidence,
        .total_incidents = g_total_incidents,
    };
}

pub fn resetStats() void {
    g_total_verdicts = 0;
    g_total_alerts = 0;
    g_total_evidence = 0;
    g_total_incidents = 0;
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

test "T4: correlation_integration emits incident from multi-category evidence" {
    if (isInitialized()) shutdown();

    init(std.testing.allocator);
    defer shutdown();

    // Network evidence first.
    var net_event = canonical.create(.wfp_sensor);
    net_event.source_ip = 0x0A0000A1;
    var net_list = detection.EvidenceList.init();
    net_list.add(.{ .detector_id = 0, .verdict = .suspicious, .rule_id = 1, .confidence = 55, .description = "n", .severity = 1 });
    try std.testing.expect(processEvidence(net_event, net_list) == null);

    // Host evidence second (same entity) -> incident.
    var host_event = canonical.create(.host_telemetry);
    host_event.source_ip = 0x0A0000A1;
    var host_list = detection.EvidenceList.init();
    host_list.add(.{ .detector_id = 2, .verdict = .malicious, .rule_id = 0, .confidence = 75, .description = "h", .severity = 2 });
    const inc = (processEvidence(host_event, host_list) orelse return error.NoIncident);
    try std.testing.expectEqual(@as(u64, 1), inc.incident_id);
    try std.testing.expect(inc.isMultiCategory());
    try std.testing.expectEqual(@as(u32, 0x0A0000A1), inc.entity_key.ip);

    const stats = getStats();
    try std.testing.expectEqual(@as(u64, 2), stats.total_evidence);
    try std.testing.expectEqual(@as(u64, 1), stats.total_incidents);
}
