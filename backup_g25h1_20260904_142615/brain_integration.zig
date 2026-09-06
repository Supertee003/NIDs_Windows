//! brain_integration.zig - AEGIS Brain Integration (Phase 11)
//!
//! Thin facade over brain_engine.zig that owns a singleton BrainAdvisor.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");

var g_advisor: ?brain.BrainAdvisor = null;
var g_initialized: bool = false;
var g_total_advices: u64 = 0;
var g_total_escalations: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_advisor = brain.BrainAdvisor.init();
    g_initialized = true;
    g_total_advices = 0;
    g_total_escalations = 0;
    std.log.info("[BRAIN] Brain integration initialized (heuristic advisor)", .{});
}

pub fn isInitialized() bool { return g_initialized; }

pub fn shutdown() void {
    if (!g_initialized) return;
    g_advisor = null;
    g_initialized = false;
    std.log.info("[BRAIN] Brain integration shutdown", .{});
}

pub fn advise(
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    flow_update: ?flow.FlowUpdate,
) brain.BrainAdvice {
    g_total_advices += 1;
    if (!g_initialized) {
        return .{
            .kind = .insufficient_data,
            .threat_score = 0,
            .recommended_verdict = av.verdict,
            .original_verdict = av.verdict,
            .confidence = 0,
            .explanation = "brain not initialized",
            .signal_detection = 0,
            .signal_correlation = 0,
            .signal_threat_intel = 0,
            .signal_flow_anomaly = 0,
            .event_id = av.event_id,
        };
    }
    if (g_advisor) |*advisor| {
        const advice = advisor.advise(event, av, alerts, ti_match, flow_update);
        if (advice.recommendsChange()) g_total_escalations += 1;
        return advice;
    }
    return .{
        .kind = .insufficient_data,
        .threat_score = 0,
        .recommended_verdict = av.verdict,
        .original_verdict = av.verdict,
        .confidence = 0,
        .explanation = "brain advisor missing",
        .signal_detection = 0,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = av.event_id,
    };
}

pub fn getStats() struct { total_advices: u64, total_escalations: u64 } {
    return .{ .total_advices = g_total_advices, .total_escalations = g_total_escalations };
}

pub fn resetStats() void {
    g_total_advices = 0;
    g_total_escalations = 0;
    if (g_advisor) |*advisor| advisor.resetStats();
}

test "brain_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init();
    defer shutdown();
    try std.testing.expect(isInitialized());

    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .benign,
        .original_verdict = .benign,
        .confidence = 30,
        .agreeing_count = 0,
        .detector_count = 0,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };

    const advice = advise(event, av, alerts, ti, null);
    try std.testing.expect(advice.kind == .insufficient_data);
    try std.testing.expect(getStats().total_advices == 1);
}

test "brain_integration: returns insufficient_data when not initialized" {
    if (isInitialized()) shutdown();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .malicious,
        .original_verdict = .malicious,
        .confidence = 80,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const advice = advise(event, av, alerts, ti, null);
    try std.testing.expect(advice.kind == .insufficient_data);
}
