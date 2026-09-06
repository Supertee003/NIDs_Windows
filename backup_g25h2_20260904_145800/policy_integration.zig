//! policy_integration.zig - AEGIS Policy Integration (Phase 12)
//!
//! Thin facade over policy_engine.zig that owns a singleton PolicyEngine.
//! Provides evaluate() API consumed by dispatcher.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");
const policy = @import("policy_engine.zig");

var g_engine: ?policy.PolicyEngine = null;
var g_initialized: bool = false;
var g_total_decisions: u64 = 0;
var g_total_blocks: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = policy.PolicyEngine.init();
    g_initialized = true;
    g_total_decisions = 0;
    g_total_blocks = 0;
    std.log.info("[POLICY] Policy integration initialized (planner, not enforcer)", .{});
}

pub fn isInitialized() bool { return g_initialized; }

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[POLICY] Policy integration shutdown", .{});
}

pub fn evaluate(
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    advice: brain.BrainAdvice,
) policy.EnforcementDecision {
    g_total_decisions += 1;
    if (!g_initialized) {
        return .{
            .action = .allow,
            .rule = .default_allow,
            .confidence = 0,
            .reason = "policy not initialized",
            .event_id = av.event_id,
            .brain_recommended_verdict = advice.recommended_verdict,
            .original_verdict = av.verdict,
            .threat_score = advice.threat_score,
        };
    }
    if (g_engine) |*engine| {
        const decision = engine.evaluate(event, av, alerts, ti_match, advice);
        if (decision.isBlocking()) g_total_blocks += 1;
        return decision;
    }
    return .{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 0,
        .reason = "policy engine missing",
        .event_id = av.event_id,
        .brain_recommended_verdict = advice.recommended_verdict,
        .original_verdict = av.verdict,
        .threat_score = advice.threat_score,
    };
}

pub fn getStats() struct { total_decisions: u64, total_blocks: u64 } {
    return .{ .total_decisions = g_total_decisions, .total_blocks = g_total_blocks };
}

pub fn resetStats() void {
    g_total_decisions = 0;
    g_total_blocks = 0;
    if (g_engine) |*engine| engine.resetStats();
}

test "policy_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init();
    defer shutdown();
    try std.testing.expect(isInitialized());

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
    const advice = brain.BrainAdvice{
        .kind = .keep_verdict,
        .threat_score = 60,
        .recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .confidence = 70,
        .explanation = "test",
        .signal_detection = 0,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = 1,
    };

    const d = evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .block);
    try std.testing.expect(d.isBlocking());

    const stats = getStats();
    try std.testing.expect(stats.total_decisions == 1);
    try std.testing.expect(stats.total_blocks == 1);
}

test "policy_integration: returns allow when not initialized" {
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
    const advice = brain.BrainAdvice{
        .kind = .keep_verdict,
        .threat_score = 60,
        .recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .confidence = 70,
        .explanation = "test",
        .signal_detection = 0,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = 1,
    };
    const d = evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .allow);
    try std.testing.expect(d.rule == .default_allow);
}
