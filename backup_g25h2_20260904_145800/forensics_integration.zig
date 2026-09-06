//! forensics_integration.zig - AEGIS Forensics Integration (Phase 14)
//!
//! Thin facade over forensics_engine.zig that owns a singleton ForensicsEngine.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const forensics = @import("forensics_engine.zig");

var g_engine: ?forensics.ForensicsEngine = null;
var g_initialized: bool = false;
var g_total_logged: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = forensics.ForensicsEngine.init();
    g_initialized = true;
    g_total_logged = 0;
    std.log.info("[FORENSICS] Forensics integration initialized (ring buffer)", .{});
}

pub fn isInitialized() bool { return g_initialized; }

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[FORENSICS] Forensics integration shutdown", .{});
}

pub fn logResult(
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    advice: brain.BrainAdvice,
    decision: policy.EnforcementDecision,
    pep_result: rust_pep.EnforcementResult,
) u64 {
    if (!g_initialized) return 0;
    if (g_engine) |*engine| {
        const seq = engine.logResult(event, av, alerts, ti_match, advice, decision, pep_result);
        if (seq > 0) g_total_logged += 1;
        return seq;
    }
    return 0;
}

pub fn getBySequence(seq: u64) ?forensics.ForensicRecord {
    if (g_engine) |*engine| return engine.getBySequence(seq);
    return null;
}

pub fn getStats() struct { total_logged: u64, ring_count: usize } {
    if (g_engine) |*engine| {
        return .{ .total_logged = g_total_logged, .ring_count = engine.count };
    }
    return .{ .total_logged = 0, .ring_count = 0 };
}

pub fn resetStats() void {
    g_total_logged = 0;
    if (g_engine) |*engine| engine.resetStats();
}

test "forensics_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init();
    defer shutdown();
    try std.testing.expect(isInitialized());

    var event = canonical.create(.zig_core);
    event.event_id = 1;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.severity = 2;

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
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 80,
        .reason = "test",
        .event_id = 1,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 60,
    };
    const pep_result = rust_pep.EnforcementResult{
        .status = .executed,
        .reason = .none,
        .requested_action = .block,
        .actual_action = .block,
        .event_id = 1,
        .blocked_ip = 0x0A000001,
        .message = "test",
    };

    const seq = logResult(event, av, alerts, ti, advice, decision, pep_result);
    try std.testing.expect(seq > 0);

    const rec = getBySequence(seq) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(rec.result.event_id == 1);
    try std.testing.expect(rec.result.aggregated_verdict == .malicious);
    try std.testing.expect(rec.result.policy_action == .block);

    const stats = getStats();
    try std.testing.expect(stats.total_logged == 1);
    try std.testing.expect(stats.ring_count == 1);
}

test "forensics_integration: returns 0 when not initialized" {
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
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 0 };
    const advice = brain.BrainAdvice{
        .kind = .insufficient_data,
        .threat_score = 0,
        .recommended_verdict = .benign,
        .original_verdict = .benign,
        .confidence = 0,
        .explanation = "test",
        .signal_detection = 0,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = 0,
    };
    const decision = policy.EnforcementDecision{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 0,
        .reason = "test",
        .event_id = 0,
        .brain_recommended_verdict = .benign,
        .original_verdict = .benign,
        .threat_score = 0,
    };
    const pep_result = rust_pep.EnforcementResult{
        .status = .no_op,
        .reason = .none,
        .requested_action = .allow,
        .actual_action = .allow,
        .event_id = 0,
        .blocked_ip = 0,
        .message = "test",
    };
    const seq = logResult(event, av, alerts, ti, advice, decision, pep_result);
    try std.testing.expect(seq == 0);
}
