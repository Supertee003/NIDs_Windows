//! policy_integration.zig - AEGIS Policy Integration (Rewrite Phase 12)
//!
//! Thin facade over policy_engine.zig that owns a singleton PolicyEngine.
//! Mirrors the pattern of brain_integration.zig and threat_intel_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create PolicyEngine
//!   evaluate(event, av, alerts, ti_match, advice) -> EnforcementDecision
//!   shutdown() -> reset engine state

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");
const policy = @import("policy_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?policy.PolicyEngine = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_evaluations: u64 = 0;
var g_total_blocks: u64 = 0;
var g_total_alerts: u64 = 0;
var g_total_allows: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_engine = policy.PolicyEngine.init();
    g_initialized = true;
    g_total_evaluations = 0;
    g_total_blocks = 0;
    g_total_alerts = 0;
    g_total_allows = 0;
    std.log.info("[POLICY] Policy integration initialized (planner, not enforcer)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_evaluations = 0;
    g_total_blocks = 0;
    g_total_alerts = 0;
    g_total_allows = 0;
    if (g_engine) |*engine| {
        engine.resetStats();
    }
}

// ============================================================
// Evaluation
// ============================================================

/// Evaluate the full context and produce an enforcement decision.
/// Returns null decision (action=allow) if not initialized.
pub fn evaluate(
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [3]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    advice: brain.BrainAdvice,
) policy.EnforcementDecision {
    if (!g_initialized) {
        return .{
            .action = .allow,
            .rule = .default_allow,
            .confidence = 0,
            .reason = "policy not initialized",
            .event_id = event.event_id,
            .brain_recommended_verdict = advice.recommended_verdict,
            .original_verdict = av.verdict,
            .threat_score = advice.threat_score,
        };
    }
    if (g_engine) |*engine| {
        const decision = engine.evaluate(event, av, alerts, ti_match, advice);
        g_total_evaluations += 1;
        switch (decision.action) {
            .allow => g_total_allows += 1,
            .alert => g_total_alerts += 1,
            .block, .quarantine => g_total_blocks += 1,
            .rate_limit, .log_only => {},
        }
        return decision;
    }
    return .{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 0,
        .reason = "policy engine not available",
        .event_id = event.event_id,
        .brain_recommended_verdict = advice.recommended_verdict,
        .original_verdict = av.verdict,
        .threat_score = advice.threat_score,
    };
}

// ============================================================
// Stats
// ============================================================

pub const PolicyStats = struct {
    total_evaluations: u64,
    total_blocks: u64,
    total_alerts: u64,
    total_allows: u64,
    brain_advice_followed: u64,
    brain_advice_overridden: u64,
};

pub fn getStats() PolicyStats {
    if (g_engine) |*engine| {
        return .{
            .total_evaluations = g_total_evaluations,
            .total_blocks = g_total_blocks,
            .total_alerts = g_total_alerts,
            .total_allows = g_total_allows,
            .brain_advice_followed = engine.brain_advice_followed,
            .brain_advice_overridden = engine.brain_advice_overridden,
        };
    }
    return .{
        .total_evaluations = 0,
        .total_blocks = 0,
        .total_alerts = 0,
        .total_allows = 0,
        .brain_advice_followed = 0,
        .brain_advice_overridden = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[POLICY] Policy integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "policy integration: full lifecycle (init, evaluate, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: evaluate returns allow when not initialized ---
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .benign,
        .confidence = 50,
        .detector_count = 3,
        .agreeing_count = 3,
        .malicious_count = 0,
        .suspicious_count = 0,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .benign,
        .indicators = @import("detection_engine.zig").Indicator.NONE,
        .event_id = event.event_id,
    };

    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti_match = threat_intel.ThreatIntelMatch{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };
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
        .event_id = event.event_id,
    };

    const empty_decision = evaluate(event, av, alerts, ti_match, advice);
    try std.testing.expect(empty_decision.action == .allow);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_evaluations == 0);

    // --- Phase C: evaluate benign context -> ALLOW ---
    const decision_allow = evaluate(event, av, alerts, ti_match, advice);
    try std.testing.expect(decision_allow.action == .allow);
    try std.testing.expect(decision_allow.rule == .default_allow);

    // --- Phase D: evaluate threat intel critical -> BLOCK ---
    const ti_critical = threat_intel.ThreatIntelMatch{
        .src_match = .{
            .ip = 0x0A0000A1,
            .severity = .critical,
            .category = .malware_c2,
            .confidence = 95,
            .source = "test",
            .first_seen_ms = 1000,
            .last_seen_ms = 2000,
            .report_count = 5,
        },
        .dst_match = null,
        .event_id = event.event_id,
    };

    const decision_block = evaluate(event, av, alerts, ti_critical, advice);
    try std.testing.expect(decision_block.action == .block);
    try std.testing.expect(decision_block.rule == .threat_intel_critical);
    try std.testing.expect(decision_block.isBlocking());

    // --- Phase E: evaluate suspicious verdict -> ALERT ---
    const av_suspicious = verdict_agg.AggregatedVerdict{
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

    const decision_alert = evaluate(event, av_suspicious, alerts, ti_match, advice);
    try std.testing.expect(decision_alert.action == .alert);
    try std.testing.expect(decision_alert.rule == .verdict_suspicious);

    const stats_after = getStats();
    try std.testing.expect(stats_after.total_evaluations == 3);
    try std.testing.expect(stats_after.total_blocks == 1);
    try std.testing.expect(stats_after.total_alerts == 1);
    try std.testing.expect(stats_after.total_allows == 1);

    // --- Phase F: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_evaluations == 0);

    // --- Phase G: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase H: after shutdown, evaluate returns allow ---
    const empty_decision2 = evaluate(event, av, alerts, ti_match, advice);
    try std.testing.expect(empty_decision2.action == .allow);
}
