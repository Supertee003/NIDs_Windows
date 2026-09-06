//! brain_integration.zig - AEGIS Brain Integration (Rewrite Phase 11)
//!
//! Thin facade over brain_engine.zig that owns a singleton BrainEngine.
//! Mirrors the pattern of threat_intel_integration.zig and correlation_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()                          -> create BrainEngine
//!   advise(event, av, alerts, ti, flow) -> BrainAdvice
//!   shutdown()                      -> reset engine state

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow_types = @import("flow_types.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?brain.BrainEngine = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_advice: u64 = 0;
var g_total_escalations: u64 = 0;
var g_total_deescalations: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_engine = brain.BrainEngine.init();
    g_initialized = true;
    g_total_advice = 0;
    g_total_escalations = 0;
    g_total_deescalations = 0;
    std.log.info("[BRAIN] Brain integration initialized (heuristic model)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_advice = 0;
    g_total_escalations = 0;
    g_total_deescalations = 0;
    if (g_engine) |*engine| {
        engine.resetStats();
    }
}

// ============================================================
// Advice
// ============================================================

/// Review the full context and produce advice.
/// Returns null advice (kind=insufficient_data) if not initialized.
pub fn advise(
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [3]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    flow_update: ?flow_types.FlowUpdate,
) brain.BrainAdvice {
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
            .event_id = event.event_id,
        };
    }
    if (g_engine) |*engine| {
        const advice = engine.advise(event, av, alerts, ti_match, flow_update);
        g_total_advice += 1;
        if (advice.recommendsEscalation()) {
            g_total_escalations += 1;
        } else if (advice.kind == .deescalate) {
            g_total_deescalations += 1;
        }
        return advice;
    }
    return .{
        .kind = .insufficient_data,
        .threat_score = 0,
        .recommended_verdict = av.verdict,
        .original_verdict = av.verdict,
        .confidence = 0,
        .explanation = "brain engine not available",
        .signal_detection = 0,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = event.event_id,
    };
}

// ============================================================
// Stats
// ============================================================

pub const BrainStats = struct {
    total_advice: u64,
    total_escalations: u64,
    total_deescalations: u64,
    keep_count: u64,
    escalate_count: u64,
    deescalate_count: u64,
    insufficient_count: u64,
};

pub fn getStats() BrainStats {
    if (g_engine) |*engine| {
        return .{
            .total_advice = g_total_advice,
            .total_escalations = g_total_escalations,
            .total_deescalations = g_total_deescalations,
            .keep_count = engine.keep_count,
            .escalate_count = engine.escalate_count,
            .deescalate_count = engine.deescalate_count,
            .insufficient_count = engine.insufficient_count,
        };
    }
    return .{
        .total_advice = 0,
        .total_escalations = 0,
        .total_deescalations = 0,
        .keep_count = 0,
        .escalate_count = 0,
        .deescalate_count = 0,
        .insufficient_count = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[BRAIN] Brain integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "brain integration: full lifecycle (init, advise, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: advise returns insufficient_data when not initialized ---
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 50,
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

    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti_match = threat_intel.ThreatIntelMatch{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };

    const empty_advice = advise(event, av, alerts, ti_match, null);
    try std.testing.expect(empty_advice.kind == .insufficient_data);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_advice == 0);

    // --- Phase C: advise with insufficient data (no signals) ---
    const av_no_signal = verdict_agg.AggregatedVerdict{
        .verdict = .benign,
        .confidence = 0,
        .detector_count = 0,
        .agreeing_count = 0,
        .malicious_count = 0,
        .suspicious_count = 0,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .benign,
        .indicators = @import("detection_engine.zig").Indicator.NONE,
        .event_id = event.event_id,
    };

    const advice_no_signal = advise(event, av_no_signal, alerts, ti_match, null);
    try std.testing.expect(advice_no_signal.kind == .insufficient_data);
    try std.testing.expect(advice_no_signal.threat_score == 0);

    // --- Phase D: advise with high signals -> escalation ---
    const av_high = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 90,
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

    const alerts_full: [3]?correlation.CorrelationAlert = .{
        .{
            .rule = .repeated_threats,
            .entity_key = correlation.EntityKey.fromSrcIp(0x0A0000A1),
            .triggering_verdict = .suspicious,
            .threat_count = 5,
            .distinct_ports = 3,
            .timestamp_ns = 1000,
            .triggering_event_id = event.event_id,
            .description = "test",
        },
        .{
            .rule = .port_scan_pattern,
            .entity_key = correlation.EntityKey.fromSrcIp(0x0A0000A1),
            .triggering_verdict = .suspicious,
            .threat_count = 5,
            .distinct_ports = 12,
            .timestamp_ns = 1000,
            .triggering_event_id = event.event_id,
            .description = "test",
        },
        null,
    };

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

    const advice_escalate = advise(event, av_high, alerts_full, ti_critical, null);
    try std.testing.expect(advice_escalate.kind == .escalate);
    try std.testing.expect(advice_escalate.recommended_verdict == .malicious);
    try std.testing.expect(advice_escalate.original_verdict == .suspicious);

    const stats_after = getStats();
    try std.testing.expect(stats_after.total_advice == 2);
    try std.testing.expect(stats_after.total_escalations == 1);

    // --- Phase E: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_advice == 0);
    try std.testing.expect(stats_reset.total_escalations == 0);

    // --- Phase F: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase G: after shutdown, advise returns insufficient_data ---
    const empty_advice2 = advise(event, av, alerts, ti_match, null);
    try std.testing.expect(empty_advice2.kind == .insufficient_data);
}
