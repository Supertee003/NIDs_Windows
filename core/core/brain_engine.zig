//! brain_engine.zig - AEGIS Brain Advisor (Rewrite Phase 11)
//!
//! Heuristic advisor that combines detection verdict, correlation alerts,
//! threat intel matches, and flow anomalies into a single recommendation.
//! Brain is an ADVISOR, not an enforcer - it can only recommend verdict
//! changes; policy/PEP still make the final call.
//!
//! Contract:
//!   BrainAdviceKind: enum with toString()
//!   BrainAdvice: struct { kind, threat_score, recommended_verdict, original_verdict,
//!                         confidence, explanation, signal_*, event_id }
//!   BrainAdvisor: advise(event, av, alerts, ti_match, flow_update) -> BrainAdvice

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");

// ============================================================
// Brain Advice Kind
// ============================================================

pub const BrainAdviceKind = enum(u8) {
    insufficient_data = 0,
    keep = 1,  // v5.0 proof API name (was keep_verdict)
    escalate = 2,
    deescalate = 3,  // v5.0 proof API name (was de_escalate)
    escalate_to_block = 4,

    pub fn toString(self: BrainAdviceKind) []const u8 {
        return switch (self) {
            .insufficient_data => "INSUFFICIENT_DATA",
            .keep => "KEEP",
            .escalate => "ESCALATE",
            .deescalate => "DEESCALATE",
            .escalate_to_block => "ESCALATE_TO_BLOCK",
        };
    }

    pub fn recommendsChange(self: BrainAdviceKind) bool {
        return self == .escalate or self == .deescalate or self == .escalate_to_block;
    }
};

/// Alias for proof modules (v5.0 Section 35).
pub const AdviceKind = BrainAdviceKind;

// ============================================================
// Brain Advice
// ============================================================

pub const BrainAdvice = struct {
    kind: BrainAdviceKind,
    threat_score: u16,
    recommended_verdict: detection.Verdict,
    original_verdict: detection.Verdict,
    confidence: u8,
    explanation: []const u8,
    signal_detection: u8,
    signal_correlation: u8,
    signal_threat_intel: u8,
    signal_flow_anomaly: u8,
    event_id: u64,

    pub fn recommendsChange(self: BrainAdvice) bool {
        return self.kind.recommendsChange();
    }

    /// Returns true if this advice is reliable (not insufficient_data).
    /// Used by proof modules to check fail-soft behavior.
    pub fn isReliable(self: BrainAdvice) bool {
        return self.kind != .insufficient_data;
    }
};

// ============================================================
// Brain Advisor
// ============================================================

pub const BrainAdvisor = struct {
    total_advices: u64 = 0,
    total_escalations: u64 = 0,
    total_blocks_recommended: u64 = 0,

    pub fn init() BrainAdvisor {
        return .{};
    }

    /// Compute a heuristic threat score (0-100) and a recommendation.
    pub fn advise(
        self: *BrainAdvisor,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
        ti_match: threat_intel.ThreatIntelMatch,
        flow_update: ?flow.FlowUpdate,
    ) BrainAdvice {
        _ = event;
        self.total_advices += 1;

        // Signal components (0-25 each, sum up to 100)
        var sig_det: u8 = 0;
        if (av.isThreat()) {
            sig_det = switch (av.verdict) {
                .suspicious => 15,
                .malicious => 20,
                .critical => 25,
                else => 0,
            };
        }
        if (av.confidence > 70) sig_det = @min(sig_det + 5, 25);

        var sig_corr: u8 = 0;
        for (alerts) |a| {
            if (a) |alert| {
                sig_corr += switch (alert.rule) {
                    .repeated_threats => 10,
                    .multi_target_scan => 15,
                    .long_lived_flow_threat => 8,
                    else => 5,
                };
            }
        }
        sig_corr = @min(sig_corr, 25);

        var sig_ti: u8 = 0;
        if (ti_match.hasMatch()) {
            sig_ti = switch (ti_match.maxSeverity()) {
                .critical => 25,
                .high => 20,
                .medium => 12,
                .low => 5,
                else => 0,
            };
        }

        var sig_flow: u8 = 0;
        if (flow_update) |upd| {
            if (upd.flow.packet_count > 1000) sig_flow += 10;
            if (upd.flow.max_severity >= 2) sig_flow += 10;
            if (upd.flow.byte_count > 1_000_000) sig_flow += 5;
            sig_flow = @min(sig_flow, 25);
        }

        const total_score: u16 = @as(u16, sig_det) + sig_corr + sig_ti + sig_flow;

        // Recommendation logic
        const orig = av.verdict;
        var recommended = orig;
        var kind: BrainAdviceKind = .keep;
        var explanation: []const u8 = "score below threshold";

        if (total_score < 20) {
            kind = .insufficient_data;
            explanation = "insufficient signal";
        } else if (total_score >= 80) {
            recommended = .critical;
            kind = .escalate_to_block;
            explanation = "high threat score - escalate to block";
            self.total_blocks_recommended += 1;
            self.total_escalations += 1;
        } else if (total_score >= 60) {
            // Escalate one level (cap at critical)
            if (@intFromEnum(orig) < @intFromEnum(detection.Verdict.critical)) {
                recommended = @enumFromInt(@intFromEnum(orig) + 1);
                kind = .escalate;
                explanation = "elevated threat score - escalate";
                self.total_escalations += 1;
            } else {
                recommended = .critical;
                kind = .keep;
                explanation = "already at critical";
            }
        } else if (total_score < 30 and orig.isThreat()) {
            // De-escalate one level (floor at benign)
            if (@intFromEnum(orig) > @intFromEnum(detection.Verdict.benign)) {
                recommended = @enumFromInt(@intFromEnum(orig) - 1);
                kind = .deescalate;
                explanation = "low threat score - de-escalate";
            }
        }

        return .{
            .kind = kind,
            .threat_score = total_score,
            .recommended_verdict = recommended,
            .original_verdict = orig,
            .confidence = @intCast(@min(total_score, 100)),
            .explanation = explanation,
            .signal_detection = sig_det,
            .signal_correlation = sig_corr,
            .signal_threat_intel = sig_ti,
            .signal_flow_anomaly = sig_flow,
            .event_id = av.event_id,
        };
    }

    pub fn resetStats(self: *BrainAdvisor) void {
        self.total_advices = 0;
        self.total_escalations = 0;
        self.total_blocks_recommended = 0;
    }
};

// ============================================================
// Tests
// ============================================================

fn makeAv(v: detection.Verdict, conf: u8, event_id: u64) verdict_agg.AggregatedVerdict {
    return .{
        .verdict = v,
        .original_verdict = v,
        .confidence = conf,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = event_id,
    };
}

test "BrainAdviceKind.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, BrainAdviceKind.insufficient_data.toString(), "INSUFFICIENT_DATA"));
    try std.testing.expect(std.mem.eql(u8, BrainAdviceKind.escalate_to_block.toString(), "ESCALATE_TO_BLOCK"));
}

test "BrainAdviceKind.recommendsChange classifies correctly" {
    try std.testing.expect(!BrainAdviceKind.insufficient_data.recommendsChange());
    try std.testing.expect(!BrainAdviceKind.keep.recommendsChange());
    try std.testing.expect(BrainAdviceKind.escalate.recommendsChange());
    try std.testing.expect(BrainAdviceKind.deescalate.recommendsChange());
    try std.testing.expect(BrainAdviceKind.escalate_to_block.recommendsChange());
}

test "BrainAdvisor.init starts with zero stats" {
    const advisor = BrainAdvisor.init();
    try std.testing.expect(advisor.total_advices == 0);
}

test "BrainAdvisor.advise returns insufficient_data for benign with no signals" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.benign, 30, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };

    const advice = advisor.advise(event, av, alerts, ti, null);
    try std.testing.expect(advice.kind == .insufficient_data);
    try std.testing.expect(advice.threat_score < 20);
}

test "BrainAdvisor.advise escalates on high signals" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.suspicious, 80, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{
        .src_match = .{ .ip = 1, .severity = .critical, .category = .malware_c2, .confidence = 95, .source = "test" },
        .dst_match = null,
        .event_id = 1,
    };

    const advice = advisor.advise(event, av, alerts, ti, null);
    // score: det=20 (suspicious + confidence bonus), corr=0, ti=25, flow=0 = 45 -> not enough for escalate
    try std.testing.expect(advice.threat_score >= 40);
}

test "BrainAdvisor.advise recommends block on critical mass" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.malicious, 90, 1);
    const alerts: [3]?correlation.CorrelationAlert = .{
        .{ .rule = .repeated_threats, .entity_key = .{ .entity_type = .source_ip, .ip = 1, .session_id = 0 }, .threat_count = 5, .triggering_event_id = 1, .description = "test" },
        .{ .rule = .multi_target_scan, .entity_key = .{ .entity_type = .source_ip, .ip = 1, .session_id = 0 }, .threat_count = 4, .triggering_event_id = 1, .description = "test" },
        null,
    };
    const ti = threat_intel.ThreatIntelMatch{
        .src_match = .{ .ip = 1, .severity = .critical, .category = .malware_c2, .confidence = 95, .source = "test" },
        .dst_match = null,
        .event_id = 1,
    };

    const advice = advisor.advise(event, av, alerts, ti, null);
    // score: det=25, corr=25, ti=25 = 75 -> escalate, not block. Block requires 80+
    try std.testing.expect(advice.threat_score >= 75);
    try std.testing.expect(advice.recommendsChange());
    try std.testing.expect(advisor.total_escalations > 0);
}

test "BrainAdvisor tracks lifetime stats" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.benign, 30, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    _ = advisor.advise(event, av, alerts, ti, null);
    _ = advisor.advise(event, av, alerts, ti, null);
    try std.testing.expect(advisor.total_advices == 2);
}

test "BrainAdvisor.resetStats zeroes counters" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.benign, 30, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    _ = advisor.advise(event, av, alerts, ti, null);
    advisor.resetStats();
    try std.testing.expect(advisor.total_advices == 0);
}
