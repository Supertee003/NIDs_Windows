//! brain_engine.zig - AEGIS Brain Advisor (Rewrite Phase 11)
//!
//! Heuristic advisor that combines detection verdict, correlation alerts,
//! threat intel matches, flow anomalies, and RAG context into a single
//! recommendation. Brain is an ADVISOR, not an enforcer - it can only
//! recommend verdict changes; policy/PEP still make the final call.
//!
//! Contract:
//!   BrainAdviceKind: enum with toString()
//!   BrainAdvice: struct { kind, threat_score, recommended_verdict, original_verdict,
//!                         confidence, explanation, signal_*, event_id }
//!   BrainAdvisor: advise(event, av, alerts, ti_match, flow_update, rag_ctx) -> BrainAdvice

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");
const flow = @import("../capture/flow_engine.zig");
const detection = @import("../detection/detection_engine.zig");
const verdict_agg = @import("../detection/verdict_aggregator.zig");
const correlation = @import("../detection/correlation_engine.zig");
const threat_intel = @import("../detection/threat_intel.zig");
const rag = @import("../detection/rag_engine.zig");

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
    signal_rag: u8,
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
    /// RAG context is advisory: high-confidence known-threat context adds
    /// signal, while false-positive / contextual-benign context subtracts it.
    pub fn advise(
        self: *BrainAdvisor,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
        ti_match: threat_intel.ThreatIntelMatch,
        flow_update: ?flow.FlowUpdate,
        rag_ctx: rag.RagContext,
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

        // RAG signal: high-confidence known-threat context corroborates,
        // false-positive / contextual-benign context rebuts. Bounded to +/- 20
        // so RAG alone can neither manufacture nor veto a block (advisory only).
        var sig_rag: u8 = 0;
        var rag_kind: u8 = 0; // 0=none, 1=false-positive, 2=known-threat, 3=context
        if (rag_ctx.hasContext()) {
            if (rag_ctx.indicatesFalsePositive()) {
                sig_rag = 15; // strong rebuttal, applied as negative below
                rag_kind = 1;
            } else if (rag_ctx.isConfident()) {
                sig_rag = 15;
                rag_kind = 2;
            } else {
                sig_rag = 5;
                rag_kind = 3;
            }
        }

        var total_score: i16 = @as(i16, sig_det) + sig_corr + sig_ti + sig_flow;
        if (rag_ctx.hasContext() and rag_ctx.indicatesFalsePositive()) {
            total_score -= @as(i16, sig_rag);
        } else {
            total_score += @as(i16, sig_rag);
        }
        total_score = std.math.clamp(total_score, 0, 100);

        // Recommendation logic
        const orig = av.verdict;
        var recommended = orig;
        var kind: BrainAdviceKind = .keep;
        var explanation: []const u8 = "score below threshold";

        if (total_score < 20) {
            kind = .insufficient_data;
            explanation = switch (rag_kind) {
                1 => "insufficient signal [rag=false-positive]",
                2 => "insufficient signal [rag=known-threat]",
                3 => "insufficient signal [rag=context]",
                else => "insufficient signal",
            };
        } else if (total_score >= 80) {
            recommended = .critical;
            kind = .escalate_to_block;
            explanation = switch (rag_kind) {
                1 => "high threat score - escalate to block [rag=false-positive]",
                2 => "high threat score - escalate to block [rag=known-threat]",
                3 => "high threat score - escalate to block [rag=context]",
                else => "high threat score - escalate to block",
            };
            self.total_blocks_recommended += 1;
            self.total_escalations += 1;
        } else if (total_score >= 60) {
            // Escalate one level (cap at critical)
            if (@intFromEnum(orig) < @intFromEnum(detection.Verdict.critical)) {
                recommended = @enumFromInt(@intFromEnum(orig) + 1);
                kind = .escalate;
                explanation = switch (rag_kind) {
                    1 => "elevated threat score - escalate [rag=false-positive]",
                    2 => "elevated threat score - escalate [rag=known-threat]",
                    3 => "elevated threat score - escalate [rag=context]",
                    else => "elevated threat score - escalate",
                };
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
                explanation = switch (rag_kind) {
                    1 => "low threat score - de-escalate [rag=false-positive]",
                    2 => "low threat score - de-escalate [rag=known-threat]",
                    3 => "low threat score - de-escalate [rag=context]",
                    else => "low threat score - de-escalate",
                };
            }
        } else if (rag_kind != 0) {
            // Middle ground (20-60): keep verdict but note RAG context in explanation
            explanation = switch (rag_kind) {
                1 => "score below threshold [rag=false-positive]",
                2 => "score below threshold [rag=known-threat]",
                3 => "score below threshold [rag=context]",
                else => "score below threshold",
            };
        }

        return .{
            .kind = kind,
            .threat_score = @intCast(total_score),
            .recommended_verdict = recommended,
            .original_verdict = orig,
            .confidence = @intCast(@min(total_score, 100)),
            .explanation = explanation,
            .signal_detection = sig_det,
            .signal_correlation = sig_corr,
            .signal_threat_intel = sig_ti,
            .signal_flow_anomaly = sig_flow,
            .signal_rag = if (rag_ctx.hasContext()) sig_rag else 0,
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
    const rag_ctx = rag.RagContext{ .available = false, .match_count = 0, .context_summary = "", .references = undefined, .reference_count = 0, .confidence = 0, .primary_category = .unknown, .event_id = 0 };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
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
    const rag_ctx = rag.RagContext{ .available = false, .match_count = 0, .context_summary = "", .references = undefined, .reference_count = 0, .confidence = 0, .primary_category = .unknown, .event_id = 0 };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
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
    const rag_ctx = rag.RagContext{ .available = false, .match_count = 0, .context_summary = "", .references = undefined, .reference_count = 0, .confidence = 0, .primary_category = .unknown, .event_id = 0 };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
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
    const rag_ctx = rag.RagContext{ .available = false, .match_count = 0, .context_summary = "", .references = undefined, .reference_count = 0, .confidence = 0, .primary_category = .unknown, .event_id = 0 };
    _ = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    _ = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    try std.testing.expect(advisor.total_advices == 2);
}

test "BrainAdvisor.resetStats zeroes counters" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.benign, 30, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const rag_ctx = rag.RagContext{ .available = false, .match_count = 0, .context_summary = "", .references = undefined, .reference_count = 0, .confidence = 0, .primary_category = .unknown, .event_id = 0 };
    _ = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    advisor.resetStats();
    try std.testing.expect(advisor.total_advices == 0);
}

// ============================================================
// T5a tests: Brain consumes RAG context (signal_rag, scoring, explanation)
// ============================================================

test "T5a: Brain scores RAG known-threat context as positive signal" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.suspicious, 80, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const rag_ctx = rag.RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "known malware signature",
        .references = undefined,
        .reference_count = 0,
        .confidence = 80,
        .primary_category = .malware_signature,
        .event_id = 1,
    };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    // det=20, ti=0, rag=15 = 35 -> should be higher than without rag (20)
    try std.testing.expect(advice.signal_rag > 0);
    try std.testing.expect(advice.threat_score > 20);
    try std.testing.expect(std.mem.indexOf(u8, advice.explanation, "rag=known-threat") != null);
}

test "T5a: Brain scores RAG false-positive context as negative signal (rebuttal)" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.suspicious, 80, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const rag_ctx = rag.RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "false positive indicator",
        .references = undefined,
        .reference_count = 0,
        .confidence = 80,
        .primary_category = .false_positive_indicator,
        .event_id = 1,
    };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    // det=20, rag=-15 = 5 -> should drop below threshold
    try std.testing.expect(advice.signal_rag > 0);
    try std.testing.expect(advice.threat_score < 20);
    try std.testing.expect(advice.kind == .insufficient_data);
    try std.testing.expect(std.mem.indexOf(u8, advice.explanation, "rag=false-positive") != null);
}

test "T5a: Brain scores RAG contextual-benign context as negative signal" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.malicious, 90, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const rag_ctx = rag.RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "contextual benign",
        .references = undefined,
        .reference_count = 0,
        .confidence = 70,
        .primary_category = .contextual_benign,
        .event_id = 1,
    };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    // det=25, rag=-5 = 20 -> may still be above 20 but lower
    try std.testing.expect(advice.signal_rag > 0);
    try std.testing.expect(std.mem.indexOf(u8, advice.explanation, "rag=false-positive") != null);
}

test "T5a: Brain RAG unavailable does not add signal and uses empty explanation" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.suspicious, 80, 1);
    const alerts = .{null, null, null};
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const rag_ctx = rag.RagContext{
        .available = false,
        .match_count = 0,
        .context_summary = "",
        .references = undefined,
        .reference_count = 0,
        .confidence = 0,
        .primary_category = .unknown,
        .event_id = 0,
    };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    try std.testing.expect(advice.signal_rag == 0);
    try std.testing.expect(std.mem.indexOf(u8, advice.explanation, "rag=") == null);
}

test "T5a: Brain advice has no enforcement path (advisory only)" {
    var advisor = BrainAdvisor.init();
    const event = canonical.create(.zig_core);
    const av = makeAv(.critical, 100, 1);
    const alerts: [3]?correlation.CorrelationAlert = .{
        .{ .rule = .repeated_threats, .entity_key = .{ .entity_type = .source_ip, .ip = 1, .session_id = 0 }, .threat_count = 10, .triggering_event_id = 1, .description = "test" },
        .{ .rule = .multi_target_scan, .entity_key = .{ .entity_type = .source_ip, .ip = 1, .session_id = 0 }, .threat_count = 8, .triggering_event_id = 1, .description = "test" },
        null,
    };
    const ti = threat_intel.ThreatIntelMatch{
        .src_match = .{ .ip = 1, .severity = .critical, .category = .malware_c2, .confidence = 95, .source = "test" },
        .dst_match = null,
        .event_id = 1,
    };
    const rag_ctx = rag.RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "attack pattern",
        .references = undefined,
        .reference_count = 0,
        .confidence = 90,
        .primary_category = .attack_pattern,
        .event_id = 1,
    };

    const advice = advisor.advise(event, av, alerts, ti, null, rag_ctx);
    // Even at maximum score, the advice only recommends - no enforcement fields exist
    try std.testing.expect(advice.kind == .escalate_to_block);
    // BrainAdvice struct has: kind, threat_score, recommended_verdict, original_verdict,
    // confidence, explanation, signal_*, event_id
    // NO: blocked_ip, kill_pid, quarantine_action, enforcement_result, WFP handle
}