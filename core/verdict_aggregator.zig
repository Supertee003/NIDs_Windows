//! verdict_aggregator.zig - AEGIS Verdict Aggregator (Rewrite Phase 8)
//!
//! Formalizes how multiple DetectionEvidence (one per detector) are combined
//! into a single aggregated verdict. Replaces Phase 7's naive maxVerdict().
//!
//! Aggregation model (Master Plan "Detection = evidence producer"):
//!   EvidenceList in  ->  VerdictAggregator  ->  AggregatedVerdict out
//!
//! The aggregator does NOT mutate evidence or events. It computes a summary.
//!
//! Quorum rules:
//!   1. If >= QUORUM_FOR_MALICIOUS detectors say MALICIOUS -> MALICIOUS
//!   2. Else if >= QUORUM_FOR_SUSPICIOUS say SUSPICIOUS/MALICIOUS -> SUSPICIOUS
//!   3. Else if any detector says ERROR (and no threats) -> UNKNOWN (fail-open)
//!   4. Else if all detectors say BENIGN -> BENIGN
//!   5. Else (mix of BENIGN/OBSERVE/UNKNOWN, no threats) -> OBSERVE
//!
//! Confidence scoring (weighted average):
//!   - Each detector's confidence (0-100) is weighted by its detector_id tier.
//!   - rule_match (id=1) gets weight 1.0 (legacy bridge, high trust)
//!   - port_scan (id=2) gets weight 0.7 (heuristic, medium trust)
//!   - high_rate (id=3) gets weight 0.5 (statistical, lower trust)
//!   - Unknown detector IDs get weight 0.3 (fail-safe)
//!
//! Escalation rules (applied AFTER quorum):
//!   - If flow.max_severity >= 3 AND aggregated == SUSPICIOUS -> escalate to MALICIOUS
//!   - If flow.packet_count > ESCALATION_PACKET_THRESHOLD AND aggregated == OBSERVE -> escalate to SUSPICIOUS

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const flow_types = @import("flow_types.zig");

// ============================================================
// Constants
// ============================================================

/// Number of MALICIOUS verdicts needed to escalate to MALICIOUS.
/// 1 = any single detector saying MALICIOUS is enough (paranoid mode).
/// 2 = at least 2 detectors must agree (consensus mode).
pub const QUORUM_FOR_MALICIOUS: usize = 1;

/// Number of SUSPICIOUS+MALICIOUS verdicts needed for SUSPICIOUS.
pub const QUORUM_FOR_SUSPICIOUS: usize = 1;

/// If flow has this many packets and aggregated verdict is OBSERVE, escalate to SUSPICIOUS.
pub const ESCALATION_PACKET_THRESHOLD: u64 = 200;

/// Minimum confidence (0-100) for a verdict to be considered "reliable".
pub const MIN_RELIABLE_CONFIDENCE: u8 = 50;

// ============================================================
// Aggregated Verdict
// ============================================================

/// The final verdict after aggregation. Contains both the verdict and
/// metadata explaining WHY (which detectors contributed, confidence, etc.)
pub const AggregatedVerdict = struct {
    verdict: detection.Verdict,
    /// Confidence score 0-100 (weighted average of contributing evidence).
    confidence: u8,
    /// Number of detectors that produced evidence.
    detector_count: usize,
    /// Number of detectors that agreed with the final verdict.
    agreeing_count: usize,
    /// Number of MALICIOUS verdicts in evidence.
    malicious_count: usize,
    /// Number of SUSPICIOUS verdicts in evidence.
    suspicious_count: usize,
    /// Number of ERROR verdicts in evidence.
    error_count: usize,
    /// True if the verdict was escalated from a lower level (e.g., OBSERVE -> SUSPICIOUS).
    escalated: bool,
    /// Original verdict BEFORE escalation (for forensics).
    original_verdict: detection.Verdict,
    /// Bitfield of all indicators from all evidence.
    indicators: u32,
    /// Triggering event_id (for correlation).
    event_id: u64,

    /// Returns true if the verdict indicates a threat (suspicious or malicious).
    pub fn isThreat(self: AggregatedVerdict) bool {
        return self.verdict.isThreat();
    }

    /// Returns true if this verdict was escalated from a lower severity.
    pub fn wasEscalated(self: AggregatedVerdict) bool {
        return self.escalated;
    }

    /// Returns true if confidence is high enough to be reliable.
    pub fn isReliable(self: AggregatedVerdict) bool {
        return self.confidence >= MIN_RELIABLE_CONFIDENCE;
    }

    /// Human-readable summary for logging.
    pub fn summary(self: AggregatedVerdict) []const u8 {
        return switch (self.verdict) {
            .benign => "benign: no threat indicators detected",
            .observe => "observe: indicators present, monitoring",
            .suspicious => "suspicious: threat indicators detected",
            .malicious => "malicious: confirmed threat",
            .unknown => "unknown: insufficient data or detector errors",
            .error_ => "error: aggregation failed",
        };
    }
};

// ============================================================
// Detector weights (for confidence scoring)
// ============================================================

/// Returns the weight (0.0-1.0) for a detector based on its ID.
/// Higher weight = more trusted detector.
fn detectorWeight(detector_id: u32) f32 {
    return switch (detector_id) {
        detection.DetectorId.rule_match => 1.0,
        detection.DetectorId.port_scan => 0.7,
        detection.DetectorId.high_rate => 0.5,
        else => 0.3, // Unknown detector - fail-safe low trust
    };
}

// ============================================================
// Verdict Aggregator
// ============================================================

pub const VerdictAggregator = struct {
    /// Total aggregations performed.
    total_aggregations: u64,
    /// Count of each final verdict.
    benign_count: u64,
    observe_count: u64,
    suspicious_count: u64,
    malicious_count: u64,
    unknown_count: u64,
    error_count: u64,
    /// Count of escalations (verdict changed during escalation step).
    total_escalations: u64,

    pub fn init() VerdictAggregator {
        return .{
            .total_aggregations = 0,
            .benign_count = 0,
            .observe_count = 0,
            .suspicious_count = 0,
            .malicious_count = 0,
            .unknown_count = 0,
            .error_count = 0,
            .total_escalations = 0,
        };
    }

    /// Aggregate evidence into a single verdict.
    /// `flow_update` is optional - used for escalation rules. Can be null.
    pub fn aggregate(
        self: *VerdictAggregator,
        evidence: detection.EvidenceList,
        flow_update: ?flow_types.FlowUpdate,
        event_id: u64,
    ) AggregatedVerdict {
        self.total_aggregations += 1;

        if (evidence.count == 0) {
            // No evidence - unknown
            self.unknown_count += 1;
            return .{
                .verdict = .unknown,
                .confidence = 0,
                .detector_count = 0,
                .agreeing_count = 0,
                .malicious_count = 0,
                .suspicious_count = 0,
                .error_count = 0,
                .escalated = false,
                .original_verdict = .unknown,
                .indicators = detection.Indicator.NONE,
                .event_id = event_id,
            };
        }

        // Tally verdicts
        var malicious_n: usize = 0;
        var suspicious_n: usize = 0;
        var observe_n: usize = 0;
        var benign_n: usize = 0;
        var unknown_n: usize = 0;
        var error_n: usize = 0;
        var all_indicators: u32 = detection.Indicator.NONE;

        var total_weighted_confidence: f32 = 0;
        var total_weight: f32 = 0;

        for (evidence.slice()) |e| {
            all_indicators |= e.indicators;
            const weight = detectorWeight(e.detector_id);
            total_weighted_confidence += @as(f32, @floatFromInt(e.confidence)) * weight;
            total_weight += weight;

            switch (e.verdict) {
                .malicious => malicious_n += 1,
                .suspicious => suspicious_n += 1,
                .observe => observe_n += 1,
                .benign => benign_n += 1,
                .unknown => unknown_n += 1,
                .error_ => error_n += 1,
            }
        }

        // Weighted confidence (0-100)
        const avg_confidence: u8 = if (total_weight > 0)
            @intFromFloat(@min(100.0, total_weighted_confidence / total_weight))
        else
            0;

        // Step 1: Quorum for MALICIOUS
        var verdict: detection.Verdict = undefined;
        var agreeing: usize = 0;

        if (malicious_n >= QUORUM_FOR_MALICIOUS) {
            verdict = .malicious;
            agreeing = malicious_n;
        } else if ((suspicious_n + malicious_n) >= QUORUM_FOR_SUSPICIOUS) {
            // Step 2: Quorum for SUSPICIOUS
            verdict = .suspicious;
            agreeing = suspicious_n + malicious_n;
        } else if (benign_n == evidence.count) {
            // Step 4: All BENIGN
            verdict = .benign;
            agreeing = benign_n;
        } else if (error_n > 0 and malicious_n == 0 and suspicious_n == 0) {
            // Step 3: Only errors, no threats - fail open to UNKNOWN
            verdict = .unknown;
            agreeing = error_n;
        } else {
            // Step 5: Mixed OBSERVE/UNKNOWN/BENIGN, no threats
            verdict = .observe;
            agreeing = observe_n;
        }

        const original_verdict = verdict;

        // Step 6: Escalation rules
        var escalated = false;
        if (flow_update) |upd| {
            // Rule 1: high flow severity + SUSPICIOUS -> MALICIOUS
            if (verdict == .suspicious and upd.flow.max_severity >= 3) {
                verdict = .malicious;
                escalated = true;
            }
            // Rule 2: high packet count + OBSERVE -> SUSPICIOUS
            else if (verdict == .observe and upd.flow.packet_count > ESCALATION_PACKET_THRESHOLD) {
                verdict = .suspicious;
                escalated = true;
            }
        }

        if (escalated) {
            self.total_escalations += 1;
        }

        // Update stats
        switch (verdict) {
            .benign => self.benign_count += 1,
            .observe => self.observe_count += 1,
            .suspicious => self.suspicious_count += 1,
            .malicious => self.malicious_count += 1,
            .unknown => self.unknown_count += 1,
            .error_ => self.error_count += 1,
        }

        return .{
            .verdict = verdict,
            .confidence = avg_confidence,
            .detector_count = evidence.count,
            .agreeing_count = agreeing,
            .malicious_count = malicious_n,
            .suspicious_count = suspicious_n,
            .error_count = error_n,
            .escalated = escalated,
            .original_verdict = original_verdict,
            .indicators = all_indicators,
            .event_id = event_id,
        };
    }

    /// Reset all stats (for tests).
    pub fn resetStats(self: *VerdictAggregator) void {
        self.* = init();
    }
};

// ============================================================
// Tests (all use local aggregator instances - parallelism-safe)
// ============================================================

test "VerdictAggregator init has zero stats" {
    const agg = VerdictAggregator.init();
    try std.testing.expect(agg.total_aggregations == 0);
    try std.testing.expect(agg.malicious_count == 0);
    try std.testing.expect(agg.total_escalations == 0);
}

test "AggregatedVerdict.isThreat matches verdict" {
    const av_benign = AggregatedVerdict{
        .verdict = .benign,
        .confidence = 80,
        .detector_count = 3,
        .agreeing_count = 3,
        .malicious_count = 0,
        .suspicious_count = 0,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .benign,
        .indicators = detection.Indicator.NONE,
        .event_id = 0,
    };
    try std.testing.expect(!av_benign.isThreat());

    const av_malicious = AggregatedVerdict{
        .verdict = .malicious,
        .confidence = 90,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 2,
        .suspicious_count = 0,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .malicious,
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = 0,
    };
    try std.testing.expect(av_malicious.isThreat());
}

test "AggregatedVerdict.isReliable threshold" {
    var av = AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 60,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = 0,
        .event_id = 0,
    };
    try std.testing.expect(av.isReliable()); // 60 >= 50

    av.confidence = 30;
    try std.testing.expect(!av.isReliable()); // 30 < 50
}

test "aggregate: empty evidence returns UNKNOWN" {
    var agg = VerdictAggregator.init();
    const empty = detection.EvidenceList.init();

    const result = agg.aggregate(empty, null, 42);
    try std.testing.expect(result.verdict == .unknown);
    try std.testing.expect(result.detector_count == 0);
    try std.testing.expect(result.event_id == 42);
    try std.testing.expect(agg.unknown_count == 1);
}

test "aggregate: all BENIGN evidence returns BENIGN" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(detection.DetectionEvidence.benign(1, 0, 0));
    list.append(detection.DetectionEvidence.benign(2, 0, 0));
    list.append(detection.DetectionEvidence.benign(3, 0, 0));

    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.verdict == .benign);
    try std.testing.expect(result.detector_count == 3);
    try std.testing.expect(result.agreeing_count == 3);
    try std.testing.expect(result.malicious_count == 0);
    try std.testing.expect(agg.benign_count == 1);
}

test "aggregate: single MALICIOUS triggers MALICIOUS (quorum=1)" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(detection.DetectionEvidence.benign(1, 0, 0));
    list.append(.{
        .verdict = .malicious,
        .detector_id = 2,
        .rule_id = 0,
        .confidence = 90,
        .severity = 3,
        .description = "test",
        .indicators = detection.Indicator.PORT_SCAN,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    list.append(detection.DetectionEvidence.benign(3, 0, 0));

    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.verdict == .malicious);
    try std.testing.expect(result.malicious_count == 1);
    try std.testing.expect(result.agreeing_count == 1);
    try std.testing.expect(agg.malicious_count == 1);
}

test "aggregate: single SUSPICIOUS triggers SUSPICIOUS (quorum=1)" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(detection.DetectionEvidence.benign(1, 0, 0));
    list.append(.{
        .verdict = .suspicious,
        .detector_id = 2,
        .rule_id = 0,
        .confidence = 60,
        .severity = 2,
        .description = "test",
        .indicators = detection.Indicator.PORT_SCAN,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });

    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.verdict == .suspicious);
    try std.testing.expect(result.suspicious_count == 1);
}

test "aggregate: only ERROR evidence returns UNKNOWN (fail-open)" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(detection.DetectionEvidence.err(1, 0, 0));
    list.append(detection.DetectionEvidence.err(2, 0, 0));

    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.verdict == .unknown);
    try std.testing.expect(result.error_count == 2);
}

test "aggregate: mixed BENIGN+OBSERVE+UNKNOWN (no threats) returns OBSERVE" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(detection.DetectionEvidence.benign(1, 0, 0));
    list.append(.{
        .verdict = .observe,
        .detector_id = 2,
        .rule_id = 0,
        .confidence = 50,
        .severity = 1,
        .description = "test",
        .indicators = detection.Indicator.HIGH_RATE,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });

    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.verdict == .observe);
    try std.testing.expect(result.agreeing_count == 1);
}

test "aggregate: confidence is weighted average" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    // rule_match (weight 1.0) confidence 80
    list.append(.{
        .verdict = .suspicious,
        .detector_id = detection.DetectorId.rule_match,
        .rule_id = 1,
        .confidence = 80,
        .severity = 2,
        .description = "test",
        .indicators = detection.Indicator.RULE_MATCH,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    // high_rate (weight 0.5) confidence 60
    list.append(.{
        .verdict = .observe,
        .detector_id = detection.DetectorId.high_rate,
        .rule_id = 0,
        .confidence = 60,
        .severity = 1,
        .description = "test",
        .indicators = detection.Indicator.HIGH_RATE,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    // Weighted: (80*1.0 + 60*0.5) / (1.0 + 0.5) = 110 / 1.5 = 73.33 -> 73
    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.confidence == 73);
}

test "aggregate: indicators are OR-combined across evidence" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(.{
        .verdict = .suspicious,
        .detector_id = 1,
        .rule_id = 1,
        .confidence = 80,
        .severity = 2,
        .description = "test",
        .indicators = detection.Indicator.RULE_MATCH,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    list.append(.{
        .verdict = .suspicious,
        .detector_id = 2,
        .rule_id = 0,
        .confidence = 60,
        .severity = 2,
        .description = "test",
        .indicators = detection.Indicator.PORT_SCAN,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });

    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.indicators & detection.Indicator.RULE_MATCH != 0);
    try std.testing.expect(result.indicators & detection.Indicator.PORT_SCAN != 0);
}

test "aggregate: escalation rule 1 (SUSPICIOUS + high flow severity -> MALICIOUS)" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(.{
        .verdict = .suspicious,
        .detector_id = 1,
        .rule_id = 1,
        .confidence = 80,
        .severity = 2,
        .description = "test",
        .indicators = detection.Indicator.RULE_MATCH,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });

    // Flow with max_severity = 3 (critical)
    const key = flow_types.FlowKey{
        .ip_a = 0x0A000001,
        .port_a = 12345,
        .ip_b = 0x0A000002,
        .port_b = 80,
        .protocol = 6,
    };
    const upd = flow_types.FlowUpdate{
        .kind = .flow_updated,
        .key = key,
        .flow = .{
            .key = key,
            .state = .established,
            .start_ns = 0,
            .last_seen_ns = 1000,
            .packet_count = 10,
            .byte_count = 1000,
            .session_id_set = 1,
            .last_session_id = 1,
            .initial_direction = 0,
            .max_severity = 3, // critical
            .rule_matched = true,
            .last_rule_id = 1,
        },
        .triggering_event_id = 0,
    };

    const result = agg.aggregate(list, upd, 0);
    try std.testing.expect(result.verdict == .malicious);
    try std.testing.expect(result.escalated == true);
    try std.testing.expect(result.original_verdict == .suspicious);
    try std.testing.expect(agg.total_escalations == 1);
    try std.testing.expect(agg.malicious_count == 1);
}

test "aggregate: escalation rule 2 (OBSERVE + high packet count -> SUSPICIOUS)" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(.{
        .verdict = .observe,
        .detector_id = 3,
        .rule_id = 0,
        .confidence = 50,
        .severity = 1,
        .description = "test",
        .indicators = detection.Indicator.HIGH_RATE,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });

    // Flow with packet_count > ESCALATION_PACKET_THRESHOLD (200)
    const key = flow_types.FlowKey{
        .ip_a = 0x0A000001,
        .port_a = 12345,
        .ip_b = 0x0A000002,
        .port_b = 80,
        .protocol = 6,
    };
    const upd = flow_types.FlowUpdate{
        .kind = .flow_updated,
        .key = key,
        .flow = .{
            .key = key,
            .state = .established,
            .start_ns = 0,
            .last_seen_ns = 1000,
            .packet_count = 300, // > 200
            .byte_count = 30000,
            .session_id_set = 1,
            .last_session_id = 1,
            .initial_direction = 0,
            .max_severity = 0,
            .rule_matched = false,
            .last_rule_id = 0,
        },
        .triggering_event_id = 0,
    };

    const result = agg.aggregate(list, upd, 0);
    try std.testing.expect(result.verdict == .suspicious);
    try std.testing.expect(result.escalated == true);
    try std.testing.expect(result.original_verdict == .observe);
}

test "aggregate: no escalation when flow is null" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(.{
        .verdict = .suspicious,
        .detector_id = 1,
        .rule_id = 1,
        .confidence = 80,
        .severity = 2,
        .description = "test",
        .indicators = detection.Indicator.RULE_MATCH,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });

    // No flow_update - no escalation possible
    const result = agg.aggregate(list, null, 0);
    try std.testing.expect(result.verdict == .suspicious);
    try std.testing.expect(result.escalated == false);
    try std.testing.expect(result.original_verdict == .suspicious);
}

test "aggregate: stats accumulate correctly" {
    var agg = VerdictAggregator.init();

    // Run 1: BENIGN
    var list1 = detection.EvidenceList.init();
    list1.append(detection.DetectionEvidence.benign(1, 0, 0));
    _ = agg.aggregate(list1, null, 0);

    // Run 2: MALICIOUS
    var list2 = detection.EvidenceList.init();
    list2.append(.{
        .verdict = .malicious,
        .detector_id = 1,
        .rule_id = 1,
        .confidence = 90,
        .severity = 3,
        .description = "test",
        .indicators = detection.Indicator.RULE_MATCH,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    _ = agg.aggregate(list2, null, 0);

    // Run 3: empty -> UNKNOWN
    const empty = detection.EvidenceList.init();
    _ = agg.aggregate(empty, null, 0);

    try std.testing.expect(agg.total_aggregations == 3);
    try std.testing.expect(agg.benign_count == 1);
    try std.testing.expect(agg.malicious_count == 1);
    try std.testing.expect(agg.unknown_count == 1);
}

test "resetStats zeroes all counters" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.append(detection.DetectionEvidence.benign(1, 0, 0));
    _ = agg.aggregate(list, null, 0);
    try std.testing.expect(agg.total_aggregations == 1);

    agg.resetStats();
    try std.testing.expect(agg.total_aggregations == 0);
    try std.testing.expect(agg.benign_count == 0);
}

test "detectorWeight: rule_match gets 1.0, unknown gets 0.3" {
    try std.testing.expect(detectorWeight(detection.DetectorId.rule_match) == 1.0);
    try std.testing.expect(detectorWeight(detection.DetectorId.port_scan) == 0.7);
    try std.testing.expect(detectorWeight(detection.DetectorId.high_rate) == 0.5);
    try std.testing.expect(detectorWeight(999) == 0.3); // unknown
}

test "AggregatedVerdict.summary returns readable description" {
    const av = AggregatedVerdict{
        .verdict = .malicious,
        .confidence = 90,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 2,
        .suspicious_count = 0,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .malicious,
        .indicators = 0,
        .event_id = 0,
    };
    const s = av.summary();
    try std.testing.expect(s.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, s, "malicious") != null);
}
