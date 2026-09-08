//! verdict_aggregator.zig - AEGIS Verdict Aggregator (Rewrite Phase 8)
//!
//! Aggregates Evidence from multiple detectors into a single AggregatedVerdict.
//! Uses voting + confidence weighting to produce a final verdict with the
//! ability to escalate if multiple high-confidence detectors agree.
//!
//! Contract:
//!   VerdictAggregator.init() -> VerdictAggregator
//!   agg.aggregate(evidence_list, flow_update, event_id) -> AggregatedVerdict

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const flow = @import("flow_engine.zig");

// ============================================================
// Aggregated Verdict
// ============================================================

pub const AggregatedVerdict = struct {
    verdict: detection.Verdict,
    original_verdict: detection.Verdict,
    confidence: u8,
    agreeing_count: u8,
    detector_count: u8,
    escalated: bool,
    event_id: u64,

    /// Returns true if the aggregated verdict is suspicious or worse.
    pub fn isThreat(self: AggregatedVerdict) bool {
        return self.verdict.isThreat();
    }

    /// Returns true if the verdict was escalated above the original.
    pub fn wasEscalated(self: AggregatedVerdict) bool {
        return self.escalated;
    }

    /// Returns true if the verdict matches or exceeds a threshold.
    pub fn isAtLeast(self: AggregatedVerdict, threshold: detection.Verdict) bool {
        return self.verdict.isAtLeast(threshold);
    }
};

// ============================================================
// Verdict Aggregator
// ============================================================

pub const VerdictAggregator = struct {
    total_aggregated: u64 = 0,
    total_escalated: u64 = 0,
    total_threats: u64 = 0,

    pub fn init() VerdictAggregator {
        return .{};
    }

    /// Aggregate evidence into a single verdict.
    /// Algorithm:
    ///   1. Compute max verdict across all evidence (the "floor").
    ///   2. Compute mean confidence weighted by detector agreement.
    ///   3. If >=2 detectors agree on the max verdict and avg confidence
    ///      >=70, escalate by one level.
    ///   4. Returns AggregatedVerdict with the final verdict and stats.
    pub fn aggregate(
        self: *VerdictAggregator,
        evidence_list: detection.EvidenceList,
        flow_update: ?flow.FlowUpdate,
        event_id: u64,
    ) AggregatedVerdict {
        _ = flow_update; // future: flow-based escalation
        self.total_aggregated += 1;

        if (evidence_list.count == 0) {
            return .{
                .verdict = .unknown,
                .original_verdict = .unknown,
                .confidence = 0,
                .agreeing_count = 0,
                .detector_count = 0,
                .escalated = false,
                .event_id = event_id,
            };
        }

        const max_v = evidence_list.maxVerdict();
        const avg_conf = blk: {
            var sum: u32 = 0;
            for (evidence_list.slice()) |e| {
                sum += e.confidence;
            }
            break :blk @as(u8, @intCast(sum / evidence_list.count));
        };

        // Count detectors that agree on the max verdict
        var agreeing: u8 = 0;
        for (evidence_list.slice()) |e| {
            if (e.verdict == max_v) agreeing += 1;
        }

        // Escalation: 2+ detectors agree AND high avg confidence
        var escalated = false;
        var final_v = max_v;
        if (agreeing >= 2 and avg_conf >= 70) {
            // Escalate one level (cap at .critical)
            if (@intFromEnum(max_v) < @intFromEnum(detection.Verdict.critical)) {
                final_v = @enumFromInt(@intFromEnum(max_v) + 1);
                escalated = true;
                self.total_escalated += 1;
            }
        }

        if (final_v.isThreat()) self.total_threats += 1;

        return .{
            .verdict = final_v,
            .original_verdict = max_v,
            .confidence = avg_conf,
            .agreeing_count = agreeing,
            .detector_count = @intCast(evidence_list.count),
            .escalated = escalated,
            .event_id = event_id,
        };
    }

    pub fn resetStats(self: *VerdictAggregator) void {
        self.total_aggregated = 0;
        self.total_escalated = 0;
        self.total_threats = 0;
    }
};

// ============================================================
// Tests
// ============================================================

fn makeEvidence(v: detection.Verdict, conf: u8, det_id: u8) detection.Evidence {
    return .{
        .detector_id = det_id,
        .verdict = v,
        .rule_id = 0,
        .confidence = conf,
        .description = "test",
    };
}

test "VerdictAggregator.init starts with zero stats" {
    const agg = VerdictAggregator.init();
    try std.testing.expect(agg.total_aggregated == 0);
    try std.testing.expect(agg.total_escalated == 0);
    try std.testing.expect(agg.total_threats == 0);
}

test "VerdictAggregator.aggregate on empty list returns unknown" {
    var agg = VerdictAggregator.init();
    const list = detection.EvidenceList.init();
    const av = agg.aggregate(list, null, 1);
    try std.testing.expect(av.verdict == .unknown);
    try std.testing.expect(av.confidence == 0);
    try std.testing.expect(av.detector_count == 0);
    try std.testing.expect(!av.escalated);
    try std.testing.expect(!av.isThreat());
}

test "VerdictAggregator.aggregate picks max verdict from single evidence" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.malicious, 80, 0));
    const av = agg.aggregate(list, null, 1);
    try std.testing.expect(av.verdict == .malicious);
    try std.testing.expect(av.original_verdict == .malicious);
    try std.testing.expect(av.confidence == 80);
    try std.testing.expect(av.agreeing_count == 1);
    try std.testing.expect(av.detector_count == 1);
    try std.testing.expect(!av.escalated);
    try std.testing.expect(av.isThreat());
}

test "VerdictAggregator.aggregate escalates when 2+ agree at high confidence" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.suspicious, 80, 0));
    list.add(makeEvidence(.suspicious, 75, 1));
    const av = agg.aggregate(list, null, 1);
    try std.testing.expect(av.escalated);
    try std.testing.expect(av.verdict == .malicious);
    try std.testing.expect(av.original_verdict == .suspicious);
    try std.testing.expect(av.agreeing_count == 2);
    try std.testing.expect(av.wasEscalated());
}

test "VerdictAggregator.aggregate does NOT escalate when confidence too low" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.suspicious, 50, 0));
    list.add(makeEvidence(.suspicious, 60, 1));
    const av = agg.aggregate(list, null, 1);
    try std.testing.expect(!av.escalated);
    try std.testing.expect(av.verdict == .suspicious);
}

test "VerdictAggregator.aggregate does NOT escalate with single detector" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.malicious, 95, 0));
    const av = agg.aggregate(list, null, 1);
    try std.testing.expect(!av.escalated);
    try std.testing.expect(av.verdict == .malicious);
}

test "VerdictAggregator.aggregate does NOT escalate past critical" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.critical, 95, 0));
    list.add(makeEvidence(.critical, 95, 1));
    const av = agg.aggregate(list, null, 1);
    try std.testing.expect(!av.escalated);
    try std.testing.expect(av.verdict == .critical);
}

test "VerdictAggregator.aggregate computes average confidence" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.suspicious, 60, 0));
    list.add(makeEvidence(.suspicious, 80, 1));
    list.add(makeEvidence(.benign, 40, 2));
    const av = agg.aggregate(list, null, 1);
    // (60+80+40)/3 = 60
    try std.testing.expect(av.confidence == 60);
}

test "VerdictAggregator tracks lifetime stats" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.suspicious, 80, 0));
    list.add(makeEvidence(.suspicious, 80, 1));
    _ = agg.aggregate(list, null, 1);
    _ = agg.aggregate(list, null, 2);
    try std.testing.expect(agg.total_aggregated == 2);
    try std.testing.expect(agg.total_escalated == 2);
    try std.testing.expect(agg.total_threats == 2);
}

test "VerdictAggregator.resetStats zeroes counters" {
    var agg = VerdictAggregator.init();
    var list = detection.EvidenceList.init();
    list.add(makeEvidence(.suspicious, 80, 0));
    list.add(makeEvidence(.suspicious, 80, 1));
    _ = agg.aggregate(list, null, 1);
    try std.testing.expect(agg.total_aggregated > 0);
    agg.resetStats();
    try std.testing.expect(agg.total_aggregated == 0);
}

test "AggregatedVerdict.isAtLeast threshold check" {
    const av = AggregatedVerdict{
        .verdict = .malicious,
        .original_verdict = .malicious,
        .confidence = 80,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = 1,
    };
    try std.testing.expect(av.isAtLeast(.suspicious));
    try std.testing.expect(av.isAtLeast(.malicious));
    try std.testing.expect(!av.isAtLeast(.critical));
}
