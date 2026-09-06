//! forensics_engine.zig - AEGIS Forensics Engine (Rewrite Phase 14)
//!
//! Records every pipeline result to a ring buffer for replay and incident
//! reconstruction. This is the FINAL stage of the pipeline - all evidence,
//! decisions, and enforcement outcomes are persisted here.
//!
//! Contract:
//!   PipelineResult: struct containing the full pipeline output for one event
//!   ForensicRecord: struct { result, sequence, logged_at_ns }
//!   ForensicsEngine: logResult(...) -> u64 (sequence number)
//!
//! NOTE: The actual NDJSON logger is in forensic_log.zig. This module owns
//! the in-memory ring buffer used for replay. The two cooperate: this
//! engine returns the sequence number, and forensic_log.zig writes the
//! NDJSON line if needed.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");

// ============================================================
// Constants
// ============================================================

pub const RING_BUFFER_CAPACITY: usize = 4096;

// ============================================================
// Pipeline Result
// ============================================================

pub const PipelineResult = struct {
    event_id: u64,
    timestamp_ns: i128,
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,

    aggregated_verdict: detection.Verdict,
    aggregated_confidence: u8,
    escalated: bool,
    original_verdict: detection.Verdict,

    correlation_alert_count: u8,
    correlation_rules: [3]u32,

    threat_intel_matched: bool,
    threat_intel_max_severity: u8,

    brain_advice_kind: u8,
    brain_threat_score: u16,
    brain_recommended_verdict: detection.Verdict,

    policy_action: policy.EnforcementAction,
    policy_rule: policy.PolicyRule,
    policy_confidence: u8,

    pep_status: rust_pep.EnforcementStatus,
    pep_rejection_reason: rust_pep.RejectionReason,
    pep_blocked_ip: u32,
};

// ============================================================
// Forensic Record (PipelineResult + bookkeeping)
// ============================================================

pub const ForensicRecord = struct {
    result: PipelineResult,
    sequence: u64,
    logged_at_ns: i128,
};

// ============================================================
// Forensics Engine (ring buffer)
// ============================================================

pub const ForensicsEngine = struct {
    ring: [RING_BUFFER_CAPACITY]ForensicRecord = undefined,
    head: usize = 0,
    count: usize = 0,
    next_sequence: u64 = 1,
    total_logged: u64 = 0,

    pub fn init() ForensicsEngine {
        return .{};
    }

    /// Log a pipeline result. Returns the assigned sequence number.
    pub fn logResult(
        self: *ForensicsEngine,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
        ti_match: threat_intel.ThreatIntelMatch,
        advice: brain.BrainAdvice,
        decision: policy.EnforcementDecision,
        pep_result: rust_pep.EnforcementResult,
    ) u64 {
        var rule_ids: [3]u32 = .{ 0, 0, 0 };
        var alert_count: u8 = 0;
        for (alerts, 0..) |a, i| {
            if (a) |alert| {
                if (alert_count < 3) {
                    rule_ids[alert_count] = @intFromEnum(alert.rule);
                    alert_count += 1;
                }
            }
            _ = i;
        }

        const result = PipelineResult{
            .event_id = event.event_id,
            .timestamp_ns = event.monotonic_ns,
            .source_ip = event.source_ip,
            .dest_ip = event.dest_ip,
            .source_port = event.source_port,
            .dest_port = event.dest_port,
            .protocol = event.protocol,

            .aggregated_verdict = av.verdict,
            .aggregated_confidence = av.confidence,
            .escalated = av.escalated,
            .original_verdict = av.original_verdict,

            .correlation_alert_count = alert_count,
            .correlation_rules = rule_ids,

            .threat_intel_matched = ti_match.hasMatch(),
            .threat_intel_max_severity = @intFromEnum(ti_match.maxSeverity()),

            .brain_advice_kind = @intFromEnum(advice.kind),
            .brain_threat_score = advice.threat_score,
            .brain_recommended_verdict = advice.recommended_verdict,

            .policy_action = decision.action,
            .policy_rule = decision.rule,
            .policy_confidence = decision.confidence,

            .pep_status = pep_result.status,
            .pep_rejection_reason = pep_result.reason,
            .pep_blocked_ip = pep_result.blocked_ip,
        };

        const seq = self.next_sequence;
        const idx = self.head;
        self.ring[idx] = .{
            .result = result,
            .sequence = seq,
            .logged_at_ns = std.time.nanoTimestamp(),
        };

        self.head = (self.head + 1) % RING_BUFFER_CAPACITY;
        if (self.count < RING_BUFFER_CAPACITY) self.count += 1;
        self.next_sequence += 1;
        self.total_logged += 1;

        return seq;
    }

    /// Get a record by sequence number (returns null if not in ring).
    pub fn getBySequence(self: *const ForensicsEngine, seq: u64) ?ForensicRecord {
        if (seq == 0) return null;
        if (seq >= self.next_sequence) return null;
        // Scan the ring (linear - capacity is bounded at 4096)
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            // Records are stored in ring starting at (head - count) mod CAPACITY
            const idx = (self.head + RING_BUFFER_CAPACITY - self.count + i) % RING_BUFFER_CAPACITY;
            if (self.ring[idx].sequence == seq) return self.ring[idx];
        }
        return null;
    }

    /// Get the most recent N records (returns slice into internal storage).
    pub fn recent(self: *const ForensicsEngine, n: usize) []const ForensicRecord {
        const actual_n = @min(n, self.count);
        const start = (self.head + RING_BUFFER_CAPACITY - actual_n) % RING_BUFFER_CAPACITY;
        // Note: this assumes no wrap-around. Caller should handle wrap if n > 0
        // and start + n > CAPACITY.
        return self.ring[start..start + actual_n];
    }

    pub fn resetStats(self: *ForensicsEngine) void {
        self.head = 0;
        self.count = 0;
        self.next_sequence = 1;
        self.total_logged = 0;
    }
};

// ============================================================
// Tests
// ============================================================

fn makeTestInputs(event_id: u64, verdict: detection.Verdict) struct {
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [3]?correlation.CorrelationAlert,
    ti: threat_intel.ThreatIntelMatch,
    advice: brain.BrainAdvice,
    decision: policy.EnforcementDecision,
    pep_result: rust_pep.EnforcementResult,
} {
    var event = canonical.create(.zig_core);
    event.event_id = event_id;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.severity = if (verdict.isThreat()) 2 else 0;

    return .{
        .event = event,
        .av = .{
            .verdict = verdict,
            .original_verdict = verdict,
            .confidence = 70,
            .agreeing_count = 1,
            .detector_count = 1,
            .escalated = false,
            .event_id = event_id,
        },
        .alerts = .{ null, null, null },
        .ti = .{ .src_match = null, .dst_match = null, .event_id = event_id },
        .advice = .{
            .kind = .keep_verdict,
            .threat_score = 40,
            .recommended_verdict = verdict,
            .original_verdict = verdict,
            .confidence = 70,
            .explanation = "test",
            .signal_detection = 0,
            .signal_correlation = 0,
            .signal_threat_intel = 0,
            .signal_flow_anomaly = 0,
            .event_id = event_id,
        },
        .decision = .{
            .action = if (verdict.isThreat()) .block else .allow,
            .rule = if (verdict.isThreat()) .verdict_malicious else .default_allow,
            .confidence = 70,
            .reason = "test",
            .event_id = event_id,
            .brain_recommended_verdict = verdict,
            .original_verdict = verdict,
            .threat_score = 40,
        },
        .pep_result = .{
            .status = .executed,
            .reason = .none,
            .requested_action = if (verdict.isThreat()) .block else .allow,
            .actual_action = if (verdict.isThreat()) .block else .allow,
            .event_id = event_id,
            .blocked_ip = if (verdict.isThreat()) 0x0A000001 else 0,
            .message = "test",
        },
    };
}

test "ForensicsEngine.init starts empty" {
    const engine = ForensicsEngine.init();
    try std.testing.expect(engine.count == 0);
    try std.testing.expect(engine.next_sequence == 1);
    try std.testing.expect(engine.total_logged == 0);
}

test "ForensicsEngine.logResult returns increasing sequence numbers" {
    var engine = ForensicsEngine.init();
    const inputs1 = makeTestInputs(1, .benign);
    const seq1 = engine.logResult(inputs1.event, inputs1.av, inputs1.alerts, inputs1.ti, inputs1.advice, inputs1.decision, inputs1.pep_result);
    try std.testing.expect(seq1 == 1);

    const inputs2 = makeTestInputs(2, .suspicious);
    const seq2 = engine.logResult(inputs2.event, inputs2.av, inputs2.alerts, inputs2.ti, inputs2.advice, inputs2.decision, inputs2.pep_result);
    try std.testing.expect(seq2 == 2);
    try std.testing.expect(engine.count == 2);
    try std.testing.expect(engine.total_logged == 2);
}

test "ForensicsEngine.logResult stores all fields" {
    var engine = ForensicsEngine.init();
    const inputs = makeTestInputs(42, .malicious);
    const seq = engine.logResult(inputs.event, inputs.av, inputs.alerts, inputs.ti, inputs.advice, inputs.decision, inputs.pep_result);
    try std.testing.expect(seq == 1);

    const rec = engine.getBySequence(seq) orelse {
        try std.testing.expect(false);
        return;
    };
    try std.testing.expect(rec.result.event_id == 42);
    try std.testing.expect(rec.result.source_ip == 0x0A000001);
    try std.testing.expect(rec.result.dest_ip == 0x0A000002);
    try std.testing.expect(rec.result.aggregated_verdict == .malicious);
    try std.testing.expect(rec.result.policy_action == .block);
    try std.testing.expect(rec.result.pep_status == .executed);
    try std.testing.expect(rec.sequence == 1);
}

test "ForensicsEngine.getBySequence returns null for unknown seq" {
    var engine = ForensicsEngine.init();
    try std.testing.expect(engine.getBySequence(0) == null);
    try std.testing.expect(engine.getBySequence(999) == null);

    const inputs = makeTestInputs(1, .benign);
    _ = engine.logResult(inputs.event, inputs.av, inputs.alerts, inputs.ti, inputs.advice, inputs.decision, inputs.pep_result);
    try std.testing.expect(engine.getBySequence(999) == null);
}

test "ForensicsEngine.recent returns last N records" {
    var engine = ForensicsEngine.init();
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        const inputs = makeTestInputs(i + 1, .benign);
        _ = engine.logResult(inputs.event, inputs.av, inputs.alerts, inputs.ti, inputs.advice, inputs.decision, inputs.pep_result);
    }
    const recent_recs = engine.recent(3);
    try std.testing.expect(recent_recs.len == 3);
    try std.testing.expect(recent_recs[0].result.event_id == 3);
    try std.testing.expect(recent_recs[2].result.event_id == 5);
}

test "ForensicsEngine.resetStats clears ring" {
    var engine = ForensicsEngine.init();
    const inputs = makeTestInputs(1, .benign);
    _ = engine.logResult(inputs.event, inputs.av, inputs.alerts, inputs.ti, inputs.advice, inputs.decision, inputs.pep_result);
    try std.testing.expect(engine.count > 0);
    engine.resetStats();
    try std.testing.expect(engine.count == 0);
    try std.testing.expect(engine.next_sequence == 1);
    try std.testing.expect(engine.total_logged == 0);
}

test "ForensicsEngine handles ring buffer wrap-around" {
    var engine = ForensicsEngine.init();
    // Log more than RING_BUFFER_CAPACITY records
    var i: u64 = 0;
    while (i < RING_BUFFER_CAPACITY + 10) : (i += 1) {
        const inputs = makeTestInputs(i + 1, .benign);
        _ = engine.logResult(inputs.event, inputs.av, inputs.alerts, inputs.ti, inputs.advice, inputs.decision, inputs.pep_result);
    }
    try std.testing.expect(engine.count == RING_BUFFER_CAPACITY);
    try std.testing.expect(engine.total_logged == RING_BUFFER_CAPACITY + 10);
}
