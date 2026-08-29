//! forensics_engine.zig - AEGIS Forensics Engine (Rewrite Phase 14)
//!
//! Final pipeline stage: logs full pipeline result for forensic analysis + replay.
//! Captures: event, aggregated verdict, correlation alerts, threat intel match,
//! brain advice, policy decision, PEP result.
//!
//! Architecture:
//!   ... -> Policy Engine (12) -> Rust PEP (13) -> Forensics (14)
//!   Forensics is the LAST stage - it records everything for later replay.
//!
//! Design:
//!   - Ring buffer (fixed-size, no allocation in hot path)
//!   - Each record captures pipeline state snapshot
//!   - Query by event_id, time range, verdict, action
//!   - Supports replay (re-process historical events through pipeline)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");

// ============================================================
// Constants
// ============================================================

/// Maximum forensic records in the ring buffer.
pub const MAX_RECORDS: usize = 4096;

// ============================================================
// Pipeline Result (snapshot of full pipeline state for one event)
// ============================================================

pub const PipelineResult = struct {
    /// Event identification.
    event_id: u64,
    timestamp_ns: i128,
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,

    /// Phase 8: Aggregated verdict.
    aggregated_verdict: detection.Verdict,
    aggregated_confidence: u8,
    escalated: bool,
    original_verdict: detection.Verdict,

    /// Phase 9: Correlation alerts summary.
    correlation_alert_count: u8,
    correlation_rules: [3]u8, // packed CorrelationRule values (0=none)

    /// Phase 10: Threat intel match.
    threat_intel_matched: bool,
    threat_intel_max_severity: u8, // ThreatSeverity value

    /// Phase 11: Brain advice.
    brain_advice_kind: u8, // AdviceKind value
    brain_threat_score: u8,
    brain_recommended_verdict: detection.Verdict,

    /// Phase 12: Policy decision.
    policy_action: policy.EnforcementAction,
    policy_rule: policy.PolicyRule,
    policy_confidence: u8,

    /// Phase 13: PEP result.
    pep_status: rust_pep.EnforcementStatus,
    pep_rejection_reason: rust_pep.RejectionReason,
    pep_blocked_ip: u32,

    /// Returns true if this result involved any threat or enforcement.
    pub fn isSignificant(self: PipelineResult) bool {
        return self.aggregated_verdict.isThreat() or
            self.correlation_alert_count > 0 or
            self.threat_intel_matched or
            self.policy_action.isRestrictive() or
            self.pep_status == .executed;
    }

    /// Returns true if this result involved a block/quarantine.
    pub fn isBlocking(self: PipelineResult) bool {
        return self.policy_action.isBlocking() and self.pep_status == .executed;
    }
};

// ============================================================
// Forensic Record (PipelineResult + forensic metadata)
// ============================================================

pub const ForensicRecord = struct {
    result: PipelineResult,
    /// Sequence number (monotonically increasing).
    sequence: u64,
    /// When this record was logged (monotonic ns).
    logged_at_ns: i128,
};

// ============================================================
// Ring Buffer (fixed-size, no allocation)
// ============================================================

pub const RingBuffer = struct {
    records: [MAX_RECORDS]ForensicRecord,
    head: usize, // next write position
    count: usize, // number of valid records (capped at MAX_RECORDS)
    sequence_counter: u64,

    pub fn init() RingBuffer {
        return .{
            .records = undefined,
            .head = 0,
            .count = 0,
            .sequence_counter = 0,
        };
    }

    /// Append a pipeline result. Overwrites oldest if full.
    pub fn append(self: *RingBuffer, result: PipelineResult, logged_at_ns: i128) u64 {
        self.sequence_counter += 1;
        const seq = self.sequence_counter;

        self.records[self.head] = .{
            .result = result,
            .sequence = seq,
            .logged_at_ns = logged_at_ns,
        };

        self.head = (self.head + 1) % MAX_RECORDS;
        if (self.count < MAX_RECORDS) {
            self.count += 1;
        }

        return seq;
    }

    /// Get a record by sequence number. Returns null if not found.
    pub fn getBySequence(self: *const RingBuffer, seq: u64) ?ForensicRecord {
        if (self.count == 0) return null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + MAX_RECORDS - self.count + i) % MAX_RECORDS;
            if (self.records[idx].sequence == seq) {
                return self.records[idx];
            }
        }
        return null;
    }

    /// Get a record by event_id. Returns null if not found.
    pub fn getByEventId(self: *const RingBuffer, event_id: u64) ?ForensicRecord {
        if (self.count == 0) return null;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + MAX_RECORDS - self.count + i) % MAX_RECORDS;
            if (self.records[idx].result.event_id == event_id) {
                return self.records[idx];
            }
        }
        return null;
    }

    /// Get records in a time range [start_ns, end_ns].
    /// Returns count found (records are NOT returned as array to avoid allocation).
    pub fn countByTimeRange(self: *const RingBuffer, start_ns: i128, end_ns: i128) usize {
        if (self.count == 0) return 0;
        var n: usize = 0;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + MAX_RECORDS - self.count + i) % MAX_RECORDS;
            const ts = self.records[idx].result.timestamp_ns;
            if (ts >= start_ns and ts <= end_ns) {
                n += 1;
            }
        }
        return n;
    }

    /// Count records with a specific verdict.
    pub fn countByVerdict(self: *const RingBuffer, v: detection.Verdict) usize {
        if (self.count == 0) return 0;
        var n: usize = 0;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + MAX_RECORDS - self.count + i) % MAX_RECORDS;
            if (self.records[idx].result.aggregated_verdict == v) {
                n += 1;
            }
        }
        return n;
    }

    /// Count records with a specific policy action.
    pub fn countByAction(self: *const RingBuffer, action: policy.EnforcementAction) usize {
        if (self.count == 0) return 0;
        var n: usize = 0;
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const idx = (self.head + MAX_RECORDS - self.count + i) % MAX_RECORDS;
            if (self.records[idx].result.policy_action == action) {
                n += 1;
            }
        }
        return n;
    }

    /// Clear all records.
    pub fn clear(self: *RingBuffer) void {
        self.head = 0;
        self.count = 0;
        self.sequence_counter = 0;
    }

    /// Current number of records.
    pub fn len(self: *const RingBuffer) usize {
        return self.count;
    }
};

// ============================================================
// Forensic Logger
// ============================================================

pub const ForensicLogger = struct {
    buffer: RingBuffer,
    /// Total results logged (lifetime, includes overwritten).
    total_logged: u64,
    /// Count of significant results (threats, blocks, etc.).
    total_significant: u64,
    /// Count of blocking results (block/quarantine executed).
    total_blocking: u64,

    pub fn init() ForensicLogger {
        return .{
            .buffer = RingBuffer.init(),
            .total_logged = 0,
            .total_significant = 0,
            .total_blocking = 0,
        };
    }

    /// Log a pipeline result. Returns the sequence number assigned.
    pub fn logResult(
        self: *ForensicLogger,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        alerts: [3]?correlation.CorrelationAlert,
        ti_match: threat_intel.ThreatIntelMatch,
        advice: brain.BrainAdvice,
        decision: policy.EnforcementDecision,
        pep_result: rust_pep.EnforcementResult,
    ) u64 {
        // Pack correlation rules into array
        var corr_rules: [3]u8 = .{ 0, 0, 0 };
        var corr_count: u8 = 0;
        for (alerts, 0..) |a, idx| {
            if (a) |alert| {
                corr_rules[idx] = @intFromEnum(alert.rule);
                corr_count += 1;
            }
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
            .correlation_alert_count = corr_count,
            .correlation_rules = corr_rules,
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

        const seq = self.buffer.append(result, event.monotonic_ns);
        self.total_logged += 1;
        if (result.isSignificant()) {
            self.total_significant += 1;
        }
        if (result.isBlocking()) {
            self.total_blocking += 1;
        }

        return seq;
    }

    /// Get a record by event_id.
    pub fn getByEventId(self: *const ForensicLogger, event_id: u64) ?ForensicRecord {
        return self.buffer.getByEventId(event_id);
    }

    /// Get a record by sequence number.
    pub fn getBySequence(self: *const ForensicLogger, seq: u64) ?ForensicRecord {
        return self.buffer.getBySequence(seq);
    }

    /// Current record count in buffer.
    pub fn recordCount(self: *const ForensicLogger) usize {
        return self.buffer.len();
    }

    /// Clear all records.
    pub fn clear(self: *ForensicLogger) void {
        self.buffer.clear();
        self.total_logged = 0;
        self.total_significant = 0;
        self.total_blocking = 0;
    }
};

// ============================================================
// Tests (all use local logger instances - parallelism-safe)
// ============================================================

test "PipelineResult.isSignificant detects threats" {
    const result_threat = PipelineResult{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = .suspicious,
        .aggregated_confidence = 70,
        .escalated = false,
        .original_verdict = .suspicious,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 50,
        .brain_recommended_verdict = .suspicious,
        .policy_action = .alert,
        .policy_rule = .verdict_suspicious,
        .policy_confidence = 70,
        .pep_status = .no_op,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0,
    };
    try std.testing.expect(result_threat.isSignificant());

    const result_benign = PipelineResult{
        .event_id = 2,
        .timestamp_ns = 2000,
        .source_ip = 0x0A000003,
        .dest_ip = 0x0A000004,
        .source_port = 80,
        .dest_port = 12345,
        .protocol = 6,
        .aggregated_verdict = .benign,
        .aggregated_confidence = 50,
        .escalated = false,
        .original_verdict = .benign,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 10,
        .brain_recommended_verdict = .benign,
        .policy_action = .allow,
        .policy_rule = .default_allow,
        .policy_confidence = 50,
        .pep_status = .no_op,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0,
    };
    try std.testing.expect(!result_benign.isSignificant());
}

test "PipelineResult.isBlocking detects executed blocks" {
    const result_blocked = PipelineResult{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x08080808,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = .malicious,
        .aggregated_confidence = 90,
        .escalated = false,
        .original_verdict = .malicious,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 80,
        .brain_recommended_verdict = .malicious,
        .policy_action = .block,
        .policy_rule = .verdict_malicious,
        .policy_confidence = 90,
        .pep_status = .executed,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0x08080808,
    };
    try std.testing.expect(result_blocked.isBlocking());

    const result_rejected = PipelineResult{
        .event_id = 2,
        .timestamp_ns = 2000,
        .source_ip = 0x7F000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = .malicious,
        .aggregated_confidence = 100,
        .escalated = false,
        .original_verdict = .malicious,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 90,
        .brain_recommended_verdict = .malicious,
        .policy_action = .block,
        .policy_rule = .verdict_malicious,
        .policy_confidence = 100,
        .pep_status = .rejected,
        .pep_rejection_reason = .localhost_protected,
        .pep_blocked_ip = 0,
    };
    try std.testing.expect(!result_rejected.isBlocking()); // rejected, not executed
}

test "RingBuffer init has zero records" {
    const rb = RingBuffer.init();
    try std.testing.expect(rb.len() == 0);
    try std.testing.expect(rb.sequence_counter == 0);
}

test "RingBuffer append and len" {
    var rb = RingBuffer.init();
    const result = PipelineResult{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = .benign,
        .aggregated_confidence = 50,
        .escalated = false,
        .original_verdict = .benign,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 0,
        .brain_recommended_verdict = .benign,
        .policy_action = .allow,
        .policy_rule = .default_allow,
        .policy_confidence = 50,
        .pep_status = .no_op,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0,
    };

    const seq = rb.append(result, 1000);
    try std.testing.expect(seq == 1);
    try std.testing.expect(rb.len() == 1);
    try std.testing.expect(rb.sequence_counter == 1);
}

test "RingBuffer getByEventId" {
    var rb = RingBuffer.init();

    var i: u64 = 0;
    while (i < 3) : (i += 1) {
        var result = PipelineResult{
            .event_id = 100 + i,
            .timestamp_ns = @intCast(i * 1000),
            .source_ip = 0x0A000001,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .benign,
            .aggregated_confidence = 50,
            .escalated = false,
            .original_verdict = .benign,
            .correlation_alert_count = 0,
            .correlation_rules = .{ 0, 0, 0 },
            .threat_intel_matched = false,
            .threat_intel_max_severity = 0,
            .brain_advice_kind = 0,
            .brain_threat_score = 0,
            .brain_recommended_verdict = .benign,
            .policy_action = .allow,
            .policy_rule = .default_allow,
            .policy_confidence = 50,
            .pep_status = .no_op,
            .pep_rejection_reason = .none,
            .pep_blocked_ip = 0,
        };
        _ = rb.append(result, @intCast(i * 1000));
    }

    const found = rb.getByEventId(101);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.result.event_id == 101);

    const not_found = rb.getByEventId(999);
    try std.testing.expect(not_found == null);
}

test "RingBuffer getBySequence" {
    var rb = RingBuffer.init();
    const result = PipelineResult{
        .event_id = 42,
        .timestamp_ns = 5000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = .benign,
        .aggregated_confidence = 50,
        .escalated = false,
        .original_verdict = .benign,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 0,
        .brain_recommended_verdict = .benign,
        .policy_action = .allow,
        .policy_rule = .default_allow,
        .policy_confidence = 50,
        .pep_status = .no_op,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0,
    };

    const seq = rb.append(result, 5000);
    try std.testing.expect(seq == 1);

    const found = rb.getBySequence(1);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.result.event_id == 42);

    const not_found = rb.getBySequence(999);
    try std.testing.expect(not_found == null);
}

test "RingBuffer countByTimeRange" {
    var rb = RingBuffer.init();

    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var result = PipelineResult{
            .event_id = i,
            .timestamp_ns = @intCast(i * 1000),
            .source_ip = 0x0A000001,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .benign,
            .aggregated_confidence = 50,
            .escalated = false,
            .original_verdict = .benign,
            .correlation_alert_count = 0,
            .correlation_rules = .{ 0, 0, 0 },
            .threat_intel_matched = false,
            .threat_intel_max_severity = 0,
            .brain_advice_kind = 0,
            .brain_threat_score = 0,
            .brain_recommended_verdict = .benign,
            .policy_action = .allow,
            .policy_rule = .default_allow,
            .policy_confidence = 50,
            .pep_status = .no_op,
            .pep_rejection_reason = .none,
            .pep_blocked_ip = 0,
        };
        _ = rb.append(result, @intCast(i * 1000));
    }

    // Timestamps: 0, 1000, 2000, 3000, 4000
    // Range [1000, 3000] should match 3 records
    const count = rb.countByTimeRange(1000, 3000);
    try std.testing.expect(count == 3);
}

test "RingBuffer countByVerdict" {
    var rb = RingBuffer.init();

    // 2 benign + 1 suspicious
    const verdicts = [_]detection.Verdict{ .benign, .benign, .suspicious };
    for (verdicts, 0..) |v, i| {
        var result = PipelineResult{
            .event_id = @intCast(i),
            .timestamp_ns = @intCast(i * 1000),
            .source_ip = 0x0A000001,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = v,
            .aggregated_confidence = 50,
            .escalated = false,
            .original_verdict = v,
            .correlation_alert_count = 0,
            .correlation_rules = .{ 0, 0, 0 },
            .threat_intel_matched = false,
            .threat_intel_max_severity = 0,
            .brain_advice_kind = 0,
            .brain_threat_score = 0,
            .brain_recommended_verdict = v,
            .policy_action = .allow,
            .policy_rule = .default_allow,
            .policy_confidence = 50,
            .pep_status = .no_op,
            .pep_rejection_reason = .none,
            .pep_blocked_ip = 0,
        };
        _ = rb.append(result, @intCast(i * 1000));
    }

    try std.testing.expect(rb.countByVerdict(.benign) == 2);
    try std.testing.expect(rb.countByVerdict(.suspicious) == 1);
    try std.testing.expect(rb.countByVerdict(.malicious) == 0);
}

test "RingBuffer countByAction" {
    var rb = RingBuffer.init();

    const actions = [_]policy.EnforcementAction{ .allow, .allow, .block, .alert };
    for (actions, 0..) |a, i| {
        var result = PipelineResult{
            .event_id = @intCast(i),
            .timestamp_ns = @intCast(i * 1000),
            .source_ip = 0x0A000001,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .benign,
            .aggregated_confidence = 50,
            .escalated = false,
            .original_verdict = .benign,
            .correlation_alert_count = 0,
            .correlation_rules = .{ 0, 0, 0 },
            .threat_intel_matched = false,
            .threat_intel_max_severity = 0,
            .brain_advice_kind = 0,
            .brain_threat_score = 0,
            .brain_recommended_verdict = .benign,
            .policy_action = a,
            .policy_rule = .default_allow,
            .policy_confidence = 50,
            .pep_status = .no_op,
            .pep_rejection_reason = .none,
            .pep_blocked_ip = 0,
        };
        _ = rb.append(result, @intCast(i * 1000));
    }

    try std.testing.expect(rb.countByAction(.allow) == 2);
    try std.testing.expect(rb.countByAction(.block) == 1);
    try std.testing.expect(rb.countByAction(.alert) == 1);
}

test "RingBuffer clear" {
    var rb = RingBuffer.init();
    const result = PipelineResult{
        .event_id = 1,
        .timestamp_ns = 1000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = .benign,
        .aggregated_confidence = 50,
        .escalated = false,
        .original_verdict = .benign,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = 0,
        .brain_recommended_verdict = .benign,
        .policy_action = .allow,
        .policy_rule = .default_allow,
        .policy_confidence = 50,
        .pep_status = .no_op,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0,
    };
    _ = rb.append(result, 1000);
    try std.testing.expect(rb.len() == 1);

    rb.clear();
    try std.testing.expect(rb.len() == 0);
    try std.testing.expect(rb.sequence_counter == 0);
}

test "ForensicLogger init has zero stats" {
    const logger = ForensicLogger.init();
    try std.testing.expect(logger.total_logged == 0);
    try std.testing.expect(logger.total_significant == 0);
    try std.testing.expect(logger.total_blocking == 0);
    try std.testing.expect(logger.recordCount() == 0);
}

test "ForensicLogger logResult creates record" {
    var logger = ForensicLogger.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 70,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = event.event_id,
    };

    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti_match = threat_intel.ThreatIntelMatch{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };
    const advice = brain.BrainAdvice{
        .kind = .keep,
        .threat_score = 50,
        .recommended_verdict = .suspicious,
        .original_verdict = .suspicious,
        .confidence = 60,
        .explanation = "test",
        .signal_detection = 50,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = event.event_id,
    };
    const decision = policy.EnforcementDecision{
        .action = .alert,
        .rule = .verdict_suspicious,
        .confidence = 70,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .suspicious,
        .original_verdict = .suspicious,
        .threat_score = 50,
    };
    const pep_result = rust_pep.EnforcementResult{
        .status = .no_op,
        .reason = .none,
        .requested_action = .alert,
        .actual_action = .alert,
        .event_id = event.event_id,
        .blocked_ip = 0,
        .message = "alert: logged only",
    };

    const seq = logger.logResult(event, av, alerts, ti_match, advice, decision, pep_result);
    try std.testing.expect(seq == 1);
    try std.testing.expect(logger.total_logged == 1);
    try std.testing.expect(logger.total_significant == 1); // alert is significant
    try std.testing.expect(logger.total_blocking == 0); // no block
    try std.testing.expect(logger.recordCount() == 1);

    // Verify we can retrieve by event_id
    const found = logger.getByEventId(event.event_id);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.result.aggregated_verdict == .suspicious);
    try std.testing.expect(found.?.result.policy_action == .alert);
}

test "ForensicLogger logResult tracks blocking" {
    var logger = ForensicLogger.init();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808; // public IP
    event.dest_ip = 0x0A000002;

    const av = verdict_agg.AggregatedVerdict{
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
        .event_id = event.event_id,
    };

    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti_match = threat_intel.ThreatIntelMatch{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };
    const advice = brain.BrainAdvice{
        .kind = .escalate,
        .threat_score = 80,
        .recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .confidence = 85,
        .explanation = "test",
        .signal_detection = 80,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = event.event_id,
    };
    const decision = policy.EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };
    const pep_result = rust_pep.EnforcementResult{
        .status = .executed,
        .reason = .none,
        .requested_action = .block,
        .actual_action = .block,
        .event_id = event.event_id,
        .blocked_ip = 0x08080808,
        .message = "IP blocked",
    };

    _ = logger.logResult(event, av, alerts, ti_match, advice, decision, pep_result);
    try std.testing.expect(logger.total_blocking == 1);
    try std.testing.expect(logger.total_significant == 1);
}

test "ForensicLogger clear resets all" {
    var logger = ForensicLogger.init();

    var event = canonical.create(.wfp_sensor);
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
        .indicators = detection.Indicator.NONE,
        .event_id = event.event_id,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{
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
    const decision = policy.EnforcementDecision{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 50,
        .reason = "test",
        .event_id = event.event_id,
        .brain_recommended_verdict = .benign,
        .original_verdict = .benign,
        .threat_score = 0,
    };
    const pep = rust_pep.EnforcementResult{
        .status = .no_op,
        .reason = .none,
        .requested_action = .allow,
        .actual_action = .allow,
        .event_id = event.event_id,
        .blocked_ip = 0,
        .message = "test",
    };

    _ = logger.logResult(event, av, alerts, ti, advice, decision, pep);
    try std.testing.expect(logger.total_logged == 1);

    logger.clear();
    try std.testing.expect(logger.total_logged == 0);
    try std.testing.expect(logger.recordCount() == 0);
}
