//! policy_engine.zig - AEGIS Policy Engine (Rewrite Phase 12)
//!
//! Decides the enforcement action based on verdict, brain advice, threat
//! intel, and correlation alerts. The Policy Engine is a PLANNER, not
//! an enforcer - the Rust PEP actually executes the action.
//!
//! Contract:
//!   EnforcementAction: enum with toString()
//!   PolicyRule: enum with toString()
//!   EnforcementDecision: struct { action, rule, confidence, reason, event_id,
//!                                  brain_recommended_verdict, original_verdict, threat_score }
//!   PolicyEngine: evaluate(event, av, alerts, ti_match, advice) -> EnforcementDecision

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");

// ============================================================
// Enforcement Action (must match canonical.PolicyAction ordering)
// ============================================================

pub const EnforcementAction = enum(u8) {
    allow = 0,
    alert = 1,
    block = 2,
    quarantine = 3,
    rate_limit = 4,
    log_only = 5,

    pub fn toString(self: EnforcementAction) []const u8 {
        return switch (self) {
            .allow => "ALLOW",
            .alert => "ALERT",
            .block => "BLOCK",
            .quarantine => "QUARANTINE",
            .rate_limit => "RATE_LIMIT",
            .log_only => "LOG_ONLY",
        };
    }

    pub fn isBlocking(self: EnforcementAction) bool {
        return self == .block or self == .quarantine;
    }

    /// Restrictiveness rank (0=allow ... 5=log_only, but block/quarantine are most restrictive)
    pub fn restrictiveness(self: EnforcementAction) u8 {
        return switch (self) {
            .allow => 0,
            .log_only => 1,
            .rate_limit => 2,
            .alert => 3,
            .block => 4,
            .quarantine => 5,
        };
    }
};

// ============================================================
// Policy Rule (why the action was chosen)
// ============================================================

pub const PolicyRule = enum(u8) {
    default_allow = 0,
    verdict_benign = 1,
    verdict_suspicious = 2,
    verdict_malicious = 3,
    verdict_critical = 4,
    brain_escalation = 5,
    threat_intel_critical = 6,
    correlation_alert = 7,
    rate_limit_high_volume = 8,

    pub fn toString(self: PolicyRule) []const u8 {
        return switch (self) {
            .default_allow => "DEFAULT_ALLOW",
            .verdict_benign => "VERDICT_BENIGN",
            .verdict_suspicious => "VERDICT_SUSPICIOUS",
            .verdict_malicious => "VERDICT_MALICIOUS",
            .verdict_critical => "VERDICT_CRITICAL",
            .brain_escalation => "BRAIN_ESCALATION",
            .threat_intel_critical => "THREAT_INTEL_CRITICAL",
            .correlation_alert => "CORRELATION_ALERT",
            .rate_limit_high_volume => "RATE_LIMIT_HIGH_VOLUME",
        };
    }
};

// ============================================================
// Enforcement Decision
// ============================================================

pub const EnforcementDecision = struct {
    action: EnforcementAction,
    rule: PolicyRule,
    confidence: u8,
    reason: []const u8,
    event_id: u64,
    brain_recommended_verdict: detection.Verdict,
    original_verdict: detection.Verdict,
    threat_score: u16,

    pub fn isBlocking(self: EnforcementDecision) bool {
        return self.action.isBlocking();
    }
};

// ============================================================
// Policy Engine
// ============================================================

pub const PolicyEngine = struct {
    total_decisions: u64 = 0,
    total_blocks: u64 = 0,
    total_alerts: u64 = 0,
    total_allows: u64 = 0,

    pub fn init() PolicyEngine {
        return .{};
    }

    pub fn evaluate(
        self: *PolicyEngine,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        alerts: [correlation.MAX_ALERTS_PER_VERDICT]?correlation.CorrelationAlert,
        ti_match: threat_intel.ThreatIntelMatch,
        advice: brain.BrainAdvice,
    ) EnforcementDecision {
        _ = event;
        self.total_decisions += 1;

        // Priority order (highest first):
        //   1. Brain escalation to block
        //   2. Threat intel critical
        //   3. Correlation alert
        //   4. Aggregated verdict
        //   5. Default allow

        if (advice.kind == .escalate_to_block) {
            self.total_blocks += 1;
            return .{
                .action = .block,
                .rule = .brain_escalation,
                .confidence = advice.confidence,
                .reason = "brain recommends block",
                .event_id = av.event_id,
                .brain_recommended_verdict = advice.recommended_verdict,
                .original_verdict = av.verdict,
                .threat_score = advice.threat_score,
            };
        }

        if (ti_match.isHighSeverity()) {
            self.total_blocks += 1;
            return .{
                .action = .block,
                .rule = .threat_intel_critical,
                .confidence = 90,
                .reason = "threat intel critical match",
                .event_id = av.event_id,
                .brain_recommended_verdict = advice.recommended_verdict,
                .original_verdict = av.verdict,
                .threat_score = advice.threat_score,
            };
        }

        // Check correlation alerts
        for (alerts) |a| {
            if (a) |alert| {
                if (alert.rule == .multi_target_scan or alert.rule == .repeated_threats) {
                    self.total_blocks += 1;
                    return .{
                        .action = .block,
                        .rule = .correlation_alert,
                        .confidence = 75,
                        .reason = "correlation alert: repeated threats or multi-target scan",
                        .event_id = av.event_id,
                        .brain_recommended_verdict = advice.recommended_verdict,
                        .original_verdict = av.verdict,
                        .threat_score = advice.threat_score,
                    };
                }
            }
        }

        // Fall through to verdict-based action
        const rule: PolicyRule = switch (av.verdict) {
            .benign => .verdict_benign,
            .suspicious => .verdict_suspicious,
            .malicious => .verdict_malicious,
            .critical => .verdict_critical,
            .unknown => .default_allow,
        };
        const action: EnforcementAction = switch (av.verdict) {
            .benign, .unknown => .allow,
            .suspicious => .alert,
            .malicious => .block,
            .critical => .block,
        };

        switch (action) {
            .block, .quarantine => self.total_blocks += 1,
            .alert => self.total_alerts += 1,
            .allow => self.total_allows += 1,
            else => {},
        }

        return .{
            .action = action,
            .rule = rule,
            .confidence = av.confidence,
            .reason = "verdict-based decision",
            .event_id = av.event_id,
            .brain_recommended_verdict = advice.recommended_verdict,
            .original_verdict = av.verdict,
            .threat_score = advice.threat_score,
        };
    }

    pub fn resetStats(self: *PolicyEngine) void {
        self.total_decisions = 0;
        self.total_blocks = 0;
        self.total_alerts = 0;
        self.total_allows = 0;
    }
};

// ============================================================
// Tests
// ============================================================

fn makeAdvice(kind: brain.BrainAdviceKind, score: u16, rec: detection.Verdict, orig: detection.Verdict, event_id: u64) brain.BrainAdvice {
    return .{
        .kind = kind,
        .threat_score = score,
        .recommended_verdict = rec,
        .original_verdict = orig,
        .confidence = 70,
        .explanation = "test",
        .signal_detection = 0,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = event_id,
    };
}

test "EnforcementAction.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.allow.toString(), "ALLOW"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.block.toString(), "BLOCK"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.quarantine.toString(), "QUARANTINE"));
}

test "EnforcementAction.isBlocking covers block and quarantine" {
    try std.testing.expect(!EnforcementAction.allow.isBlocking());
    try std.testing.expect(!EnforcementAction.alert.isBlocking());
    try std.testing.expect(EnforcementAction.block.isBlocking());
    try std.testing.expect(EnforcementAction.quarantine.isBlocking());
}

test "EnforcementAction.restrictiveness ranks correctly" {
    try std.testing.expect(EnforcementAction.allow.restrictiveness() == 0);
    try std.testing.expect(EnforcementAction.quarantine.restrictiveness() == 5);
}

test "PolicyRule.toString returns uppercase" {
    try std.testing.expect(std.mem.eql(u8, PolicyRule.default_allow.toString(), "DEFAULT_ALLOW"));
    try std.testing.expect(std.mem.eql(u8, PolicyRule.threat_intel_critical.toString(), "THREAT_INTEL_CRITICAL"));
}

test "PolicyEngine.init starts with zero stats" {
    const engine = PolicyEngine.init();
    try std.testing.expect(engine.total_decisions == 0);
}

test "PolicyEngine.evaluate returns allow for benign verdict" {
    var engine = PolicyEngine.init();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .benign,
        .original_verdict = .benign,
        .confidence = 30,
        .agreeing_count = 0,
        .detector_count = 0,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const advice = makeAdvice(.keep_verdict, 10, .benign, .benign, 1);

    const d = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .allow);
    try std.testing.expect(d.rule == .verdict_benign);
    try std.testing.expect(!d.isBlocking());
}

test "PolicyEngine.evaluate returns alert for suspicious verdict" {
    var engine = PolicyEngine.init();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .original_verdict = .suspicious,
        .confidence = 60,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const advice = makeAdvice(.keep_verdict, 40, .suspicious, .suspicious, 1);

    const d = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .alert);
    try std.testing.expect(d.rule == .verdict_suspicious);
}

test "PolicyEngine.evaluate returns block for malicious verdict" {
    var engine = PolicyEngine.init();
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
    const advice = makeAdvice(.keep_verdict, 60, .malicious, .malicious, 1);

    const d = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .block);
    try std.testing.expect(d.rule == .verdict_malicious);
    try std.testing.expect(d.isBlocking());
}

test "PolicyEngine.evaluate prefers brain escalation over verdict" {
    var engine = PolicyEngine.init();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .original_verdict = .suspicious,
        .confidence = 60,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const advice = makeAdvice(.escalate_to_block, 90, .critical, .suspicious, 1);

    const d = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .block);
    try std.testing.expect(d.rule == .brain_escalation);
}

test "PolicyEngine.evaluate prefers threat intel critical over verdict" {
    var engine = PolicyEngine.init();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .original_verdict = .suspicious,
        .confidence = 60,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{ null, null, null };
    const ti = threat_intel.ThreatIntelMatch{
        .src_match = .{ .ip = 1, .severity = .critical, .category = .malware_c2, .confidence = 95, .source = "test" },
        .dst_match = null,
        .event_id = 1,
    };
    const advice = makeAdvice(.keep_verdict, 50, .suspicious, .suspicious, 1);

    const d = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .block);
    try std.testing.expect(d.rule == .threat_intel_critical);
}

test "PolicyEngine.evaluate prefers correlation alert over verdict" {
    var engine = PolicyEngine.init();
    const event = canonical.create(.zig_core);
    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .original_verdict = .suspicious,
        .confidence = 60,
        .agreeing_count = 1,
        .detector_count = 1,
        .escalated = false,
        .event_id = 1,
    };
    const alerts: [3]?correlation.CorrelationAlert = .{
        .{ .rule = .repeated_threats, .entity_key = .{ .entity_type = .source_ip, .ip = 1, .session_id = 0 }, .threat_count = 5, .triggering_event_id = 1, .description = "test" },
        null,
        null,
    };
    const ti = threat_intel.ThreatIntelMatch{ .src_match = null, .dst_match = null, .event_id = 1 };
    const advice = makeAdvice(.keep_verdict, 40, .suspicious, .suspicious, 1);

    const d = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(d.action == .block);
    try std.testing.expect(d.rule == .correlation_alert);
}

test "PolicyEngine tracks lifetime stats" {
    var engine = PolicyEngine.init();
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
    const advice = makeAdvice(.keep_verdict, 60, .malicious, .malicious, 1);
    _ = engine.evaluate(event, av, alerts, ti, advice);
    _ = engine.evaluate(event, av, alerts, ti, advice);
    try std.testing.expect(engine.total_decisions == 2);
    try std.testing.expect(engine.total_blocks == 2);
}

test "PolicyEngine.resetStats zeroes counters" {
    var engine = PolicyEngine.init();
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
    const advice = makeAdvice(.keep_verdict, 60, .malicious, .malicious, 1);
    _ = engine.evaluate(event, av, alerts, ti, advice);
    engine.resetStats();
    try std.testing.expect(engine.total_decisions == 0);
}
