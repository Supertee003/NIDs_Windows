//! policy_engine.zig - AEGIS Policy Engine (Rewrite Phase 12)
//!
//! Policy Enforcement Point (PEP) decision maker.
//! Policy = plan (evaluate -> plan -> execute pattern from Master Plan).
//!
//! Architecture:
//!   Detection (7) -> Aggregation (8) -> Correlation (9) -> Threat Intel (10)
//!   -> Brain Advisor (11) -> Policy Engine (12) -> [future Rust PEP (13)]
//!
//! Policy Engine is a PLANNER, not an enforcer:
//!   - Evaluates full context (verdict, alerts, threat intel, brain advice)
//!   - Produces EnforcementDecision (action + reason + source)
//!   - Does NOT execute the action itself (Phase 13 Rust PEP executes)
//!
//! Policy precedence (highest to lowest - first match wins):
//!   1. Threat Intel critical severity -> BLOCK (override)
//!   2. Correlation target_repeated -> BLOCK (under attack)
//!   3. Brain escalate + threat_score >= 70 -> BLOCK
//!   4. AggregatedVerdict malicious -> BLOCK
//!   5. Brain escalate + threat_score < 70 -> ALERT
//!   6. AggregatedVerdict suspicious -> ALERT
//!   7. Correlation repeated_threats/port_scan -> ALERT
//!   8. Threat Intel high/medium -> ALERT
//!   9. Else -> ALLOW

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation = @import("correlation_engine.zig");
const threat_intel = @import("threat_intel.zig");
const brain = @import("brain_engine.zig");

// ============================================================
// Enforcement Action
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

    /// Returns true if this action blocks traffic.
    pub fn isBlocking(self: EnforcementAction) bool {
        return self == .block or self == .quarantine;
    }

    /// Returns true if this action is restrictive (block, quarantine, rate_limit).
    pub fn isRestrictive(self: EnforcementAction) bool {
        return self == .block or self == .quarantine or self == .rate_limit;
    }
};

// ============================================================
// Policy Rule (which rule triggered the decision)
// ============================================================

pub const PolicyRule = enum(u8) {
    /// No rule matched - default allow.
    default_allow = 0,
    /// Threat intel critical severity triggered block.
    threat_intel_critical = 1,
    /// Correlation target_repeated triggered block.
    correlation_target_repeated = 2,
    /// Brain advice recommended escalation with high score.
    brain_escalate_high = 3,
    /// Aggregated verdict was malicious.
    verdict_malicious = 4,
    /// Brain advice recommended escalation with moderate score.
    brain_escalate_moderate = 5,
    /// Aggregated verdict was suspicious.
    verdict_suspicious = 6,
    /// Correlation repeated_threats or port_scan triggered alert.
    correlation_threat = 7,
    /// Threat intel high or medium severity triggered alert.
    threat_intel_alert = 8,

    pub fn toString(self: PolicyRule) []const u8 {
        return switch (self) {
            .default_allow => "DEFAULT_ALLOW",
            .threat_intel_critical => "THREAT_INTEL_CRITICAL",
            .correlation_target_repeated => "CORRELATION_TARGET_REPEATED",
            .brain_escalate_high => "BRAIN_ESCALATE_HIGH",
            .verdict_malicious => "VERDICT_MALICIOUS",
            .brain_escalate_moderate => "BRAIN_ESCALATE_MODERATE",
            .verdict_suspicious => "VERDICT_SUSPICIOUS",
            .correlation_threat => "CORRELATION_THREAT",
            .threat_intel_alert => "THREAT_INTEL_ALERT",
        };
    }
};

// ============================================================
// Enforcement Decision
// ============================================================

pub const EnforcementDecision = struct {
    action: EnforcementAction,
    rule: PolicyRule,
    /// Confidence in the decision (0-100).
    confidence: u8,
    /// Human-readable reason (static string).
    reason: []const u8,
    /// The event_id that was evaluated.
    event_id: u64,
    /// The recommended verdict from brain (for forensics).
    brain_recommended_verdict: detection.Verdict,
    /// The original aggregated verdict.
    original_verdict: detection.Verdict,
    /// Threat score from brain (for forensics).
    threat_score: u8,

    /// Returns true if this decision blocks traffic.
    pub fn isBlocking(self: EnforcementDecision) bool {
        return self.action.isBlocking();
    }

    /// Returns true if this decision is restrictive.
    pub fn isRestrictive(self: EnforcementDecision) bool {
        return self.action.isRestrictive();
    }

    /// Returns true if the brain's recommendation was followed.
    pub fn followedBrainAdvice(self: EnforcementDecision) bool {
        if (self.rule == .brain_escalate_high or self.rule == .brain_escalate_moderate) {
            return true;
        }
        return false;
    }
};

// ============================================================
// Policy Engine
// ============================================================

pub const PolicyEngine = struct {
    /// Total evaluations performed.
    total_evaluations: u64,
    /// Count of each action.
    allow_count: u64,
    alert_count: u64,
    block_count: u64,
    quarantine_count: u64,
    rate_limit_count: u64,
    log_only_count: u64,
    /// Count of brain advice followed.
    brain_advice_followed: u64,
    /// Count of brain advice overridden (policy decided differently).
    brain_advice_overridden: u64,

    pub fn init() PolicyEngine {
        return .{
            .total_evaluations = 0,
            .allow_count = 0,
            .alert_count = 0,
            .block_count = 0,
            .quarantine_count = 0,
            .rate_limit_count = 0,
            .log_only_count = 0,
            .brain_advice_followed = 0,
            .brain_advice_overridden = 0,
        };
    }

    /// Evaluate the full context and produce an enforcement decision.
    /// Does NOT execute the action - Phase 13 Rust PEP executes.
    pub fn evaluate(
        self: *PolicyEngine,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        alerts: [3]?correlation.CorrelationAlert,
        ti_match: threat_intel.ThreatIntelMatch,
        advice: brain.BrainAdvice,
    ) EnforcementDecision {
        self.total_evaluations += 1;

        const event_id = event.event_id;
        const original_verdict = av.verdict;
        const brain_recommended = advice.recommended_verdict;
        const threat_score = advice.threat_score;

        // --- Policy precedence (first match wins) ---

        // Rule 1: Threat Intel critical severity -> BLOCK
        if (ti_match.maxSeverity() == .critical) {
            self.block_count += 1;
            self.brain_advice_followed += 1; // Brain likely recommended escalation too
            return .{
                .action = .block,
                .rule = .threat_intel_critical,
                .confidence = 100,
                .reason = "threat intel: critical severity IP match",
                .event_id = event_id,
                .brain_recommended_verdict = brain_recommended,
                .original_verdict = original_verdict,
                .threat_score = threat_score,
            };
        }

        // Rule 2: Correlation target_repeated -> BLOCK (under attack)
        for (alerts) |a| {
            if (a) |alert| {
                if (alert.rule == .target_repeated) {
                    self.block_count += 1;
                    return .{
                        .action = .block,
                        .rule = .correlation_target_repeated,
                        .confidence = 90,
                        .reason = "correlation: target receiving repeated threats",
                        .event_id = event_id,
                        .brain_recommended_verdict = brain_recommended,
                        .original_verdict = original_verdict,
                        .threat_score = threat_score,
                    };
                }
            }
        }

        // Rule 3: Brain escalate + threat_score >= 70 -> BLOCK
        if (advice.kind == .escalate and threat_score >= 70) {
            self.block_count += 1;
            self.brain_advice_followed += 1;
            return .{
                .action = .block,
                .rule = .brain_escalate_high,
                .confidence = advice.confidence,
                .reason = "brain: high threat score, escalate to block",
                .event_id = event_id,
                .brain_recommended_verdict = brain_recommended,
                .original_verdict = original_verdict,
                .threat_score = threat_score,
            };
        }

        // Rule 4: AggregatedVerdict malicious -> BLOCK
        if (av.verdict == .malicious) {
            self.block_count += 1;
            // Check if brain disagreed (would have recommended de-escalation)
            if (advice.kind == .deescalate) {
                self.brain_advice_overridden += 1;
            }
            return .{
                .action = .block,
                .rule = .verdict_malicious,
                .confidence = av.confidence,
                .reason = "aggregated verdict: malicious",
                .event_id = event_id,
                .brain_recommended_verdict = brain_recommended,
                .original_verdict = original_verdict,
                .threat_score = threat_score,
            };
        }

        // Rule 5: Brain escalate + threat_score < 70 -> ALERT
        if (advice.kind == .escalate) {
            self.alert_count += 1;
            self.brain_advice_followed += 1;
            return .{
                .action = .alert,
                .rule = .brain_escalate_moderate,
                .confidence = advice.confidence,
                .reason = "brain: moderate threat score, escalate to alert",
                .event_id = event_id,
                .brain_recommended_verdict = brain_recommended,
                .original_verdict = original_verdict,
                .threat_score = threat_score,
            };
        }

        // Rule 6: AggregatedVerdict suspicious -> ALERT
        if (av.verdict == .suspicious) {
            self.alert_count += 1;
            return .{
                .action = .alert,
                .rule = .verdict_suspicious,
                .confidence = av.confidence,
                .reason = "aggregated verdict: suspicious",
                .event_id = event_id,
                .brain_recommended_verdict = brain_recommended,
                .original_verdict = original_verdict,
                .threat_score = threat_score,
            };
        }

        // Rule 7: Correlation repeated_threats or port_scan -> ALERT
        for (alerts) |a| {
            if (a) |alert| {
                if (alert.rule == .repeated_threats or alert.rule == .port_scan_pattern) {
                    self.alert_count += 1;
                    return .{
                        .action = .alert,
                        .rule = .correlation_threat,
                        .confidence = 70,
                        .reason = "correlation: threat pattern detected",
                        .event_id = event_id,
                        .brain_recommended_verdict = brain_recommended,
                        .original_verdict = original_verdict,
                        .threat_score = threat_score,
                    };
                }
            }
        }

        // Rule 8: Threat Intel high or medium -> ALERT
        const ti_sev = ti_match.maxSeverity();
        if (ti_sev == .high or ti_sev == .medium) {
            self.alert_count += 1;
            return .{
                .action = .alert,
                .rule = .threat_intel_alert,
                .confidence = 75,
                .reason = "threat intel: medium/high severity match",
                .event_id = event_id,
                .brain_recommended_verdict = brain_recommended,
                .original_verdict = original_verdict,
                .threat_score = threat_score,
            };
        }

        // Rule 9: Default -> ALLOW
        self.allow_count += 1;
        // Check if brain recommended de-escalation and we allowed (followed)
        if (advice.kind == .deescalate) {
            self.brain_advice_followed += 1;
        }
        return .{
            .action = .allow,
            .rule = .default_allow,
            .confidence = 50,
            .reason = "no threat indicators, default allow",
            .event_id = event_id,
            .brain_recommended_verdict = brain_recommended,
            .original_verdict = original_verdict,
            .threat_score = threat_score,
        };
    }

    /// Reset all stats (for tests).
    pub fn resetStats(self: *PolicyEngine) void {
        self.* = init();
    }
};

// ============================================================
// Tests (all use local engine instances - parallelism-safe)
// ============================================================

test "EnforcementAction.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.allow.toString(), "ALLOW"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.alert.toString(), "ALERT"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.block.toString(), "BLOCK"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.quarantine.toString(), "QUARANTINE"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.rate_limit.toString(), "RATE_LIMIT"));
    try std.testing.expect(std.mem.eql(u8, EnforcementAction.log_only.toString(), "LOG_ONLY"));
}

test "EnforcementAction.isBlocking and isRestrictive" {
    try std.testing.expect(!EnforcementAction.allow.isBlocking());
    try std.testing.expect(!EnforcementAction.alert.isBlocking());
    try std.testing.expect(EnforcementAction.block.isBlocking());
    try std.testing.expect(EnforcementAction.quarantine.isBlocking());
    try std.testing.expect(!EnforcementAction.rate_limit.isBlocking());
    try std.testing.expect(!EnforcementAction.log_only.isBlocking());

    try std.testing.expect(!EnforcementAction.allow.isRestrictive());
    try std.testing.expect(!EnforcementAction.alert.isRestrictive());
    try std.testing.expect(EnforcementAction.block.isRestrictive());
    try std.testing.expect(EnforcementAction.quarantine.isRestrictive());
    try std.testing.expect(EnforcementAction.rate_limit.isRestrictive());
    try std.testing.expect(!EnforcementAction.log_only.isRestrictive());
}

test "PolicyRule.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, PolicyRule.default_allow.toString(), "DEFAULT_ALLOW"));
    try std.testing.expect(std.mem.eql(u8, PolicyRule.threat_intel_critical.toString(), "THREAT_INTEL_CRITICAL"));
    try std.testing.expect(std.mem.eql(u8, PolicyRule.correlation_target_repeated.toString(), "CORRELATION_TARGET_REPEATED"));
    try std.testing.expect(std.mem.eql(u8, PolicyRule.brain_escalate_high.toString(), "BRAIN_ESCALATE_HIGH"));
    try std.testing.expect(std.mem.eql(u8, PolicyRule.verdict_malicious.toString(), "VERDICT_MALICIOUS"));
    try std.testing.expect(std.mem.eql(u8, PolicyRule.verdict_suspicious.toString(), "VERDICT_SUSPICIOUS"));
}

test "PolicyEngine init has zero stats" {
    const engine = PolicyEngine.init();
    try std.testing.expect(engine.total_evaluations == 0);
    try std.testing.expect(engine.allow_count == 0);
    try std.testing.expect(engine.block_count == 0);
}

test "EnforcementDecision.isBlocking and isRestrictive" {
    const block_decision = EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = 0,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };
    try std.testing.expect(block_decision.isBlocking());
    try std.testing.expect(block_decision.isRestrictive());

    const allow_decision = EnforcementDecision{
        .action = .allow,
        .rule = .default_allow,
        .confidence = 50,
        .reason = "test",
        .event_id = 0,
        .brain_recommended_verdict = .benign,
        .original_verdict = .benign,
        .threat_score = 10,
    };
    try std.testing.expect(!allow_decision.isBlocking());
    try std.testing.expect(!allow_decision.isRestrictive());
}

test "EnforcementDecision.followedBrainAdvice" {
    const followed = EnforcementDecision{
        .action = .block,
        .rule = .brain_escalate_high,
        .confidence = 85,
        .reason = "test",
        .event_id = 0,
        .brain_recommended_verdict = .malicious,
        .original_verdict = .suspicious,
        .threat_score = 80,
    };
    try std.testing.expect(followed.followedBrainAdvice());

    const not_followed = EnforcementDecision{
        .action = .block,
        .rule = .verdict_malicious,
        .confidence = 90,
        .reason = "test",
        .event_id = 0,
        .brain_recommended_verdict = .suspicious,
        .original_verdict = .malicious,
        .threat_score = 80,
    };
    try std.testing.expect(!not_followed.followedBrainAdvice());
}

// Helper to create a benign context for tests
fn createBenignContext(event_id: u64) struct {
    event: canonical.CanonicalEvent,
    av: verdict_agg.AggregatedVerdict,
    alerts: [3]?correlation.CorrelationAlert,
    ti_match: threat_intel.ThreatIntelMatch,
    advice: brain.BrainAdvice,
} {
    var event = canonical.create(.wfp_sensor);
    event.event_id = event_id;
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    return .{
        .event = event,
        .av = .{
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
            .event_id = event_id,
        },
        .alerts = .{ null, null, null },
        .ti_match = .{
            .src_match = null,
            .dst_match = null,
            .event_id = event_id,
        },
        .advice = .{
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
            .event_id = event_id,
        },
    };
}

test "evaluate: benign context returns ALLOW" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(1);

    const decision = engine.evaluate(ctx.event, ctx.av, ctx.alerts, ctx.ti_match, ctx.advice);

    try std.testing.expect(decision.action == .allow);
    try std.testing.expect(decision.rule == .default_allow);
    try std.testing.expect(engine.allow_count == 1);
    try std.testing.expect(engine.total_evaluations == 1);
}

test "evaluate: threat intel critical triggers BLOCK (highest precedence)" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(2);

    // Override: critical threat intel match
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
        .event_id = 2,
    };

    const decision = engine.evaluate(ctx.event, ctx.av, ctx.alerts, ti_critical, ctx.advice);

    try std.testing.expect(decision.action == .block);
    try std.testing.expect(decision.rule == .threat_intel_critical);
    try std.testing.expect(decision.confidence == 100);
    try std.testing.expect(engine.block_count == 1);
}

test "evaluate: correlation target_repeated triggers BLOCK" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(3);

    // Override: target_repeated correlation alert
    const alerts: [3]?correlation.CorrelationAlert = .{
        .{
            .rule = .target_repeated,
            .entity_key = correlation.EntityKey.fromDstIp(0x0A000002),
            .triggering_verdict = .suspicious,
            .threat_count = 6,
            .distinct_ports = 0,
            .timestamp_ns = 1000,
            .triggering_event_id = 3,
            .description = "under attack",
        },
        null,
        null,
    };

    const decision = engine.evaluate(ctx.event, ctx.av, alerts, ctx.ti_match, ctx.advice);

    try std.testing.expect(decision.action == .block);
    try std.testing.expect(decision.rule == .correlation_target_repeated);
    try std.testing.expect(decision.confidence == 90);
}

test "evaluate: brain escalate high score triggers BLOCK" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(4);

    // Override: brain advice recommends escalation with high score
    const advice_escalate = brain.BrainAdvice{
        .kind = .escalate,
        .threat_score = 80,
        .recommended_verdict = .malicious,
        .original_verdict = .suspicious,
        .confidence = 85,
        .explanation = "high threat score",
        .signal_detection = 80,
        .signal_correlation = 70,
        .signal_threat_intel = 90,
        .signal_flow_anomaly = 60,
        .event_id = 4,
    };

    const decision = engine.evaluate(ctx.event, ctx.av, ctx.alerts, ctx.ti_match, advice_escalate);

    try std.testing.expect(decision.action == .block);
    try std.testing.expect(decision.rule == .brain_escalate_high);
    try std.testing.expect(decision.confidence == 85);
    try std.testing.expect(engine.brain_advice_followed == 1);
}

test "evaluate: aggregated verdict malicious triggers BLOCK" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(5);

    // Override: malicious verdict
    const av_malicious = verdict_agg.AggregatedVerdict{
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
        .event_id = 5,
    };

    const decision = engine.evaluate(ctx.event, av_malicious, ctx.alerts, ctx.ti_match, ctx.advice);

    try std.testing.expect(decision.action == .block);
    try std.testing.expect(decision.rule == .verdict_malicious);
    try std.testing.expect(decision.confidence == 90);
}

test "evaluate: brain escalate moderate score triggers ALERT" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(6);

    // Override: brain advice recommends escalation with moderate score (< 70)
    const advice_escalate_moderate = brain.BrainAdvice{
        .kind = .escalate,
        .threat_score = 55,
        .recommended_verdict = .suspicious,
        .original_verdict = .observe,
        .confidence = 60,
        .explanation = "moderate threat score",
        .signal_detection = 50,
        .signal_correlation = 60,
        .signal_threat_intel = 50,
        .signal_flow_anomaly = 40,
        .event_id = 6,
    };

    const decision = engine.evaluate(ctx.event, ctx.av, ctx.alerts, ctx.ti_match, advice_escalate_moderate);

    try std.testing.expect(decision.action == .alert);
    try std.testing.expect(decision.rule == .brain_escalate_moderate);
    try std.testing.expect(engine.brain_advice_followed == 1);
}

test "evaluate: aggregated verdict suspicious triggers ALERT" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(7);

    // Override: suspicious verdict
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
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = 7,
    };

    const decision = engine.evaluate(ctx.event, av_suspicious, ctx.alerts, ctx.ti_match, ctx.advice);

    try std.testing.expect(decision.action == .alert);
    try std.testing.expect(decision.rule == .verdict_suspicious);
    try std.testing.expect(decision.confidence == 70);
}

test "evaluate: correlation repeated_threats triggers ALERT" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(8);

    const alerts: [3]?correlation.CorrelationAlert = .{
        .{
            .rule = .repeated_threats,
            .entity_key = correlation.EntityKey.fromSrcIp(0x0A000001),
            .triggering_verdict = .suspicious,
            .threat_count = 4,
            .distinct_ports = 2,
            .timestamp_ns = 1000,
            .triggering_event_id = 8,
            .description = "repeated threats",
        },
        null,
        null,
    };

    const decision = engine.evaluate(ctx.event, ctx.av, alerts, ctx.ti_match, ctx.advice);

    try std.testing.expect(decision.action == .alert);
    try std.testing.expect(decision.rule == .correlation_threat);
    try std.testing.expect(decision.confidence == 70);
}

test "evaluate: threat intel high triggers ALERT" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(9);

    const ti_high = threat_intel.ThreatIntelMatch{
        .src_match = .{
            .ip = 0x0A0000B2,
            .severity = .high,
            .category = .botnet,
            .confidence = 85,
            .source = "test",
            .first_seen_ms = 1000,
            .last_seen_ms = 2000,
            .report_count = 3,
        },
        .dst_match = null,
        .event_id = 9,
    };

    const decision = engine.evaluate(ctx.event, ctx.av, ctx.alerts, ti_high, ctx.advice);

    try std.testing.expect(decision.action == .alert);
    try std.testing.expect(decision.rule == .threat_intel_alert);
    try std.testing.expect(decision.confidence == 75);
}

test "evaluate: stats accumulate correctly" {
    var engine = PolicyEngine.init();

    // Run 1: ALLOW
    const ctx1 = createBenignContext(1);
    _ = engine.evaluate(ctx1.event, ctx1.av, ctx1.alerts, ctx1.ti_match, ctx1.advice);

    // Run 2: BLOCK (threat intel critical)
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
        .event_id = 2,
    };
    _ = engine.evaluate(ctx1.event, ctx1.av, ctx1.alerts, ti_critical, ctx1.advice);

    // Run 3: ALERT (suspicious verdict)
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
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = 3,
    };
    _ = engine.evaluate(ctx1.event, av_suspicious, ctx1.alerts, ctx1.ti_match, ctx1.advice);

    try std.testing.expect(engine.total_evaluations == 3);
    try std.testing.expect(engine.allow_count == 1);
    try std.testing.expect(engine.block_count == 1);
    try std.testing.expect(engine.alert_count == 1);
}

test "evaluate: brain advice overridden when verdict is malicious" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(10);

    // Brain recommends de-escalation, but verdict is malicious
    const av_malicious = verdict_agg.AggregatedVerdict{
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
        .event_id = 10,
    };

    const advice_deescalate = brain.BrainAdvice{
        .kind = .deescalate,
        .threat_score = 20,
        .recommended_verdict = .suspicious,
        .original_verdict = .malicious,
        .confidence = 30,
        .explanation = "low threat score",
        .signal_detection = 20,
        .signal_correlation = 0,
        .signal_threat_intel = 0,
        .signal_flow_anomaly = 0,
        .event_id = 10,
    };

    const decision = engine.evaluate(ctx.event, av_malicious, ctx.alerts, ctx.ti_match, advice_deescalate);

    // Policy should BLOCK (malicious verdict) despite brain recommending de-escalation
    try std.testing.expect(decision.action == .block);
    try std.testing.expect(decision.rule == .verdict_malicious);
    try std.testing.expect(engine.brain_advice_overridden == 1);
}

test "resetStats zeroes all counters" {
    var engine = PolicyEngine.init();
    const ctx = createBenignContext(1);
    _ = engine.evaluate(ctx.event, ctx.av, ctx.alerts, ctx.ti_match, ctx.advice);
    try std.testing.expect(engine.total_evaluations == 1);

    engine.resetStats();
    try std.testing.expect(engine.total_evaluations == 0);
    try std.testing.expect(engine.allow_count == 0);
}
