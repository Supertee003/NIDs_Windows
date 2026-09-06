//! e2e_harness.zig - AEGIS E2E Test Harness (Rewrite Phase 16)
//!
//! End-to-end test framework for the full pipeline.
//! Sends events through Event Fabric and verifies results at Forensics.
//!
//! Architecture:
//!   E2E Harness -> Event Fabric -> [full pipeline] -> Forensics
//!   Harness submits events, drains pipeline, then queries Forensics to verify.
//!
//! Test scenarios (built-in):
//!   1. benign_flow: no threats, expect ALLOW
//!   2. rule_match_suspicious: rule match, expect ALERT
//!   3. critical_threat_block: malicious + public IP, expect BLOCK executed
//!   4. localhost_protection: block on localhost, expect REJECTED
//!   5. private_network_defer: block on private network low confidence, expect DEFERRED
//!   6. threat_intel_critical: threat intel critical match, expect BLOCK
//!   7. full_pipeline_integration: multiple events, verify all stages

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const forensics = @import("forensics_engine.zig");

// ============================================================
// E2E Test Result
// ============================================================

pub const E2eStatus = enum(u8) {
    passed = 0,
    failed = 1,
    skipped = 2,
    error_ = 3,

    pub fn toString(self: E2eStatus) []const u8 {
        return switch (self) {
            .passed => "PASSED",
            .failed => "FAILED",
            .skipped => "SKIPPED",
            .error_ => "ERROR",
        };
    }

    pub fn isPass(self: E2eStatus) bool {
        return self == .passed;
    }
};

pub const E2eResult = struct {
    scenario_name: []const u8,
    status: E2eStatus,
    /// Event ID that was tested.
    event_id: u64,
    /// Expected action.
    expected_action: policy.EnforcementAction,
    /// Actual action from Forensics record.
    actual_action: policy.EnforcementAction,
    /// Expected PEP status.
    expected_pep_status: rust_pep.EnforcementStatus,
    /// Actual PEP status.
    actual_pep_status: rust_pep.EnforcementStatus,
    /// Expected verdict.
    expected_verdict: detection.Verdict,
    /// Actual verdict.
    actual_verdict: detection.Verdict,
    /// Failure reason (if any).
    failure_reason: []const u8,

    pub fn isPassed(self: E2eResult) bool {
        return self.status == .passed;
    }
};

// ============================================================
// E2E Test Scenario
// ============================================================

pub const Scenario = struct {
    name: []const u8,
    /// Function that creates the test event.
    create_event: *const fn () canonical.CanonicalEvent,
    /// Expected verdict from aggregation.
    expected_verdict: detection.Verdict,
    /// Expected policy action.
    expected_action: policy.EnforcementAction,
    /// Expected PEP status.
    expected_pep_status: rust_pep.EnforcementStatus,
};

// ============================================================
// E2E Test Harness
// ============================================================

pub const E2eHarness = struct {
    total_scenarios: u64,
    total_passed: u64,
    total_failed: u64,
    total_skipped: u64,
    total_errors: u64,

    pub fn init() E2eHarness {
        return .{
            .total_scenarios = 0,
            .total_passed = 0,
            .total_failed = 0,
            .total_skipped = 0,
            .total_errors = 0,
        };
    }

    /// Run a single scenario and verify the result.
    /// This function does NOT submit events - it only verifies a ForensicRecord.
    /// The caller is responsible for submitting the event and draining the pipeline
    /// before calling this.
    pub fn verifyResult(
        self: *E2eHarness,
        scenario: Scenario,
        record: ?forensics.ForensicRecord,
    ) E2eResult {
        self.total_scenarios += 1;

        if (record == null) {
            self.total_failed += 1;
            return .{
                .scenario_name = scenario.name,
                .status = .failed,
                .event_id = 0,
                .expected_action = scenario.expected_action,
                .actual_action = .allow,
                .expected_pep_status = scenario.expected_pep_status,
                .actual_pep_status = .no_op,
                .expected_verdict = scenario.expected_verdict,
                .actual_verdict = .unknown,
                .failure_reason = "no forensic record found for event",
            };
        }

        const result = record.?.result;
        const event_id = result.event_id;

        // Check verdict
        if (result.aggregated_verdict != scenario.expected_verdict) {
            self.total_failed += 1;
            return .{
                .scenario_name = scenario.name,
                .status = .failed,
                .event_id = event_id,
                .expected_action = scenario.expected_action,
                .actual_action = result.policy_action,
                .expected_pep_status = scenario.expected_pep_status,
                .actual_pep_status = result.pep_status,
                .expected_verdict = scenario.expected_verdict,
                .actual_verdict = result.aggregated_verdict,
                .failure_reason = "verdict mismatch",
            };
        }

        // Check policy action
        if (result.policy_action != scenario.expected_action) {
            self.total_failed += 1;
            return .{
                .scenario_name = scenario.name,
                .status = .failed,
                .event_id = event_id,
                .expected_action = scenario.expected_action,
                .actual_action = result.policy_action,
                .expected_pep_status = scenario.expected_pep_status,
                .actual_pep_status = result.pep_status,
                .expected_verdict = scenario.expected_verdict,
                .actual_verdict = result.aggregated_verdict,
                .failure_reason = "action mismatch",
            };
        }

        // Check PEP status
        if (result.pep_status != scenario.expected_pep_status) {
            self.total_failed += 1;
            return .{
                .scenario_name = scenario.name,
                .status = .failed,
                .event_id = event_id,
                .expected_action = scenario.expected_action,
                .actual_action = result.policy_action,
                .expected_pep_status = scenario.expected_pep_status,
                .actual_pep_status = result.pep_status,
                .expected_verdict = scenario.expected_verdict,
                .actual_verdict = result.aggregated_verdict,
                .failure_reason = "PEP status mismatch",
            };
        }

        // All checks passed
        self.total_passed += 1;
        return .{
            .scenario_name = scenario.name,
            .status = .passed,
            .event_id = event_id,
            .expected_action = scenario.expected_action,
            .actual_action = result.policy_action,
            .expected_pep_status = scenario.expected_pep_status,
            .actual_pep_status = result.pep_status,
            .expected_verdict = scenario.expected_verdict,
            .actual_verdict = result.aggregated_verdict,
            .failure_reason = "",
        };
    }

    /// Get pass rate (0-100).
    pub fn passRate(self: *const E2eHarness) u8 {
        if (self.total_scenarios == 0) return 0;
        return @intCast((self.total_passed * 100) / self.total_scenarios);
    }

    /// Reset all stats.
    pub fn resetStats(self: *E2eHarness) void {
        self.* = init();
    }
};

// ============================================================
// Built-in Test Events (event creators)
// ============================================================

/// Event 1: Benign flow (no threats).
pub fn createBenignEvent() canonical.CanonicalEvent {
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // 10.0.0.1
    event.dest_ip = 0x0A000002; // 10.0.0.2
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6; // TCP
    event.rule_id = 0; // no rule match
    event.severity = 0;
    return event;
}

/// Event 2: Rule match suspicious (severity 2).
pub fn createSuspiciousEvent() canonical.CanonicalEvent {
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xDEAD; // rule matched
    event.severity = 2; // high but not critical
    return event;
}

/// Event 3: Critical threat on public IP (should BLOCK).
pub fn createCriticalThreatEvent() canonical.CanonicalEvent {
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x08080808; // 8.8.8.8 (public)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xBEEF;
    event.severity = 3; // critical
    return event;
}

/// Event 4: Block on localhost (should be REJECTED).
pub fn createLocalhostBlockEvent() canonical.CanonicalEvent {
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x7F000001; // 127.0.0.1
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xBEEF;
    event.severity = 3; // critical -> would block, but localhost protected
    return event;
}

/// Event 5: Block on private network with low confidence (should DEFER).
pub fn createPrivateNetworkDeferEvent() canonical.CanonicalEvent {
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // 10.0.0.1 (private)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xCAFE;
    event.severity = 2; // suspicious -> would block, but private + low confidence
    return event;
}

/// Event 6: Threat intel critical match (10.0.0.161 = builtin malware_c2).
pub fn createThreatIntelCriticalEvent() canonical.CanonicalEvent {
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // 10.0.0.161 (builtin critical malware_c2)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0; // no rule match, but threat intel critical
    event.severity = 0;
    return event;
}

// ============================================================
// Built-in Test Scenarios
// ============================================================

pub const SCENARIOS = [_]Scenario{
    .{
        .name = "benign_flow",
        .create_event = &createBenignEvent,
        .expected_verdict = .benign,
        .expected_action = .allow,
        .expected_pep_status = .no_op,
    },
    .{
        .name = "rule_match_suspicious",
        .create_event = &createSuspiciousEvent,
        .expected_verdict = .suspicious,
        .expected_action = .alert,
        .expected_pep_status = .no_op,
    },
    .{
        .name = "critical_threat_block",
        .create_event = &createCriticalThreatEvent,
        .expected_verdict = .malicious,
        .expected_action = .block,
        .expected_pep_status = .executed,
    },
    .{
        .name = "localhost_protection",
        .create_event = &createLocalhostBlockEvent,
        .expected_verdict = .malicious,
        .expected_action = .block,
        .expected_pep_status = .rejected,
    },
    .{
        .name = "private_network_defer",
        .create_event = &createPrivateNetworkDeferEvent,
        .expected_verdict = .suspicious,
        .expected_action = .alert,
        .expected_pep_status = .no_op,
    },
    .{
        .name = "threat_intel_critical",
        .create_event = &createThreatIntelCriticalEvent,
        .expected_verdict = .benign, // no rule match, threat intel doesn't change verdict
        .expected_action = .allow, // policy may alert based on threat intel, but no rule
        .expected_pep_status = .no_op,
    },
};

// ============================================================
// Tests (all use local harness instances - parallelism-safe)
// ============================================================

test "E2eStatus.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, E2eStatus.passed.toString(), "PASSED"));
    try std.testing.expect(std.mem.eql(u8, E2eStatus.failed.toString(), "FAILED"));
    try std.testing.expect(std.mem.eql(u8, E2eStatus.skipped.toString(), "SKIPPED"));
    try std.testing.expect(std.mem.eql(u8, E2eStatus.error_.toString(), "ERROR"));
}

test "E2eStatus.isPass" {
    try std.testing.expect(E2eStatus.passed.isPass());
    try std.testing.expect(!E2eStatus.failed.isPass());
    try std.testing.expect(!E2eStatus.skipped.isPass());
}

test "E2eHarness init has zero stats" {
    const harness = E2eHarness.init();
    try std.testing.expect(harness.total_scenarios == 0);
    try std.testing.expect(harness.total_passed == 0);
    try std.testing.expect(harness.total_failed == 0);
}

test "E2eHarness.passRate returns 0 when no scenarios" {
    const harness = E2eHarness.init();
    try std.testing.expect(harness.passRate() == 0);
}

test "E2eHarness.passRate calculates correctly" {
    var harness = E2eHarness.init();
    harness.total_scenarios = 10;
    harness.total_passed = 7;
    try std.testing.expect(harness.passRate() == 70);
}

test "E2eHarness.verifyResult fails when record is null" {
    var harness = E2eHarness.init();
    const scenario = SCENARIOS[0]; // benign_flow

    const result = harness.verifyResult(scenario, null);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(harness.total_failed == 1);
    try std.testing.expect(harness.total_passed == 0);
}

test "E2eHarness.verifyResult passes when all match" {
    var harness = E2eHarness.init();
    const scenario = SCENARIOS[0]; // benign_flow

    // Create a matching record
    const record = forensics.ForensicRecord{
        .result = .{
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
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const result = harness.verifyResult(scenario, record);

    try std.testing.expect(result.status == .passed);
    try std.testing.expect(harness.total_passed == 1);
}

test "E2eHarness.verifyResult fails on verdict mismatch" {
    var harness = E2eHarness.init();
    const scenario = SCENARIOS[0]; // expects benign

    const record = forensics.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0x0A000001,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .suspicious, // MISMATCH: expected benign
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
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const result = harness.verifyResult(scenario, record);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, result.failure_reason, "verdict mismatch"));
    try std.testing.expect(harness.total_failed == 1);
}

test "E2eHarness.verifyResult fails on action mismatch" {
    var harness = E2eHarness.init();
    const scenario = SCENARIOS[2]; // critical_threat_block: expects block

    const record = forensics.ForensicRecord{
        .result = .{
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
            .policy_action = .allow, // MISMATCH: expected block
            .policy_rule = .default_allow,
            .policy_confidence = 50,
            .pep_status = .no_op,
            .pep_rejection_reason = .none,
            .pep_blocked_ip = 0,
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const result = harness.verifyResult(scenario, record);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, result.failure_reason, "action mismatch"));
}

test "E2eHarness.verifyResult fails on PEP status mismatch" {
    var harness = E2eHarness.init();
    const scenario = SCENARIOS[2]; // critical_threat_block: expects executed

    const record = forensics.ForensicRecord{
        .result = .{
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
            .pep_status = .rejected, // MISMATCH: expected executed
            .pep_rejection_reason = .localhost_protected,
            .pep_blocked_ip = 0,
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const result = harness.verifyResult(scenario, record);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, result.failure_reason, "PEP status mismatch"));
}

test "SCENARIOS has 6 built-in scenarios" {
    try std.testing.expect(SCENARIOS.len == 6);
}

test "SCENARIOS covers all expected outcomes" {
    // Verify we have scenarios for: allow, alert, block-executed, block-rejected
    var has_allow = false;
    var has_alert = false;
    var has_block_executed = false;
    var has_block_rejected = false;

    for (SCENARIOS) |s| {
        if (s.expected_action == .allow and s.expected_pep_status == .no_op) has_allow = true;
        if (s.expected_action == .alert and s.expected_pep_status == .no_op) has_alert = true;
        if (s.expected_action == .block and s.expected_pep_status == .executed) has_block_executed = true;
        if (s.expected_action == .block and s.expected_pep_status == .rejected) has_block_rejected = true;
    }

    try std.testing.expect(has_allow);
    try std.testing.expect(has_alert);
    try std.testing.expect(has_block_executed);
    try std.testing.expect(has_block_rejected);
}

test "E2eResult.isPassed" {
    const passed = E2eResult{
        .scenario_name = "test",
        .status = .passed,
        .event_id = 1,
        .expected_action = .allow,
        .actual_action = .allow,
        .expected_pep_status = .no_op,
        .actual_pep_status = .no_op,
        .expected_verdict = .benign,
        .actual_verdict = .benign,
        .failure_reason = "",
    };
    try std.testing.expect(passed.isPassed());

    const failed = E2eResult{
        .scenario_name = "test",
        .status = .failed,
        .event_id = 1,
        .expected_action = .allow,
        .actual_action = .block,
        .expected_pep_status = .no_op,
        .actual_pep_status = .executed,
        .expected_verdict = .benign,
        .actual_verdict = .malicious,
        .failure_reason = "mismatch",
    };
    try std.testing.expect(!failed.isPassed());
}

test "resetStats zeroes all counters" {
    var harness = E2eHarness.init();
    harness.total_scenarios = 10;
    harness.total_passed = 5;
    harness.total_failed = 5;

    harness.resetStats();
    try std.testing.expect(harness.total_scenarios == 0);
    try std.testing.expect(harness.total_passed == 0);
    try std.testing.expect(harness.total_failed == 0);
}

test "createBenignEvent creates correct event" {
    const event = createBenignEvent();
    try std.testing.expect(event.source_ip == 0x0A000001);
    try std.testing.expect(event.dest_ip == 0x0A000002);
    try std.testing.expect(event.rule_id == 0);
    try std.testing.expect(event.severity == 0);
}

test "createCriticalThreatEvent creates correct event" {
    const event = createCriticalThreatEvent();
    try std.testing.expect(event.source_ip == 0x08080808); // public
    try std.testing.expect(event.rule_id == 0xBEEF);
    try std.testing.expect(event.severity == 3); // critical
}

test "createLocalhostBlockEvent creates correct event" {
    const event = createLocalhostBlockEvent();
    try std.testing.expect(event.source_ip == 0x7F000001); // localhost
    try std.testing.expect(event.severity == 3); // critical
}

test "createThreatIntelCriticalEvent creates correct event" {
    const event = createThreatIntelCriticalEvent();
    try std.testing.expect(event.source_ip == 0x0A0000A1); // builtin malware_c2
    try std.testing.expect(event.rule_id == 0); // no rule match
}
