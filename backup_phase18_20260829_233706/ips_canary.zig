//! ips_canary.zig - AEGIS IPS Canary (Rewrite Phase 18)
//!
//! Canary mechanism to verify the IPS (Intrusion Prevention System) is working.
//! Like a "canary in a coal mine" - sends synthetic test events that SHOULD
//! trigger specific enforcement actions, then verifies the pipeline caught them.
//!
//! Architecture:
//!   Canary injects test events -> pipeline processes them -> Canary verifies
//!   results at Forensics match expected enforcement actions.
//!
//! Use cases:
//!   1. Health check: verify IPS is blocking when it should
//!   2. Regression detection: canary failures indicate pipeline breakage
//!   3. Compliance: periodic audit that enforcement is active
//!
//! Design:
//!   - CanaryToken: unique identifier for each canary test (magic number + sequence)
//!   - CanaryResult: expected vs actual enforcement outcome
//!   - CanaryHealth: aggregate health status (healthy/degraded/failed)
//!   - Does NOT modify real traffic - canary events use reserved IP ranges

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const forensics = @import("forensics_engine.zig");

// ============================================================
// Constants
// ============================================================

/// Magic number to identify canary events (0x43414E41 = "CANA").
pub const CANARY_MAGIC: u32 = 0x43414E41;

/// Canary test event IP range: 203.0.113.0/24 (TEST-NET-3, documentation).
/// Using this reserved range ensures canary events don't affect real traffic.
pub const CANARY_IP_BASE: u32 = 0xCB007100; // 203.0.113.0

/// Number of built-in canary tests.
pub const CANARY_TEST_COUNT: usize = 4;

// ============================================================
// Canary Token
// ============================================================

/// Unique identifier for a canary test. Embedded in the event's session_id
/// so we can look it up later in Forensics.
pub const CanaryToken = struct {
    magic: u32, // CANARY_MAGIC (0x43414E41)
    test_id: u8, // Which canary test (0-3)
    sequence: u8, // Sequence number (for repeated runs)
    reserved: u16, // Padding (zero)

    /// Pack the token into a u64 for embedding in session_id.
    pub fn pack(self: CanaryToken) u64 {
        return (@as(u64, self.magic) << 32) |
            (@as(u64, self.test_id) << 24) |
            (@as(u64, self.sequence) << 16) |
            @as(u64, self.reserved);
    }

    /// Unpack a u64 into a CanaryToken. Returns null if magic doesn't match.
    pub fn unpack(session_id: u64) ?CanaryToken {
        const magic = @as(u32, @intCast(session_id >> 32));
        if (magic != CANARY_MAGIC) return null;
        return .{
            .magic = magic,
            .test_id = @intCast((session_id >> 24) & 0xFF),
            .sequence = @intCast((session_id >> 16) & 0xFF),
            .reserved = @intCast(session_id & 0xFFFF),
        };
    }

    /// Returns true if this is a valid canary token.
    pub fn isValid(self: CanaryToken) bool {
        return self.magic == CANARY_MAGIC;
    }
};

// ============================================================
// Canary Test Definition
// ============================================================

pub const CanaryTest = struct {
    id: u8,
    name: []const u8,
    /// Function that creates the canary event with embedded token.
    create_event: *const fn (token: CanaryToken) canonical.CanonicalEvent,
    /// Expected enforcement action.
    expected_action: policy.EnforcementAction,
    /// Expected PEP status.
    expected_pep_status: rust_pep.EnforcementStatus,
    /// Expected verdict.
    expected_verdict: detection.Verdict,
};

// ============================================================
// Canary Result
// ============================================================

pub const CanaryStatus = enum(u8) {
    /// Canary passed - enforcement worked as expected.
    passed = 0,
    /// Canary failed - enforcement did NOT work as expected.
    failed = 1,
    /// Canary not found in Forensics (pipeline didn't process it).
    not_found = 2,
    /// Canary error (e.g., canary subsystem not initialized).
    error_ = 3,

    pub fn toString(self: CanaryStatus) []const u8 {
        return switch (self) {
            .passed => "PASSED",
            .failed => "FAILED",
            .not_found => "NOT_FOUND",
            .error_ => "ERROR",
        };
    }

    pub fn isHealthy(self: CanaryStatus) bool {
        return self == .passed;
    }
};

pub const CanaryResult = struct {
    test_id: u8,
    test_name: []const u8,
    status: CanaryStatus,
    token: CanaryToken,
    /// Actual enforcement action from Forensics (if found).
    actual_action: policy.EnforcementAction,
    /// Actual PEP status.
    actual_pep_status: rust_pep.EnforcementStatus,
    /// Actual verdict.
    actual_verdict: detection.Verdict,
    /// Failure reason (if any).
    failure_reason: []const u8,

    pub fn isPassed(self: CanaryResult) bool {
        return self.status == .passed;
    }
};

// ============================================================
// Canary Health
// ============================================================

pub const HealthLevel = enum(u8) {
    /// All canaries passed.
    healthy = 0,
    /// Some canaries failed but critical ones passed.
    degraded = 1,
    /// Critical canaries failed - IPS may be broken.
    failed = 2,
    /// No canaries run yet.
    unknown = 3,

    pub fn toString(self: HealthLevel) []const u8 {
        return switch (self) {
            .healthy => "HEALTHY",
            .degraded => "DEGRADED",
            .failed => "FAILED",
            .unknown => "UNKNOWN",
        };
    }

    pub fn isHealthy(self: HealthLevel) bool {
        return self == .healthy;
    }
};

// ============================================================
// IPS Canary Engine
// ============================================================

pub const IpsCanary = struct {
    /// Total canaries run (lifetime).
    total_canaries: u64,
    /// Total passed.
    total_passed: u64,
    /// Total failed.
    total_failed: u64,
    /// Total not found.
    total_not_found: u64,
    /// Last sequence number used.
    last_sequence: u8,
    /// Last health level.
    last_health: HealthLevel,

    pub fn init() IpsCanary {
        return .{
            .total_canaries = 0,
            .total_passed = 0,
            .total_failed = 0,
            .total_not_found = 0,
            .last_sequence = 0,
            .last_health = .unknown,
        };
    }

    /// Create a canary event for a specific test.
    /// The token is embedded in session_id for later lookup.
    pub fn createCanaryEvent(self: *IpsCanary, canary_test: CanaryTest) canonical.CanonicalEvent {
        self.last_sequence +%= 1; // Wrapping counter
        const token = CanaryToken{
            .magic = CANARY_MAGIC,
            .test_id = canary_test.id,
            .sequence = self.last_sequence,
            .reserved = 0,
        };

        var event = canary_test.create_event(token);
        // Embed token in session_id
        event.session_id = token.pack();
        return event;
    }

    /// Verify a canary result against a forensic record.
    /// Returns the canary result status.
    pub fn verifyCanary(
        self: *IpsCanary,
        canary_test: CanaryTest,
        record: ?forensics.ForensicRecord,
    ) CanaryResult {
        self.total_canaries += 1;

        if (record == null) {
            self.total_not_found += 1;
            self.last_health = .degraded;
            return .{
                .test_id = canary_test.id,
                .test_name = canary_test.name,
                .status = .not_found,
                .token = .{
                    .magic = CANARY_MAGIC,
                    .test_id = canary_test.id,
                    .sequence = 0,
                    .reserved = 0,
                },
                .actual_action = .allow,
                .actual_pep_status = .no_op,
                .actual_verdict = .unknown,
                .failure_reason = "canary event not found in forensics",
            };
        }

        const result = record.?.result;
        const token = CanaryToken.unpack(result.event_id) orelse CanaryToken{
            .magic = 0,
            .test_id = 0,
            .sequence = 0,
            .reserved = 0,
        };

        // Check verdict
        if (result.aggregated_verdict != canary_test.expected_verdict) {
            self.total_failed += 1;
            self.last_health = if (canary_test.id < 2) .failed else .degraded;
            return .{
                .test_id = canary_test.id,
                .test_name = canary_test.name,
                .status = .failed,
                .token = token,
                .actual_action = result.policy_action,
                .actual_pep_status = result.pep_status,
                .actual_verdict = result.aggregated_verdict,
                .failure_reason = "verdict mismatch",
            };
        }

        // Check action
        if (result.policy_action != canary_test.expected_action) {
            self.total_failed += 1;
            self.last_health = if (canary_test.id < 2) .failed else .degraded;
            return .{
                .test_id = canary_test.id,
                .test_name = canary_test.name,
                .status = .failed,
                .token = token,
                .actual_action = result.policy_action,
                .actual_pep_status = result.pep_status,
                .actual_verdict = result.aggregated_verdict,
                .failure_reason = "action mismatch",
            };
        }

        // Check PEP status
        if (result.pep_status != canary_test.expected_pep_status) {
            self.total_failed += 1;
            self.last_health = if (canary_test.id < 2) .failed else .degraded;
            return .{
                .test_id = canary_test.id,
                .test_name = canary_test.name,
                .status = .failed,
                .token = token,
                .actual_action = result.policy_action,
                .actual_pep_status = result.pep_status,
                .actual_verdict = result.aggregated_verdict,
                .failure_reason = "PEP status mismatch",
            };
        }

        // All checks passed
        self.total_passed += 1;
        self.updateHealth();
        return .{
            .test_id = canary_test.id,
            .test_name = canary_test.name,
            .status = .passed,
            .token = token,
            .actual_action = result.policy_action,
            .actual_pep_status = result.pep_status,
            .actual_verdict = result.aggregated_verdict,
            .failure_reason = "",
        };
    }

    /// Update health level based on recent results.
    fn updateHealth(self: *IpsCanary) void {
        if (self.total_canaries == 0) {
            self.last_health = .unknown;
            return;
        }
        const pass_rate = (self.total_passed * 100) / self.total_canaries;
        if (pass_rate == 100) {
            self.last_health = .healthy;
        } else if (pass_rate >= 75) {
            self.last_health = .degraded;
        } else {
            self.last_health = .failed;
        }
    }

    /// Get current health level.
    pub fn getHealth(self: *const IpsCanary) HealthLevel {
        return self.last_health;
    }

    /// Get pass rate (0-100).
    pub fn passRate(self: *const IpsCanary) u8 {
        if (self.total_canaries == 0) return 0;
        return @intCast((self.total_passed * 100) / self.total_canaries);
    }

    /// Reset all stats.
    pub fn reset(self: *IpsCanary) void {
        self.* = init();
    }
};

// ============================================================
// Built-in Canary Test Events
// ============================================================

/// Test 0 (CRITICAL): Should be BLOCKED. Malicious event on public IP.
/// This is a critical canary - if it fails, IPS is broken.
pub fn createBlockCanaryEvent(token: CanaryToken) canonical.CanonicalEvent {
    _ = token;
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0xCB007101; // 203.0.113.1 (TEST-NET-3, public)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xCAFE; // known bad rule
    event.severity = 3; // critical
    return event;
}

/// Test 1 (CRITICAL): Should be REJECTED. Block on localhost.
/// Critical canary - verifies PEP validation is active.
pub fn createRejectCanaryEvent(token: CanaryToken) canonical.CanonicalEvent {
    _ = token;
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x7F000001; // 127.0.0.1 (localhost)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xCAFE;
    event.severity = 3; // critical -> would block, but localhost protected
    return event;
}

/// Test 2 (NON-CRITICAL): Should be ALERT. Suspicious event.
pub fn createAlertCanaryEvent(token: CanaryToken) canonical.CanonicalEvent {
    _ = token;
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0xCB007102; // 203.0.113.2 (TEST-NET-3, public)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xBEEF;
    event.severity = 2; // suspicious
    return event;
}

/// Test 3 (NON-CRITICAL): Should be ALLOW. Benign event.
pub fn createAllowCanaryEvent(token: CanaryToken) canonical.CanonicalEvent {
    _ = token;
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0xCB007103; // 203.0.113.3 (TEST-NET-3, public)
    event.dest_ip = 0x0A000002;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0; // no rule match
    event.severity = 0;
    return event;
}

// ============================================================
// Built-in Canary Tests
// ============================================================

pub const CANARY_TESTS = [_]CanaryTest{
    .{
        .id = 0,
        .name = "block_critical",
        .create_event = &createBlockCanaryEvent,
        .expected_action = .block,
        .expected_pep_status = .executed,
        .expected_verdict = .malicious,
    },
    .{
        .id = 1,
        .name = "reject_localhost",
        .create_event = &createRejectCanaryEvent,
        .expected_action = .block,
        .expected_pep_status = .rejected,
        .expected_verdict = .malicious,
    },
    .{
        .id = 2,
        .name = "alert_suspicious",
        .create_event = &createAlertCanaryEvent,
        .expected_action = .alert,
        .expected_pep_status = .no_op,
        .expected_verdict = .suspicious,
    },
    .{
        .id = 3,
        .name = "allow_benign",
        .create_event = &createAllowCanaryEvent,
        .expected_action = .allow,
        .expected_pep_status = .no_op,
        .expected_verdict = .benign,
    },
};

// ============================================================
// Tests (all use local canary instances - parallelism-safe)
// ============================================================

test "CanaryToken pack and unpack" {
    const token = CanaryToken{
        .magic = CANARY_MAGIC,
        .test_id = 2,
        .sequence = 5,
        .reserved = 0,
    };
    const packed_val = token.pack();
    const unpacked = CanaryToken.unpack(packed_val);

    try std.testing.expect(unpacked != null);
    try std.testing.expect(unpacked.?.magic == CANARY_MAGIC);
    try std.testing.expect(unpacked.?.test_id == 2);
    try std.testing.expect(unpacked.?.sequence == 5);
}

test "CanaryToken unpack returns null for non-canary session_id" {
    const result = CanaryToken.unpack(0x00000000DEADBEEF);
    try std.testing.expect(result == null);
}

test "CanaryToken isValid" {
    const valid = CanaryToken{
        .magic = CANARY_MAGIC,
        .test_id = 0,
        .sequence = 0,
        .reserved = 0,
    };
    try std.testing.expect(valid.isValid());

    const invalid = CanaryToken{
        .magic = 0xDEADBEEF,
        .test_id = 0,
        .sequence = 0,
        .reserved = 0,
    };
    try std.testing.expect(!invalid.isValid());
}

test "CanaryStatus.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, CanaryStatus.passed.toString(), "PASSED"));
    try std.testing.expect(std.mem.eql(u8, CanaryStatus.failed.toString(), "FAILED"));
    try std.testing.expect(std.mem.eql(u8, CanaryStatus.not_found.toString(), "NOT_FOUND"));
    try std.testing.expect(std.mem.eql(u8, CanaryStatus.error_.toString(), "ERROR"));
}

test "CanaryStatus.isHealthy" {
    try std.testing.expect(CanaryStatus.passed.isHealthy());
    try std.testing.expect(!CanaryStatus.failed.isHealthy());
}

test "HealthLevel.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, HealthLevel.healthy.toString(), "HEALTHY"));
    try std.testing.expect(std.mem.eql(u8, HealthLevel.degraded.toString(), "DEGRADED"));
    try std.testing.expect(std.mem.eql(u8, HealthLevel.failed.toString(), "FAILED"));
    try std.testing.expect(std.mem.eql(u8, HealthLevel.unknown.toString(), "UNKNOWN"));
}

test "HealthLevel.isHealthy" {
    try std.testing.expect(HealthLevel.healthy.isHealthy());
    try std.testing.expect(!HealthLevel.degraded.isHealthy());
}

test "IpsCanary init has zero stats and unknown health" {
    const canary = IpsCanary.init();
    try std.testing.expect(canary.total_canaries == 0);
    try std.testing.expect(canary.total_passed == 0);
    try std.testing.expect(canary.getHealth() == .unknown);
}

test "IpsCanary createCanaryEvent embeds token in session_id" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0]; // block_critical

    const event = canary.createCanaryEvent(test_def);

    // Verify the token is embedded in session_id
    const token = CanaryToken.unpack(event.session_id);
    try std.testing.expect(token != null);
    try std.testing.expect(token.?.magic == CANARY_MAGIC);
    try std.testing.expect(token.?.test_id == 0);
    try std.testing.expect(token.?.sequence > 0); // should have been incremented
}

test "IpsCanary verifyCanary fails when record is null (not_found)" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0];

    const result = canary.verifyCanary(test_def, null);

    try std.testing.expect(result.status == .not_found);
    try std.testing.expect(canary.total_not_found == 1);
    try std.testing.expect(canary.getHealth() == .degraded); // not_found -> degraded
}

test "IpsCanary verifyCanary passes when all match" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0]; // expects malicious, block, executed

    const record = forensics.ForensicRecord{
        .result = .{
            .event_id = CanaryToken{ .magic = CANARY_MAGIC, .test_id = 0, .sequence = 1, .reserved = 0 }.pack(),
            .timestamp_ns = 1000,
            .source_ip = 0xCB007101,
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
            .pep_blocked_ip = 0xCB007101,
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const result = canary.verifyCanary(test_def, record);

    try std.testing.expect(result.status == .passed);
    try std.testing.expect(canary.total_passed == 1);
    try std.testing.expect(canary.getHealth() == .healthy);
}

test "IpsCanary verifyCanary fails on verdict mismatch" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0]; // expects malicious

    var record = forensics.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0xCB007101,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .benign, // MISMATCH
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
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };
    _ = &record;

    const result = canary.verifyCanary(test_def, record);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, result.failure_reason, "verdict mismatch"));
    try std.testing.expect(canary.total_failed == 1);
}

test "IpsCanary verifyCanary fails on action mismatch" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0]; // expects block

    const record = forensics.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0xCB007101,
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

    const result = canary.verifyCanary(test_def, record);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, result.failure_reason, "action mismatch"));
}

test "IpsCanary verifyCanary fails on PEP status mismatch" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0]; // expects executed

    const record = forensics.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0xCB007101,
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

    const result = canary.verifyCanary(test_def, record);

    try std.testing.expect(result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, result.failure_reason, "PEP status mismatch"));
}

test "IpsCanary critical test failure sets health to failed" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[0]; // id=0 (critical)

    const record = forensics.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0xCB007101,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .benign, // MISMATCH on critical test
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
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    _ = canary.verifyCanary(test_def, record);
    try std.testing.expect(canary.getHealth() == .failed); // critical test (id<2) failed
}

test "IpsCanary non-critical test failure sets health to degraded" {
    var canary = IpsCanary.init();
    const test_def = CANARY_TESTS[2]; // id=2 (non-critical)

    const record = forensics.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0xCB007102,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = .benign, // MISMATCH on non-critical test
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
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    _ = canary.verifyCanary(test_def, record);
    try std.testing.expect(canary.getHealth() == .degraded); // non-critical test (id>=2) failed
}

test "IpsCanary passRate" {
    var canary = IpsCanary.init();
    try std.testing.expect(canary.passRate() == 0);

    // Simulate 3 passed, 1 failed
    canary.total_canaries = 4;
    canary.total_passed = 3;
    canary.total_failed = 1;
    try std.testing.expect(canary.passRate() == 75); // 3/4 = 75%
}

test "CANARY_TESTS has 4 built-in tests" {
    try std.testing.expect(CANARY_TESTS.len == 4);
}

test "CANARY_TESTS covers all enforcement paths" {
    var has_block_executed = false;
    var has_block_rejected = false;
    var has_alert = false;
    var has_allow = false;

    for (CANARY_TESTS) |t| {
        if (t.expected_action == .block and t.expected_pep_status == .executed) has_block_executed = true;
        if (t.expected_action == .block and t.expected_pep_status == .rejected) has_block_rejected = true;
        if (t.expected_action == .alert) has_alert = true;
        if (t.expected_action == .allow) has_allow = true;
    }

    try std.testing.expect(has_block_executed);
    try std.testing.expect(has_block_rejected);
    try std.testing.expect(has_alert);
    try std.testing.expect(has_allow);
}

test "CanaryResult.isPassed" {
    const passed = CanaryResult{
        .test_id = 0,
        .test_name = "test",
        .status = .passed,
        .token = .{ .magic = CANARY_MAGIC, .test_id = 0, .sequence = 1, .reserved = 0 },
        .actual_action = .block,
        .actual_pep_status = .executed,
        .actual_verdict = .malicious,
        .failure_reason = "",
    };
    try std.testing.expect(passed.isPassed());

    const failed = CanaryResult{
        .test_id = 0,
        .test_name = "test",
        .status = .failed,
        .token = .{ .magic = CANARY_MAGIC, .test_id = 0, .sequence = 1, .reserved = 0 },
        .actual_action = .allow,
        .actual_pep_status = .no_op,
        .actual_verdict = .benign,
        .failure_reason = "mismatch",
    };
    try std.testing.expect(!failed.isPassed());
}

test "IpsCanary reset zeroes everything" {
    var canary = IpsCanary.init();
    canary.total_canaries = 10;
    canary.total_passed = 8;
    canary.total_failed = 2;
    canary.last_health = .degraded;

    canary.reset();
    try std.testing.expect(canary.total_canaries == 0);
    try std.testing.expect(canary.total_passed == 0);
    try std.testing.expect(canary.getHealth() == .unknown);
}

test "createBlockCanaryEvent uses TEST-NET-3 IP range" {
    const event = createBlockCanaryEvent(.{ .magic = CANARY_MAGIC, .test_id = 0, .sequence = 1, .reserved = 0 });
    // 203.0.113.0/24 = 0xCB007100 - 0xCB0071FF
    try std.testing.expect((event.source_ip & 0xFFFFFF00) == 0xCB007100);
    try std.testing.expect(event.severity == 3); // critical
}

test "createRejectCanaryEvent uses localhost" {
    const event = createRejectCanaryEvent(.{ .magic = CANARY_MAGIC, .test_id = 1, .sequence = 1, .reserved = 0 });
    try std.testing.expect(event.source_ip == 0x7F000001); // 127.0.0.1
}
