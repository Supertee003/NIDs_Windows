//! e2e_harness_integration.zig - AEGIS E2E Harness Integration (Rewrite Phase 16)
//!
//! Thin facade over e2e_harness.zig that owns a singleton E2eHarness.
//! Provides E2E test verification API for the full pipeline.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create E2eHarness
//!   verifyResult(scenario, record) -> E2eResult
//!   shutdown() -> reset harness state

const std = @import("std");
const forensics = @import("forensics_engine.zig");
const e2e = @import("e2e_harness.zig");

// ============================================================
// Singleton state
// ============================================================

var g_harness: ?e2e.E2eHarness = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_verifications: u64 = 0;
var g_total_passed: u64 = 0;
var g_total_failed: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_harness = e2e.E2eHarness.init();
    g_initialized = true;
    g_total_verifications = 0;
    g_total_passed = 0;
    g_total_failed = 0;
    std.log.info("[E2E] E2E harness integration initialized (6 built-in scenarios)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_verifications = 0;
    g_total_passed = 0;
    g_total_failed = 0;
    if (g_harness) |*harness| {
        harness.resetStats();
    }
}

// ============================================================
// Verification
// ============================================================

/// Verify a scenario result against a forensic record.
/// Returns E2eResult (status=failed if not initialized).
pub fn verifyResult(
    scenario: e2e.Scenario,
    record: ?forensics.ForensicRecord,
) e2e.E2eResult {
    if (!g_initialized) {
        return .{
            .scenario_name = scenario.name,
            .status = .error_,
            .event_id = 0,
            .expected_action = scenario.expected_action,
            .actual_action = .allow,
            .expected_pep_status = scenario.expected_pep_status,
            .actual_pep_status = .no_op,
            .expected_verdict = scenario.expected_verdict,
            .actual_verdict = .unknown,
            .failure_reason = "E2E harness not initialized",
        };
    }
    if (g_harness) |*harness| {
        const result = harness.verifyResult(scenario, record);
        g_total_verifications += 1;
        if (result.isPassed()) {
            g_total_passed += 1;
        } else {
            g_total_failed += 1;
        }
        return result;
    }
    return .{
        .scenario_name = scenario.name,
        .status = .error_,
        .event_id = 0,
        .expected_action = scenario.expected_action,
        .actual_action = .allow,
        .expected_pep_status = scenario.expected_pep_status,
        .actual_pep_status = .no_op,
        .expected_verdict = scenario.expected_verdict,
        .actual_verdict = .unknown,
        .failure_reason = "E2E harness not available",
    };
}

// ============================================================
// Stats
// ============================================================

pub const E2eStats = struct {
    total_verifications: u64,
    total_passed: u64,
    total_failed: u64,
    pass_rate: u8,
};

pub fn getStats() E2eStats {
    if (g_harness) |*harness| {
        return .{
            .total_verifications = g_total_verifications,
            .total_passed = g_total_passed,
            .total_failed = g_total_failed,
            .pass_rate = harness.passRate(),
        };
    }
    return .{
        .total_verifications = 0,
        .total_passed = 0,
        .total_failed = 0,
        .pass_rate = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_harness = null;
    g_initialized = false;
    std.log.info("[E2E] E2E harness integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "e2e harness integration: full lifecycle (init, verify, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: verifyResult returns error when not initialized ---
    const scenario = @import("e2e_harness.zig").SCENARIOS[0];
    const empty_result = verifyResult(scenario, null);
    try std.testing.expect(empty_result.status == .error_);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_verifications == 0);

    // --- Phase C: verifyResult with null record -> failed ---
    const failed_result = verifyResult(scenario, null);
    try std.testing.expect(failed_result.status == .failed);
    try std.testing.expect(std.mem.eql(u8, failed_result.failure_reason, "no forensic record found for event"));

    const stats_after_fail = getStats();
    try std.testing.expect(stats_after_fail.total_verifications == 1);
    try std.testing.expect(stats_after_fail.total_failed == 1);

    // --- Phase D: verifyResult with matching record -> passed ---
    const forensics_engine = @import("forensics_engine.zig");
    const record = forensics_engine.ForensicRecord{
        .result = .{
            .event_id = 1,
            .timestamp_ns = 1000,
            .source_ip = 0x0A000001,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = @import("detection_engine.zig").Verdict.benign,
            .aggregated_confidence = 50,
            .escalated = false,
            .original_verdict = @import("detection_engine.zig").Verdict.benign,
            .correlation_alert_count = 0,
            .correlation_rules = .{ 0, 0, 0 },
            .threat_intel_matched = false,
            .threat_intel_max_severity = 0,
            .brain_advice_kind = 0,
            .brain_threat_score = 0,
            .brain_recommended_verdict = @import("detection_engine.zig").Verdict.benign,
            .policy_action = @import("policy_engine.zig").EnforcementAction.allow,
            .policy_rule = @import("policy_engine.zig").PolicyRule.default_allow,
            .policy_confidence = 50,
            .pep_status = @import("rust_pep.zig").EnforcementStatus.no_op,
            .pep_rejection_reason = @import("rust_pep.zig").RejectionReason.none,
            .pep_blocked_ip = 0,
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const passed_result = verifyResult(scenario, record);
    try std.testing.expect(passed_result.status == .passed);

    const stats_after_pass = getStats();
    try std.testing.expect(stats_after_pass.total_verifications == 2);
    try std.testing.expect(stats_after_pass.total_passed == 1);
    try std.testing.expect(stats_after_pass.total_failed == 1);

    // --- Phase E: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_verifications == 0);

    // --- Phase F: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase G: after shutdown, verifyResult returns error ---
    const empty_result2 = verifyResult(scenario, null);
    try std.testing.expect(empty_result2.status == .error_);
}
