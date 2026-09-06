//! ips_canary_integration.zig - AEGIS IPS Canary Integration (Rewrite Phase 18)
//!
//! Thin facade over ips_canary.zig that owns a singleton IpsCanary.
//! Provides canary verification API for IPS health monitoring.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create IpsCanary
//!   createCanaryEvent(test) -> CanonicalEvent (with embedded token)
//!   verifyCanary(test, record) -> CanaryResult
//!   shutdown() -> reset canary state

const std = @import("std");
const canonical = @import("canonical_event.zig");
const forensics = @import("forensics_engine.zig");
const canary = @import("ips_canary.zig");

// ============================================================
// Singleton state
// ============================================================

var g_canary: ?canary.IpsCanary = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_canaries: u64 = 0;
var g_total_passed: u64 = 0;
var g_total_failed: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_canary = canary.IpsCanary.init();
    g_initialized = true;
    g_total_canaries = 0;
    g_total_passed = 0;
    g_total_failed = 0;
    std.log.info("[CANARY] IPS Canary integration initialized (4 built-in tests)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_canaries = 0;
    g_total_passed = 0;
    g_total_failed = 0;
    if (g_canary) |*c| {
        c.reset();
    }
}

// ============================================================
// Canary Operations
// ============================================================

/// Create a canary event for a specific test.
/// The token is embedded in session_id for later lookup.
pub fn createCanaryEvent(canary_test: canary.CanaryTest) canonical.CanonicalEvent {
    if (!g_initialized) {
        return canonical.create(.zig_core); // fallback
    }
    if (g_canary) |*c| {
        return c.createCanaryEvent(canary_test);
    }
    return canonical.create(.zig_core);
}

/// Verify a canary result against a forensic record.
/// Returns error result if not initialized.
pub fn verifyCanary(
    canary_test: canary.CanaryTest,
    record: ?forensics.ForensicRecord,
) canary.CanaryResult {
    if (!g_initialized) {
        return .{
            .test_id = canary_test.id,
            .test_name = canary_test.name,
            .status = .error_,
            .token = .{ .magic = 0, .test_id = 0, .sequence = 0, .reserved = 0 },
            .actual_action = .allow,
            .actual_pep_status = .no_op,
            .actual_verdict = .unknown,
            .failure_reason = "canary not initialized",
        };
    }
    if (g_canary) |*c| {
        const result = c.verifyCanary(canary_test, record);
        g_total_canaries += 1;
        if (result.isPassed()) {
            g_total_passed += 1;
        } else {
            g_total_failed += 1;
        }
        return result;
    }
    return .{
        .test_id = canary_test.id,
        .test_name = canary_test.name,
        .status = .error_,
        .token = .{ .magic = 0, .test_id = 0, .sequence = 0, .reserved = 0 },
        .actual_action = .allow,
        .actual_pep_status = .no_op,
        .actual_verdict = .unknown,
        .failure_reason = "canary engine not available",
    };
}

// ============================================================
// Health
// ============================================================

/// Get current IPS health level.
pub fn getHealth() canary.HealthLevel {
    if (g_canary) |*c| {
        return c.getHealth();
    }
    return .unknown;
}

/// Get pass rate (0-100).
pub fn passRate() u8 {
    if (g_canary) |*c| {
        return c.passRate();
    }
    return 0;
}

// ============================================================
// Stats
// ============================================================

pub const CanaryStats = struct {
    total_canaries: u64,
    total_passed: u64,
    total_failed: u64,
    pass_rate: u8,
    health_level: canary.HealthLevel,
};

pub fn getStats() CanaryStats {
    if (g_canary) |*c| {
        return .{
            .total_canaries = g_total_canaries,
            .total_passed = g_total_passed,
            .total_failed = g_total_failed,
            .pass_rate = c.passRate(),
            .health_level = c.getHealth(),
        };
    }
    return .{
        .total_canaries = 0,
        .total_passed = 0,
        .total_failed = 0,
        .pass_rate = 0,
        .health_level = .unknown,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_canary = null;
    g_initialized = false;
    std.log.info("[CANARY] IPS Canary integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "ips canary integration: full lifecycle (init, create, verify, health, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: createCanaryEvent returns fallback when not initialized ---
    const test_def = @import("ips_canary.zig").CANARY_TESTS[0];
    const fallback_event = createCanaryEvent(test_def);
    try std.testing.expect(fallback_event.source == .zig_core); // fallback

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_canaries == 0);
    try std.testing.expect(stats_init.health_level == .unknown);

    // --- Phase C: createCanaryEvent embeds token ---
    const canary_event = createCanaryEvent(test_def);
    const token = @import("ips_canary.zig").CanaryToken.unpack(canary_event.session_id);
    try std.testing.expect(token != null);
    try std.testing.expect(token.?.magic == @import("ips_canary.zig").CANARY_MAGIC);

    // --- Phase D: verifyCanary with null record -> not_found ---
    const not_found_result = verifyCanary(test_def, null);
    try std.testing.expect(not_found_result.status == .not_found);

    const stats_after_not_found = getStats();
    try std.testing.expect(stats_after_not_found.total_canaries == 1);
    try std.testing.expect(stats_after_not_found.total_failed == 1);

    // --- Phase E: verifyCanary with matching record -> passed ---
    const forensics_engine = @import("forensics_engine.zig");
    const canary_mod = @import("ips_canary.zig");
    const record = forensics_engine.ForensicRecord{
        .result = .{
            .event_id = blk: {
                const tok = canary_mod.CanaryToken{ .magic = canary_mod.CANARY_MAGIC, .test_id = 0, .sequence = 1, .reserved = 0 };
                break :blk tok.pack();
            },
            .timestamp_ns = 1000,
            .source_ip = 0xCB007101,
            .dest_ip = 0x0A000002,
            .source_port = 12345,
            .dest_port = 80,
            .protocol = 6,
            .aggregated_verdict = @import("detection_engine.zig").Verdict.malicious,
            .aggregated_confidence = 90,
            .escalated = false,
            .original_verdict = @import("detection_engine.zig").Verdict.malicious,
            .correlation_alert_count = 0,
            .correlation_rules = .{ 0, 0, 0 },
            .threat_intel_matched = false,
            .threat_intel_max_severity = 0,
            .brain_advice_kind = 0,
            .brain_threat_score = 80,
            .brain_recommended_verdict = @import("detection_engine.zig").Verdict.malicious,
            .policy_action = @import("policy_engine.zig").EnforcementAction.block,
            .policy_rule = @import("policy_engine.zig").PolicyRule.verdict_malicious,
            .policy_confidence = 90,
            .pep_status = @import("rust_pep.zig").EnforcementStatus.executed,
            .pep_rejection_reason = @import("rust_pep.zig").RejectionReason.none,
            .pep_blocked_ip = 0xCB007101,
        },
        .sequence = 1,
        .logged_at_ns = 1000,
    };

    const passed_result = verifyCanary(test_def, record);
    try std.testing.expect(passed_result.status == .passed);

    const stats_after_pass = getStats();
    try std.testing.expect(stats_after_pass.total_canaries == 2);
    try std.testing.expect(stats_after_pass.total_passed == 1);
    try std.testing.expect(stats_after_pass.total_failed == 1);

    // --- Phase F: resetStats ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_canaries == 0);
    try std.testing.expect(stats_reset.health_level == .unknown);

    // --- Phase G: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase H: after shutdown, verifyCanary returns error ---
    const error_result = verifyCanary(test_def, null);
    try std.testing.expect(error_result.status == .error_);
}
