//! replay_integration.zig - AEGIS Replay Integration (Rewrite Phase 15)
//!
//! Thin facade over replay_engine.zig that owns a singleton ReplayEngine.
//! Provides replay comparison API for regression testing and rule tuning.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()     -> create ReplayEngine
//!   compare(original, replayed) -> ReplayResult
//!   shutdown() -> reset engine state

const std = @import("std");
const forensics = @import("forensics_engine.zig");
const replay = @import("replay_engine.zig");

// ============================================================
// Singleton state
// ============================================================

var g_engine: ?replay.ReplayEngine = null;
var g_initialized: bool = false;

// Lifetime stats
var g_total_comparisons: u64 = 0;
var g_total_matches: u64 = 0;
var g_total_diffs: u64 = 0;
var g_total_regressions: u64 = 0;
var g_total_improvements: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_engine = replay.ReplayEngine.init();
    g_initialized = true;
    g_total_comparisons = 0;
    g_total_matches = 0;
    g_total_diffs = 0;
    g_total_regressions = 0;
    g_total_improvements = 0;
    std.log.info("[REPLAY] Replay integration initialized (regression testing)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_comparisons = 0;
    g_total_matches = 0;
    g_total_diffs = 0;
    g_total_regressions = 0;
    g_total_improvements = 0;
    if (g_engine) |*engine| {
        engine.resetStats();
    }
}

// ============================================================
// Comparison
// ============================================================

/// Compare two pipeline results. Returns ReplayResult.
/// Returns no_diff result if not initialized.
pub fn compare(
    original: forensics.PipelineResult,
    replayed: forensics.PipelineResult,
) replay.ReplayResult {
    if (!g_initialized) {
        return .{
            .original = original,
            .replayed = replayed,
            .diff = .no_diff,
            .confidence_delta = 0,
            .threat_score_delta = 0,
            .more_restrictive = false,
            .less_restrictive = false,
        };
    }
    if (g_engine) |*engine| {
        const result = engine.compare(original, replayed);
        g_total_comparisons += 1;
        if (result.diff == .no_diff) {
            g_total_matches += 1;
        } else {
            g_total_diffs += 1;
            if (result.isRegression()) {
                g_total_regressions += 1;
            } else if (result.isImprovement()) {
                g_total_improvements += 1;
            }
        }
        return result;
    }
    return .{
        .original = original,
        .replayed = replayed,
        .diff = .no_diff,
        .confidence_delta = 0,
        .threat_score_delta = 0,
        .more_restrictive = false,
        .less_restrictive = false,
    };
}

// ============================================================
// Stats
// ============================================================

pub const ReplayIntegrationStats = struct {
    total_comparisons: u64,
    total_matches: u64,
    total_diffs: u64,
    total_regressions: u64,
    total_improvements: u64,
};

pub fn getStats() ReplayIntegrationStats {
    if (g_engine) |*engine| {
        return .{
            .total_comparisons = g_total_comparisons,
            .total_matches = g_total_matches,
            .total_diffs = g_total_diffs,
            .total_regressions = g_total_regressions,
            .total_improvements = g_total_improvements,
        };
    }
    return .{
        .total_comparisons = 0,
        .total_matches = 0,
        .total_diffs = 0,
        .total_regressions = 0,
        .total_improvements = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[REPLAY] Replay integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "replay integration: full lifecycle (init, compare, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: compare returns no_diff when not initialized ---
    const orig = @import("forensics_engine.zig").PipelineResult{
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
        .brain_threat_score = 10,
        .brain_recommended_verdict = @import("detection_engine.zig").Verdict.benign,
        .policy_action = @import("policy_engine.zig").EnforcementAction.allow,
        .policy_rule = @import("policy_engine.zig").PolicyRule.default_allow,
        .policy_confidence = 50,
        .pep_status = @import("rust_pep.zig").EnforcementStatus.no_op,
        .pep_rejection_reason = @import("rust_pep.zig").RejectionReason.none,
        .pep_blocked_ip = 0,
    };
    const replay_result_same = orig;

    const empty_result = compare(orig, replay_result_same);
    try std.testing.expect(empty_result.diff == .no_diff);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.total_comparisons == 0);

    // --- Phase C: compare identical results -> match ---
    const match_result = compare(orig, replay_result_same);
    try std.testing.expect(match_result.diff == .no_diff);

    const stats_after_match = getStats();
    try std.testing.expect(stats_after_match.total_comparisons == 1);
    try std.testing.expect(stats_after_match.total_matches == 1);

    // --- Phase D: compare different results -> diff ---
    var replayed_diff = orig;
    replayed_diff.aggregated_verdict = @import("detection_engine.zig").Verdict.suspicious;
    replayed_diff.policy_action = @import("policy_engine.zig").EnforcementAction.alert;

    const diff_result = compare(orig, replayed_diff);
    try std.testing.expect(diff_result.diff == .verdict_changed);
    try std.testing.expect(diff_result.more_restrictive);

    const stats_after_diff = getStats();
    try std.testing.expect(stats_after_diff.total_comparisons == 2);
    try std.testing.expect(stats_after_diff.total_diffs == 1);

    // --- Phase E: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_comparisons == 0);
    try std.testing.expect(stats_reset.total_diffs == 0);

    // --- Phase F: double-init is no-op, double-shutdown is no-op ---
    init(); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase G: after shutdown, compare returns no_diff ---
    const empty_result2 = compare(orig, replay_result_same);
    try std.testing.expect(empty_result2.diff == .no_diff);
}
