//! replay_engine.zig - AEGIS Replay Engine (Rewrite Phase 15)
//!
//! Replays historical events from Forensics through the pipeline.
//! Use cases:
//!   1. Regression testing: replay old events, verify new rules produce same/different results
//!   2. Rule tuning: "what-if" scenarios with modified detection thresholds
//!   3. Incident reconstruction: replay events around a security incident
//!
//! Architecture:
//!   Forensics (14) -> Replay Engine (15)
//!   Replay reads PipelineResult records from ForensicLogger ring buffer.
//!   Each replayed event is compared to its original result.
//!
//! Design:
//!   - ReplaySource: iterator over historical PipelineResult records
//!   - ReplayResult: comparison between original and replayed pipeline output
//!   - ReplayStats: aggregate stats (matches, diffs, regressions, improvements)
//!   - Does NOT modify the live pipeline - replay is read-only analysis

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const forensics = @import("forensics_engine.zig");

// ============================================================
// Replay Comparison Result
// ============================================================

pub const DiffKind = enum(u8) {
    /// No difference - original and replayed match.
    no_diff = 0,
    /// Verdict changed (e.g., benign -> suspicious).
    verdict_changed = 1,
    /// Policy action changed (e.g., allow -> block).
    action_changed = 2,
    /// PEP status changed (e.g., executed -> rejected).
    pep_status_changed = 3,
    /// Confidence changed significantly (>20 points).
    confidence_shift = 4,
    /// Threat score changed significantly (>20 points).
    threat_score_shift = 5,

    pub fn toString(self: DiffKind) []const u8 {
        return switch (self) {
            .no_diff => "NO_DIFF",
            .verdict_changed => "VERDICT_CHANGED",
            .action_changed => "ACTION_CHANGED",
            .pep_status_changed => "PEP_STATUS_CHANGED",
            .confidence_shift => "CONFIDENCE_SHIFT",
            .threat_score_shift => "THREAT_SCORE_SHIFT",
        };
    }

    /// Returns true if this diff represents a regression (worse outcome).
    pub fn isRegression(self: DiffKind) bool {
        return self == .verdict_changed or self == .action_changed or self == .pep_status_changed;
    }
};

pub const ReplayResult = struct {
    original: forensics.PipelineResult,
    replayed: forensics.PipelineResult,
    diff: DiffKind,
    /// Delta in confidence (replayed - original, can be negative).
    confidence_delta: i16,
    /// Delta in threat score (replayed - original, can be negative).
    threat_score_delta: i16,
    /// True if the replayed result is more restrictive (e.g., allow -> block).
    more_restrictive: bool,
    /// True if the replayed result is less restrictive (e.g., block -> allow).
    less_restrictive: bool,

    /// Returns true if the replay produced a different outcome.
    pub fn hasDiff(self: ReplayResult) bool {
        return self.diff != .no_diff;
    }

    /// Returns true if the replay is a regression (outcome got worse).
    pub fn isRegression(self: ReplayResult) bool {
        return self.diff.isRegression() and self.less_restrictive;
    }

    /// Returns true if the replay is an improvement (outcome got better).
    pub fn isImprovement(self: ReplayResult) bool {
        return self.diff.isRegression() and self.more_restrictive;
    }
};

// ============================================================
// Replay Stats
// ============================================================

pub const ReplayStats = struct {
    total_replayed: u64,
    total_matches: u64,
    total_diffs: u64,
    total_regressions: u64,
    total_improvements: u64,
    /// Count by diff kind.
    verdict_changed_count: u64,
    action_changed_count: u64,
    pep_status_changed_count: u64,
    confidence_shift_count: u64,
    threat_score_shift_count: u64,
};

// ============================================================
// Replay Engine
// ============================================================

/// Confidence/threat score delta threshold for flagging a shift.
pub const SHIFT_THRESHOLD: i16 = 20;

pub const ReplayEngine = struct {
    stats: ReplayStats,

    pub fn init() ReplayEngine {
        return .{
            .stats = .{
                .total_replayed = 0,
                .total_matches = 0,
                .total_diffs = 0,
                .total_regressions = 0,
                .total_improvements = 0,
                .verdict_changed_count = 0,
                .action_changed_count = 0,
                .pep_status_changed_count = 0,
                .confidence_shift_count = 0,
                .threat_score_shift_count = 0,
            },
        };
    }

    /// Compare two pipeline results and produce a ReplayResult.
    /// This is the core comparison function - does NOT execute anything.
    pub fn compare(
        self: *ReplayEngine,
        original: forensics.PipelineResult,
        replayed: forensics.PipelineResult,
    ) ReplayResult {
        self.stats.total_replayed += 1;

        const confidence_delta: i16 = @as(i16, replayed.aggregated_confidence) - @as(i16, original.aggregated_confidence);
        const threat_score_delta: i16 = @as(i16, replayed.brain_threat_score) - @as(i16, original.brain_threat_score);

        // Determine diff kind (priority order: verdict > action > pep > confidence > threat_score)
        var diff: DiffKind = .no_diff;

        if (original.aggregated_verdict != replayed.aggregated_verdict) {
            diff = .verdict_changed;
        } else if (original.policy_action != replayed.policy_action) {
            diff = .action_changed;
        } else if (original.pep_status != replayed.pep_status) {
            diff = .pep_status_changed;
        } else if (@abs(confidence_delta) > SHIFT_THRESHOLD) {
            diff = .confidence_shift;
        } else if (@abs(threat_score_delta) > SHIFT_THRESHOLD) {
            diff = .threat_score_shift;
        }

        // Determine if more or less restrictive
        const more_restrictive = isMoreRestrictive(replayed.policy_action, original.policy_action) or
            (replayed.pep_status == .executed and original.pep_status != .executed);
        const less_restrictive = isMoreRestrictive(original.policy_action, replayed.policy_action) or
            (original.pep_status == .executed and replayed.pep_status != .executed);

        const result = ReplayResult{
            .original = original,
            .replayed = replayed,
            .diff = diff,
            .confidence_delta = confidence_delta,
            .threat_score_delta = threat_score_delta,
            .more_restrictive = more_restrictive,
            .less_restrictive = less_restrictive,
        };

        // Update stats
        if (diff == .no_diff) {
            self.stats.total_matches += 1;
        } else {
            self.stats.total_diffs += 1;
            switch (diff) {
                .verdict_changed => self.stats.verdict_changed_count += 1,
                .action_changed => self.stats.action_changed_count += 1,
                .pep_status_changed => self.stats.pep_status_changed_count += 1,
                .confidence_shift => self.stats.confidence_shift_count += 1,
                .threat_score_shift => self.stats.threat_score_shift_count += 1,
                .no_diff => {},
            }
            if (result.isRegression()) {
                self.stats.total_regressions += 1;
            } else if (result.isImprovement()) {
                self.stats.total_improvements += 1;
            }
        }

        return result;
    }

    /// Get current replay stats.
    pub fn getStats(self: *const ReplayEngine) ReplayStats {
        return self.stats;
    }

    /// Reset all stats.
    pub fn resetStats(self: *ReplayEngine) void {
        self.stats = .{
            .total_replayed = 0,
            .total_matches = 0,
            .total_diffs = 0,
            .total_regressions = 0,
            .total_improvements = 0,
            .verdict_changed_count = 0,
            .action_changed_count = 0,
            .pep_status_changed_count = 0,
            .confidence_shift_count = 0,
            .threat_score_shift_count = 0,
        };
    }
};

// ============================================================
// Restrictiveness helpers
// ============================================================

/// Returns true if action `a` is more restrictive than action `b`.
/// Restrictiveness order: block > quarantine > rate_limit > alert > log_only > allow
fn isMoreRestrictive(a: policy.EnforcementAction, b: policy.EnforcementAction) bool {
    return actionRestrictiveness(a) > actionRestrictiveness(b);
}

fn actionRestrictiveness(a: policy.EnforcementAction) u8 {
    return switch (a) {
        .allow => 0,
        .log_only => 1,
        .alert => 2,
        .rate_limit => 3,
        .quarantine => 4,
        .block => 5,
    };
}

// ============================================================
// Tests (all use local engine instances - parallelism-safe)
// ============================================================

test "DiffKind.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, DiffKind.no_diff.toString(), "NO_DIFF"));
    try std.testing.expect(std.mem.eql(u8, DiffKind.verdict_changed.toString(), "VERDICT_CHANGED"));
    try std.testing.expect(std.mem.eql(u8, DiffKind.action_changed.toString(), "ACTION_CHANGED"));
    try std.testing.expect(std.mem.eql(u8, DiffKind.pep_status_changed.toString(), "PEP_STATUS_CHANGED"));
    try std.testing.expect(std.mem.eql(u8, DiffKind.confidence_shift.toString(), "CONFIDENCE_SHIFT"));
    try std.testing.expect(std.mem.eql(u8, DiffKind.threat_score_shift.toString(), "THREAT_SCORE_SHIFT"));
}

test "DiffKind.isRegression" {
    try std.testing.expect(!DiffKind.no_diff.isRegression());
    try std.testing.expect(DiffKind.verdict_changed.isRegression());
    try std.testing.expect(DiffKind.action_changed.isRegression());
    try std.testing.expect(DiffKind.pep_status_changed.isRegression());
    try std.testing.expect(!DiffKind.confidence_shift.isRegression());
    try std.testing.expect(!DiffKind.threat_score_shift.isRegression());
}

test "actionRestrictiveness ordering" {
    try std.testing.expect(actionRestrictiveness(.allow) < actionRestrictiveness(.log_only));
    try std.testing.expect(actionRestrictiveness(.log_only) < actionRestrictiveness(.alert));
    try std.testing.expect(actionRestrictiveness(.alert) < actionRestrictiveness(.rate_limit));
    try std.testing.expect(actionRestrictiveness(.rate_limit) < actionRestrictiveness(.quarantine));
    try std.testing.expect(actionRestrictiveness(.quarantine) < actionRestrictiveness(.block));
}

test "isMoreRestrictive" {
    try std.testing.expect(isMoreRestrictive(.block, .allow));
    try std.testing.expect(isMoreRestrictive(.block, .alert));
    try std.testing.expect(isMoreRestrictive(.quarantine, .allow));
    try std.testing.expect(!isMoreRestrictive(.allow, .block));
    try std.testing.expect(!isMoreRestrictive(.alert, .alert));
}

test "ReplayEngine init has zero stats" {
    const engine = ReplayEngine.init();
    try std.testing.expect(engine.stats.total_replayed == 0);
    try std.testing.expect(engine.stats.total_matches == 0);
    try std.testing.expect(engine.stats.total_diffs == 0);
}

// Helper to create a PipelineResult for tests
fn makeResult(
    event_id: u64,
    verdict: detection.Verdict,
    confidence: u8,
    action: policy.EnforcementAction,
    pep_status: rust_pep.EnforcementStatus,
    threat_score: u8,
) forensics.PipelineResult {
    return .{
        .event_id = event_id,
        .timestamp_ns = @intCast(event_id * 1000),
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = verdict,
        .aggregated_confidence = confidence,
        .escalated = false,
        .original_verdict = verdict,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = threat_score,
        .brain_recommended_verdict = verdict,
        .policy_action = action,
        .policy_rule = .default_allow,
        .policy_confidence = confidence,
        .pep_status = pep_status,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = 0,
    };
}

test "compare: identical results produce no_diff" {
    var engine = ReplayEngine.init();
    const orig = makeResult(1, .benign, 50, .allow, .no_op, 10);
    const replay = makeResult(1, .benign, 50, .allow, .no_op, 10);

    const result = engine.compare(orig, replay);

    try std.testing.expect(result.diff == .no_diff);
    try std.testing.expect(!result.hasDiff());
    try std.testing.expect(result.confidence_delta == 0);
    try std.testing.expect(result.threat_score_delta == 0);
    try std.testing.expect(engine.stats.total_replayed == 1);
    try std.testing.expect(engine.stats.total_matches == 1);
}

test "compare: verdict changed is detected" {
    var engine = ReplayEngine.init();
    const orig = makeResult(1, .benign, 50, .allow, .no_op, 10);
    const replay = makeResult(1, .suspicious, 70, .alert, .no_op, 50);

    const result = engine.compare(orig, replay);

    try std.testing.expect(result.diff == .verdict_changed);
    try std.testing.expect(result.hasDiff());
    try std.testing.expect(result.more_restrictive); // benign -> suspicious
    try std.testing.expect(!result.less_restrictive);
    try std.testing.expect(engine.stats.verdict_changed_count == 1);
    try std.testing.expect(engine.stats.total_diffs == 1);
}

test "compare: action changed is detected (regression)" {
    var engine = ReplayEngine.init();
    // Original: block (good), Replay: allow (regression - missed threat)
    const orig = makeResult(1, .malicious, 90, .block, .executed, 80);
    const replay = makeResult(1, .malicious, 90, .allow, .no_op, 80);

    const result = engine.compare(orig, replay);

    // Verdict is the same (malicious), so action_changed takes priority
    try std.testing.expect(result.diff == .action_changed);
    try std.testing.expect(result.less_restrictive); // block -> allow = regression
    try std.testing.expect(result.isRegression());
    try std.testing.expect(engine.stats.total_regressions == 1);
}

test "compare: action changed is detected (improvement)" {
    var engine = ReplayEngine.init();
    // Original: allow (missed), Replay: block (improvement - now catches threat)
    const orig = makeResult(1, .suspicious, 70, .allow, .no_op, 50);
    const replay = makeResult(1, .suspicious, 70, .block, .executed, 50);

    const result = engine.compare(orig, replay);

    try std.testing.expect(result.diff == .action_changed);
    try std.testing.expect(result.more_restrictive); // allow -> block = improvement
    try std.testing.expect(result.isImprovement());
    try std.testing.expect(engine.stats.total_improvements == 1);
}

test "compare: PEP status changed is detected" {
    var engine = ReplayEngine.init();
    const orig = makeResult(1, .malicious, 90, .block, .rejected, 80);
    const replay = makeResult(1, .malicious, 90, .block, .executed, 80);

    const result = engine.compare(orig, replay);

    // Verdict and action are same, so pep_status_changed
    try std.testing.expect(result.diff == .pep_status_changed);
    try std.testing.expect(result.more_restrictive); // rejected -> executed
    try std.testing.expect(engine.stats.pep_status_changed_count == 1);
}

test "compare: confidence shift is detected" {
    var engine = ReplayEngine.init();
    const orig = makeResult(1, .suspicious, 50, .alert, .no_op, 50);
    const replay = makeResult(1, .suspicious, 80, .alert, .no_op, 50);

    const result = engine.compare(orig, replay);

    // Verdict, action, pep same. Confidence delta = 30 > SHIFT_THRESHOLD (20)
    try std.testing.expect(result.diff == .confidence_shift);
    try std.testing.expect(result.confidence_delta == 30);
    try std.testing.expect(engine.stats.confidence_shift_count == 1);
}

test "compare: small confidence change is NOT flagged" {
    var engine = ReplayEngine.init();
    const orig = makeResult(1, .suspicious, 50, .alert, .no_op, 50);
    const replay = makeResult(1, .suspicious, 60, .alert, .no_op, 50);

    const result = engine.compare(orig, replay);

    // Confidence delta = 10 < SHIFT_THRESHOLD (20) -> no_diff
    try std.testing.expect(result.diff == .no_diff);
    try std.testing.expect(result.confidence_delta == 10);
}

test "compare: threat score shift is detected" {
    var engine = ReplayEngine.init();
    const orig = makeResult(1, .suspicious, 50, .alert, .no_op, 30);
    const replay = makeResult(1, .suspicious, 50, .alert, .no_op, 70);

    const result = engine.compare(orig, replay);

    // Verdict, action, pep, confidence same. Threat score delta = 40 > 20
    try std.testing.expect(result.diff == .threat_score_shift);
    try std.testing.expect(result.threat_score_delta == 40);
    try std.testing.expect(engine.stats.threat_score_shift_count == 1);
}

test "compare: priority order (verdict > action > pep > confidence > threat_score)" {
    var engine = ReplayEngine.init();

    // Everything changed - verdict should win
    const orig = makeResult(1, .benign, 50, .allow, .no_op, 10);
    const replay = makeResult(1, .malicious, 90, .block, .executed, 80);

    const result = engine.compare(orig, replay);
    try std.testing.expect(result.diff == .verdict_changed);

    // Verdict same, action+pep+conf+score changed - action should win
    const orig2 = makeResult(2, .suspicious, 50, .allow, .no_op, 10);
    const replay2 = makeResult(2, .suspicious, 90, .block, .executed, 80);
    const result2 = engine.compare(orig2, replay2);
    try std.testing.expect(result2.diff == .action_changed);
}

test "compare: stats accumulate correctly" {
    var engine = ReplayEngine.init();

    // Run 1: match
    _ = engine.compare(
        makeResult(1, .benign, 50, .allow, .no_op, 10),
        makeResult(1, .benign, 50, .allow, .no_op, 10),
    );

    // Run 2: verdict changed
    _ = engine.compare(
        makeResult(2, .benign, 50, .allow, .no_op, 10),
        makeResult(2, .suspicious, 70, .alert, .no_op, 50),
    );

    // Run 3: action changed (regression)
    _ = engine.compare(
        makeResult(3, .malicious, 90, .block, .executed, 80),
        makeResult(3, .malicious, 90, .allow, .no_op, 80),
    );

    try std.testing.expect(engine.stats.total_replayed == 3);
    try std.testing.expect(engine.stats.total_matches == 1);
    try std.testing.expect(engine.stats.total_diffs == 2);
    try std.testing.expect(engine.stats.verdict_changed_count == 1);
    try std.testing.expect(engine.stats.action_changed_count == 1);
    try std.testing.expect(engine.stats.total_regressions == 1);
}

test "ReplayResult.hasDiff, isRegression, isImprovement" {
    var engine = ReplayEngine.init();

    // No diff
    const no_diff = engine.compare(
        makeResult(1, .benign, 50, .allow, .no_op, 10),
        makeResult(1, .benign, 50, .allow, .no_op, 10),
    );
    try std.testing.expect(!no_diff.hasDiff());
    try std.testing.expect(!no_diff.isRegression());
    try std.testing.expect(!no_diff.isImprovement());

    // Regression: block -> allow
    const regression = engine.compare(
        makeResult(2, .malicious, 90, .block, .executed, 80),
        makeResult(2, .malicious, 90, .allow, .no_op, 80),
    );
    try std.testing.expect(regression.hasDiff());
    try std.testing.expect(regression.isRegression());
    try std.testing.expect(!regression.isImprovement());

    // Improvement: allow -> block
    const improvement = engine.compare(
        makeResult(3, .suspicious, 70, .allow, .no_op, 50),
        makeResult(3, .suspicious, 70, .block, .executed, 50),
    );
    try std.testing.expect(improvement.hasDiff());
    try std.testing.expect(!improvement.isRegression());
    try std.testing.expect(improvement.isImprovement());
}

test "resetStats zeroes all counters" {
    var engine = ReplayEngine.init();
    _ = engine.compare(
        makeResult(1, .benign, 50, .allow, .no_op, 10),
        makeResult(1, .suspicious, 70, .alert, .no_op, 50),
    );
    try std.testing.expect(engine.stats.total_replayed == 1);

    engine.resetStats();
    try std.testing.expect(engine.stats.total_replayed == 0);
    try std.testing.expect(engine.stats.total_diffs == 0);
    try std.testing.expect(engine.stats.total_matches == 0);
}
