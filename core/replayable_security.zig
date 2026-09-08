//! replayable_security.zig - AEGIS Replayable Security (T19 / Step 58)
//!
//! Replays historical events against OLD vs NEW security atoms and
//! reports the difference with a reason. The three replayable atoms
//! (mandated):
//!
//!   rules   - detection rules / signatures / rule-set version
//!   policy  - enforcement policy version
//!   context - evidence/RAG context version
//!
//! Output model (mandated):
//!   original  - verdict/action at the historical atom versions
//!   replayed  - verdict/action at the new atom versions
//!   difference- none / verdict_changed / action_changed
//!   reason    - which atom version deltas caused the difference
//!
//! Deterministic: the caller re-evaluates the event against the new
//! atoms and supplies the new verdict/action; this engine computes the
//! diff + attribution (it is the replay harness, not the detector).
//!
//! Self-contained: imports std only. Fixed capacity, fails soft.

const std = @import("std");

pub const Verdict = enum(u8) {
    unknown = 0,
    benign = 1,
    suspicious = 2,
    malicious = 3,
    critical = 4,

    pub fn label(self: Verdict) []const u8 {
        return switch (self) {
            .unknown => "unknown",
            .benign => "benign",
            .suspicious => "suspicious",
            .malicious => "malicious",
            .critical => "critical",
        };
    }
};

pub const Action = enum(u8) {
    allow = 0,
    alert = 1,
    rate_limit = 2,
    quarantine = 3,
    block = 4,

    pub fn label(self: Action) []const u8 {
        return switch (self) {
            .allow => "allow",
            .alert => "alert",
            .rate_limit => "rate_limit",
            .quarantine => "quarantine",
            .block => "block",
        };
    }
};

pub const AtomVersions = struct {
    rules_version: u64 = 0,
    policy_version: u64 = 0,
    context_version: u64 = 0,
};

pub const Difference = enum(u8) {
    none = 0,
    verdict_changed = 1,
    action_changed = 2,

    pub fn label(self: Difference) []const u8 {
        return switch (self) {
            .none => "none",
            .verdict_changed => "verdict_changed",
            .action_changed => "action_changed",
        };
    }
};

pub const ReplayedOutcome = struct {
    verdict: Verdict = .unknown,
    action: Action = .allow,
};

pub const ReplayCase = struct {
    event_id: u64,
    original: ReplayedOutcome,
    original_atoms: AtomVersions,
};

pub const ReplayResult = struct {
    event_id: u64,
    original: ReplayedOutcome,
    replayed: ReplayedOutcome,
    original_atoms: AtomVersions,
    replayed_atoms: AtomVersions,
    difference: Difference = .none,
    reason: []const u8 = "no difference",
    reason_buf: [REASON_CAP]u8 = undefined,
};

pub const MAX_REASONS: usize = 3;
pub const REASON_CAP: usize = 64;

pub const ReplayStats = struct {
    cases: usize = 0,
    matched: usize = 0,
    changed: usize = 0,
    verdict_changed: usize = 0,
    action_changed: usize = 0,
};

pub const SecurityReplay = struct {
    /// Replay a historical event + outcome against NEW atoms/outcome.
    /// Returns original/replayed/difference/reason, attributing the
    /// difference to the exact atom version deltas.
    pub fn replay(
        _: *const SecurityReplay,
        case: ReplayCase,
        new_atoms: AtomVersions,
        new_outcome: ReplayedOutcome,
    ) ReplayResult {
        var result = ReplayResult{
            .event_id = case.event_id,
            .original = case.original,
            .replayed = new_outcome,
            .original_atoms = case.original_atoms,
            .replayed_atoms = new_atoms,
        };
        if (case.original.verdict != new_outcome.verdict) {
            result.difference = .verdict_changed;
        } else if (case.original.action != new_outcome.action) {
            result.difference = .action_changed;
        } else {
            result.difference = .none;
            result.reason = "no difference";
            return result;
        }
        var i: usize = 0;
        if (case.original_atoms.rules_version != new_atoms.rules_version) {
            i += writeReason(&result.reason_buf, i, "rules", case.original_atoms.rules_version, new_atoms.rules_version);
        }
        if (case.original_atoms.policy_version != new_atoms.policy_version) {
            i += writeReason(&result.reason_buf, i, "policy", case.original_atoms.policy_version, new_atoms.policy_version);
        }
        if (case.original_atoms.context_version != new_atoms.context_version) {
            i += writeReason(&result.reason_buf, i, "context", case.original_atoms.context_version, new_atoms.context_version);
        }
        if (i == 0) {
            result.reason = "outcome changed with no atom delta";
        } else {
            result.reason = result.reason_buf[0..i];
        }
        return result;
    }

    pub fn summarize(_: *const SecurityReplay, results: []const ReplayResult) ReplayStats {
        var s = ReplayStats{};
        for (results) |r| {
            s.cases += 1;
            switch (r.difference) {
                .none => s.matched += 1,
                .verdict_changed => {
                    s.changed += 1;
                    s.verdict_changed += 1;
                },
                .action_changed => {
                    s.changed += 1;
                    s.action_changed += 1;
                },
            }
        }
        return s;
    }
};

fn writeReason(buf: []u8, at: usize, atom: []const u8, old: u64, new: u64) usize {
    const part = std.fmt.bufPrint(buf[at..], "{s}:{d}->{d};", .{ atom, old, new }) catch return 0;
    return part.len;
}

// ============================================================
// Tests
// ============================================================

test "identical atoms and outcome produce no difference" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 1,
        .original = .{ .verdict = .malicious, .action = .block },
        .original_atoms = .{ .rules_version = 3, .policy_version = 2, .context_version = 1 },
    };
    const res = engine.replay(case, .{ .rules_version = 3, .policy_version = 2, .context_version = 1 }, .{ .verdict = .malicious, .action = .block });
    try std.testing.expectEqualStrings("no difference", res.reason);
    try std.testing.expectEqual(Difference.none, res.difference);
}

test "verdict change is reported with attribution to rules" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 2,
        .original = .{ .verdict = .benign, .action = .allow },
        .original_atoms = .{ .rules_version = 3, .policy_version = 2, .context_version = 1 },
    };
    const res = engine.replay(case, .{ .rules_version = 4, .policy_version = 2, .context_version = 1 }, .{ .verdict = .malicious, .action = .block });
    try std.testing.expectEqual(Difference.verdict_changed, res.difference);
    try std.testing.expect(std.mem.indexOf(u8, res.reason, "rules:3->4") != null);
    try std.testing.expect(std.mem.indexOf(u8, res.reason, "policy") == null);
}

test "action change is reported with attribution to policy" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 3,
        .original = .{ .verdict = .malicious, .action = .alert },
        .original_atoms = .{ .rules_version = 3, .policy_version = 2, .context_version = 1 },
    };
    const res = engine.replay(case, .{ .rules_version = 3, .policy_version = 3, .context_version = 1 }, .{ .verdict = .malicious, .action = .block });
    try std.testing.expectEqual(Difference.action_changed, res.difference);
    try std.testing.expect(std.mem.indexOf(u8, res.reason, "policy:2->3") != null);
}

test "attribution cites context delta" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 4,
        .original = .{ .verdict = .suspicious, .action = .alert },
        .original_atoms = .{ .rules_version = 3, .policy_version = 2, .context_version = 1 },
    };
    const res = engine.replay(case, .{ .rules_version = 3, .policy_version = 2, .context_version = 2 }, .{ .verdict = .malicious, .action = .quarantine });
    try std.testing.expectEqual(Difference.verdict_changed, res.difference);
    try std.testing.expect(std.mem.indexOf(u8, res.reason, "context:1->2") != null);
}

test "multi-atom change cites all three deltas" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 5,
        .original = .{ .verdict = .benign, .action = .allow },
        .original_atoms = .{ .rules_version = 1, .policy_version = 1, .context_version = 1 },
    };
    const res = engine.replay(case, .{ .rules_version = 2, .policy_version = 2, .context_version = 2 }, .{ .verdict = .critical, .action = .block });
    for ([_][]const u8{ "rules:1->2", "policy:1->2", "context:1->2" }) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, res.reason, needle) != null);
    }
}

test "replay result carries original and replayed outcomes" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 6,
        .original = .{ .verdict = .malicious, .action = .block },
        .original_atoms = .{ .rules_version = 3, .policy_version = 2, .context_version = 1 },
    };
    const res = engine.replay(case, .{ .rules_version = 3, .policy_version = 2, .context_version = 1 }, .{ .verdict = .malicious, .action = .block });
    try std.testing.expectEqualStrings("malicious", res.original.verdict.label());
    try std.testing.expectEqualStrings("block", res.replayed.action.label());
    try std.testing.expectEqual(@as(u64, 6), res.event_id);
}

test "summary counts matched vs changed" {
    const engine = SecurityReplay{};
    const case = ReplayCase{
        .event_id = 1,
        .original = .{ .verdict = .benign, .action = .allow },
        .original_atoms = .{ .rules_version = 1, .policy_version = 1, .context_version = 1 },
    };
    const r0 = engine.replay(case, .{ .rules_version = 1, .policy_version = 1, .context_version = 1 }, .{ .verdict = .benign, .action = .allow });
    const r1 = engine.replay(case, .{ .rules_version = 2, .policy_version = 1, .context_version = 1 }, .{ .verdict = .malicious, .action = .block });
    const r2 = engine.replay(case, .{ .rules_version = 1, .policy_version = 2, .context_version = 1 }, .{ .verdict = .benign, .action = .quarantine });
    const results = [_]ReplayResult{ r0, r1, r2 };
    const s = engine.summarize(&results);
    try std.testing.expectEqual(@as(usize, 3), s.cases);
    try std.testing.expectEqual(@as(usize, 1), s.matched);
    try std.testing.expectEqual(@as(usize, 2), s.changed);
    try std.testing.expectEqual(@as(usize, 1), s.verdict_changed);
    try std.testing.expectEqual(@as(usize, 1), s.action_changed);
}

test "regression-style verdict change labels each difference kind" {
    try std.testing.expectEqualStrings("none", Difference.none.label());
    try std.testing.expectEqualStrings("verdict_changed", Difference.verdict_changed.label());
    try std.testing.expectEqualStrings("action_changed", Difference.action_changed.label());
}