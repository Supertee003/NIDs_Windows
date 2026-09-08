//! shadow_decision.zig - AEGIS Shadow Decision Comparison (T19 / Step 57)
//!
//! Compares the CURRENT (live) security decision against a CANDIDATE
//! decision produced by an experimental detector/policy/RAG curve.
//! The candidate can NEVER enforce: the comparison is purely analytical
//! and produces no enforcement output.
//!
//! Six comparison dimensions (mandated):
//!   decision, evidence, confidence, false-positive indication,
//!   policy version, detector version
//!
//! Self-contained: imports std only. Deterministic offline.

const std = @import("std");

pub const Dimension = enum(u8) {
    decision = 0,
    evidence = 1,
    confidence = 2,
    false_positive = 3,
    policy_version = 4,
    detector_version = 5,

    pub const COUNT: usize = 6;

    pub fn label(self: Dimension) []const u8 {
        return switch (self) {
            .decision => "decision",
            .evidence => "evidence",
            .confidence => "confidence",
            .false_positive => "false_positive",
            .policy_version => "policy_version",
            .detector_version => "detector_version",
        };
    }
};

pub const Decision = enum(u8) {
    allow = 0,
    monitor = 1,
    rate_limit = 2,
    quarantine = 3,
    block = 4,

    pub fn label(self: Decision) []const u8 {
        return switch (self) {
            .allow => "allow",
            .monitor => "monitor",
            .rate_limit => "rate_limit",
            .quarantine => "quarantine",
            .block => "block",
        };
    }
};

pub const DecisionInput = struct {
    decision: Decision = .monitor,
    evidence_fingerprint: u64 = 0,
    confidence: u8 = 0,
    false_positive: bool = false,
    policy_version: u64 = 0,
    detector_version: u64 = 0,
    candidate_enforce: bool = false, // shadow candidates may never enforce
};

pub const ShadowOutcome = enum(u8) {
    agree = 0,
    differ = 1,
};

pub const FieldComparison = struct {
    dimension: Dimension,
    equal: bool,
    note: []const u8,
};

pub const ShadowComparison = struct {
    live: DecisionInput,
    candidate: DecisionInput,
    diffs: [Dimension.COUNT]FieldComparison = undefined,
    diff_count: usize = 0,
    outcome: ShadowOutcome = .agree,
    candidate_enforced: bool = false, // architecturally always false

    pub fn differs(self: *const ShadowComparison, dim: Dimension) bool {
        for (self.diffs[0..self.diff_count]) |d| {
            if (d.dimension == dim) return !d.equal;
        }
        return false;
    }
};

pub const ShadowEngine = struct {
    /// Compare a live decision against a candidate. The candidate's
    /// enforce flag is forcibly cleared before comparison: a shadow
    /// decision never enforces.
    pub fn compare(_: *const ShadowEngine, live: DecisionInput, candidate: DecisionInput) ShadowComparison {
        var c = candidate;
        c.candidate_enforce = false;
        var cmp = ShadowComparison{ .live = live, .candidate = c };
        addCompare(&cmp, .decision, live.decision == c.decision, "live vs candidate decision");
        addCompare(&cmp, .evidence, live.evidence_fingerprint == c.evidence_fingerprint, "evidence fingerprint");
        addCompare(&cmp, .confidence, live.confidence == c.confidence, "confidence");
        addCompare(&cmp, .false_positive, live.false_positive == c.false_positive, "false-positive indication");
        addCompare(&cmp, .policy_version, live.policy_version == c.policy_version, "policy version");
        addCompare(&cmp, .detector_version, live.detector_version == c.detector_version, "detector version");
        cmp.candidate_enforced = false;
        return cmp;
    }
};

fn addCompare(cmp: *ShadowComparison, dim: Dimension, equal: bool, note: []const u8) void {
    cmp.diffs[cmp.diff_count] = .{ .dimension = dim, .equal = equal, .note = note };
    cmp.diff_count += 1;
    if (!equal) cmp.outcome = .differ;
}

test "identical decisions agree on all six dimensions" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(ShadowOutcome.agree, cmp.outcome);
    try std.testing.expectEqual(@as(usize, 6), cmp.diff_count);
    try std.testing.expectEqual(false, cmp.differs(.decision));
    try std.testing.expectEqual(false, cmp.candidate_enforced);
}

test "candidate enforce flag is forcibly cleared" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3, .candidate_enforce = true };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(false, cmp.candidate.candidate_enforce);
    try std.testing.expectEqual(false, cmp.candidate_enforced);
}

test "decision difference is flagged" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .quarantine, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(ShadowOutcome.differ, cmp.outcome);
    try std.testing.expectEqual(true, cmp.differs(.decision));
}

test "evidence difference is flagged" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 8, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(true, cmp.differs(.evidence));
}

test "confidence difference is flagged" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 60, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(true, cmp.differs(.confidence));
}

test "false-positive indication difference is flagged" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = true, .policy_version = 2, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(true, cmp.differs(.false_positive));
}

test "policy version difference is flagged" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 3, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(true, cmp.differs(.policy_version));
}

test "detector version difference is flagged" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 4 };
    const cmp = engine.compare(live, cand);
    try std.testing.expectEqual(true, cmp.differs(.detector_version));
}

test "shadow comparison never yields an enforcement output" {
    const engine = ShadowEngine{};
    const live = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cand = DecisionInput{ .decision = .block, .evidence_fingerprint = 7, .confidence = 90, .false_positive = false, .policy_version = 2, .detector_version = 3 };
    const cmp = engine.compare(live, cand);
    // Nothing escorts an action out: no rule, no dispatch, no PEP target.
    try std.testing.expectEqual(false, cmp.candidate_enforced);
}