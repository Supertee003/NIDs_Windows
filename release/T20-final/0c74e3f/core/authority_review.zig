const std = @import("std");

// ============================================================
// Step 59 - Final Review: the accountability checklist.
//
// AEGIS is enforced only by the Rust PEP. Every other component
// holds zero enforcement authority. This module encodes the
// twelve non-negotiable authority clauses as data and reviews an
// observed deployment before it may ship.
// ============================================================

pub const Subject = enum {
    sensor,
    detector,
    rag,
    brain,
    go,
    typescript,
    cpp,
    policy,
    cli,
    rust_pep,
    windows,
};

pub const Capability = enum {
    enforce,
    authorize,
    execute_policy,
    bypass_pep,
    final_verdict,
    comply,
    audit,
};

pub const AuthorityClause = struct {
    subject: Subject,
    capability: Capability,
    allowed: bool,
};

pub const CLAUSE_COUNT: usize = 12;

/// The twelve-accountability checklist. Each row fixes one
/// subject/capability pair to a truth value; a deployment whose
/// observed facts contradict any row is NOT authoritative.
pub const AUTHORITY_CHECKLIST: [CLAUSE_COUNT]AuthorityClause = .{
    .{ .subject = .sensor, .capability = .enforce, .allowed = false },
    .{ .subject = .detector, .capability = .enforce, .allowed = false },
    .{ .subject = .rag, .capability = .authorize, .allowed = false },
    .{ .subject = .brain, .capability = .enforce, .allowed = false },
    .{ .subject = .go, .capability = .enforce, .allowed = false },
    .{ .subject = .typescript, .capability = .enforce, .allowed = false },
    .{ .subject = .cpp, .capability = .bypass_pep, .allowed = false },
    .{ .subject = .policy, .capability = .execute_policy, .allowed = false },
    .{ .subject = .cli, .capability = .bypass_pep, .allowed = false },
    .{ .subject = .rust_pep, .capability = .final_verdict, .allowed = true },
    .{ .subject = .windows, .capability = .comply, .allowed = true },
    .{ .subject = .windows, .capability = .audit, .allowed = true },
};

pub const Checked = struct {
    clause: AuthorityClause,
    holds: bool,
};

pub const ReviewOutcome = struct {
    checked: [CLAUSE_COUNT]Checked = undefined,
    count: usize = 0,
    passing: usize = 0,
    authoritative: bool = false,
};

pub fn findClause(subject: Subject, capability: Capability) ?usize {
    for (AUTHORITY_CHECKLIST, 0..) |cl, i| {
        if (cl.subject == subject and cl.capability == capability) return i;
    }
    return null;
}

pub const AuthorityReview = struct {
    /// Compare observed facts (one per checklist row, same order)
    /// against the checklist. A row holds only when the observed
    /// subject/capability pair AND truth value match exactly, so a
    /// mis-ordered observation is caught just like a lie.
    pub fn review(_: *const AuthorityReview, observed: []const AuthorityClause) ReviewOutcome {
        var out = ReviewOutcome{};
        out.count = @min(observed.len, CLAUSE_COUNT);
        for (0..out.count) |k| {
            const exp = AUTHORITY_CHECKLIST[k];
            const obs = observed[k];
            const holds = exp.subject == obs.subject and exp.capability == obs.capability and exp.allowed == obs.allowed;
            out.checked[k] = .{ .clause = exp, .holds = holds };
            if (holds) out.passing += 1;
        }
        out.authoritative = out.passing == out.count;
        return out;
    }
};

// ============================================================
// Tests
// ============================================================

test "checklist fixes all twelve mandated rows" {
    try std.testing.expectEqual(12, CLAUSE_COUNT);
    try std.testing.expectEqual(CLAUSE_COUNT, AUTHORITY_CHECKLIST.len);
    try std.testing.expect(findClause(.sensor, .enforce) != null);
    try std.testing.expect(findClause(.detector, .enforce) != null);
    try std.testing.expect(findClause(.rag, .authorize) != null);
    try std.testing.expect(findClause(.brain, .enforce) != null);
    try std.testing.expect(findClause(.go, .enforce) != null);
    try std.testing.expect(findClause(.typescript, .enforce) != null);
    try std.testing.expect(findClause(.cpp, .bypass_pep) != null);
    try std.testing.expect(findClause(.policy, .execute_policy) != null);
    try std.testing.expect(findClause(.cli, .bypass_pep) != null);
    try std.testing.expect(findClause(.rust_pep, .final_verdict) != null);
    try std.testing.expect(findClause(.windows, .comply) != null);
    try std.testing.expect(findClause(.windows, .audit) != null);
}

test "enforcement and authorization stay forbidden to non-PEP components" {
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.sensor, .enforce).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.detector, .enforce).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.rag, .authorize).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.brain, .enforce).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.go, .enforce).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.typescript, .enforce).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.cpp, .bypass_pep).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.policy, .execute_policy).?].allowed);
    try std.testing.expect(!AUTHORITY_CHECKLIST[findClause(.cli, .bypass_pep).?].allowed);
}

test "rust pep is the final authority and windows follows it" {
    try std.testing.expect(AUTHORITY_CHECKLIST[findClause(.rust_pep, .final_verdict).?].allowed);
    try std.testing.expect(AUTHORITY_CHECKLIST[findClause(.windows, .comply).?].allowed);
    try std.testing.expect(AUTHORITY_CHECKLIST[findClause(.windows, .audit).?].allowed);
}

test "review passes when every observed row matches the checklist" {
    const engine = AuthorityReview{};
    var observed: [CLAUSE_COUNT]AuthorityClause = undefined;
    for (AUTHORITY_CHECKLIST, 0..) |cl, k| observed[k] = cl;
    const out = engine.review(&observed);
    try std.testing.expectEqual(12, out.count);
    try std.testing.expectEqual(12, out.passing);
    try std.testing.expect(out.authoritative);
    for (out.checked) |chk| try std.testing.expect(chk.holds);
}

test "review fails closed when a sensor is granted enforcement" {
    const engine = AuthorityReview{};
    var observed: [CLAUSE_COUNT]AuthorityClause = undefined;
    for (AUTHORITY_CHECKLIST, 0..) |cl, k| observed[k] = cl;
    observed[findClause(.sensor, .enforce).?].allowed = true;
    const out = engine.review(&observed);
    try std.testing.expectEqual(11, out.passing);
    try std.testing.expect(!out.authoritative);
}

test "review fails closed when a component lies about its identity" {
    const engine = AuthorityReview{};
    var observed: [CLAUSE_COUNT]AuthorityClause = undefined;
    for (AUTHORITY_CHECKLIST, 0..) |cl, k| observed[k] = cl;
    var swapped = observed;
    const sensor_idx = findClause(.sensor, .enforce).?;
    const detector_idx = findClause(.detector, .enforce).?;
    swapped[sensor_idx] = AUTHORITY_CHECKLIST[detector_idx];
    const out = engine.review(&swapped);
    try std.testing.expect(!out.authoritative);
}

test "review fails closed when the cpp layer claims pep bypass" {
    const engine = AuthorityReview{};
    var observed: [CLAUSE_COUNT]AuthorityClause = undefined;
    for (AUTHORITY_CHECKLIST, 0..) |cl, k| observed[k] = cl;
    observed[findClause(.cpp, .bypass_pep).?].allowed = true;
    const out = engine.review(&observed);
    try std.testing.expect(!out.authoritative);
}

test "review fails closed when the cli claims bypass of authorization" {
    const engine = AuthorityReview{};
    var observed: [CLAUSE_COUNT]AuthorityClause = undefined;
    for (AUTHORITY_CHECKLIST, 0..) |cl, k| observed[k] = cl;
    observed[findClause(.cli, .bypass_pep).?].allowed = true;
    const out = engine.review(&observed);
    try std.testing.expect(!out.authoritative);
}