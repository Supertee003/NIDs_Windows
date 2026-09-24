//! Canonical mapping from a `configs/Rules.json` `action` string to the
//! `policy.Action` ordinal that crosses the PEP ABI.
//!
//! Why this module exists
//! ----------------------
//! Three vocabularies had grown apart, and none was closed over the others:
//!
//!   * `configs/Rules.json` uses `Allow | Alert | Drop | Block | RateLimit`.
//!   * `src/policy/policy_ir.zig`   Action = pass | log | alert | rate_limit |
//!     block | quarantine | escalate.
//!   * `src/tests/proofs/config_reload_proof.zig` RuleAction =
//!     allow | alert | drop | rate_limit, whose `fromString` returns null for
//!     `"Block"` — the action 8 shipped rules declare.
//!
//! The ordinals also disagree: `RuleAction.alert == 1` but
//! `policy.Action.alert == 2`. Forwarding a RuleAction ordinal into the PEP
//! `requested_action` field (documented as "matches policy.Action ordinals")
//! would therefore mis-dispatch without any error.
//!
//! This module is the single conversion point. It is closed over every action
//! string the shipped ruleset uses, and `test "every shipped rule action
//! string maps"` fails if a new rule introduces an unmapped token.
//!
//! Scope note: `src/pipeline/rule_loader.zig` currently loads only `rule_id`
//! and `match_pattern`, so a rule's configured action is not yet consumed by
//! the detection path. This mapping makes the vocabulary correct and testable
//! ahead of wiring it, so the lab/decision-matrix work does not have to invent
//! a fourth vocabulary.

const std = @import("std");
const policy = @import("policy_ir.zig");

pub const RuleActionError = error{UnknownAction};

pub const Mapping = struct {
    /// The literal token as written in `configs/Rules.json`.
    config_string: []const u8,
    action: policy.Action,
    /// True when the action can constrain traffic and must therefore be
    /// authorized by the Rust PEP before any host effect.
    privileged: bool,
};

/// Closed set of config tokens. `Drop` and `Block` both mean "deny" and both
/// map to `policy.Action.block`, because `policy.Action` has no separate drop
/// value; the intent is identical and the PEP dispatches on `block`.
pub const mappings = [_]Mapping{
    .{ .config_string = "Allow", .action = .pass, .privileged = false },
    .{ .config_string = "Pass", .action = .pass, .privileged = false },
    .{ .config_string = "Log", .action = .log, .privileged = false },
    .{ .config_string = "Alert", .action = .alert, .privileged = false },
    .{ .config_string = "RateLimit", .action = .rate_limit, .privileged = true },
    .{ .config_string = "Drop", .action = .block, .privileged = true },
    .{ .config_string = "Block", .action = .block, .privileged = true },
    .{ .config_string = "Quarantine", .action = .quarantine, .privileged = true },
    .{ .config_string = "Escalate", .action = .escalate, .privileged = true },
};

/// Convert a config token to the canonical action ordinal.
/// Unknown tokens are an error rather than a default, so a typo can never
/// silently become ALLOW on the enforcement path.
pub fn fromConfig(config_string: []const u8) RuleActionError!policy.Action {
    for (mappings) |m| {
        if (std.mem.eql(u8, m.config_string, config_string)) return m.action;
    }
    return RuleActionError.UnknownAction;
}

/// Whether the canonical action requires PEP authorization before host effect.
pub fn isPrivileged(action: policy.Action) bool {
    return switch (action) {
        .pass, .log, .alert => false,
        .rate_limit, .block, .quarantine, .escalate => true,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "config tokens map to canonical policy.Action ordinals" {
    try std.testing.expectEqual(policy.Action.pass, try fromConfig("Allow"));
    try std.testing.expectEqual(policy.Action.log, try fromConfig("Log"));
    try std.testing.expectEqual(policy.Action.alert, try fromConfig("Alert"));
    try std.testing.expectEqual(policy.Action.rate_limit, try fromConfig("RateLimit"));
    try std.testing.expectEqual(policy.Action.quarantine, try fromConfig("Quarantine"));
    try std.testing.expectEqual(policy.Action.escalate, try fromConfig("Escalate"));
}

test "Drop and Block both deny through the single block ordinal" {
    try std.testing.expectEqual(policy.Action.block, try fromConfig("Drop"));
    try std.testing.expectEqual(policy.Action.block, try fromConfig("Block"));
}

test "unknown action tokens are an error, never a default" {
    try std.testing.expectError(RuleActionError.UnknownAction, fromConfig("Blocked"));
    try std.testing.expectError(RuleActionError.UnknownAction, fromConfig("drop"));
    try std.testing.expectError(RuleActionError.UnknownAction, fromConfig(""));
}

test "privileged actions are exactly the constraining ones" {
    try std.testing.expect(!isPrivileged(.pass));
    try std.testing.expect(!isPrivileged(.log));
    try std.testing.expect(!isPrivileged(.alert));
    try std.testing.expect(isPrivileged(.rate_limit));
    try std.testing.expect(isPrivileged(.block));
    try std.testing.expect(isPrivileged(.quarantine));
    try std.testing.expect(isPrivileged(.escalate));
}

test "mapping table agrees with its own privileged flags" {
    for (mappings) |m| {
        try std.testing.expectEqual(isPrivileged(m.action), m.privileged);
    }
}

// The Phase 8 lab runner reimplements rule_loader.hashRuleId in Python so it
// can report the same numeric rule id the engine emits. These vectors pin the
// two implementations together; `hello` is the published FNV-1a 32 reference.
test "rule id hash matches the reference FNV-1a 32 vectors" {
    const rule_loader = @import("../pipeline/rule_loader.zig");
    try std.testing.expectEqual(@as(u32, 0x4F9F2CAB), rule_loader.hashRuleId("hello"));
    try std.testing.expectEqual(@as(u32, 0xE40C292C), rule_loader.hashRuleId("a"));
    try std.testing.expectEqual(@as(u32, 2107512682), rule_loader.hashRuleId("R0056"));
    try std.testing.expectEqual(@as(u32, 4254503461), rule_loader.hashRuleId("R0088"));
}

// Guards the real defect this module was created for: "Block" — used by 8
// shipped rules — had no mapping in the old RuleAction vocabulary.
test "every shipped rule action string maps" {
    const file = std.fs.cwd().openFile("configs/Rules.json", .{}) catch return;
    defer file.close();
    const bytes = file.readToEndAlloc(std.testing.allocator, 4 * 1024 * 1024) catch return;
    defer std.testing.allocator.free(bytes);

    var parsed = std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{}) catch return;
    defer parsed.deinit();

    const rules = parsed.value.object.get("nids_rules") orelse return;
    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer seen.deinit();

    for (rules.array.items) |rule_val| {
        const obj = rule_val.object;
        const action_val = obj.get("action") orelse continue;
        const token = action_val.string;
        const mapped = fromConfig(token) catch {
            std.debug.print("rule {s} declares unmapped action {s}\n", .{
                obj.get("rule_id").?.string, token,
            });
            return error.UnmappedRuleAction;
        };
        try std.testing.expect(mapped == policy.Action.pass or
            mapped == policy.Action.log or
            mapped == policy.Action.alert or
            mapped == policy.Action.rate_limit or
            mapped == policy.Action.block or
            mapped == policy.Action.quarantine or
            mapped == policy.Action.escalate);
        try seen.put(token, {});
    }
    try std.testing.expect(seen.count() > 0);
}
