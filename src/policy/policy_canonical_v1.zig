//! Versioned canonical policy byte encoder (S4).
//!
//! Additive evidence/validation utility only. It does not change the legacy
//! compiler hash, policy_signing.canonicalDigest, or ADR-0005 exact-file
//! sidecar. See shared/policy/policy_canonical_v1.md.

const std = @import("std");

pub const Error = error{
    InvalidInput,
    TooManyRules,
    TooManyConditions,
    StringTooLong,
    InvalidOrdinal,
    OutOfMemory,
};

pub const MAX_STRING_BYTES = 256;
pub const MAX_RULES = 64;
pub const MAX_CONDITIONS = 4;

pub const ConditionV1 = struct {
    field: u8,
    operator: u8,
    value: u64,
    value2: u64,
};

pub const RuleV1 = struct {
    id: u32,
    name: []const u8,
    description: []const u8,
    priority: u8,
    action: u8,
    enabled: bool,
    conditions: []const ConditionV1,
};

pub const SignatureInputV1 = struct {
    ir_magic: u32,
    ir_version: u16,
    ir_hash: u64,
    policy_version: u32,
    expiry_ms: i64,
    rules: []const RuleV1,
};

fn writeString(writer: anytype, value: []const u8, field: []const u8) Error!void {
    _ = field;
    if (value.len > MAX_STRING_BYTES) return Error.StringTooLong;
    try writer.writeInt(u32, @intCast(value.len), .little);
    try writer.writeAll(value);
}

fn validateOrdinals(rule: RuleV1) Error!void {
    if (rule.priority > 0xff) return Error.InvalidOrdinal;
    if (rule.action > 5) return Error.InvalidOrdinal;
    if (rule.conditions.len > MAX_CONDITIONS) return Error.TooManyConditions;
    for (rule.conditions) |cond| {
        if (cond.field > 8) return Error.InvalidOrdinal;
        if (cond.operator > 5) return Error.InvalidOrdinal;
    }
}

/// Encode one representation-B rule into `PC01RULE` canonical bytes.
pub fn canonicalRuleBytesV1(allocator: std.mem.Allocator, rule: RuleV1) Error![]u8 {
    try validateOrdinals(rule);
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    const w = list.writer();
    try w.writeAll("PC01RULE");
    try w.writeInt(u16, 1, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, rule.id, .little);
    try w.writeByte(rule.priority);
    try w.writeByte(rule.action);
    try w.writeByte(if (rule.enabled) 1 else 0);
    try w.writeByte(@intCast(rule.conditions.len));
    try writeString(w, rule.name, "name");
    try writeString(w, rule.description, "description");
    for (rule.conditions) |cond| {
        try w.writeByte(cond.field);
        try w.writeByte(cond.operator);
        try w.writeInt(u64, cond.value, .little);
        try w.writeInt(u64, cond.value2, .little);
    }
    return try list.toOwnedSlice();
}

fn requireRules(rules: []const RuleV1) Error!void {
    if (rules.len < 1 or rules.len > MAX_RULES) return Error.TooManyRules;
}

/// Versioned rule-set digest pre-image (`PC01SETS`).
pub fn canonicalRuleSetBytesV1(allocator: std.mem.Allocator, rules: []const RuleV1) Error![]u8 {
    try requireRules(rules);
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    const w = list.writer();
    try w.writeAll("PC01SETS");
    try w.writeInt(u16, 1, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, @intCast(rules.len), .little);
    for (rules) |rule| {
        const bytes = try canonicalRuleBytesV1(allocator, rule);
        defer allocator.free(bytes);
        try w.writeAll(bytes);
    }
    return try list.toOwnedSlice();
}

pub fn policyRuleSetDigestV1(allocator: std.mem.Allocator, rules: []const RuleV1) Error![32]u8 {
    const preimage = try canonicalRuleSetBytesV1(allocator, rules);
    defer allocator.free(preimage);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(preimage, &digest, .{});
    return digest;
}

/// Versioned signed-policy digest pre-image (`PC01SIGN`).
pub fn canonicalSignatureBytesV1(
    allocator: std.mem.Allocator,
    input: SignatureInputV1,
) Error![]u8 {
    try requireRules(input.rules);
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();
    const w = list.writer();
    try w.writeAll("PC01SIGN");
    try w.writeInt(u16, 1, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, input.ir_magic, .little);
    try w.writeInt(u16, input.ir_version, .little);
    try w.writeInt(u16, @intCast(input.rules.len), .little);
    try w.writeInt(u64, input.ir_hash, .little);
    try w.writeInt(u32, input.policy_version, .little);
    try w.writeInt(i64, input.expiry_ms, .little);
    for (input.rules) |rule| {
        const bytes = try canonicalRuleBytesV1(allocator, rule);
        defer allocator.free(bytes);
        try w.writeAll(bytes);
    }
    return try list.toOwnedSlice();
}

pub fn canonicalSignatureDigestV1(
    allocator: std.mem.Allocator,
    input: SignatureInputV1,
) Error![32]u8 {
    const preimage = try canonicalSignatureBytesV1(allocator, input);
    defer allocator.free(preimage);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(preimage, &digest, .{});
    return digest;
}
