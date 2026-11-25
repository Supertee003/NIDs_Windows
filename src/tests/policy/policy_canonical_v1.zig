//! S4 E2: Zig consumes the shared canonical policy byte vectors read-only.
//!
//! The vector stays in shared/vectors/ and is surfaced through build options,
//! the same pattern used by ts_ir_loader.zig (embedding across the src/ module
//! root is rejected by Zig). Tests never rewrite the vector file.

const std = @import("std");
const canon = @import("../../policy/policy_canonical_v1.zig");
const build_configs = @import("core_test_configs");

const Error = canon.Error;
const MAX_STRING_BYTES = canon.MAX_STRING_BYTES;
const ConditionV1 = canon.ConditionV1;
const RuleV1 = canon.RuleV1;
const canonicalRuleBytesV1 = canon.canonicalRuleBytesV1;
const policyRuleSetDigestV1 = canon.policyRuleSetDigestV1;
const canonicalSignatureDigestV1 = canon.canonicalSignatureDigestV1;

const vector_json = build_configs.policy_canonical_v1_vector_json;

fn expectHexEqual(actual: []const u8, expected_hex: []const u8) !void {
    try std.testing.expectEqual(actual.len * 2, expected_hex.len);
    for (actual, 0..) |byte, i| {
        const hi = std.fmt.charToDigit(expected_hex[i * 2], 16) catch return error.InvalidVector;
        const lo = std.fmt.charToDigit(expected_hex[i * 2 + 1], 16) catch return error.InvalidVector;
        try std.testing.expectEqual(byte, (hi << 4) | lo);
    }
}

fn expectDigestHex(actual: [32]u8, expected_hex: []const u8) !void {
    const rendered = std.fmt.bytesToHex(actual, .lower);
    try std.testing.expectEqualStrings(expected_hex, &rendered);
}

fn parseHexU64(text: []const u8) !u64 {
    try std.testing.expect(std.mem.startsWith(u8, text, "0x"));
    return std.fmt.parseInt(u64, text[2..], 16) catch return error.InvalidVector;
}

fn jsonInt(value: std.json.Value, field: []const u8) !i64 {
    _ = field;
    return switch (value) {
        .integer => |v| v,
        else => error.InvalidVector,
    };
}

fn parseRules(allocator: std.mem.Allocator, rules_value: std.json.Value) ![]RuleV1 {
    const items = switch (rules_value) {
        .array => |a| a.items,
        else => return error.InvalidVector,
    };
    const rules = try allocator.alloc(RuleV1, items.len);
    for (items, 0..) |item, i| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.InvalidVector,
        };
        const cond_items = switch (obj.get("conditions") orelse return error.InvalidVector) {
            .array => |a| a.items,
            else => return error.InvalidVector,
        };
        const conditions = try allocator.alloc(ConditionV1, cond_items.len);
        for (cond_items, 0..) |cond_item, ci| {
            const cond_obj = switch (cond_item) {
                .object => |o| o,
                else => return error.InvalidVector,
            };
            conditions[ci] = .{
                .field = @intCast(try jsonInt(cond_obj.get("field") orelse return error.InvalidVector, "field")),
                .operator = @intCast(try jsonInt(cond_obj.get("operator") orelse return error.InvalidVector, "operator")),
                .value = try parseHexU64(switch (cond_obj.get("value") orelse return error.InvalidVector) {
                    .string => |s| s,
                    else => return error.InvalidVector,
                }),
                .value2 = try parseHexU64(switch (cond_obj.get("value2") orelse return error.InvalidVector) {
                    .string => |s| s,
                    else => return error.InvalidVector,
                }),
            };
        }
        rules[i] = .{
            .id = @intCast(try jsonInt(obj.get("id") orelse return error.InvalidVector, "id")),
            .name = switch (obj.get("name") orelse return error.InvalidVector) {
                .string => |s| s,
                else => return error.InvalidVector,
            },
            .description = switch (obj.get("description") orelse return error.InvalidVector) {
                .string => |s| s,
                else => return error.InvalidVector,
            },
            .priority = @intCast(try jsonInt(obj.get("priority") orelse return error.InvalidVector, "priority")),
            .action = @intCast(try jsonInt(obj.get("action") orelse return error.InvalidVector, "action")),
            .enabled = switch (obj.get("enabled") orelse return error.InvalidVector) {
                .bool => |b| b,
                else => return error.InvalidVector,
            },
            .conditions = conditions,
        };
    }
    return rules;
}

test "Zig canonical policy bytes match the shared V1 vectors" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, vector_json, .{});
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidVector,
    };
    const cases = switch (root.get("cases") orelse return error.InvalidVector) {
        .array => |a| a.items,
        else => return error.InvalidVector,
    };
    try std.testing.expect(cases.len >= 4);

    for (cases) |case_value| {
        const case_obj = switch (case_value) {
            .object => |o| o,
            else => return error.InvalidVector,
        };
        const rules = try parseRules(allocator, case_obj.get("rules") orelse return error.InvalidVector);
        const expected_rules = switch (case_obj.get("expected_rule_bytes_hex") orelse return error.InvalidVector) {
            .array => |a| a.items,
            else => return error.InvalidVector,
        };
        try std.testing.expectEqual(rules.len, expected_rules.len);
        for (rules, 0..) |rule, i| {
            const bytes = try canonicalRuleBytesV1(allocator, rule);
            defer allocator.free(bytes);
            try expectHexEqual(
                bytes,
                switch (expected_rules[i]) {
                    .string => |s| s,
                    else => return error.InvalidVector,
                },
            );
        }

        const set_digest = try policyRuleSetDigestV1(allocator, rules);
        try expectDigestHex(
            set_digest,
            switch (case_obj.get("expected_rule_set_digest_hex") orelse return error.InvalidVector) {
                .string => |s| s,
                else => return error.InvalidVector,
            },
        );

        const signature_digest = try canonicalSignatureDigestV1(allocator, .{
            .ir_magic = @intCast(try jsonInt(case_obj.get("ir_magic") orelse return error.InvalidVector, "ir_magic")),
            .ir_version = @intCast(try jsonInt(case_obj.get("ir_version") orelse return error.InvalidVector, "ir_version")),
            .ir_hash = try parseHexU64(switch (case_obj.get("ir_hash") orelse return error.InvalidVector) {
                .string => |s| s,
                else => return error.InvalidVector,
            }),
            .policy_version = @intCast(try jsonInt(case_obj.get("policy_version") orelse return error.InvalidVector, "policy_version")),
            .expiry_ms = try jsonInt(case_obj.get("expiry_ms") orelse return error.InvalidVector, "expiry_ms"),
            .rules = rules,
        });
        try expectDigestHex(
            signature_digest,
            switch (case_obj.get("expected_signature_digest_hex") orelse return error.InvalidVector) {
                .string => |s| s,
                else => return error.InvalidVector,
            },
        );
    }
}

test "Zig V1 encoder rejects non-representable inputs" {
    const allocator = std.testing.allocator;
    const cond = [_]ConditionV1{};
    var long_name: [MAX_STRING_BYTES + 1]u8 = undefined;
    @memset(&long_name, 'x');
    const too_long = RuleV1{
        .id = 1,
        .name = &long_name,
        .description = "",
        .priority = 1,
        .action = 1,
        .enabled = true,
        .conditions = &cond,
    };
    const bad_action = RuleV1{
        .id = 1,
        .name = "r",
        .description = "",
        .priority = 1,
        .action = 6,
        .enabled = true,
        .conditions = &cond,
    };
    try std.testing.expectError(Error.StringTooLong, canonicalRuleBytesV1(allocator, too_long));
    try std.testing.expectError(Error.InvalidOrdinal, canonicalRuleBytesV1(allocator, bad_action));
}
