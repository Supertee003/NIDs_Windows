//! T3-TSIR-025: the TS-authored golden IR loads byte-identical in Zig.
//!
//! The fixture (ts_policy/tests/fixtures/policy_ir_002.json) is produced by
//! the TypeScript compiler test and surfaced here through the
//! `core_test_configs` build option (same pattern as configs/test/*.json).
//! This keeps policy_plane.zig production-importable: the options import
//! lives in the test mirror, never in the loader module.

const std = @import("std");
const plane = @import("../../policy/policy_plane.zig");
const build_configs = @import("core_test_configs");

const fixture_json = build_configs.policy_ir_fixture_json;

test "TS golden fixture loads with exact rule identity" {
    var loaded = try plane.loadIrFromJson(std.testing.allocator, fixture_json);
    defer loaded.deinit();
    try std.testing.expect(loaded.ir.isValid());
    try std.testing.expectEqual(@as(u16, 2), loaded.ir.rule_count);

    const r1 = loaded.ir.rules[0];
    try std.testing.expectEqual(@as(u32, 101), r1.id);
    try std.testing.expectEqualStrings("block-tor-exit", r1.name);
    try std.testing.expectEqual(@as(u8, 200), r1.priority);
    try std.testing.expectEqual(plane.PolicyActionDef.block, r1.action);
    try std.testing.expect(r1.enabled);
    try std.testing.expectEqual(@as(u8, 2), r1.condition_count);
    try std.testing.expectEqual(plane.ConditionType.src_ip, r1.conditions[0].?.field);
    try std.testing.expectEqual(@as(u64, 0x0A000005), r1.conditions[0].?.value);
    try std.testing.expectEqual(plane.ConditionType.dst_port, r1.conditions[1].?.field);
    try std.testing.expectEqual(@as(u64, 443), r1.conditions[1].?.value);

    const r2 = loaded.ir.rules[1];
    try std.testing.expectEqual(@as(u32, 102), r2.id);
    try std.testing.expectEqualStrings("alert-dns-tunnel", r2.name);
    try std.testing.expectEqual(@as(u8, 50), r2.priority);
    try std.testing.expectEqual(plane.PolicyActionDef.alert, r2.action);
    try std.testing.expectEqual(@as(u8, 1), r2.condition_count);
    // String kinds hash (FNV-1a-64); pinned non-zero and stable.
    const h = r2.conditions[0].?.value;
    try std.testing.expect(h != 0);
    try std.testing.expect(h != 0x0A000005);

    // Exact audit identity from the TS side.
    try std.testing.expectEqualStrings(
        "d491b5d078fba52d10f07b33620720059953d8e38cb755e6159c0c5885fdf8dd",
        &loaded.hash_hex,
    );
    try std.testing.expectEqualStrings("ts_policy-1.0.0", loaded.ir.compiler_version);
    try std.testing.expectEqual(@as(i64, 1700000000000), loaded.ir.compiled_at_ms);
}
