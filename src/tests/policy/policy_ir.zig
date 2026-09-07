// Aggregator test: runs unit tests from src/policy/policy_ir.zig
const std = @import("std");

comptime {
    _ = @import("../../policy/policy_ir.zig");
}

test "policy_ir module imports cleanly" {
    try std.testing.expect(true);
}
