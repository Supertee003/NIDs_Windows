// Aggregator test: runs unit tests from src/forensic/policy_contract.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/policy_contract.zig");
}

test "policy_contract module imports cleanly" {
    try std.testing.expect(true);
}
