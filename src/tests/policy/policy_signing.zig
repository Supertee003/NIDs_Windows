// Aggregator test: runs unit tests from src/policy/policy_signing.zig
const std = @import("std");

comptime {
    _ = @import("../../policy/policy_signing.zig");
}

test "policy_signing module imports cleanly" {
    try std.testing.expect(true);
}
