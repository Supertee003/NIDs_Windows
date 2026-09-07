// Aggregator test: runs unit tests from src/reliability/security_check.zig
const std = @import("std");

comptime {
    _ = @import("../../reliability/security_check.zig");
}

test "security_check module imports cleanly" {
    try std.testing.expect(true);
}
