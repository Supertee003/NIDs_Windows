// Aggregator test: runs unit tests from src/federation/aggregator.zig
const std = @import("std");

comptime {
    _ = @import("../../federation/aggregator.zig");
}

test "aggregator module imports cleanly" {
    try std.testing.expect(true);
}
