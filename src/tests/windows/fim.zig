// Aggregator test: runs unit tests from src/windows/fim.zig
const std = @import("std");

comptime {
    _ = @import("../../windows/fim.zig");
}

test "fim module imports cleanly" {
    try std.testing.expect(true);
}
