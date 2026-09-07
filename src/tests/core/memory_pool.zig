// Aggregator test: runs unit tests from src/core/memory_pool.zig
const std = @import("std");

comptime {
    _ = @import("../../core/memory_pool.zig");
}

test "memory_pool module imports cleanly" {
    try std.testing.expect(true);
}
