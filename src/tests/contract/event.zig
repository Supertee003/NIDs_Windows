// Aggregator test: runs unit tests from src/contract/event.zig
const std = @import("std");

comptime {
    _ = @import("../../contract/event.zig");
}

test "event module imports cleanly" {
    try std.testing.expect(true);
}
