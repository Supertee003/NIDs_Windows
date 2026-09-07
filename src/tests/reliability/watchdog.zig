// Aggregator test: runs unit tests from src/reliability/watchdog.zig
const std = @import("std");

comptime {
    _ = @import("../../reliability/watchdog.zig");
}

test "watchdog module imports cleanly" {
    try std.testing.expect(true);
}
