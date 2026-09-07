// Aggregator test: runs unit tests from src/windows/etw_realtime.zig
const std = @import("std");

comptime {
    _ = @import("../../windows/etw_realtime.zig");
}

test "etw_realtime module imports cleanly" {
    try std.testing.expect(true);
}
