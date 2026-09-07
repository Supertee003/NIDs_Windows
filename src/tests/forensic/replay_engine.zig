// Aggregator test: runs unit tests from src/forensic/replay_engine.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/replay_engine.zig");
}

test "replay_engine module imports cleanly" {
    try std.testing.expect(true);
}
