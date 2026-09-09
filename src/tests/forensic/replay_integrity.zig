// Aggregator test: runs unit tests from src/forensic/replay_integrity.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/replay_integrity.zig");
}

test "replay_integrity module imports cleanly" {
    try std.testing.expect(true);
}
