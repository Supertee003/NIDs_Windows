// Aggregator test: runs unit tests from src/forensic/replay_verifier.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/replay_verifier.zig");
}

test "replay_verifier module imports cleanly" {
    try std.testing.expect(true);
}
