// Aggregator test: runs unit tests from src/forensic/release_gate.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/release_gate.zig");
}

test "release_gate module imports cleanly" {
    try std.testing.expect(true);
}
