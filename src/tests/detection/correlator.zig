// Aggregator test: runs unit tests from src/detection/correlator.zig
const std = @import("std");

comptime {
    _ = @import("../../detection/correlator.zig");
}

test "correlator module imports cleanly" {
    try std.testing.expect(true);
}
