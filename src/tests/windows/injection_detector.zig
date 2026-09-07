// Aggregator test: runs unit tests from src/windows/injection_detector.zig
const std = @import("std");

comptime {
    _ = @import("../../windows/injection_detector.zig");
}

test "injection_detector module imports cleanly" {
    try std.testing.expect(true);
}
