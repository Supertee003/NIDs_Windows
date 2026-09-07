// Aggregator test: runs unit tests from src/detection/anomaly_detector.zig
const std = @import("std");

comptime {
    _ = @import("../../detection/anomaly_detector.zig");
}

test "anomaly_detector module imports cleanly" {
    try std.testing.expect(true);
}
