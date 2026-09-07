// Aggregator test: runs unit tests from src/detection/proto_anomaly.zig
const std = @import("std");

comptime {
    _ = @import("../../detection/proto_anomaly.zig");
}

test "proto_anomaly module imports cleanly" {
    try std.testing.expect(true);
}
