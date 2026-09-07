// Aggregator test: runs unit tests from src/windows/host_telemetry.zig
const std = @import("std");

comptime {
    _ = @import("../../windows/host_telemetry.zig");
}

test "host_telemetry module imports cleanly" {
    try std.testing.expect(true);
}
