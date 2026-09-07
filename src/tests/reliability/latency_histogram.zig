// Aggregator test: runs unit tests from src/reliability/latency_histogram.zig
const std = @import("std");

comptime {
    _ = @import("../../reliability/latency_histogram.zig");
}

test "latency_histogram module imports cleanly" {
    try std.testing.expect(true);
}
