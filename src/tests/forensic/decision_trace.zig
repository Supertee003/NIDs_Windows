// Aggregator test: runs unit tests from src/forensic/decision_trace.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/decision_trace.zig");
}

test "decision_trace module imports cleanly" {
    try std.testing.expect(true);
}
