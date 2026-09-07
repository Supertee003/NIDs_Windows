// Aggregator test: runs unit tests from src/core/diagnostics.zig
const std = @import("std");

comptime {
    _ = @import("../../core/diagnostics.zig");
}

test "diagnostics module imports cleanly" {
    try std.testing.expect(true);
}
