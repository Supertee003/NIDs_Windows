// Aggregator test: runs unit tests from src/forensic/forensic_pipeline.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/forensic_pipeline.zig");
}

test "forensic_pipeline module imports cleanly" {
    try std.testing.expect(true);
}
