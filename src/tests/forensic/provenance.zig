// Aggregator test: runs unit tests from src/forensic/provenance.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/provenance.zig");
}

test "provenance module imports cleanly" {
    try std.testing.expect(true);
}
