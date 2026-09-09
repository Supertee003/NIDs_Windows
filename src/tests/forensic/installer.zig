// Aggregator test: runs unit tests from src/forensic/installer.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/installer.zig");
}

test "installer module imports cleanly" {
    try std.testing.expect(true);
}
