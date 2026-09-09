// Aggregator test: runs unit tests from src/forensic/release_manifest.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/release_manifest.zig");
}

test "release_manifest module imports cleanly" {
    try std.testing.expect(true);
}
