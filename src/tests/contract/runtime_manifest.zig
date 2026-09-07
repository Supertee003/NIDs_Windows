// Aggregator test: runs unit tests from src/contract/runtime_manifest.zig
const std = @import("std");

comptime {
    _ = @import("../../contract/runtime_manifest.zig");
}

test "runtime_manifest module imports cleanly" {
    try std.testing.expect(true);
}
