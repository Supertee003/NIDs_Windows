// Aggregator test: runs unit tests from src/federation/node_registry.zig
const std = @import("std");

comptime {
    _ = @import("../../federation/node_registry.zig");
}

test "node_registry module imports cleanly" {
    try std.testing.expect(true);
}
