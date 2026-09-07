// Aggregator test: runs unit tests from src/federation/cluster_coord.zig
const std = @import("std");

comptime {
    _ = @import("../../federation/cluster_coord.zig");
}

test "cluster_coord module imports cleanly" {
    try std.testing.expect(true);
}
