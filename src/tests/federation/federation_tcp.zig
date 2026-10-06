// Aggregator test: runs unit tests from src/federation/federation_tcp.zig
const std = @import("std");

comptime {
    _ = @import("../../federation/federation_tcp.zig");
}

test "federation_tcp module imports cleanly" {
    try std.testing.expect(true);
}
