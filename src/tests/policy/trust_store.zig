// Aggregator test: runs unit tests from src/policy/trust_store.zig
const std = @import("std");

comptime {
    _ = @import("../../policy/trust_store.zig");
}

test "trust_store module imports cleanly" {
    try std.testing.expect(true);
}
