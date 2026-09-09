// Aggregator test: runs unit tests from src/forensic/integration_contract.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/integration_contract.zig");
}

test "integration_contract module imports cleanly" {
    try std.testing.expect(true);
}
