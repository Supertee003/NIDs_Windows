// Aggregator test: runs unit tests from src/forensic/python_contract.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/python_contract.zig");
}

test "python_contract module imports cleanly" {
    try std.testing.expect(true);
}
