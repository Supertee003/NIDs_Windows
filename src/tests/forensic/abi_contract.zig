// Aggregator test: runs unit tests from src/forensic/abi_contract.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/abi_contract.zig");
}

test "abi_contract module imports cleanly" {
    try std.testing.expect(true);
}
