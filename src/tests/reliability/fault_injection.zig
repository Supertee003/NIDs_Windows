// Aggregator test: runs unit tests from src/reliability/fault_injection.zig
const std = @import("std");

comptime {
    _ = @import("../../reliability/fault_injection.zig");
}

test "fault_injection module imports cleanly" {
    try std.testing.expect(true);
}
