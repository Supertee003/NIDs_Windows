// Aggregator test: runs unit tests from src/forensic/siem_forwarder.zig
const std = @import("std");

comptime {
    _ = @import("../../forensic/siem_forwarder.zig");
}

test "siem_forwarder module imports cleanly" {
    try std.testing.expect(true);
}
