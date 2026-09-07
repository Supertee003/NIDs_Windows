// Aggregator test: runs unit tests from src/windows/registry_monitor.zig
const std = @import("std");

comptime {
    _ = @import("../../windows/registry_monitor.zig");
}

test "registry_monitor module imports cleanly" {
    try std.testing.expect(true);
}
