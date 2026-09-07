// Aggregator test: runs unit tests from src/policy/action_dispatcher.zig
const std = @import("std");

comptime {
    _ = @import("../../policy/action_dispatcher.zig");
}

test "action_dispatcher module imports cleanly" {
    try std.testing.expect(true);
}
