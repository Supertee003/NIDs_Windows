// Aggregator test: runs unit tests from src/capture/flow_table.zig
const std = @import("std");

comptime {
    _ = @import("../../capture/flow_table.zig");
}

test "flow_table module imports cleanly" {
    try std.testing.expect(true);
}
