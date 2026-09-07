// Aggregator test: runs unit tests from src/detection/threat_tracker.zig
const std = @import("std");

comptime {
    _ = @import("../../detection/threat_tracker.zig");
}

test "threat_tracker module imports cleanly" {
    try std.testing.expect(true);
}
