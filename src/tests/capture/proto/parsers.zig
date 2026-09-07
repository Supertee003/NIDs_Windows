// Aggregator test: runs unit tests from src/capture/proto/parsers.zig
const std = @import("std");

comptime {
    _ = @import("../../capture/proto/parsers.zig");
}

test "parsers module imports cleanly" {
    try std.testing.expect(true);
}
