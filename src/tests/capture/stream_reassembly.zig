// Aggregator test: runs unit tests from src/capture/stream_reassembly.zig
const std = @import("std");

comptime {
    _ = @import("../../capture/stream_reassembly.zig");
}

test "stream_reassembly module imports cleanly" {
    try std.testing.expect(true);
}
