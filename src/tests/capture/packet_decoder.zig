// Aggregator test: runs unit tests from src/capture/packet_decoder.zig
const std = @import("std");

comptime {
    _ = @import("../../capture/packet_decoder.zig");
}

test "packet_decoder module imports cleanly" {
    try std.testing.expect(true);
}
