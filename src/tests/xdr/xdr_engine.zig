// Aggregator test: runs unit tests from src/xdr/xdr_engine.zig
const std = @import("std");

comptime {
    _ = @import("../../xdr/xdr_engine.zig");
}

test "xdr_engine module imports cleanly" {
    try std.testing.expect(true);
}
