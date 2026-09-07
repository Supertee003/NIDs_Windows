// Aggregator test: runs unit tests from src/detection/signature_engine.zig
const std = @import("std");

comptime {
    _ = @import("../../detection/signature_engine.zig");
}

test "signature_engine module imports cleanly" {
    try std.testing.expect(true);
}
