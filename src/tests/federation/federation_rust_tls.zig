// Aggregator test: runs unit tests from src/federation/federation_rust_tls.zig
const std = @import("std");

comptime {
    _ = @import("../../federation/federation_rust_tls.zig");
}

test "federation_rust_tls module imports cleanly" {
    try std.testing.expect(true);
}
