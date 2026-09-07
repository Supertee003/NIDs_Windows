// Aggregator test: runs unit tests from src/policy/pep_bindings.zig
const std = @import("std");

comptime {
    _ = @import("../../policy/pep_bindings.zig");
}

test "pep_bindings module imports cleanly" {
    try std.testing.expect(true);
}
