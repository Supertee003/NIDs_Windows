const std = @import("std");

// Operator, CLI, and legacy harness modules stay type-checked without
// executing their timing-sensitive or real-I/O tests in `zig build test`.
comptime {
    _ = @import("tests/cli_imports.zig");
    _ = @import("tests/core/core_modules.zig");
}

test "compile-only operator imports resolve" {
    try std.testing.expect(true);
}
