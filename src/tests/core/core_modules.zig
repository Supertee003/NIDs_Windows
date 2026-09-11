// REBUILD-002: Core (reconstruction area) proof/test modules
// These files were orphaned by the src/ migration — none had a build root,
// so none of their tests ever ran. Importing them here puts every test block
// in src/core back into the compiled test graph. Zero production behavior change.
comptime {
    _ = @import("bisect_a.zig");
    _ = @import("bisect_b.zig");
    _ = @import("core_configs.zig");
    _ = @import("../cli_imports.zig");
}

test "core_modules: all orphaned src/core modules compile" {
    // Reaching this test body means every import above resolved.
    try std.testing.expect(true);
}

const std = @import("std");
