//! REBUILD-003: executable root for the perf benchmark CLI tool.
//! The CLI lives in src/tests/cli/ (proof/tooling separation) but Zig roots
//! inside src/tests/ cannot import ../../core, so the executable is rooted
//! here at src/ where the whole tree is inside the module path.
pub const main = @import("tests/cli/perf_benchmark_cli.zig").main;
