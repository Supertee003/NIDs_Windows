// Fuzz entry shim: keeps the fuzz module rooted at src/ so
// fuzz_main.zig (under src/tests/) can reach sibling modules via ../.
const std = @import("std");

pub const main = @import("tests/fuzz_main.zig").main;