// Fuzz entry point â€” basic Aho-Corasick + decoder fuzzers
const std = @import("std");
const sig = @import("../detection/signature_engine.zig");
const decoder = @import("../capture/packet_decoder.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Build a small AC with a few patterns
    var ac = try sig.AhoCorasick.init(alloc, 10000);
    defer ac.deinit();
    try ac.addPattern(1, "evil");
    try ac.addPattern(2, "malware");
    try ac.addPattern(3, "exploit");
    try ac.build();

    // Generate random inputs and feed through
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const len = prng.random().uintLessThan(usize, 1024) + 1;
        const buf = try alloc.alloc(u8, len);
        defer alloc.free(buf);
        prng.random().bytes(buf);
        const matches = try ac.match(buf, alloc);
        defer alloc.free(matches);
        // Also feed to decoder
        _ = decoder.decode(buf);
    }
}
