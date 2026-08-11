//! nids_main.zig — AEGIS NIDS Main Entry Point (Layer 2: Zig)
//!
//! Initializes all subsystems and starts the capture/analysis loop.
//! This is the native entry point; Python orchestration calls this
//! via the ctypes bridge.

const std = @import("std");
const capture = @import("nids_capture.zig");
const analyze = @import("nids_analyze.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("AEGIS NIDS Core starting...", .{});

    // ── Default intrusion detection patterns ──
    const patterns = [_][]const u8{
        // Web attack signatures
        "UNION SELECT",
        "' OR 1=1--",
        "<script>",
        "../etc/passwd",
        "cmd.exe",

        // Shellcode markers
        "\xFF\xD8\xFF",      // JPEG magic (steganography carrier)
        "\x4D\x5A",          // PE executable (MZ header)

        // C2 patterns
        "POST /gate",
        "GET /beacon",
        "Content-Type: application/octet-stream",
    };

    // ── Initialize subsystems ──
    try capture.init(allocator, &patterns);
    try analyze.init(allocator);

    std.log.info("AEGIS NIDS Core initialized — {} patterns loaded", .{patterns.len});

    // ── Start capture loop ──
    try capture.run();

    // ── Cleanup ──
    analyze.deinit();
    capture.deinit();

    std.log.info("AEGIS NIDS Core stopped", .{});
}
