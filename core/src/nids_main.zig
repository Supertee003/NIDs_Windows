const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");
const windows_capture = @import("windows_capture.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.fs.cwd().makeDir("logs") catch |err| {
        if (err != error.PathAlreadyExists) std.debug.print("Log dir status: {}\n", .{err});
    };

    std.debug.print("===========================================\n", .{});
    std.debug.print(" Aegis NIDS Core [Hybrid Architecture] Start\n", .{});
    std.debug.print("===========================================\n", .{});

    // 1. Run analysis engine first
    const t_analyze = try std.Thread.spawn(.{}, nids_analyze.analyze_packets, .{allocator});
    std.time.sleep(500 * std.time.ns_per_ms); // wait for analyzer to be ready

    // 2. Run TCP capture sensor (nids_capture removed: broken pipe capture + ANSI escape codes on Windows)
    // H1: nids_capture used std.process.Child pipe capture - does not work for raw socket capture on Windows
    // H2: nids_capture contained ANSI escape codes - Windows console does not support without VTM
    // H3: Module was imported but all functionality was broken dead code
    const t_tcp_cap = try std.Thread.spawn(.{}, windows_capture.capture_packets, .{ allocator, "127.0.0.1" });

    // Main thread waits forever
    t_analyze.join();
    t_tcp_cap.join();
}
