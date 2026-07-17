const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");
const windows_capture = @import("windows_capture.zig");
const nids_capture = @import("nids_capture.zig");

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

    // 1. รันสมองกลก่อน
    const t_analyze = try std.Thread.spawn(.{}, nids_analyze.analyze_packets, .{allocator});
    std.time.sleep(500 * std.time.ns_per_ms); // รอให้สมองพร้อม

    // 2. รันเซ็นเซอร์ตากับหู พร้อมส่ง IP ให้ทำงานสัมพันธ์กัน
    const t_pipe_cap = try std.Thread.spawn(.{}, nids_capture.capture_packets, .{ allocator, "127.0.0.1" });
    const t_tcp_cap = try std.Thread.spawn(.{}, windows_capture.capture_packets, .{ allocator, "127.0.0.1" });

    // ให้ Main Thread รอไปตลอดกาล
    t_analyze.join();
    t_pipe_cap.join();
    t_tcp_cap.join();
}
