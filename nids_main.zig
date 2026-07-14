const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");
const windows_capture = @import("windows_capture.zig");
const nids_capture = @import("nids_capture.zig");
const minifilter_reader = @import("minifilter_reader.zig");
const pipe_monitor = @import("pipe_monitor.zig");

// =====================================================================
// nids_main.zig — AEGIS NIDS Core (5-Thread Hybrid Architecture)
// ---------------------------------------------------------------------
//   Thread 1: analyze_packets (TCP :12345 + Named Pipe aegis_nids)
//   Thread 2: capture_packets  (Sensor Pipe aegis_sensor_pipe — จาก Python)
//   Thread 3: windows_capture  (WFP device \\.\AegisWfpDevice — kernel)
//   Thread 4: minifilter_reader (AegisMinifilterPort — kernel)
//   Thread 5: pipe_monitor     (enumerate \\.\pipe\ — user-mode polling)
//
//   Threads 4 & 5 จะ retry ตลอด จนกว่า driver/service จะพร้อม
//   ทำให้สามารถ load driver ทีหลังได้โดยไม่ต้อง restart NIDS
// =====================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.fs.cwd().makeDir("logs") catch |err| {
        if (err != error.PathAlreadyExists) std.debug.print("Log dir status: {}\n", .{err});
    };

    std.debug.print("===========================================\n", .{});
    std.debug.print(" AEGIS NIDS Core [3-Layer Hybrid Architecture] Start\n", .{});
    std.debug.print("===========================================\n", .{});
    std.debug.print(" Threads:\n", .{});
    std.debug.print("   1. Analyze (TCP :12345 + Pipe aegis_nids)\n", .{});
    std.debug.print("   2. Sensor Pipe (aegis_sensor_pipe from Python)\n", .{});
    std.debug.print("   3. WFP Reader (\\\\.\\AegisWfpDevice)\n", .{});
    std.debug.print("   4. Minifilter Reader (\\\\AegisMinifilterPort)\n", .{});
    std.debug.print("   5. Pipe Monitor (enumerate \\\\.\\pipe\\)\n", .{});
    std.debug.print("===========================================\n", .{});

    // Thread 1: Analysis engine + TCP/pipe listeners
    const t_analyze = try std.Thread.spawn(.{}, nids_analyze.analyze_packets, .{allocator});
    std.time.sleep(500 * std.time.ns_per_ms); // รอให้ engine พร้อม

    // Thread 2: Sensor pipe (Python → Zig)
    const t_pipe_cap = try std.Thread.spawn(.{}, nids_capture.capture_packets, .{ allocator, "127.0.0.1" });

    // Thread 3: WFP device reader (kernel)
    const t_wfp_cap = try std.Thread.spawn(.{}, windows_capture.capture_packets, .{ allocator, "127.0.0.1" });

    // Thread 4: Minifilter reader (kernel) — จะ retry จนกว่า driver จะ load
    const t_minifilter = try std.Thread.spawn(.{}, minifilter_reader.run, .{allocator});

    // Thread 5: Pipe monitor (user-mode polling)
    const t_pipe_mon = try std.Thread.spawn(.{}, pipe_monitor.run, .{allocator});

    // รอ thread หลัก (analyze) — ไม่มีวัน return เพราะลูปไม่รู้จบ
    t_analyze.join();
    t_pipe_cap.join();
    t_wfp_cap.join();
    t_minifilter.join();
    t_pipe_mon.join();
}
