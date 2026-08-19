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

    // Box-drawing banner (64-char wide, ANSI colored)
    // NOTE: UTF-8 code page is set by run_aegis.bat (chcp 65001) before launch
    const CYN = "\x1b[96m";
    const GRN = "\x1b[92m";
    const BLD = "\x1b[1m";
    const DIM = "\x1b[2m";
    const RST = "\x1b[0m";

    std.debug.print("\n", .{});
    std.debug.print(CYN ++ "╔════════════════════════════════════════════════════════════╗" ++ RST ++ "\n", .{});
    std.debug.print(CYN ++ "║" ++ RST ++ " " ++ BLD ++ "AEGIS NIDS — Core Engine (Zig)" ++ RST ++ " " ++ DIM ++ "v2.0" ++ RST ++ "                " ++ CYN ++ "║" ++ RST ++ "\n", .{});
    std.debug.print(CYN ++ "║" ++ RST ++ " " ++ DIM ++ "Tier-1 Pattern Match + Packet Capture + Pipe Monitor" ++ RST ++ " " ++ CYN ++ "║" ++ RST ++ "\n", .{});
    std.debug.print(CYN ++ "╠════════════════════════════════════════════════════════════╣" ++ RST ++ "\n", .{});
    std.debug.print(CYN ++ "║" ++ RST ++ " " ++ GRN ++ "WFP Capture" ++ RST ++ " │ " ++ GRN ++ "TCP Listener" ++ RST ++ " │ " ++ GRN ++ "Named Pipe IPC" ++ RST ++ "   " ++ CYN ++ "║" ++ RST ++ "\n", .{});
    std.debug.print(CYN ++ "╚════════════════════════════════════════════════════════════╝" ++ RST ++ "\n", .{});
    std.debug.print("\n", .{});

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
