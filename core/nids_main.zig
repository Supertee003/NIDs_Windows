//! nids_main.zig - AEGIS NIDS Main Entry Point
//!
const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");
const windows_capture = @import("windows_capture.zig");
const nids_capture = @import("nids_capture.zig");
const minifilter_reader = @import("minifilter_reader.zig");
const pipe_monitor = @import("pipe_monitor.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.fs.cwd().makeDir("logs") catch |err| {
        if (err != error.PathAlreadyExists) std.debug.print("Log dir: {}\n", .{err});
    };

    const CYN = "\x1b[96m";
    const GRN = "\x1b[92m";
    const RST = "\x1b[0m";
    const BLD = "\x1b[1m";

    std.debug.print("\n", .{});
    std.debug.print(CYN ++ "\xe2\x95\x94" ++ RST, .{});  // top-left corner
    std.debug.print("\n", .{});

    std.debug.print("\n" ++ CYN ++ BLD ++ "  AEGIS NIDS v2.1 - 5-Thread Architecture" ++ RST ++ "\n", .{});
    std.debug.print("  " ++ GRN ++ "T1 Analyze" ++ RST ++ " | " ++ GRN ++ "T2 Pipe" ++ RST ++ " | " ++ GRN ++ "T3 WFP" ++ RST ++ " | " ++ GRN ++ "T4 Mini" ++ RST ++ " | " ++ GRN ++ "T5 PipeMon" ++ RST ++ "\n", .{});
    std.debug.print("\n", .{});

    // ==============================================================
    // Bridge initialization (BP2: now actually wired in)
    // ==============================================================
    
// BP8: Ctrl-C handler for graceful shutdown
extern "kernel32" fn SetConsoleCtrlHandler(
    handler: ?*const fn (u32) callconv(.C) bool,
    add: bool,
) bool;

fn aegisCtrlHandler(dwCtrlType: u32) callconv(.C) bool {
    _ = dwCtrlType;
    std.debug.print("\n\x1b[33m[SHUTDOWN] Ctrl-C received, exiting...\x1b[0m\n", .{});
    std.os.exit(0);
}

    
    _ = SetConsoleCtrlHandler(aegisCtrlHandler, true);
    defer bridge_init.shutdownAll();

    // ==============================================================
    // Spawn threads (BP3: graceful error handling)
    // ==============================================================
    std.debug.print("[AEGIS] Spawning threads...\n", .{});

    // T1: 3-Tier Analysis Engine (always required)
    const t_analyze = std.Thread.spawn(.{}, nids_analyze.analyze_packets, .{allocator}) catch |err| {
        std.debug.print("\x1b[33m[WARN] T1 Analyze failed: {}\x1b[0m\n", .{err});
        null;
    };
    if (t_analyze != null) {
        std.debug.print("  [OK] T1 Analyze\n", .{});
        std.time.sleep(500 * std.time.ns_per_ms);
    }

    // T2: Named Pipe IPC Sensor
    const t_pipe = std.Thread.spawn(.{}, nids_capture.capture_packets, .{ allocator, "127.0.0.1" }) catch |err| {
        std.debug.print("\x1b[33m[WARN] T2 Pipe Sensor failed: {}\x1b[0m\n", .{err});
        null;
    };
    if (t_pipe != null) std.debug.print("  [OK] T2 Pipe Sensor\n", .{});

    // T3: WFP Kernel Traffic Sensor
    const t_wfp = std.Thread.spawn(.{}, windows_capture.capture_packets, .{ allocator, "127.0.0.1" }) catch |err| {
        std.debug.print("\x1b[33m[WARN] T3 WFP Capture failed: {}\x1b[0m\n", .{err});
        null;
    };
    if (t_wfp != null) std.debug.print("  [OK] T3 WFP Capture\n", .{});

    // T4: Minifilter Event Reader + R2002
    const t_mini = std.Thread.spawn(.{}, minifilter_reader.minifilterReaderLoop, .{}) catch |err| {
        std.debug.print("\x1b[33m[WARN] T4 Minifilter failed: {}\x1b[0m\n", .{err});
        null;
    };
    if (t_mini != null) std.debug.print("  [OK] T4 Minifilter + R2002\n", .{});

    // T5: Named Pipe Scanner
    const t_pmon = std.Thread.spawn(.{}, pipe_monitor.pipeMonitorLoop, .{}) catch |err| {
        std.debug.print("\x1b[33m[WARN] T5 Pipe Monitor failed: {}\x1b[0m\n", .{err});
        null;
    };
    if (t_pmon != null) std.debug.print("  [OK] T5 Pipe Monitor\n", .{});

    // Count active threads
    var active: u32 = 0;
    if (t_analyze != null) active += 1;
    if (t_pipe != null) active += 1;
    if (t_wfp != null) active += 1;
    if (t_mini != null) active += 1;
    if (t_pmon != null) active += 1;

    std.debug.print("\n\x1b[32m[AEGIS] {d}/5 threads active\x1b[0m\n", .{active});

    if (active == 0) {
        std.debug.print("\x1b[31m[FATAL] No threads spawned! Exiting.\x1b[0m\n", .{});
        return;
    }

    // ==============================================================
    // Main thread: join all spawned threads
    // ==============================================================
    if (t_analyze) |t| t.join();
    if (t_pipe) |t| t.join();
    if (t_wfp) |t| t.join();
    if (t_mini) |t| t.join();
    if (t_pmon) |t| t.join();
}