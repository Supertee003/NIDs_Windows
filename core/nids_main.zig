//! nids_main.zig - AEGIS NIDS Main Entry Point
//!
//! 5-Thread Architecture:
//!   T1: 3-Tier Analysis Engine (nids_analyze.zig)
//!   T2: Named Pipe IPC Sensor (nids_capture.zig)
//!   T3: WFP Kernel Traffic Sensor (windows_capture.zig)
//!   T4: Minifilter Event Reader (minifilter_reader.zig)
//!   T5: Named Pipe Scanner (pipe_monitor.zig)
//!
//! BP-FIX: Removed std.os.exit(0) from Ctrl+C handler (was skipping all defers),
//!         added bridge_init import, removed unused ANSI color constants,
//!         added bridge_init.initAll() call, use optional thread pattern.

const std = @import("std");
const bridge_init = @import("bridge_init.zig");
const nids_analyze = @import("nids_analyze.zig");
const windows_capture = @import("windows_capture.zig");
const nids_capture = @import("nids_capture.zig");
const minifilter_reader = @import("minifilter_reader.zig");
const pipe_monitor = @import("pipe_monitor.zig");
const forensic_log = @import("forensic_log.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // UX-12: Enable Virtual Terminal Processing for ANSI color codes on Windows
    // (Without this, \x1b[31;1m appears as literal text on Windows 10 <= 1809)
    enableVirtualTerminal();

    std.fs.cwd().makeDir("logs") catch |err| {
        if (err != error.PathAlreadyExists) {
            std.log.err("[MAIN] Failed to create logs dir: {}", .{err});
        }
    };

    // IR-01: Initialize persistent forensic logger (logs/aegis_core.ndjson)
    forensic_log.init();
    defer forensic_log.shutdown();

    // BP-I3: Use AEGIS_VERSION constant from bridge_init (was hardcoded "v2.1")
    std.log.info("[MAIN] AEGIS NIDS {s} - 5-Thread Architecture", .{bridge_init.AEGIS_VERSION});

    // Initialize all bridges (WFP, C++ IPC, Rust Shield, UDP Brain)
    bridge_init.initAll();
    defer bridge_init.shutdownAll();

    // T1: 3-Tier Analysis Engine (required - fail if can't spawn)
    const t_analyze = std.Thread.spawn(.{}, nids_analyze.analyze_packets, .{allocator}) catch |err| {
        std.log.err("[MAIN] T1 Analyze failed to spawn: {}", .{err});
        return err;
    };
    std.log.info("[MAIN] T1 Analyze spawned", .{});

    // Give analyzer time to initialize rules before other sensors connect
    std.time.sleep(500 * std.time.ns_per_ms);

    // T2: Named Pipe IPC Sensor (optional - sensor pipe for Python scripts)
    const t_pipe: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, nids_capture.capture_packets, .{ allocator, "127.0.0.1" }) catch |err| {
            std.log.warn("[MAIN] T2 Pipe Sensor failed: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };
    if (t_pipe != null) std.log.info("[MAIN] T2 Pipe Sensor spawned", .{});

    // T3: WFP Kernel Traffic Sensor (optional - requires kernel driver)
    const t_wfp: ?std.Thread = std.Thread.spawn(.{}, windows_capture.capture_packets, .{ allocator, "127.0.0.1" }) catch |err| {
        std.log.warn("[MAIN] T3 WFP Capture failed: {}", .{err});
        null;
    };
    if (t_wfp != null) std.log.info("[MAIN] T3 WFP Capture spawned", .{});

    // T4: Minifilter Event Reader (optional - requires kernel driver)
    const t_mini: ?std.Thread = std.Thread.spawn(.{}, minifilter_reader.minifilterReaderLoop, .{}) catch |err| {
        std.log.warn("[MAIN] T4 Minifilter failed: {}", .{err});
        null;
    };
    if (t_mini != null) std.log.info("[MAIN] T4 Minifilter spawned", .{});

    // T5: Named Pipe Scanner (optional)
    const t_pmon: ?std.Thread = std.Thread.spawn(.{}, pipe_monitor.pipeMonitorLoop, .{}) catch |err| {
        std.log.warn("[MAIN] T5 Pipe Monitor failed: {}", .{err});
        null;
    };
    if (t_pmon != null) std.log.info("[MAIN] T5 Pipe Monitor spawned", .{});

    // Report active thread count
    var active: u32 = 1; // T1 always running
    if (t_pipe != null) active += 1;
    if (t_wfp != null) active += 1;
    if (t_mini != null) active += 1;
    if (t_pmon != null) active += 1;
    std.log.info("[MAIN] {d}/5 threads active", .{active});

    // Wait for all threads to complete
    t_analyze.join();
    if (t_pipe) |t| t.join();
    if (t_wfp) |t| t.join();
    if (t_mini) |t| t.join();
    if (t_pmon) |t| t.join();

    std.log.info("[MAIN] Shutdown complete", .{});
}

// ============================================================
// UX-12: Enable Virtual Terminal Processing for ANSI color codes
// ============================================================

const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
const STD_OUTPUT_HANDLE: u32 = @bitCast(@as(i32, -11));
const STD_ERROR_HANDLE: u32 = @bitCast(@as(i32, -12));

extern "kernel32" fn GetStdHandle(nStdHandle: u32) ?*anyopaque;
extern "kernel32" fn GetConsoleMode(hConsoleHandle: ?*anyopaque, lpMode: *u32) i32;
extern "kernel32" fn SetConsoleMode(hConsoleHandle: ?*anyopaque, dwMode: u32) i32;

fn enableVirtualTerminal() void {
    // Enable VT processing on stdout
    const stdout = GetStdHandle(STD_OUTPUT_HANDLE) orelse return;
    var mode: u32 = 0;
    if (GetConsoleMode(stdout, &mode) == 0) return;
    _ = SetConsoleMode(stdout, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    // Enable VT processing on stderr (for std.log.warn/err)
    const stderr = GetStdHandle(STD_ERROR_HANDLE) orelse return;
    if (GetConsoleMode(stderr, &mode) == 0) return;
    _ = SetConsoleMode(stderr, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
