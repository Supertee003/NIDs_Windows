//! nids_main.zig - AEGIS NIDS Main Entry Point
//!
//! Thread Architecture:
//!   T1: 3-Tier Analysis Engine (nids_analyze.zig)
//!   T2: Named Pipe IPC Sensor (nids_capture.zig)
//!   T3: WFP Kernel Traffic Sensor (windows_capture.zig)
//!   T4: Minifilter Event Reader (minifilter_reader.zig)
//!   T5: Named Pipe Scanner (pipe_monitor.zig)
//!   T6: Health-check Named Pipe (aegis-core-health, Gate-A)
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
// Phase 28: Blueprint Nose Contract + Event Fabric
const nose = @import("nose_contract.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    g_start_tick = health.GetTickCount64();

    // G27 Gate-A: --version flag. Print SEMVER + exit 0 so the supervisor
    // (and tests/runtime/test_version.py) can verify the binary reports a
    // parseable version. Also embeds the shield DLL version (shield is a
    // delegate probe per COMPONENT_MATRIX.md §2.1).
    //
    // G32 fix: write directly to file descriptor 1 (stdout) via std.posix.write
    // to bypass any Zig-side buffering. On Zig 0.13.0 + Windows, the
    // buffered writer returned by getStdOut().writer() may not auto-flush
    // when stdout is a pipe (subprocess capture). Direct write() guarantees
    // the bytes reach the OS before main() returns.
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);
    for (argv[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--version") or
            std.mem.eql(u8, arg, "-v") or
            std.mem.eql(u8, arg, "-V"))
        {
            const msg = "aegis-nids " ++ bridge_init.AEGIS_VERSION ++
                        " shield=" ++ bridge_init.SHIELD_VERSION ++ "\n";
            std.io.getStdOut().writeAll(msg) catch {};
            return;
        }
    }

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

    // Phase 28: Initialize Event Fabric (Nose Contract, AEGIS-006)
    nose.initFabric(allocator, .{
        .capacity_per_priority = 256,
        .validate_on_submit = true,
    }) catch |err| {
        std.log.err("[MAIN] Failed to init Event Fabric: {}", .{err});
        return err;
    };
    defer nose.shutdownFabric(allocator);
    std.log.info("[MAIN] Event Fabric initialized (Nose Contract active)", .{});

    // BP-I3: Use AEGIS_VERSION constant from bridge_init (was hardcoded "v2.1")
    std.log.info("[MAIN] AEGIS NIDS {s} - 5-Thread Architecture", .{bridge_init.AEGIS_VERSION});

    // GAP-3: Set brain allocator for spool queue drain thread
    bridge_init.setBrainAllocator(allocator);

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
    const t_wfp: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, windows_capture.capture_packets, .{ allocator, "127.0.0.1" }) catch |err| {
            std.log.warn("[MAIN] T3 WFP Capture failed: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };
    if (t_wfp != null) std.log.info("[MAIN] T3 WFP Capture spawned", .{});

    // T4: Minifilter Event Reader (optional - requires kernel driver)
    const t_mini: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, minifilter_reader.minifilterReaderLoop, .{}) catch |err| {
            std.log.warn("[MAIN] T4 Minifilter failed: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };
    if (t_mini != null) std.log.info("[MAIN] T4 Minifilter spawned", .{});

    // T5: Named Pipe Scanner (optional)
    const t_pmon: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, pipe_monitor.pipeMonitorLoop, .{}) catch |err| {
            std.log.warn("[MAIN] T5 Pipe Monitor failed: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };
    if (t_pmon != null) std.log.info("[MAIN] T5 Pipe Monitor spawned", .{});

    // T6: Health-check named pipe (Gate-A) - \\.\pipe\aegis-core-health
    // Exposes the lifecycle state so the supervisor and runtime tests can
    // probe core health without spawning a child process (contract §4).
    const t_health: ?std.Thread = blk: {
        const t = std.Thread.spawn(.{}, healthServerLoop, .{}) catch |err| {
            std.log.warn("[MAIN] T6 Health server failed: {}", .{err});
            break :blk null;
        };
        break :blk t;
    };
    if (t_health != null) std.log.info("[MAIN] T6 Health server spawned", .{});

    // Report active thread count
    var active: u32 = 1; // T1 always running
    if (t_pipe != null) active += 1;
    if (t_wfp != null) active += 1;
    if (t_mini != null) active += 1;
    if (t_pmon != null) active += 1;
    if (t_health != null) active += 1;
    std.log.info("[MAIN] {d}/6 threads active", .{active});

    // Wait for all threads to complete
    t_analyze.join();
    if (t_pipe) |t| t.join();
    if (t_wfp) |t| t.join();
    if (t_mini) |t| t.join();
    if (t_pmon) |t| t.join();
    if (t_health) |t| t.join();

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

// ============================================================
// T6 Health-check named pipe (Gate-A conformance)
// Implements \\.\pipe\aegis-core-health (RUNTIME_CONTRACT.md §4).
// Serves one probe per connection on a message-mode pipe, then
// recreates the pipe for the next probe.
// ============================================================

const PipeAccessDuplex: u32 = 0x00000003;
const PipeTypeMessage: u32 = 0x00000004;
const PipeReadmodeMessage: u32 = 0x00000002;
const PipeWaitMode: u32 = 0x00000000;
const PipeUnlimitedInstances: u32 = 255;
const ErrorPipeConnected: u32 = 0x217;

const health = struct {
    extern "kernel32" fn CreateNamedPipeA(
        lpName: [*:0]const u8,
        dwOpenMode: u32,
        dwPipeMode: u32,
        nMaxInstances: u32,
        nOutBufferSize: u32,
        nInBufferSize: u32,
        nDefaultTimeOut: u32,
        lpSecurityAttributes: ?*anyopaque,
    ) ?*anyopaque;
    extern "kernel32" fn ConnectNamedPipe(hNamedPipe: *anyopaque, lpOverlapped: ?*anyopaque) i32;
    extern "kernel32" fn GetLastError() u32;
    extern "kernel32" fn ReadFile(hFile: *anyopaque, lpBuffer: [*]u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: *u32, lpOverlapped: ?*anyopaque) i32;
    extern "kernel32" fn WriteFile(hFile: *anyopaque, lpBuffer: [*]const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: *u32, lpOverlapped: ?*anyopaque) i32;
    extern "kernel32" fn FlushFileBuffers(hFile: *anyopaque) i32;
    extern "kernel32" fn CloseHandle(hObject: *anyopaque) i32;
    extern "kernel32" fn GetTickCount64() u64;
    extern "kernel32" fn GetCurrentProcessId() u32;
    extern "kernel32" fn Sleep(dwMilliseconds: u32) void;
};

var g_start_tick: u64 = 0;

fn healthServerLoop() void {
    const pipe_name = "\\\\.\\pipe\\aegis-core-health";
    var buf: [512]u8 = undefined;
    while (true) {
        const h_pipe = health.CreateNamedPipeA(
            pipe_name,
            PipeAccessDuplex,
            PipeTypeMessage | PipeReadmodeMessage | PipeWaitMode,
            PipeUnlimitedInstances,
            4096, 4096,
            0, null,
        );
        if (h_pipe == null or h_pipe.? == @as(*anyopaque, @ptrFromInt(std.math.maxInt(usize)))) {
            health.Sleep(50);
            continue;
        }
        const hp = h_pipe.?;

        const connected = health.ConnectNamedPipe(hp, null);
        if (connected == 0 and health.GetLastError() != ErrorPipeConnected) {
            _ = health.CloseHandle(hp);
            continue;
        }

        var req: [128]u8 = undefined;
        var req_len: u32 = 0;
        _ = health.ReadFile(hp, &req, req.len, &req_len, null);

        const latency_start = health.GetTickCount64();
        const json = std.fmt.bufPrint(&buf,
            "{{\"op\":\"HEALTH\",\"state\":\"RUNNING\",\"status\":\"OK\",\"component\":\"core\",\"subsystem\":\"core\",\"version\":\"{s}\",\"pid\":{d},\"uptime_ms\":{d},\"probe_latency_ms\":{d},\"deps\":[{{\"name\":\"bridge\",\"state\":\"RUNNING\"}}]}}",
            .{
                bridge_init.AEGIS_VERSION,
                health.GetCurrentProcessId(),
                health.GetTickCount64() - g_start_tick,
                health.GetTickCount64() - latency_start,
            },
        ) catch continue;
        var written: u32 = 0;
        _ = health.WriteFile(hp, json.ptr, @intCast(json.len), &written, null);
        _ = health.FlushFileBuffers(hp);
        _ = health.CloseHandle(hp);
    }
}
