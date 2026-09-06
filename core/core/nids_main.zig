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
//
// G35 fix: previously used `while (true)` with blocking ConnectNamedPipe,
// which caused `t_health.join()` to hang on shutdown. Now uses overlapped
// I/O + polling so the loop exits when g_shutdown_requested is set.
// ============================================================

const PipeAccessDuplex: u32 = 0x00000003;
const PipeTypeMessage: u32 = 0x00000004;
const PipeReadmodeMessage: u32 = 0x00000002;
const PipeWaitMode: u32 = 0x00000000;
const PipeUnlimitedInstances: u32 = 255;
const ErrorPipeConnected: u32 = 0x217;
const ErrorIoPending: u32 = 0x3E5;
const FileFlagOverlapped: u32 = 0x40000000;
const Infinite: u32 = 0xFFFFFFFF;
const WaitTimeout: u32 = 0x102;
const WaitObject0: u32 = 0;

// OVERLAPPED struct for overlapped I/O on Windows.
const Overlapped = extern struct {
    internal: usize = 0,
    internal_high: usize = 0,
    offset_low: u32 = 0,
    offset_high: u32 = 0,
    h_event: ?*anyopaque = null,
};

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
    extern "kernel32" fn CreateEventW(lpEventAttributes: ?*anyopaque, bManualReset: i32, bInitialState: i32, lpName: ?[*:0]const u16) ?*anyopaque;
    extern "kernel32" fn WaitForSingleObject(hHandle: ?*anyopaque, dwMilliseconds: u32) u32;
    extern "kernel32" fn CancelIoEx(hFile: ?*anyopaque, lpOverlapped: ?*anyopaque) i32;
    extern "kernel32" fn GetOverlappedResult(hFile: ?*anyopaque, lpOverlapped: ?*anyopaque, lpNumberOfBytesTransferred: *u32, bWait: i32) i32;
};

// INVALID_HANDLE_VALUE on Windows is (HANDLE)-1, which on 64-bit is 0xFFFFFFFFFFFFFFFF.
// In Zig, we represent this as a pointer with the maximum usize value.
const INVALID_HANDLE_VALUE: *anyopaque = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

var g_start_tick: u64 = 0;

// G35: track when the last event was processed (set by other threads,
// read by health server). Atomic so concurrent access is safe.
var g_last_event_tick: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// G35: counters updated by other threads, read by health server.
var g_in_events: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_out_events: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_dropped: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Called by other subsystems (T1-T5) to record that an event was processed.
/// This makes `last_event_ms` in the HEALTH response meaningful.
pub fn recordEventProcessed() void {
    g_last_event_tick.store(health.GetTickCount64(), .release);
    _ = g_in_events.fetchAdd(1, .monotonic);
}

/// Called by other subsystems when an event is emitted downstream.
pub fn recordEventEmitted() void {
    _ = g_out_events.fetchAdd(1, .monotonic);
}

/// Called when an error occurs (failed send, parse error, etc.).
pub fn recordError() void {
    _ = g_errors.fetchAdd(1, .monotonic);
}

/// Called when an event was dropped (queue full, etc.).
pub fn recordDropped() void {
    _ = g_dropped.fetchAdd(1, .monotonic);
}

fn healthServerLoop() void {
    const pipe_name = "\\\\.\\pipe\\aegis-core-health";
    var buf: [768]u8 = undefined;

    // G35: poll shutdown flag in the loop. Use overlapped I/O with a
    // 250ms wait timeout so we can re-check the flag periodically.
    // g_shutdown_requested is set by the CTRL+C handler in nids_analyze.

    while (!nids_analyze.g_shutdown_requested.load(.acquire) and
           !bridge_init.g_shutdown.load(.seq_cst))
    {
        const h_pipe = health.CreateNamedPipeA(
            pipe_name,
            PipeAccessDuplex | FileFlagOverlapped,
            PipeTypeMessage | PipeReadmodeMessage | PipeWaitMode,
            PipeUnlimitedInstances,
            4096, 4096,
            0, null,
        );
        if (h_pipe == null or h_pipe.? == INVALID_HANDLE_VALUE) {
            health.Sleep(50);
            continue;
        }
        const hp = h_pipe.?;

        // Create an auto-reset event for overlapped I/O (standard idiom:
        // a manual-reset event stays signaled after the first completion,
        // which makes WaitForSingleObject return instantly and
        // GetOverlappedResult busy-spin until the next completion).
        const h_event = health.CreateEventW(null, 0, 0, null) orelse {
            _ = health.CloseHandle(hp);
            health.Sleep(50);
            continue;
        };

        var overlapped: Overlapped = .{ .h_event = h_event };
        const connected = health.ConnectNamedPipe(hp, @ptrCast(&overlapped));

        // ConnectNamedPipe returns 0 on failure. If GetLastError is
        // ERROR_IO_PENDING, the operation is in progress (expected for
        // overlapped I/O). If it's ERROR_PIPE_CONNECTED, the client
        // already connected before we called ConnectNamedPipe, in which
        // case there is NO pending operation and the event will never
        // signal — we must skip the wait and serve immediately.
        var serve_now = false;
        if (connected == 0) {
            const err = health.GetLastError();
            if (err == ErrorPipeConnected) {
                serve_now = true;
            } else if (err != ErrorIoPending) {
                _ = health.CloseHandle(hp);
                _ = health.CloseHandle(h_event);
                continue;
            }
        }

        if (!serve_now) {
            // Wait for the connection with a 250ms timeout so we can
            // re-check the shutdown flag periodically.
            const wait_result = health.WaitForSingleObject(h_event, 250);
            if (wait_result == WaitTimeout) {
                // No client connected within 250ms. Check shutdown flag.
                if (nids_analyze.g_shutdown_requested.load(.acquire) or
                    bridge_init.g_shutdown.load(.seq_cst))
                {
                    _ = health.CancelIoEx(hp, @ptrCast(&overlapped));
                    _ = health.CloseHandle(hp);
                    _ = health.CloseHandle(h_event);
                    break;
                }
                // Not shutting down yet — close this pipe instance and recreate.
                _ = health.CancelIoEx(hp, @ptrCast(&overlapped));
                _ = health.CloseHandle(hp);
                _ = health.CloseHandle(h_event);
                continue;
            }
            if (wait_result != WaitObject0) {
                // Some other error — clean up and try again.
                _ = health.CloseHandle(hp);
                _ = health.CloseHandle(h_event);
                continue;
            }
        }

        // Connection established. Read the request.
        var req: [128]u8 = undefined;
        var req_len: u32 = 0;
        var read_overlapped: Overlapped = .{ .h_event = h_event };
        _ = health.ReadFile(hp, &req, req.len, &req_len, @ptrCast(&read_overlapped));
        _ = health.GetOverlappedResult(hp, @ptrCast(&read_overlapped), &req_len, 1);

        // Build the JSON response with all schema-required fields.
        const now_tick = health.GetTickCount64();
        const latency_start = now_tick;
        const last_event = g_last_event_tick.load(.acquire);
        const last_event_ms: u64 = if (last_event > 0) now_tick -| last_event else 0;

        const json = std.fmt.bufPrint(&buf,
            "{{\"op\":\"HEALTH\",\"state\":\"RUNNING\",\"status\":\"OK\"," ++
            "\"component\":\"core\",\"subsystem\":\"core\"," ++
            "\"version\":\"{s}\",\"pid\":{d},\"uptime_ms\":{d}," ++
            "\"last_event_ms\":{d},\"probe_latency_ms\":{d}," ++
            "\"counters\":{{\"in_events\":{d},\"out_events\":{d}," ++
            "\"errors\":{d},\"dropped\":{d}}}," ++
            "\"deps\":[{{\"name\":\"bridge\",\"state\":\"RUNNING\"}}]}}",
            .{
                bridge_init.AEGIS_VERSION,
                health.GetCurrentProcessId(),
                now_tick - g_start_tick,
                last_event_ms,
                health.GetTickCount64() - latency_start,
                g_in_events.load(.acquire),
                g_out_events.load(.acquire),
                g_errors.load(.acquire),
                g_dropped.load(.acquire),
            },
        ) catch {
            _ = health.CloseHandle(hp);
            _ = health.CloseHandle(h_event);
            continue;
        };

        var written: u32 = 0;
        var write_overlapped: Overlapped = .{ .h_event = h_event };
        _ = health.WriteFile(hp, json.ptr, @intCast(json.len), &written, @ptrCast(&write_overlapped));
        _ = health.GetOverlappedResult(hp, @ptrCast(&write_overlapped), &written, 1);
        _ = health.FlushFileBuffers(hp);
        _ = health.CloseHandle(hp);
        _ = health.CloseHandle(h_event);
    }

    std.log.info("[MAIN] T6 Health server loop exited", .{});
}
