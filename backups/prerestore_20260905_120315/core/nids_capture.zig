//! nids_capture.zig - AEGIS NIDS Named Pipe IPC Sensor (Thread 2)
//!
//! Creates a named pipe server (\\.\pipe\aegis_sensor_pipe) that
//! accepts connections from Python sensor scripts. Payloads received
//! via the pipe are forwarded to nids_analyze.inspect_packet()
//! for 3-tier threat analysis.

const std = @import("std");
const bridge_init = @import("bridge_init.zig");
const win = std.os.windows;
const nids_analyze = @import("nids_analyze.zig");

// Win32 FFI
extern "kernel32" fn CreateNamedPipeA(
    lpName: [*:0]const u8,
    dwOpenMode: u32,
    dwPipeMode: u32,
    nMaxInstances: u32,
    nOutBufferSize: u32,
    nInBufferSize: u32,
    nDefaultTimeOut: u32,
    lpSecurityAttributes: ?*anyopaque,
) win.HANDLE;

extern "kernel32" fn ConnectNamedPipe(hNamedPipe: win.HANDLE, lpOverlapped: ?*anyopaque) win.BOOL;
extern "kernel32" fn DisconnectNamedPipe(hNamedPipe: win.HANDLE) win.BOOL;
extern "kernel32" fn ReadFile(
    hFile: win.HANDLE,
    lpBuffer: [*]u8,
    nNumberOfBytesToRead: u32,
    lpNumberOfBytesRead: ?*u32,
    lpOverlapped: ?*anyopaque,
) win.BOOL;

// ====== BP19: Admin-Only Pipe ACL via SDDL ======
extern "advapi32" fn ConvertStringSecurityDescriptorToSecurityDescriptorA(
    StringSecurityDescriptor: [*:0]const u8,
    StringSDRevision: u32,
    SecurityDescriptor: *?*anyopaque,
    SecurityDescriptorSize: ?*u32,
) i32;

extern "kernel32" fn LocalFree(hMem: ?*anyopaque) ?*anyopaque;

const SDDL_ADMIN_ONLY = "D:(A;;GA;;;BA)";
const SDDL_REVISION: u32 = 1;

const AegisSecurityAttributes = extern struct {
    nLength: u32,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: i32,
};
const PIPE_ACCESS_DUPLEX = 0x00000003;
const PIPE_TYPE_MESSAGE = 0x00000004;
const PIPE_READMODE_MESSAGE = 0x00000002;
const PIPE_WAIT = 0x00000000;
const PIPE_UNLIMITED_INSTANCES = 255;

// BP-O2: Overlapped I/O for shutdown-responsive ConnectNamedPipe (Phase 8)
// Phase 9: Uses shared win32_io.zig module (was duplicated in 3 files)
const win32_io = @import("win32_io.zig");
const OVERLAPPED = win32_io.OVERLAPPED;
const FILE_FLAG_OVERLAPPED = win32_io.FILE_FLAG_OVERLAPPED;
const ERROR_IO_PENDING = win32_io.ERROR_IO_PENDING;
const WAIT_OBJECT_0 = win32_io.WAIT_OBJECT_0;
const WAIT_TIMEOUT = win32_io.WAIT_TIMEOUT;
const IO_POLL_TIMEOUT_MS = win32_io.IO_POLL_TIMEOUT_MS;
// Phase 28: Blueprint Nose Contract for event submission
const nose = @import("nose_contract.zig");
const nose_int = @import("nose_integration.zig");

/// Thread 2 entry point: Named Pipe IPC Sensor.
///
/// Creates a named pipe server (\\.\pipe\aegis_sensor_pipe) that accepts
/// connections from Python sensor scripts. Payloads received via the pipe
/// are forwarded to nids_analyze.inspect_packet() for 3-tier threat analysis.
///
/// Parameters `allocator` and `address` are currently unused (reserved for
/// future filtering/logging features).
///
/// Loops forever until bridge_init.g_shutdown is set by CTRL+C handler.
pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = allocator;
    _ = address;

    const pipe_name = "\\\\.\\pipe\\aegis_sensor_pipe";

    std.log.info("[PIPE SENSOR] Initializing Named Pipe Server", .{});
    std.debug.print("[PIPE SENSOR] Initializing Named Pipe Server...\n", .{});

    // BP19: Create admin-only security descriptor for pipe
    var pipe_sd: ?*anyopaque = null;
    var sec_attr = AegisSecurityAttributes{
        .nLength = @sizeOf(AegisSecurityAttributes),
        .lpSecurityDescriptor = null,
        .bInheritHandle = 0,
    };
    if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
        SDDL_ADMIN_ONLY,
        SDDL_REVISION,
        &pipe_sd,
        null,
    ) != 0) {
        sec_attr.lpSecurityDescriptor = pipe_sd;
        std.log.info("[PIPE SENSOR] Pipe ACL: Admin-only (SDDL)", .{});
        std.debug.print("[PIPE SENSOR] Pipe ACL: Admin-only (SDDL enforced)\n", .{});
    } else {
        // P-08 CRITICAL FIX: SDDL failure = fail-closed (was fail-open with NULL DACL)
        // NULL security descriptor uses default DACL which may allow non-admin connections
        std.log.err("[PIPE SENSOR] CRITICAL: SDDL conversion failed - REFUSING to create pipe (fail-closed)", .{});
        std.debug.print("\x1b[31m[PIPE SENSOR] CRITICAL: SDDL failed - refusing to create pipe (fail-closed)\x1b[0m\n", .{});
        return;
    }
    defer if (pipe_sd) |sd| {
        _ = LocalFree(sd);
    };
    // BP-O2: Add FILE_FLAG_OVERLAPPED for shutdown-responsive ConnectNamedPipe
    const handle = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096,
        4096,
        0,
        @ptrCast(&sec_attr),
    );

    if (handle == win.INVALID_HANDLE_VALUE) {
        std.log.err("[PIPE SENSOR] Failed to create Named Pipe", .{});
        std.debug.print("[-] IPC Error: Failed to create Named Pipe.\n", .{});
        return;
    }
    defer win.CloseHandle(handle);

    // BP-O2: Create event for overlapped ConnectNamedPipe
    // Phase 9: Uses win32_io.createIoEvent() helper
    const io_event = win32_io.createIoEvent() orelse {
        std.log.err("[PIPE SENSOR] CreateEventA failed - cannot use overlapped I/O", .{});
        return;
    };
    defer _ = win.CloseHandle(io_event);

    var buffer: [4096]u8 = undefined;

    std.log.info("[PIPE SENSOR] Listening on {s} - Waiting for scripts", .{pipe_name});
    std.debug.print("[PIPE SENSOR] Listening on {s} - Waiting for Python scripts...\n", .{pipe_name});

    while (true) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        // BP-O2: Overlapped ConnectNamedPipe with 1s timeout for shutdown responsiveness
        // Phase 9: Uses win32_io helper constants and functions
        var overlapped: OVERLAPPED = std.mem.zeroes(OVERLAPPED);
        overlapped.event = io_event;
        _ = win32_io.ResetEvent(io_event);
        const connect_rc = ConnectNamedPipe(handle, &overlapped);
        const err = win.kernel32.GetLastError();

        // Overlapped: connect_rc=0 + ERROR_IO_PENDING = pending (expected)
        // connect_rc!=0 = completed synchronously
        // err=PIPE_CONNECTED = client connected between Create and Connect
        const connected = (connect_rc != 0) or (err == win.Win32Error.PIPE_CONNECTED);
        if (!connected and @intFromEnum(err) == ERROR_IO_PENDING) {
            // Wait for client with 1s timeout via shared helper
            const wait_result = win32_io.waitOverlapped(handle, &overlapped, io_event, IO_POLL_TIMEOUT_MS);
            switch (wait_result) {
                .timeout => continue,
                .wait_error => {
                    std.log.warn("[PIPE SENSOR] WaitForSingleObject failed", .{});
                    std.time.sleep(100 * std.time.ns_per_ms);
                    continue;
                },
                .result_error => {
                    const io_err = win.kernel32.GetLastError();
                    if (io_err != win.Win32Error.PIPE_CONNECTED) {
                        std.log.warn("[PIPE SENSOR] GetOverlappedResult failed: {d}", .{io_err});
                        continue;
                    }
                },
                .completed, .completed_after_wait => {},
            }
        } else if (!connected) {
            std.log.warn("[PIPE SENSOR] ConnectNamedPipe failed: {d}", .{err});
            std.time.sleep(100 * std.time.ns_per_ms);
            continue;
        }

        // Connected — read data from client
        {
            var bytes_read: u32 = 0;
            const read_success = ReadFile(
                handle,
                &buffer,
                buffer.len,
                &bytes_read,
                null,
            ) != 0;

            if (read_success and bytes_read > 0) {
                const payload = buffer[0..bytes_read];
                std.log.info("[PIPE SENSOR] Captured Pipe Payload ({d} bytes)", .{bytes_read});
                std.debug.print("[PIPE SENSOR] Captured Pipe Payload ({d} bytes)\n", .{bytes_read});

                const ctx = nids_analyze.PacketContext{
                    .is_pipe = true,
                    .layer_id = 3,
                };

                // Phase 28 + STEP 4: Submit event to Event Fabric via pressure-aware submit
                {
                    var sensor_event = nose.createEvent(.pipe_sensor);
                    sensor_event.event_type = .forward;
                    sensor_event.payload_length = @intCast(payload.len);
                    sensor_event.layer_id = 3;
                    sensor_event.is_pipe = 1;
                    sensor_event.timestamp_ms = @intCast(std.time.milliTimestamp());
                    // STEP 4: use nose_integration.submit() for backpressure-aware sampling
                    const submit_result = nose_int.submit(sensor_event);
                    switch (submit_result) {
                        .accepted => {},
                        .dropped_at_source => {
                            std.log.debug("[PIPE SENSOR] Event dropped at source (pressure sampling)", .{});
                        },
                        .dropped_by_fabric, .rejected => {
                            std.log.warn("[PIPE SENSOR] Event Fabric submit failed: {s}", .{@tagName(submit_result)});
                        },
                        .not_initialized => {
                            std.log.warn("[PIPE SENSOR] Event Fabric not initialized", .{});
                        },
                    }
                }

                const is_safe = nids_analyze.inspect_packet(payload, ctx) catch |analyze_err| blk: {
                    std.log.warn("[PIPE SENSOR] Analyze error: {any} - fail-open", .{analyze_err});
                    std.debug.print("[PIPE SENSOR] Analyze error: {any} - event allowed (fail-open)\n", .{analyze_err});
                    _ = nids_analyze.g_analyze_errors.fetchAdd(1, .monotonic);
                    break :blk true;
                };
                if (!is_safe) {
                    std.log.warn("[BLOCK] Threat blocked at Named Pipe sensor", .{});
                    std.debug.print("\x1b[31;1m[PIPE SENSOR] Threat blocked at Named Pipe!\x1b[0m\n", .{});
                }
            }

            _ = DisconnectNamedPipe(handle);
        }
    }
}
