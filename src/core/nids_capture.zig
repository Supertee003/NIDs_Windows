//! nids_capture.zig - AEGIS NIDS Named Pipe IPC Sensor (Thread 2)
//!
//! Creates a named pipe server (\\.\pipe\aegis_sensor_pipe) that
//! accepts connections from Python sensor scripts. Payloads received
//! via the pipe are submitted to the daemon-owned canonical event queue.
//! Detection, policy, and forensic processing are performed by the pipeline
//! worker; this adapter must not call the legacy nids_analyze entrypoint.

const std = @import("std");
const bridge_init = @import("bridge_init.zig");
const win = std.os.windows;
const runtime_state = @import("../pipeline/runtime_state.zig");
const event = @import("../contract/event.zig");
const event_queue = @import("../pipeline/event_queue.zig");

// One identity is minted at the acquisition boundary. Wall-clock time alone
// is not unique when multiple clients send within the same millisecond.
var g_pipe_event_id: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

fn parseIpv4(text: []const u8) ?u32 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var value: u32 = 0;
    var count: u8 = 0;
    while (parts.next()) |part| {
        if (count >= 4 or part.len == 0) return null;
        const octet = std.fmt.parseInt(u8, part, 10) catch return null;
        value = (value << 8) | octet;
        count += 1;
    }
    return if (count == 4) value else null;
}

fn applyJsonMetadata(ev: *event.IpcEvent, payload: []const u8) void {
    var parsed = std.json.parseFromSlice(std.json.Value, std.heap.page_allocator, payload, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const obj = parsed.value.object;

    if (obj.get("src_ip")) |v| if (v == .string) {
        if (parseIpv4(v.string)) |ip| ev.src_ip = ip;
    };
    if (obj.get("dst_ip")) |v| if (v == .string) {
        if (parseIpv4(v.string)) |ip| ev.dst_ip = ip;
    };
    if (obj.get("src_port")) |v| {
        if (v == .integer and v.integer >= 0) {
            ev.src_port = @intCast(@min(v.integer, 65535));
        }
    }
    if (obj.get("dst_port")) |v| {
        if (v == .integer and v.integer >= 0) {
            ev.dst_port = @intCast(@min(v.integer, 65535));
        }
    }
    if (obj.get("protocol")) |v| if (v == .string) {
        ev.protocol = if (std.ascii.eqlIgnoreCase(v.string, "TCP")) 6 else if (std.ascii.eqlIgnoreCase(v.string, "UDP")) 17 else if (std.ascii.eqlIgnoreCase(v.string, "ICMP")) 1 else 0;
    };
    if (obj.get("severity")) |v| if (v == .string) {
        ev.severity = if (std.ascii.eqlIgnoreCase(v.string, "Critical")) .critical else if (std.ascii.eqlIgnoreCase(v.string, "High")) .alert else if (std.ascii.eqlIgnoreCase(v.string, "Medium")) .warning else .info;
    };
}

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

const SDDL_ADMIN_ONLY = "D:(A;;GA;;;BA)(A;;GA;;;AU)";
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
const win32_io = @import("../windows/win32_io.zig");
const OVERLAPPED = win32_io.OVERLAPPED;
const FILE_FLAG_OVERLAPPED = win32_io.FILE_FLAG_OVERLAPPED;
const ERROR_IO_PENDING = win32_io.ERROR_IO_PENDING;
const WAIT_OBJECT_0 = win32_io.WAIT_OBJECT_0;
const WAIT_TIMEOUT = win32_io.WAIT_TIMEOUT;
const IO_POLL_TIMEOUT_MS = win32_io.IO_POLL_TIMEOUT_MS;
/// Thread 2 entry point: Named Pipe IPC Sensor.
///
/// Creates a named pipe server (\\.\pipe\aegis_sensor_pipe) that accepts
/// connections from Python sensor scripts. Payloads received via the pipe
/// are submitted to the canonical event queue for daemon-owned processing.
///
/// Parameters `allocator` and `address` are currently unused (reserved for
/// future filtering/logging features).
///
/// Loops forever until bridge_init.g_shutdown is set by CTRL+C handler.
pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = allocator;
    _ = address;

    const pipe_name = "\\\\.\\pipe\\aegis_sensor_pipe_t1";

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
        runtime_state.markWorkerFailure(.sensor);
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
        runtime_state.markWorkerFailure(.sensor);
        return;
    }
    defer win.CloseHandle(handle);
    runtime_state.g_sensor_ready.store(true, .release);
    defer runtime_state.g_sensor_ready.store(false, .release);

    // BP-O2: Create event for overlapped ConnectNamedPipe
    // Phase 9: Uses win32_io.createIoEvent() helper
    const io_event = win32_io.createIoEvent() orelse {
        std.log.err("[PIPE SENSOR] CreateEventA failed - cannot use overlapped I/O", .{});
        runtime_state.markWorkerFailure(.sensor);
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

        // Connected — read data using the same overlapped I/O contract as
        // CreateNamedPipe. Passing a null OVERLAPPED to ReadFile on a handle
        // created with FILE_FLAG_OVERLAPPED is not a valid synchronous read
        // path and can leave the payload unconsumed even though the client
        // successfully connected.
        {
            var bytes_read: u32 = 0;
            var read_overlapped: OVERLAPPED = std.mem.zeroes(OVERLAPPED);
            read_overlapped.event = io_event;
            _ = win32_io.ResetEvent(io_event);
            const read_success = ReadFile(
                handle,
                &buffer,
                buffer.len,
                &bytes_read,
                &read_overlapped,
            ) != 0;

            var read_completed = read_success;
            if (!read_success and @intFromEnum(win.kernel32.GetLastError()) == ERROR_IO_PENDING) {
                const read_wait = win32_io.waitOverlapped(handle, &read_overlapped, io_event, IO_POLL_TIMEOUT_MS);
                switch (read_wait) {
                    .completed, .completed_after_wait => {
                        read_completed = win32_io.GetOverlappedResult(
                            handle,
                            &read_overlapped,
                            &bytes_read,
                            0,
                        ) != 0;
                    },
                    .timeout => {
                        std.log.debug("[PIPE SENSOR] Read timed out; closing client", .{});
                    },
                    .wait_error, .result_error => {
                        std.log.warn("[PIPE SENSOR] Overlapped read failed: {s}", .{@tagName(read_wait)});
                    },
                }
            }

            if (read_completed and bytes_read > 0) {
                const payload = buffer[0..bytes_read];
                std.log.info("[PIPE SENSOR] Captured Pipe Payload ({d} bytes)", .{bytes_read});
                std.debug.print("[PIPE SENSOR] Captured Pipe Payload ({d} bytes)\n", .{bytes_read});

                // The sensor path must feed the same canonical queue as every
                // other acquisition adapter. Previously this worker only
                // called the legacy string scanner, so transport succeeded
                // while pipeline metrics and forensic records remained zero.
                var queued_event = event.IpcEvent.init(.packet_captured);
                queued_event.source = .system;
                queued_event.timestamp_ns = @intCast(std.time.nanoTimestamp());
                queued_event.event_id = g_pipe_event_id.fetchAdd(1, .monotonic) + 1;
                queued_event.flags |= 0x0000_0004; // pipe-originated
                queued_event.setPayload(payload);
                applyJsonMetadata(&queued_event, payload);
                if (!event_queue.pushEvent(queued_event, payload)) {
                    std.log.warn("[PIPE SENSOR] Canonical event queue full; event dropped", .{});
                } else {
                    std.log.info("[PIPE SENSOR] Canonical event queued: event_id={d}", .{queued_event.event_id});
                }

                // The refactored daemon owns detection, policy, and forensic
                // processing. Do not call the legacy nids_analyze/Nose fabric
                // here: those globals are initialized only by the orphaned
                // nids_main entrypoint and produced false "not initialized"
                // diagnostics in the production daemon. The canonical queue
                // above is now the sole sensor-to-detector boundary.
            }

            _ = DisconnectNamedPipe(handle);
        }
    }
}
