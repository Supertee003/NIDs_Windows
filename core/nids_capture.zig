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
        SDDL_ADMIN_ONLY, SDDL_REVISION, &pipe_sd, null,
    ) != 0) {
        sec_attr.lpSecurityDescriptor = pipe_sd;
        std.log.info("[IPC SENSOR] Pipe ACL: Admin-only (SDDL)", .{});
        std.debug.print("[IPC SENSOR] Pipe ACL: Admin-only (SDDL enforced)\n", .{});
    } else {
        std.log.warn("[PIPE] Failed to set admin-only ACL - pipe may accept non-admin connections", .{});
        std.debug.print("[IPC SENSOR] WARNING: Failed to set pipe ACL, using default\n", .{});
    }
    defer if (pipe_sd) |sd| { _ = LocalFree(sd); };
const handle = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096,
        4096,
        0,
        @ptrCast(&sec_attr),
    );

    if (handle == win.INVALID_HANDLE_VALUE) {
        std.log.err("[IPC SENSOR] Failed to create Named Pipe", .{});
        std.debug.print("[-] IPC Error: Failed to create Named Pipe.\n", .{});
        return;
    }
    defer win.CloseHandle(handle);

    var buffer: [4096]u8 = undefined;

    std.log.info("[PIPE SENSOR] Listening on {} - Waiting for scripts", .{pipe_name});
    std.debug.print("[PIPE SENSOR] Listening on {} - Waiting for Python scripts...\n", .{pipe_name});

    while (true) {

        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        const connected = ConnectNamedPipe(handle, null) != 0;
        const err = win.kernel32.GetLastError();

        if (connected or err == win.Win32Error.PIPE_CONNECTED) {
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
                std.log.info("[PIPE SENSOR] Captured Pipe Payload ({} bytes)", .{bytes_read});
                std.debug.print("[PIPE SENSOR] Captured Pipe Payload ({} bytes)\n", .{bytes_read});

                const ctx = nids_analyze.PacketContext{
                    .is_pipe = true,
                    .layer_id = 3,
                };

                const is_safe = nids_analyze.inspect_packet(payload, ctx) catch |analyze_err| blk: {
                    std.log.warn("[PIPE SENSOR] Analyze error: {} - fail-open", .{analyze_err});
                    std.debug.print("[PIPE SENSOR] Analyze error: {} - event allowed (fail-open)\n", .{analyze_err});
                    _ = nids_analyze.g_analyze_errors.fetchAdd(1, .seq_cst);
                    break :blk true;
                };
                if (!is_safe) {
                    std.log.warn("[BLOCK] Threat blocked at Named Pipe sensor", .{});
                std.debug.print("\x1b[31;1m[PIPE SENSOR] Threat blocked at Named Pipe!\x1b[0m\n", .{});
                }
            }

            _ = DisconnectNamedPipe(handle);
        } else {
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
}
