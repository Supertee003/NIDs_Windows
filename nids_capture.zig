const std = @import("std");
const win = std.os.windows;
const nids_analyze = @import("nids_analyze.zig");

// Windows API declarations for Named Pipe (IPC)
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

// Windows Pipe constants
const PIPE_ACCESS_DUPLEX = 0x00000003;
const PIPE_TYPE_MESSAGE = 0x00000004;
const PIPE_READMODE_MESSAGE = 0x00000002;
const PIPE_WAIT = 0x00000000;
const PIPE_UNLIMITED_INSTANCES = 255;

pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) !void {
    _ = allocator;
    _ = address;

    const pipe_name = "\\\\.\\pipe\\aegis_sensor_pipe";

    std.debug.print("[IPC SENSOR] Initializing Named Pipe Server...\n", .{});

    // 1. Create Named Pipe
    const handle = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096,
        4096,
        0,
        null,
    );

    if (handle == win.INVALID_HANDLE_VALUE) {
        std.debug.print("[-] IPC Error: Failed to create Named Pipe.\n", .{});
        return;
    }
    defer win.CloseHandle(handle);

    var buffer: [4096]u8 = undefined;

    std.debug.print("[IPC SENSOR] Listening on {s} - Waiting for Python scripts...\n", .{pipe_name});

    // 2. Accept connections from Python
    while (true) {
        const connected = ConnectNamedPipe(handle, null) != 0;
        const err = win.kernel32.GetLastError();

        if (connected or err == win.Win32Error.PIPE_CONNECTED) {

            // 3. Read payload
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
                std.debug.print("[IPC SENSOR] Captured Pipe Payload ({} bytes)\n", .{bytes_read});

                // Named Pipe has no 5-tuple — use PacketContext with defaults
                const ctx = nids_analyze.PacketContext{
                    .is_pipe = true,
                    .layer_id = 3,  // L2_PIPE
                };

                const is_safe = try nids_analyze.inspect_packet(payload, ctx);
                if (!is_safe) {
                    std.debug.print("\\x1b[31;1m[IPC SENSOR] Threat blocked at Named Pipe!\\x1b[0m\\n", .{});
                }
            }

            // 4. Disconnect for next client
            _ = DisconnectNamedPipe(handle);
        } else {
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
}
