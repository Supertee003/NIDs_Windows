const std = @import("std");
const win = std.os.windows;
const nids_analyze = @import("nids_analyze.zig");

// ประกาศใช้งาน Windows API สำหรับสร้างและจัดการ Named Pipe (IPC)
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

// ค่าคงที่สำหรับ Windows Pipe
const PIPE_ACCESS_DUPLEX = 0x00000003;
const PIPE_TYPE_MESSAGE = 0x00000004;
const PIPE_READMODE_MESSAGE = 0x00000002;
const PIPE_WAIT = 0x00000000;
const PIPE_UNLIMITED_INSTANCES = 255;

pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) !void {
    _ = allocator;
    _ = address;

    // ชื่อ Pipe ต้องตรงกับในไฟล์ Python (R0064.py, R0106.py)
    const pipe_name = "\\\\.\\pipe\\aegis_sensor_pipe";

    std.debug.print("[IPC SENSOR] Initializing Named Pipe Server...\n", .{});

    // 1. สร้างท่อ Named Pipe
    const handle = CreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096, // Out Buffer Size
        4096, // In Buffer Size
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

    // 2. ลูปเปิดรับการเชื่อมต่อจาก Python
    while (true) {
        // รอจนกว่าจะมี Client (Python) เชื่อมต่อเข้ามา
        const connected = ConnectNamedPipe(handle, null) != 0;
        const err = win.kernel32.GetLastError();

        if (connected or err == win.Win32Error.PIPE_CONNECTED) {

            // 3. อ่านข้อมูล Payload ที่ถูกส่งเข้ามา
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

                // ==============================================================
                // ⚠️ เอาคอมเมนต์ออก เพื่อส่งข้อมูลไปให้ nids_analyze ตรวจสอบ!
                const is_safe = try nids_analyze.inspect_packet(payload, true);
                if (!is_safe) {
                    std.debug.print("\\x1b[31;1m[IPC SENSOR] 🚨 Threat blocked at Named Pipe!\\x1b[0m\\n", .{});
                    // เราจะแค่ Print หรือจะเพิ่มลอจิกอื่นๆ ตรงนี้ก็ได้ครับ เพราะในเซ็นเซอร์เราจัดการได้อิสระ
                }
                // ==============================================================
            }

            // 4. ตัดการเชื่อมต่อของ Python นัดเดิม เพื่อเตรียมท่อให้พร้อมรับนัดถัดไป
            _ = DisconnectNamedPipe(handle);
        } else {
            // หากเกิด Error ให้พักเล็กน้อยแล้ววนลูปใหม่
            std.time.sleep(10 * std.time.ns_per_ms);
        }
    }
}
