const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");

// =====================================================================
// windows_capture.zig — WFP Kernel Event Reader
// ---------------------------------------------------------------------
//   อ่าน events จาก WFP callout driver ผ่าน DeviceIoControl
//   ใช้ IOCTL_AEGIS_READ_EVENTS เพื่อ batch-read events จาก ring buffer
//
//   โครงสร้างของแต่ละ event ใน output buffer:
//     [AEGIS_EVENT_HEADER (40 bytes)]
//     [payload (variable, ตาม header.event_size - EVENT_HEADER_SIZE)]
//   แต่ละ batch อาจมีหลาย events ติด ๆ กัน
//
//   ถ้า driver ยังไม่พร้อม จะ retry ทุก 30s
// =====================================================================

const win = std.os.windows;

// --- Windows API externs ---
extern "kernel32" fn CreateFileA(
    lpFileName: [*:0]const u8,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?win.HANDLE,
) win.HANDLE;

extern "kernel32" fn DeviceIoControl(
    hDevice: win.HANDLE,
    dwIoControlCode: u32,
    lpInBuffer: ?*anyopaque,
    nInBufferSize: u32,
    lpOutBuffer: ?*anyopaque,
    nOutBufferSize: u32,
    lpBytesReturned: ?*u32,
    lpOverlapped: ?*anyopaque,
) win.BOOL;

extern "kernel32" fn CloseHandle(hObject: win.HANDLE) win.BOOL;

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;

const WFP_DEVICE_NAME = "\\\\.\\AegisWfpDevice";
const RETRY_INTERVAL_NS: u64 = 30 * std.time.ns_per_s;
const READ_BUFFER_SIZE: usize = 65536; // 64KB

pub fn capture_packets(allocator: std.mem.Allocator, address: []const u8) void {
    _ = allocator;
    _ = address;

    std.debug.print("[WFP READER] Thread started. Will retry every 30s if driver is missing.\n", .{});

    while (true) {
        const device = CreateFileA(
            WFP_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null,
            OPEN_EXISTING,
            0,
            null,
        );

        if (device == INVALID_HANDLE_VALUE) {
            std.debug.print("[WFP READER] Device not found. Retrying in 30s...\n", .{});
            std.time.sleep(RETRY_INTERVAL_NS);
            continue;
        }

        std.debug.print("[WFP READER] Connected to {s}. Reading events via IOCTL...\n", .{WFP_DEVICE_NAME});

        var buf: [READ_BUFFER_SIZE]u8 = undefined;

        // Inner loop — batch-read events
        while (true) {
            var bytes_returned: u32 = 0;
            const ok = DeviceIoControl(
                device,
                nids_analyze.IOCTL_AEGIS_READ_EVENTS,
                null,
                0,
                &buf,
                @intCast(buf.len),
                &bytes_returned,
                null,
            );

            if (ok == 0) {
                std.debug.print("[WFP READER] IOCTL failed (err={}). Reconnecting in 5s...\n", .{win.kernel32.GetLastError()});
                std.time.sleep(5 * std.time.ns_per_s);
                break;
            }

            if (bytes_returned < nids_analyze.EVENT_HEADER_SIZE) {
                // ไม่มี event ใหม่ — sleep สั้น ๆ แล้ว read ใหม่
                std.time.sleep(50 * std.time.ns_per_ms);
                continue;
            }

            // Parse events ออกจาก buffer — แต่ละ event = header + payload
            var offset: usize = 0;
            while (offset + nids_analyze.EVENT_HEADER_SIZE <= bytes_returned) {
                const hdr_ptr: *const nids_analyze.EventHeader =
                    @ptrCast(@alignCast(&buf[offset]));

                const total_event_size = @as(usize, hdr_ptr.event_size);
                if (total_event_size < nids_analyze.EVENT_HEADER_SIZE) break;
                if (offset + total_event_size > bytes_returned) break;

                const payload_start = offset + nids_analyze.EVENT_HEADER_SIZE;
                const payload_end = offset + total_event_size;
                const payload = buf[payload_start..payload_end];

                _ = nids_analyze.inspect_event(hdr_ptr, payload) catch |err| {
                    std.debug.print("[WFP READER] inspect_event error: {}\n", .{err});
                };

                offset += total_event_size;
            }
        }

        _ = CloseHandle(device);
    }
}
