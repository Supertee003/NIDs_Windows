const std = @import("std");
const nids_analyze = @import("nids_analyze.zig");

// =====================================================================
// minifilter_reader.zig
// ---------------------------------------------------------------------
// อ่าน events จาก Aegis Minifilter Driver ผ่าน FilterCommunicationPort
//
// Flow:
//   1. FilterConnectCommunicationPort("\\AegisMinifilterPort")
//   2. FilterGetMessage() วนลูป — รับ message จาก minifilter
//   3. แต่ละ message ประกอบด้วย:
//        [FILTER_MESSAGE_HEADER (kernel-filled)]
//        [AEGIS_EVENT_HEADER]
//        [payload: file path / process image name]
//   4. ส่งต่อไป inspect_event()
//
// NOTE: ถ้า minifilter driver ยังไม่ถูก load (FltLoad) จะ retry ทุก 30s
//       เหมือน windows_capture.zig
// =====================================================================

const win = std.os.windows;

// --- Windows API externs สำหรับ FilterManager user-mode API ---
// NOTE: ต้อง link กับ fltlib.lib (Windows SDK) ตอน build

const HRESULT = i32;
const HANDLE = win.HANDLE;
const S_OK: HRESULT = 0;
const HRESULT_FROM_WIN32_ERROR_PIPE_NOT_AVAILABLE: HRESULT = -2147024848; // 0x80070016

extern "fltkernel" fn FilterConnectCommunicationPort(
    lpPortName: [*:0]const u16, // LPCWSTR
    dwOptions: u32,
    lpContext: ?*anyopaque,
    wContextSize: u16,
    lpSecurityAttributes: ?*anyopaque,
    lpPortHandle: *HANDLE,
) HRESULT;

extern "fltkernel" fn FilterClose(
    hPort: HANDLE,
) HRESULT;

extern "fltkernel" fn FilterGetMessage(
    hPort: HANDLE,
    lpMessageBuffer: *anyopaque,
    dwMessageBufferSize: u32,
    lpOverlapped: ?*anyopaque,
) HRESULT;

const MINIFILTER_PORT_NAME = [21:0]u16{ '\\', 'A', 'e', 'g', 'i', 's', 'M', 'i', 'n', 'i', 'f', 'i', 'l', 't', 'e', 'r', 'P', 'o', 'r', 't' } ++ .{};

/// User-mode mirror ของ FILTER_MESSAGE_HEADER (simplified)
/// ขนาดจริง ~16 bytes — ดู fltUserStructures.h
const FILTER_MESSAGE_HEADER = extern struct {
    reply_length: u32,
    message_id: u64,
};

const MAX_PAYLOAD_SIZE: usize = 65536;
const RETRY_INTERVAL_NS: u64 = 30 * std.time.ns_per_s;

pub fn run(allocator: std.mem.Allocator) void {
    _ = allocator;

    std.debug.print("[MINIFILTER] Thread started. Looking for \\\\AegisMinifilterPort...\n", .{});

    while (true) {
        var port: HANDLE = win.INVALID_HANDLE_VALUE;
        const port_name_slice: [*:0]const u16 = &MINIFILTER_PORT_NAME;

        const hr = FilterConnectCommunicationPort(port_name_slice, 0, null, 0, null, &port);
        if (hr != S_OK or port == win.INVALID_HANDLE_VALUE) {
            std.debug.print("[MINIFILTER] Port not connected (hr=0x{x:0>8}). Retrying in 30s...\n", .{@as(u32, @bitCast(hr))});
            std.time.sleep(RETRY_INTERVAL_NS);
            continue;
        }

        std.debug.print("[MINIFILTER] Connected to port. Reading messages...\n", .{});

        // Buffer สำหรับรับ message: FILTER_MESSAGE_HEADER + AEGIS_EVENT_HEADER + payload
        var msg_buf: [MAX_PAYLOAD_SIZE]u8 = undefined;

        while (true) {
            const got = FilterGetMessage(port, &msg_buf, @intCast(msg_buf.len), null);
            if (got != S_OK) {
                std.debug.print("[MINIFILTER] FilterGetMessage failed (hr=0x{x:0>8}). Reconnecting in 5s...\n", .{@as(u32, @bitCast(got))});
                std.time.sleep(5 * std.time.ns_per_s);
                break;
            }

            // ข้าม FILTER_MESSAGE_HEADER (16 bytes) ไปยัง AEGIS_EVENT_HEADER
            const filter_hdr_size = @sizeOf(FILTER_MESSAGE_HEADER);
            if (msg_buf.len <= filter_hdr_size + nids_analyze.EVENT_HEADER_SIZE) continue;

            const event_hdr_ptr: *const nids_analyze.EventHeader =
                @ptrCast(@alignCast(&msg_buf[filter_hdr_size]));

            const payload_start = filter_hdr_size + nids_analyze.EVENT_HEADER_SIZE;
            const payload_end = @as(usize, filter_hdr_size) + event_hdr_ptr.event_size;
            const payload_end_clamped = @min(payload_end, msg_buf.len);
            if (payload_end_clamped <= payload_start) continue;

            const payload = msg_buf[payload_start..payload_end_clamped];
            _ = nids_analyze.inspect_event(event_hdr_ptr, payload) catch |err| {
                std.debug.print("[MINIFILTER] inspect_event error: {}\n", .{err});
            };
        }

        _ = FilterClose(port);
    }
}
