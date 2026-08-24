//! minifilter_reader.zig - AEGIS NIDS Minifilter Reader (Thread 4)
//!
//! Reads file/process events from the AEGIS minifilter driver via
//! FilterCommunicationPort (FilterGetMessage API). Converts kernel
//! AEGIS_FILE_EVENT structures to Zig format and sends to nids_analyze
//! for rule matching.
//!
//! Architecture: User-mode Zig reader (KERNEL_FILE/KERNEL_PROCESS layer)
//! Communication: FilterGetMessage() from kernel -> Zig event processing
//!
//! BP4: std.log -> std.debug.print, !void -> void

const std = @import("std");
const bridge_init = @import("bridge_init.zig");

// ====== AEGIS File/Process Event (matches kernel struct) ======
pub const AegisFileEvent = extern struct {
    event_type: u32,      // 1=KERNEL_FILE, 2=KERNEL_PROCESS
    operation: u32,       // IRP_MJ_CREATE/WRITE/etc. or PROCESS_CREATE/EXIT
    file_name_len: u32,   // Length of file name following this header
    process_id: u32,      // PID of the process
    rule_id: u32,         // Matched rule ID
    severity: u32,        // 0=Low, 1=Medium, 2=High, 3=Critical
    reserved: u32,
    timestamp: u64,       // Event timestamp
};

// ====== Event type constants ======
pub const EVENT_KERNEL_FILE = 1;
pub const EVENT_KERNEL_PROCESS = 2;
pub const PROCESS_CREATE = 0x100;
pub const PROCESS_EXIT = 0x101;

// ====== Convert event fields to string ======
pub fn eventTypeToString(event_type: u32) []const u8 {
    return switch (event_type) {
        EVENT_KERNEL_FILE => "KERNEL_FILE",
        EVENT_KERNEL_PROCESS => "KERNEL_PROCESS",
        else => "UNKNOWN",
    };
}

pub fn operationToString(operation: u32) []const u8 {
    return switch (operation) {
        0x00 => "IRP_MJ_CREATE",
        0x04 => "IRP_MJ_WRITE",
        0x0C => "IRP_MJ_SET_INFORMATION",
        PROCESS_CREATE => "PROCESS_CREATE",
        PROCESS_EXIT => "PROCESS_EXIT",
        else => "UNKNOWN_OP",
    };
}

pub fn severityToString(severity: u32) []const u8 {
    return switch (severity) {
        0 => "Low",
        1 => "Medium",
        2 => "High",
        3 => "Critical",
        else => "Unknown",
    };
}

// ====== Minifilter Win32 API bindings (fltlib.dll) ======
const win = std.os.windows;
const HANDLE = win.HANDLE;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));
const HRESULT = i32;

const FILTER_COMMUNICATION_PORT_READ_MESSAGE = 0x0001;

// FilterGetMessage is in fltlib.dll - declare as extern
extern "fltlib" fn FilterConnectCommunicationPort(
    lpPortName: [*:0]const u16,
    dwOptions: u32,
    lpContext: ?*const anyopaque,
    dwSizeOfContext: u32,
    lpOverlapped: ?*anyopaque,
    hPort: *HANDLE,
) HRESULT;

extern "fltlib" fn FilterGetMessage(
    hPort: HANDLE,
    lpMessageBuffer: *anyopaque,
    dwMessageBufferSize: u32,
    lpOverlapped: ?*anyopaque,
) HRESULT;

extern "fltlib" fn FilterCloseCommunicationPort(hPort: HANDLE) HRESULT;

// Port name as UTF-16LE
const MINIFILTER_PORT = [_:0]u16{
    '\', '\', 'A', 'e', 'g', 'i', 's', 'M', 'i', 'n', 'i', 'f', 'i', 'l', 't', 'e', 'r', 'P', 'o', 'r', 't'
};


// BP11: Verify port name starts with backslash at compile time
comptime {
    if (MINIFILTER_PORT[0] != 0x5C) {
        @compileError("MINIFILTER_PORT[0] must be 0x5C (backslash)");
    }
}
/// Statistics
var g_events_received: u64 = 0;
var g_events_processed: u64 = 0;
var g_driver_connected: bool = false;

// ====== Main minifilter reader loop (Thread 4) ======
/// BP4: Returns void (not !void) to avoid thread panic on error.
pub fn minifilterReaderLoop() void {
    std.debug.print("[MINI] Thread 4 started - connecting to minifilter driver...\n", .{});

    var hPort: HANDLE = INVALID_HANDLE_VALUE;
    var retry_count: u32 = 0;

    // Try to connect to minifilter communication port
    while (true) {
        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        const hr = FilterConnectCommunicationPort(
            &MINIFILTER_PORT,
            0,          // no options
            null,       // no context
            0,          // context size
            null,       // not overlapped
            &hPort,
        );

        if (hr >= 0) {
            g_driver_connected = true;
            std.debug.print("\x1b[32m[MINI] Connected to AegisMinifilterPort\x1b[0m\n", .{});
            break;
        }

        retry_count += 1;
        if (retry_count == 1) {
            std.debug.print("\x1b[33m[MINI] Driver not available (hr=0x{x}), retrying every 10s\x1b[0m\n", .{@as(u32, @bitCast(hr))});
        }
        std.time.sleep(10 * std.time.ns_per_s);
    }
    defer {
        if (hPort != INVALID_HANDLE_VALUE) {
            _ = FilterCloseCommunicationPort(hPort);
        }
        g_driver_connected = false;
    }

    // Message buffer: AegisFileEvent header (40 bytes) + file name (512 max)
    var msg_buf: [1024]u8 align(@alignOf(AegisFileEvent)) = undefined;

    std.debug.print("[MINI] Reading events from kernel...\n", .{});

    while (true) {

        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        const hr = FilterGetMessage(
            hPort,
            @ptrCast(&msg_buf),
            msg_buf.len,
            null,  // not overlapped
        );

        if (hr >= 0) {
            g_events_received += 1;

            // Parse the AEGIS_FILE_EVENT header
            if (msg_buf.len >= @sizeOf(AegisFileEvent)) {
                const evt: *align(1) const AegisFileEvent =
                    @ptrCast(msg_buf[0..@sizeOf(AegisFileEvent)]);

                // Extract file name if present
                const name_offset = @sizeOf(AegisFileEvent);
                const name_len = @min(evt.file_name_len, msg_buf.len - name_offset);
                const file_name = msg_buf[name_offset .. name_offset + name_len];

                // Convert to ASCII for printing
                var name_buf: [512]u8 = undefined;
                var name_len_out: usize = 0;
                for (file_name) |ch| {
                    if (ch >= 0x20 and ch < 0x7F and name_len_out < name_buf.len) {
                        name_buf[name_len_out] = ch;
                        name_len_out += 1;
                    } else if (name_len_out > 0) {
                        break;
                    }
                }
                const name_str = name_buf[0..name_len_out];

                // Print event
                const evt_type = eventTypeToString(evt.event_type);
                const op_str = operationToString(evt.operation);
                const sev_str = severityToString(evt.severity);

                if (evt.severity >= 2) {
                    std.log.warn("[ALERT] MINI {} | {} | PID={} | sev={} | {}", .{
                    std.debug.print("\x1b[31;1m[MINI ALERT] {} | {} | PID={} | sev={} | {}\x1b[0m\n", .{
                        evt_type, op_str, evt.process_id, sev_str, name_str
                    });
                } else {
                    std.debug.print("[MINI] {} | {} | PID={} | {}\n", .{
                        evt_type, op_str, evt.process_id, name_str
                    });
                }

                g_events_processed += 1;
            }
        } else {
            // FilterGetMessage failed - check for ERROR_NO_MORE_ITEMS
            const err_code = @as(u32, @bitCast(hr));
            if (err_code == 0x8000001A) {
                // No more items - normal, just wait and retry
                std.time.sleep(100 * std.time.ns_per_ms);
            } else {
                std.debug.print("[MINI] FilterGetMessage error: 0x{x}\n", .{err_code});
                std.time.sleep(1 * std.time.ns_per_s);
            }
        }
    }
}

/// Get statistics (callable from other threads)
pub fn getStats() struct { received: u64, processed: u64, connected: bool } {
    return .{ .received = g_events_received, .processed = g_events_processed, .connected = g_driver_connected };
}
test "MINIFILTER_PORT starts with backslash" {
    try std.testing.expect(MINIFILTER_PORT[0] == 0x5C);
    try std.testing.expect(MINIFILTER_PORT[1] == 0x5C);
    // Third char should be 'A' (65)
    try std.testing.expect(MINIFILTER_PORT[2] == 0x41);
}

test "event type/operation strings are non-empty" {
    try std.testing.expect(eventTypeToString(EVENT_KERNEL_FILE).len > 0);
    try std.testing.expect(eventTypeToString(EVENT_KERNEL_PROCESS).len > 0);
    try std.testing.expect(operationToString(PROCESS_CREATE).len > 0);
    try std.testing.expect(severityToString(2).len > 0);
}
