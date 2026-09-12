//! wfp_ioctl.zig - AEGIS NIDS WFP Driver IOCTL Bridge (M2)
//!
//! Provides user-mode READ-ONLY functions to communicate with the AEGIS WFP
//! kernel driver (aegis_wfp.sys) via DeviceIoControl.
//!
//! SECURITY (PEP-001): This module is READ-ONLY telemetry transport.
//! Privileged enforcement (block/unblock) is PROHIBITED here.
//! All privileged actions MUST go through rust_pep.zig -> pep_bindings -> Rust PEP.
//!
//! Kernel IOCTLs (from aegis_wfp.h):
//!   IOCTL_AEGIS_READ_EVENTS  = CTL_CODE(0x12, 0x800, 0, FILE_READ_DATA)
//!   IOCTL_AEGIS_GET_STATS    = CTL_CODE(0x12, 0x802, 0, FILE_READ_DATA)
//!
//! Device: \\.\AegisWfpDevice

const std = @import("std");

// ============================================================
// IOCTL Code Constants (must match aegis_wfp.h CTL_CODE macro)
// ============================================================

const FILE_DEVICE_NETWORK: u32 = 0x12;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA: u32 = 0x0001;

fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) u32 {
    return (device_type << 16) | (access << 14) | (function << 2) | method;
}

pub const IOCTL_AEGIS_READ_EVENTS = CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_AEGIS_GET_STATS   = CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA);

// ============================================================
// WFP Event Header (must match aegis_wfp.h AEGIS_EVENT_HEADER)
// ============================================================

pub const WfpEventHeader = extern struct {
    event_type: u32,
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    direction: u8,
    layer_id: u8,
    flags: u8,
    payload_length: u32,
    rule_id: u32,
    severity: u32,
    reserved: u32,
    timestamp: u64,
};

// Ring stats returned by IOCTL_AEGIS_GET_STATS
pub const WfpRingStats = extern struct {
    currentUsedBytes: u32,
    capacity: u32,
    totalEvents: u32,
    droppedEvents: u32,
};

// ============================================================
// Win32 FFI Declarations (kernel32.dll)
// ============================================================

const HANDLE = *anyopaque;
const DWORD = u32;
const BOOL = i32;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const OPEN_EXISTING: u32 = 3;

extern "kernel32" fn CreateFileA(
    lpFileName: [*:0]const u8,
    dwDesiredAccess: DWORD,
    dwShareMode: DWORD,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: DWORD,
    dwFlagsAndAttributes: DWORD,
    hTemplateFile: HANDLE,
) HANDLE;

extern "kernel32" fn CloseHandle(hObject: HANDLE) BOOL;

extern "kernel32" fn DeviceIoControl(
    hDevice: HANDLE,
    dwIoControlCode: DWORD,
    lpInBuffer: ?*const anyopaque,
    nInBufferSize: DWORD,
    lpOutBuffer: ?*anyopaque,
    nOutBufferSize: DWORD,
    lpBytesReturned: *DWORD,
    lpOverlapped: ?*anyopaque,
) BOOL;

extern "kernel32" fn GetLastError() DWORD;

// ============================================================
// Module State
// ============================================================

const WFP_DEVICE_NAME = "\\\\.\\AegisWfpDevice";

var g_device: ?HANDLE = null;
var g_initialized: bool = false;

// ============================================================
// Public API: Initialization
// ============================================================

/// Open the AEGIS WFP device driver.
/// Returns true on success. Safe to call multiple times.
pub fn init() bool {
    if (g_initialized and g_device != null) return true;

    const handle = CreateFileA(
        WFP_DEVICE_NAME,
        GENERIC_READ, // PEP-001: read-only transport — no write access
        0,       // no sharing
        null,    // default security
        OPEN_EXISTING,
        0,       // no flags
        INVALID_HANDLE_VALUE,
    );

    if (handle == INVALID_HANDLE_VALUE) {
        const err = GetLastError();
        if (@import("builtin").is_test) {
            std.log.debug("[WFP IOCTL] Cannot open {any}: error=0x{x}", .{ WFP_DEVICE_NAME, err });
        } else {
            std.log.err("[WFP IOCTL] Cannot open {any}: error=0x{x}", .{ WFP_DEVICE_NAME, err });
            std.debug.print("[WFP IOCTL] Cannot open {any}: error=0x{x}\n", .{ WFP_DEVICE_NAME, err });
        }
        return false;
    }

    g_device = handle;
    g_initialized = true;
    std.log.info("[WFP IOCTL] Device opened successfully", .{});
    std.debug.print("[WFP IOCTL] Device opened successfully\n", .{});
    return true;
}

/// Close the WFP device handle.
pub fn shutdown() void {
    if (g_device) |handle| {
        _ = CloseHandle(handle);
        g_device = null;
    }
    g_initialized = false;
    std.log.info("[WFP IOCTL] Device closed", .{});
    std.debug.print("[WFP IOCTL] Device closed\n", .{});
}

/// Check if the WFP device is connected and ready.
pub fn isConnected() bool {
    return g_device != null;
}

// ============================================================
// Public API: read_events (READ-ONLY telemetry)
// ============================================================

/// Read events from the WFP driver ring buffer via IOCTL.
/// Fills `out_buf` with raw event data (WfpEventHeader + payload).
///
/// @param out_buf  Output buffer for event data
/// @return Number of bytes read, or 0 if no events / error
pub fn read_events(out_buf: []u8) u32 {
    if (g_device == null) return 0;

    var bytes_returned: DWORD = 0;
    const buf_size: u32 = std.math.cast(u32, out_buf.len) orelse 0;
    if (buf_size == 0) return 0;
    const ok = DeviceIoControl(
        g_device.?,
        IOCTL_AEGIS_READ_EVENTS,
        null, 0,            // no input buffer
        out_buf.ptr,
        buf_size,
        &bytes_returned,
        null,
    );

    if (ok == 0) {
        const err = GetLastError();
        if (err != 0x8000001A) {
            std.log.warn("[WFP IOCTL] read_events failed: error=0x{x}", .{err});
            std.debug.print("[WFP IOCTL] read_events failed: error=0x{x}\n", .{err});
        }
        return 0;
    }

    return bytes_returned;
}

// ============================================================
// Public API: get_stats (READ-ONLY telemetry)
// ============================================================

/// Get WFP ring buffer statistics from the kernel driver.
/// Returns null if the device is not open or IOCTL fails.
pub fn get_stats() ?WfpRingStats {
    if (g_device == null) return null;

    var stats: WfpRingStats = undefined;
    var bytes_returned: DWORD = 0;

    const ok = DeviceIoControl(
        g_device.?,
        IOCTL_AEGIS_GET_STATS,
        null, 0,            // no input buffer
        @ptrCast(&stats),
        @sizeOf(WfpRingStats),
        &bytes_returned,
        null,
    );

    if (ok == 0 or bytes_returned < @sizeOf(WfpRingStats)) {
        return null;
    }

    return stats;
}

// ============================================================
// Utility: IPv4 formatting
// ============================================================

/// Format an IPv4 (network byte order) as "a.b.c.d" string.
pub fn formatIpv4(ipv4: u32, buf: []u8) []const u8 {
    const a = (ipv4 >> 24) & 0xFF;
    const b = (ipv4 >> 16) & 0xFF;
    const c = (ipv4 >> 8) & 0xFF;
    const d = (ipv4 >> 0) & 0xFF;
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a, b, c, d }) catch "?.?.?.?";
}

/// Parse "a.b.c.d" string to network-byte-order u32.
pub fn parseIpv4(str: []const u8) ?u32 {
    var parts: [4]u16 = undefined;
    var part_idx: usize = 0;
    var current: u16 = 0;

    for (str) |ch| {
        if (ch == '.') {
            if (part_idx >= 3) return null;
            if (current > 255) return null;
            parts[part_idx] = current;
            part_idx += 1;
            current = 0;
        } else if (ch >= '0' and ch <= '9') {
            current = current * 10 + (ch - '0');
            if (current > 255) return null;
        } else {
            return null;
        }
    }
    if (part_idx != 3) return null;
    if (current > 255) return null;
    parts[3] = current;

    return (@as(u32, @intCast(parts[0])) << 24) |
        (@as(u32, @intCast(parts[1])) << 16) |
        (@as(u32, @intCast(parts[2])) << 8) |
        @as(u32, @intCast(parts[3]));
}

// ============================================================
// Tests
// ============================================================

test "IOCTL codes match WFP protocol spec" {
    try std.testing.expect(IOCTL_AEGIS_READ_EVENTS == 0x00126000);
    try std.testing.expect(IOCTL_AEGIS_GET_STATS == 0x00126008);
}

test "formatIpv4 renders dotted-quad correctly" {
    var buf: [16]u8 = undefined;
    const result = formatIpv4(0xC0A80164, &buf);
    try std.testing.expect(std.mem.eql(u8, result, "192.168.1.100"));
}

test "formatIpv4 renders loopback address" {
    var buf: [16]u8 = undefined;
    const result = formatIpv4(0x7F000001, &buf);
    try std.testing.expect(std.mem.eql(u8, result, "127.0.0.1"));
}

test "formatIpv4 renders 0.0.0.0" {
    var buf: [16]u8 = undefined;
    const result = formatIpv4(0, &buf);
    try std.testing.expect(std.mem.eql(u8, result, "0.0.0.0"));
}

test "parseIpv4 parses valid dotted-quad" {
    const result = parseIpv4("10.0.0.1") orelse return error.TestFailed;
    try std.testing.expect(result == 0x0A000001);
}

test "parseIpv4 parses 192.168.1.100" {
    const result = parseIpv4("192.168.1.100") orelse return error.TestFailed;
    try std.testing.expect(result == 0xC0A80164);
}

test "parseIpv4 rejects invalid input" {
    try std.testing.expect(parseIpv4("256.0.0.1") == null);
    try std.testing.expect(parseIpv4("10.0.0") == null);
    try std.testing.expect(parseIpv4("10.0.0.1.2") == null);
    try std.testing.expect(parseIpv4("abc.def.ghi.jkl") == null);
    try std.testing.expect(parseIpv4("") == null);
}

test "parseIpv4 rejects octets over 255" {
    try std.testing.expect(parseIpv4("10.0.0.256") == null);
    try std.testing.expect(parseIpv4("10.0.0.999") == null);
}

test "parseIpv4 and formatIpv4 round-trip" {
    var buf: [16]u8 = undefined;
    const original: u32 = 0xC0A80164;
    const parsed = parseIpv4("192.168.1.100") orelse return error.TestFailed;
    try std.testing.expect(parsed == original);
    const formatted = formatIpv4(parsed, &buf);
    try std.testing.expect(std.mem.eql(u8, formatted, "192.168.1.100"));
}
