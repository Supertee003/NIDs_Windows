//! wfp_ioctl.zig - AEGIS NIDS WFP Driver IOCTL Bridge (M2)
//!
//! Provides user-mode functions to communicate with the AEGIS WFP
//! kernel driver (aegis_wfp.sys) via DeviceIoControl.
//!
//! Kernel IOCTLs (from aegis_wfp.h):
//!   IOCTL_AEGIS_READ_EVENTS  = CTL_CODE(0x12, 0x800, 0, FILE_READ_DATA)
//!   IOCTL_AEGIS_BLOCK_FLOW   = CTL_CODE(0x12, 0x801, 0, FILE_WRITE_DATA)
//!   IOCTL_AEGIS_GET_STATS    = CTL_CODE(0x12, 0x802, 0, FILE_READ_DATA)
//!
//! Device: \\.\AegisWfpDevice

const std = @import("std");

// ============================================================
// IR-02: Persist blocked IPs to logs/blocked_ips.json
// Allows IR analysts to enumerate blocked IPs after restart
// ============================================================

fn persistBlockedIps() void {
    const file = std.fs.cwd().createFile("logs\\blocked_ips.json", .{ .truncate = true }) catch return;
    defer file.close();

    g_blocked_lock.lock();
    defer g_blocked_lock.unlock();

    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    writer.print("[", .{}) catch return;
    var i: u32 = 0;
    while (i < g_blocked_count) : (i += 1) {
        const ip = g_blocked_ips[i];
        const a = (ip >> 24) & 0xFF;
        const b = (ip >> 16) & 0xFF;
        const c = (ip >> 8) & 0xFF;
        const d = ip & 0xFF;
        if (i > 0) writer.print(",", .{}) catch return;
        writer.print("\"{d}.{d}.{d}.{d}\"", .{ a, b, c, d }) catch return;
    }
    writer.print("]\n", .{}) catch return;

    const written = fbs.getWritten();
    _ = file.writeAll(written) catch return;
}

// ============================================================
// IOCTL Code Constants (must match aegis_wfp.h CTL_CODE macro)
// ============================================================
// CTL_CODE(DeviceType, Function, Method, Access)
//   = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method

const FILE_DEVICE_NETWORK: u32 = 0x12;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;

fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) u32 {
    return (device_type << 16) | (access << 14) | (function << 2) | method;
}

pub const IOCTL_AEGIS_READ_EVENTS = CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA);
pub const IOCTL_AEGIS_BLOCK_FLOW  = CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA);
// ====== BP20: Unblock Flow IOCTL ======
pub const IOCTL_AEGIS_UNBLOCK_FLOW = CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA);
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
// Blocked IP Tracking Table (user-mode)
// ============================================================
// Stores blocked ipv4 addresses for user-mode tracking.
// Future: when kernel adds IOCTL_AEGIS_UNBLOCK_FLOW, we can
// implement real unblock by calling FwpmFilterDeleteById.

const MAX_BLOCKED_IPS = 256;

var g_blocked_ips: [MAX_BLOCKED_IPS]u32 = [_]u32{0} ** MAX_BLOCKED_IPS;
var g_blocked_count: u32 = 0;
var g_blocked_lock: std.Thread.Mutex = .{};

fn findBlockedIndex(ip: u32) ?usize {
    for (g_blocked_ips[0..g_blocked_count], 0..) |blocked_ip, i| {
        if (blocked_ip == ip) return i;
    }
    return null;
}

fn addBlockedIp(ip: u32) bool {
    if (g_blocked_count >= MAX_BLOCKED_IPS) return false;
    if (findBlockedIndex(ip) != null) return true; // already tracked
    g_blocked_ips[g_blocked_count] = ip;
    g_blocked_count += 1;
    return true;
}

fn removeBlockedIp(ip: u32) bool {
    const idx = findBlockedIndex(ip) orelse return false;
    // Swap-remove: move last element to deleted slot
    const last = g_blocked_count - 1;
    if (idx < last) {
        g_blocked_ips[idx] = g_blocked_ips[last];
    }
    g_blocked_ips[last] = 0;
    g_blocked_count -= 1;
    return true;
}

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
        GENERIC_READ | GENERIC_WRITE,
        0,       // no sharing
        null,    // default security
        OPEN_EXISTING,
        0,       // no flags
        INVALID_HANDLE_VALUE,
    );

    if (handle == INVALID_HANDLE_VALUE) {
        const err = GetLastError();
        std.log.err("[WFP IOCTL] Cannot open {}: error=0x{x}", .{ WFP_DEVICE_NAME, err });
        std.debug.print("[WFP IOCTL] Cannot open {}: error=0x{x}\n", .{ WFP_DEVICE_NAME, err });
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
// Public API: block_ip
// ============================================================

/// Block an IPv4 address by sending IOCTL_AEGIS_BLOCK_FLOW to the
/// kernel WFP driver. The driver adds a WFP filter with
/// FWP_ACTION_BLOCK at FWPM_LAYER_INBOUND_TRANSPORT_V4.
///
/// @param ipv4  IPv4 address in **network byte order** (big-endian)
///              e.g. 192.168.1.100 = 0xC0A80164
/// @return true if IOCTL succeeded
pub fn block_ip(ipv4: u32) bool {
    if (g_device == null) {
        std.log.warn("[WFP IOCTL] block_ip: device not open", .{});
        std.debug.print("[WFP IOCTL] block_ip: device not open\n", .{});
        return false;
    }

    var bytes_returned: DWORD = 0;
    const ok = DeviceIoControl(
        g_device.?,
        IOCTL_AEGIS_BLOCK_FLOW,
        @ptrCast(&ipv4),
        @sizeOf(u32),
        null, 0,        // no output buffer
        &bytes_returned,
        null,           // not overlapped
    );

    if (ok == 0) {
        const err = GetLastError();
        std.log.err("[WFP IOCTL] block_ip(0x{x}) failed: error=0x{x}", .{ ipv4, err });
        std.debug.print("[WFP IOCTL] block_ip(0x{x}) failed: error=0x{x}\n", .{ ipv4, err });
        return false;
    }

    // Track in user-mode table
    g_blocked_lock.lock();
    if (!addBlockedIp(ipv4)) {
        std.log.warn("[WFP] Blocked IP table full ({} entries), tracking overflow", .{MAX_BLOCKED_IPS});
    }
    g_blocked_lock.unlock();

    // IR-02: Persist blocked IPs to logs/blocked_ips.json for IR analysts
    persistBlockedIps();

    // Network byte order: extract MSB-first for human-readable IP
    const d = (ipv4 >> 0) & 0xFF;
    const c = (ipv4 >> 8) & 0xFF;
    const b = (ipv4 >> 16) & 0xFF;
    const a = (ipv4 >> 24) & 0xFF;
    std.log.info("[WFP IOCTL] BLOCKED {}.{}.{}.{} (IOCTL sent)", .{ a, b, c, d });
    std.debug.print("[WFP IOCTL] BLOCKED {}.{}.{}.{} (IOCTL sent)\n", .{ a, b, c, d });
    return true;
}

/// Unblock an IPv4 address.
/// NOTE: The kernel driver does not yet implement IOCTL_AEGIS_UNBLOCK_FLOW.
/// This function removes the IP from the user-mode tracking table.
/// When the kernel unblock IOCTL is added, this will also call it.
///
/// @param ipv4  IPv4 address in network byte order
/// @return true if the IP was in the blocked table and removed
pub fn unblock_ip(ipv4: u32) bool {
    g_blocked_lock.lock();
    const removed = removeBlockedIp(ipv4);
    g_blocked_lock.unlock();

    if (!removed) {
        const d = (ipv4 >> 0) & 0xFF;
        const c = (ipv4 >> 8) & 0xFF;
        const b = (ipv4 >> 16) & 0xFF;
        const a = (ipv4 >> 24) & 0xFF;
        std.log.warn("[WFP IOCTL] unblock_ip({}.{}.{}.{}): not in blocked table", .{ a, b, c, d });
        std.debug.print("[WFP IOCTL] unblock_ip({}.{}.{}.{}): not in blocked table\n", .{ a, b, c, d });
        return false;
    }

    const d = (ipv4 >> 0) & 0xFF;
    const c = (ipv4 >> 8) & 0xFF;
    const b = (ipv4 >> 16) & 0xFF;
    const a = (ipv4 >> 24) & 0xFF;
    std.log.info("[WFP IOCTL] UNBLOCKED {}.{}.{}.{} (tracking only)", .{ a, b, c, d });
    std.debug.print("[WFP IOCTL] UNBLOCKED {}.{}.{}.{} (tracking only - kernel IOCTL pending)\n", .{ a, b, c, d });

    // TODO: When kernel driver implements IOCTL_AEGIS_UNBLOCK_FLOW handler
    // (already defined as IOCTL_AEGIS_UNBLOCK_FLOW at top of file), call
    // DeviceIoControl here with the stored filter ID for FwpmFilterDeleteById.
    return true;
}

/// Get the count of currently blocked IPs.
pub fn getBlockedCount() u32 {
    g_blocked_lock.lock();
    const count = g_blocked_count;
    g_blocked_lock.unlock();
    return count;
}

// ============================================================
// Public API: read_events (replaces windows_capture.zig ReadFile)
// ============================================================

/// Read events from the WFP driver ring buffer via IOCTL.
/// Fills `out_buf` with raw event data (WfpEventHeader + payload).
///
/// @param out_buf  Output buffer for event data
/// @return Number of bytes read, or 0 if no events / error
pub fn read_events(out_buf: []u8) u32 {
    if (g_device == null) return 0;

    var bytes_returned: DWORD = 0;
    // BP-S3: Safe cast to prevent panic on >4GiB buffers (defense-in-depth)
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
        // STATUS_NO_MORE_ENTRIES (0x8000001A) is not a real error - just empty
        if (err != 0x8000001A) {
            // BP-L14: read_events error visible in release builds
            std.log.warn("[WFP IOCTL] read_events failed: error=0x{x}", .{err});
            std.debug.print("[WFP IOCTL] read_events failed: error=0x{x}\n", .{err});
        }
        return 0;
    }

    return bytes_returned;
}

// ============================================================
// Public API: get_stats
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
    // FIX: MSB-first extraction (was LSB-first, producing reversed IP)
    const a = (ipv4 >> 24) & 0xFF;
    const b = (ipv4 >> 16) & 0xFF;
    const c = (ipv4 >> 8) & 0xFF;
    const d = (ipv4 >> 0) & 0xFF;
    return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ a, b, c, d }) catch "?.?.?.?";
}

/// Parse "a.b.c.d" string to network-byte-order u32.
pub fn parseIpv4(str: []const u8) ?u32 {
    var parts: [4]u16 = undefined; // FIX: u16 to avoid overflow on "256"
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

    // Network byte order (MSB first): a.b.c.d → (a<<24)|(b<<16)|(c<<8)|d
    return (@as(u32, @intCast(parts[0])) << 24) |
        (@as(u32, @intCast(parts[1])) << 16) |
        (@as(u32, @intCast(parts[2])) << 8) |
        @as(u32, @intCast(parts[3]));
}

// ============================================================
// Convenience: block by dotted-quad string
// ============================================================

/// Block an IP from a "a.b.c.d" string.
pub fn block_ip_str(ip_str: []const u8) bool {
    const ip = parseIpv4(ip_str) orelse {
        // BP-L14: Invalid IP warning visible in release builds
        std.log.warn("[WFP IOCTL] Invalid IP: {s}", .{ip_str});
        std.debug.print("[WFP IOCTL] Invalid IP: {s}\n", .{ip_str});
        return false;
    };
    return block_ip(ip);
}

/// Unblock an IP from a "a.b.c.d" string.
pub fn unblock_ip_str(ip_str: []const u8) bool {
    const ip = parseIpv4(ip_str) orelse {
        // BP-L14: Invalid IP warning visible in release builds
        std.log.warn("[WFP IOCTL] Invalid IP: {s}", .{ip_str});
        std.debug.print("[WFP IOCTL] Invalid IP: {s}\n", .{ip_str});
        return false;
    };
    return unblock_ip(ip);
}
test "IOCTL codes match WFP protocol spec" {
    try std.testing.expect(IOCTL_AEGIS_READ_EVENTS == 0x00126000);
    try std.testing.expect(IOCTL_AEGIS_BLOCK_FLOW == 0x0012A004);
    try std.testing.expect(IOCTL_AEGIS_GET_STATS == 0x00126008);
    try std.testing.expect(IOCTL_AEGIS_UNBLOCK_FLOW == 0x0012A00C);
}

// ============================================================
// Phase 10: Unit tests for pure functions
// ============================================================

test "formatIpv4 renders dotted-quad correctly" {
    var buf: [16]u8 = undefined;
    // 192.168.1.100 in network byte order = 0xC0A80164
    const result = formatIpv4(0xC0A80164, &buf);
    try std.testing.expect(std.mem.eql(u8, result, "192.168.1.100"));
}

test "formatIpv4 renders loopback address" {
    var buf: [16]u8 = undefined;
    // 127.0.0.1 in network byte order = 0x7F000001
    const result = formatIpv4(0x7F000001, &buf);
    try std.testing.expect(std.mem.eql(u8, result, "127.0.0.1"));
}

test "formatIpv4 renders 0.0.0.0" {
    var buf: [16]u8 = undefined;
    const result = formatIpv4(0, &buf);
    try std.testing.expect(std.mem.eql(u8, result, "0.0.0.0"));
}

test "parseIpv4 parses valid dotted-quad" {
    // 10.0.0.1 in network byte order = 0x0A000001
    const result = parseIpv4("10.0.0.1") orelse return error.TestFailed;
    try std.testing.expect(result == 0x0A000001);
}

test "parseIpv4 parses 192.168.1.100" {
    const result = parseIpv4("192.168.1.100") orelse return error.TestFailed;
    try std.testing.expect(result == 0xC0A80164);
}

test "parseIpv4 rejects invalid input" {
    try std.testing.expect(parseIpv4("256.0.0.1") == null); // octet > 255
    try std.testing.expect(parseIpv4("10.0.0") == null); // only 3 octets
    try std.testing.expect(parseIpv4("10.0.0.1.2") == null); // too many octets
    try std.testing.expect(parseIpv4("abc.def.ghi.jkl") == null); // non-numeric
    try std.testing.expect(parseIpv4("") == null); // empty
}

test "parseIpv4 rejects octets over 255" {
    try std.testing.expect(parseIpv4("10.0.0.256") == null);
    try std.testing.expect(parseIpv4("10.0.0.999") == null);
}

test "parseIpv4 and formatIpv4 round-trip" {
    var buf: [16]u8 = undefined;
    const original: u32 = 0xC0A80164; // 192.168.1.100
    const parsed = parseIpv4("192.168.1.100") orelse return error.TestFailed;
    try std.testing.expect(parsed == original);
    const formatted = formatIpv4(parsed, &buf);
    try std.testing.expect(std.mem.eql(u8, formatted, "192.168.1.100"));
}

test "addBlockedIp and findBlockedIndex track IPs" {
    // Reset state for deterministic test
    g_blocked_count = 0;
    @memset(g_blocked_ips[0..], 0);

    try std.testing.expect(addBlockedIp(0xC0A80164)); // 192.168.1.100
    try std.testing.expect(g_blocked_count == 1);
    try std.testing.expect(findBlockedIndex(0xC0A80164) != null);

    // Adding same IP again should succeed (idempotent)
    try std.testing.expect(addBlockedIp(0xC0A80164));
    try std.testing.expect(g_blocked_count == 1); // count unchanged
}

test "removeBlockedIp removes tracked IP" {
    g_blocked_count = 0;
    @memset(g_blocked_ips[0..], 0);

    _ = addBlockedIp(0x0A000001); // 10.0.0.1
    _ = addBlockedIp(0x0A000002); // 10.0.0.2
    try std.testing.expect(g_blocked_count == 2);

    try std.testing.expect(removeBlockedIp(0x0A000001));
    try std.testing.expect(g_blocked_count == 1);
    try std.testing.expect(findBlockedIndex(0x0A000001) == null);
    try std.testing.expect(findBlockedIndex(0x0A000002) != null);
}

test "removeBlockedIp returns false for untracked IP" {
    g_blocked_count = 0;
    @memset(g_blocked_ips[0..], 0);

    try std.testing.expect(!removeBlockedIp(0xC0A80164));
}

test "addBlockedIp respects MAX_BLOCKED_IPS limit" {
    g_blocked_count = 0;
    @memset(g_blocked_ips[0..], 0);

    // Fill table to capacity
    var i: u32 = 0;
    while (i < MAX_BLOCKED_IPS) : (i += 1) {
        try std.testing.expect(addBlockedIp(0x0A000000 + i));
    }
    try std.testing.expect(g_blocked_count == MAX_BLOCKED_IPS);

    // Next add should fail (table full)
    try std.testing.expect(!addBlockedIp(0xFFFFFFFF));
    try std.testing.expect(g_blocked_count == MAX_BLOCKED_IPS);
}
