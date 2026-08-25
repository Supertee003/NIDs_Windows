//! pipe_monitor.zig - AEGIS NIDS Pipe Monitor Sensor (Thread 5)
//!
//! Polls \\.\pipe\* and checks for suspicious named pipes.
//! Matches against known attack tool patterns (Cobalt Strike, PsExec, etc.)
//!
//! BP1 Fix: Removed module-level GPA, uses std.debug.print,
//!          accepts allocator parameter, handles errors gracefully.

const std = @import("std");
const bridge_init = @import("bridge_init.zig");

// ====== Suspicious Named Pipe Patterns ======
const SUSPICIOUS_PIPE_PATTERNS = [_][]const u8{
    "MSSE-",           // Cobalt Strike (R3001)
    "postex_",         // Cobalt Strike post-exploitation
    "status_",         // Cobalt Strike status pipe
    "psexec",          // PsExec remote execution (R3002)
    "PAExec",          // PsExec variant
    "meterpreter",     // Meterpreter (R3004)
    "atsvc",           // atexec scheduled task (R3005)
    "anonymous",       // Anonymous pipe (R3003)
    "MSF",             // Metasploit
    "msf",             // Metasploit lowercase
};

// ====== Win32 FFI for pipe enumeration ======
const win = std.os.windows;
const HANDLE = win.HANDLE;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// BP-M17: Named constants for magic numbers
const MAX_PATH_W: usize = 260;       // Win32 MAX_PATH wide-char limit
const PM_ALERT_BUF: usize = 300;     // printAlert ASCII conversion buffer
const PM_ASCII_MAX: u16 = 128;       // ASCII printable boundary
const PM_INITIAL_DELAY_S: u64 = 3;   // Settle delay before first scan
const PM_SCAN_INTERVAL_S: u64 = 10; // Scan interval between pipe sweeps

const WIN32_FIND_DATAW = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: u64,
    ftLastAccessTime: u64,
    ftLastWriteTime: u64,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [MAX_PATH_W]u16,
    cAlternateFileName: [14]u16,
};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

extern "kernel32" fn FindFirstFileW(lpFileName: [*:0]const u16, lpFindFileData: *WIN32_FIND_DATAW) HANDLE;
extern "kernel32" fn FindNextFileW(hFindFile: HANDLE, lpFindFileData: *WIN32_FIND_DATAW) i32;
extern "kernel32" fn FindClose(hFindFile: HANDLE) i32;

const PIPE_SEARCH_PATH = [_:0]u16{
    '\', '\', '.', '\', 'p', 'i', 'p', 'e', '\', '*'
};

// ====== Pipe Statistics ======
var g_total_scans: u32 = 0;
var g_suspicious_found: u32 = 0;

/// Check if a pipe name matches any suspicious pattern (case-insensitive)
fn isSuspiciousPipe(name: []const u16) ?[]const u8 {
    // Convert to lowercase ASCII for matching
    for (SUSPICIOUS_PIPE_PATTERNS) |pattern| {
        if (name.len < pattern.len) continue;
        var match = true;
        for (0..pattern.len) |i| {
            const wc = name[i];
            if (wc < 128) {
                const ch_lower = std.ascii.toLower(@as(u8, @intCast(wc)));
                if (ch_lower != std.ascii.toLower(pattern[i])) {
                    match = false;
                    break;
                }
            } else {
                match = false;
                break;
            }
        }
        if (match) return pattern;
    }
    return null;
}

/// Scan all named pipes using Win32 FindFirstFileW
fn scanPipes() void {
    var find_data: WIN32_FIND_DATAW = undefined;

    const hFind = FindFirstFileW(&PIPE_SEARCH_PATH, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) return;
    defer _ = FindClose(hFind);

    var pipe_count: u32 = 0;
    var suspicious_count: u32 = 0;

    // First file
    if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0) {
        pipe_count += 1;
        const name_len = std.mem.lenZ(&find_data.cFileName);
        const name = find_data.cFileName[0..name_len];
        if (isSuspiciousPipe(name)) |pattern| {
            suspicious_count += 1;
            g_suspicious_found += 1;
            printAlert(name, pattern);
        }
    }

    // Remaining files
    while (FindNextFileW(hFind, &find_data) != 0) {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0) {
            pipe_count += 1;
            const name_len = std.mem.lenZ(&find_data.cFileName);
            const name = find_data.cFileName[0..name_len];
            if (isSuspiciousPipe(name)) |pattern| {
                suspicious_count += 1;
                g_suspicious_found += 1;
                printAlert(name, pattern);
            }
        }
    }

    g_total_scans += 1;
    std.log.info("[PM] Scan #{d}: {d} pipes, {d} suspicious", .{
        g_total_scans, pipe_count, suspicious_count
    });
    std.debug.print("[PM] Scan #{d}: {d} pipes, {d} suspicious\n", .{
        g_total_scans, pipe_count, suspicious_count
    });
}

fn printAlert(name_wide: []const u16, pattern: []const u8) void {
    // Convert wide name to ASCII for printing
    var buf: [PM_ALERT_BUF]u8 = undefined;
    var len: usize = 0;
    for (name_wide) |ch| {
        if (ch < PM_ASCII_MAX and len < buf.len) {
            buf[len] = @intCast(ch);
            len += 1;
        } else {
            break;
        }
    }
    const name_str = buf[0..len];

    std.log.warn("[PM ALERT] Suspicious pipe: {s} (matched: {s})", .{ name_str, pattern });
    std.debug.print("\x1b[31;1m[PM ALERT] Suspicious pipe: {s} (matched: {s})\x1b[0m\n", .{ name_str, pattern });
}

/// Print cumulative statistics
pub fn printStats() void {
    // BP-L16: Stats visible in release builds via std.log
    std.log.info("[PM] Stats: {d} scans, {d} total suspicious pipes found", .{
        g_total_scans, g_suspicious_found
    });
    std.debug.print("[PM] Stats: {d} scans, {d} total suspicious pipes found\n", .{
        g_total_scans, g_suspicious_found
    });
}

/// Main pipe monitor loop (Thread 5)
/// BP1: No longer takes allocator - uses stack/local allocation only
pub fn pipeMonitorLoop() void {
    std.log.info("[PM] Thread 5 started - scanning pipes every {d}s", .{PM_SCAN_INTERVAL_S});
    std.debug.print("[PM] Thread 5 started - scanning pipes every {d}s\n", .{PM_SCAN_INTERVAL_S});

    // Initial delay to let system settle
    std.time.sleep(PM_INITIAL_DELAY_S * std.time.ns_per_s);

    while (true) {

        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        scanPipes();
        printStats();
        std.time.sleep(PM_SCAN_INTERVAL_S * std.time.ns_per_s);
    }
}

// ============================================================
// Phase 10: Unit tests for suspicious pipe pattern matching
// ============================================================

test "isSuspiciousPipe detects Cobalt Strike MSSE pattern" {
    // "MSSE-1234" as UTF-16LE
    const pipe_name = [_]u16{ 'M', 'S', 'S', 'E', '-', '1', '2', '3', '4' };
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.eql(u8, result.?, "MSSE-"));
}

test "isSuspiciousPipe detects PsExec pattern" {
    const pipe_name = [_]u16{ 'p', 's', 'e', 'x', 'e', 'c', '-', 's', 'v', 'c' };
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result != null);
}

test "isSuspiciousPipe detects meterpreter pattern (case-insensitive)" {
    const pipe_name = [_]u16{ 'M', 'E', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'E', 'R' };
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.eql(u8, result.?, "meterpreter"));
}

test "isSuspiciousPipe returns null for benign pipe" {
    const pipe_name = [_]u16{ 's', 'q', 'l', 'q', 'u', 'e', 'r', 'y' };
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result == null);
}

test "isSuspiciousPipe returns null for empty pipe name" {
    const pipe_name = [_]u16{};
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result == null);
}

test "isSuspiciousPipe handles short names that don't match any pattern" {
    const pipe_name = [_]u16{ 'a', 'b', 'c' };
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result == null);
}

test "isSuspiciousPipe detects atsvc pattern" {
    const pipe_name = [_]u16{ 'a', 't', 's', 'v', 'c' };
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.eql(u8, result.?, "atsvc"));
}

test "isSuspiciousPipe handles non-ASCII characters gracefully" {
    // Unicode chars above 128 should not crash, just not match
    const pipe_name = [_]u16{ 0x4E2D, 0x6587, 0x7BA1, 0x9053 }; // Chinese chars
    const result = isSuspiciousPipe(&pipe_name);
    try std.testing.expect(result == null);
}
