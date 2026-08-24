//! pipe_monitor.zig - AEGIS NIDS Pipe Monitor Sensor (Thread 5)
//!
//! Polls \\.
\pipe\* and checks for suspicious named pipes.
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

const WIN32_FIND_DATAW = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: u64,
    ftLastAccessTime: u64,
    ftLastWriteTime: u64,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [260]u16,
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
    std.debug.print("[PM] Scan #{d}: {d} pipes, {d} suspicious\n", .{
        g_total_scans, pipe_count, suspicious_count
    });
}

fn printAlert(name_wide: []const u16, pattern: []const u8) void {
    // Convert wide name to ASCII for printing
    var buf: [300]u8 = undefined;
    var len: usize = 0;
    for (name_wide) |ch| {
        if (ch < 128 and len < buf.len) {
            buf[len] = @intCast(ch);
            len += 1;
        } else {
            break;
        }
    }
    const name_str = buf[0..len];

    std.debug.print("\x1b[31;1m[PM ALERT] Suspicious pipe: {s} (matched: {s})\x1b[0m\n", .{ name_str, pattern });
}

/// Print cumulative statistics
pub fn printStats() void {
    std.debug.print("[PM] Stats: {d} scans, {d} total suspicious pipes found\n", .{
        g_total_scans, g_suspicious_found
    });
}

/// Main pipe monitor loop (Thread 5)
/// BP1: No longer takes allocator - uses stack/local allocation only
pub fn pipeMonitorLoop() void {
    std.debug.print("[PM] Thread 5 started - scanning pipes every 10s\n", .{});

    // Initial delay to let system settle
    std.time.sleep(3 * std.time.ns_per_s);

    while (true) {

        if (bridge_init.g_shutdown.load(.seq_cst)) break;
        scanPipes();
        printStats();
        std.time.sleep(10 * std.time.ns_per_s);
    }
}