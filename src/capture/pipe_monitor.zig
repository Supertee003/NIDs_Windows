//! pipe_monitor.zig - AEGIS NIDS Pipe Monitor Sensor (Thread 5)
//!
//! Polls \\.\pipe\* and checks for suspicious named pipes.
//! Matches against known attack tool patterns (Cobalt Strike, PsExec, etc.)
//!
//! BP1 Fix: Removed module-level GPA, uses std.debug.print,
//!          accepts allocator parameter, handles errors gracefully.

const std = @import("std");
const bridge_init = @import("../core/bridge_init.zig");

/// Capture-local observation contract. The application boundary converts this
/// into the frozen IpcEvent type; keeping it local permits direct Zig tests.
pub const PipeObservation = struct {
    kind: u8 = 40, // signature_match
    severity: u8 = 4, // warning
    source: u8 = 5, // capture_pipe_monitor
    payload_len: u32 = 0,
    payload_hash: u32 = 0,
    timestamp_ns: u64 = 0,
};

pub const EventPublisher = *const fn (PipeObservation, []const u8) bool;
var g_event_publisher: ?EventPublisher = null;

/// Install the event-fabric sink from the application module. Keeping this
/// seam callback-based allows direct Zig tests of this capture module without
/// importing a sibling module outside the direct test module path.
pub fn setEventPublisher(publisher: ?EventPublisher) void {
    g_event_publisher = publisher;
}

// ====== Suspicious Named Pipe Patterns ======
const SUSPICIOUS_PIPE_PATTERNS = [_][]const u8{
    "MSSE-", // Cobalt Strike (R3001)
    "postex_", // Cobalt Strike post-exploitation
    "status_", // Cobalt Strike status pipe
    "psexec", // PsExec remote execution (R3002)
    "PAExec", // PsExec variant
    "meterpreter", // Meterpreter (R3004)
    "atsvc", // atexec scheduled task (R3005)
    "anonymous", // Anonymous pipe (R3003)
    "MSF", // Metasploit
    "msf", // Metasploit lowercase
};

// ====== Win32 FFI for pipe enumeration ======
const win = std.os.windows;
const HANDLE = win.HANDLE;
const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))));

// BP-M17: Named constants for magic numbers
const MAX_PATH_W: usize = 260; // Win32 MAX_PATH wide-char limit
const PM_ALERT_BUF: usize = 300; // printAlert ASCII conversion buffer
const PM_ASCII_MAX: u16 = 128; // ASCII printable boundary
const PM_INITIAL_DELAY_S: u64 = 3; // Settle delay before first scan
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
    cFileName: [MAX_PATH_W:0]u16,
    cAlternateFileName: [14]u16,
};

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

extern "kernel32" fn FindFirstFileW(lpFileName: [*:0]const u16, lpFindFileData: *WIN32_FIND_DATAW) HANDLE;
extern "kernel32" fn FindNextFileW(hFindFile: HANDLE, lpFindFileData: *WIN32_FIND_DATAW) i32;
extern "kernel32" fn FindClose(hFindFile: HANDLE) i32;

const PIPE_SEARCH_PATH = [_:0]u16{ '\\', '\\', '.', '\\', 'p', 'i', 'p', 'e', '\\', '*' };

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

fn encodePipeName(name_wide: []const u16, out: []u8) []const u8 {
    var len: usize = 0;
    for (name_wide) |ch| {
        if (ch >= PM_ASCII_MAX or len >= out.len) break;
        out[len] = @intCast(ch);
        len += 1;
    }
    return out[0..len];
}

/// Publish a bounded observation for the normal detector/forensic pipeline.
/// This is observation-only: policy evaluation decides any later action.
fn publishPipeObservation(name_wide: []const u16) bool {
    var payload_buf: [PM_ALERT_BUF]u8 = undefined;
    const payload = encodePipeName(name_wide, &payload_buf);
    if (payload.len == 0) return false;
    const observation = PipeObservation{
        .payload_len = @intCast(payload.len),
        .payload_hash = fnv1a32(payload),
        .timestamp_ns = @intCast(std.time.nanoTimestamp()),
    };
    if (g_event_publisher) |publish| return publish(observation, payload);
    return false;
}

fn fnv1a32(data: []const u8) u32 {
    var hash: u32 = 0x811c9dc5;
    for (data) |byte| {
        hash ^= byte;
        hash *%= 0x01000193;
    }
    return hash;
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
        const name_len = std.mem.indexOfSentinel(u16, 0, &find_data.cFileName);
        const name = find_data.cFileName[0..name_len];
        if (isSuspiciousPipe(name)) |pattern| {
            suspicious_count += 1;
            g_suspicious_found += 1;
            printAlert(name, pattern);
            _ = publishPipeObservation(name);
        }
    }

    while (FindNextFileW(hFind, &find_data) != 0) {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0) {
            const name_len = std.mem.indexOfSentinel(u16, 0, &find_data.cFileName);
            const name = find_data.cFileName[0..name_len];
            if (isSuspiciousPipe(name)) |pattern| {
                suspicious_count += 1;
                g_suspicious_found += 1;
                printAlert(name, pattern);
                _ = publishPipeObservation(name);
            }
        }
    }

    g_total_scans += 1;
    std.log.info("[PM] Scan #{d}: {d} pipes, {d} suspicious", .{ g_total_scans, pipe_count, suspicious_count });
    std.debug.print("[PM] Scan #{d}: {d} pipes, {d} suspicious\n", .{ g_total_scans, pipe_count, suspicious_count });
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
    std.log.info("[PM] Stats: {d} scans, {d} total suspicious pipes found", .{ g_total_scans, g_suspicious_found });
    std.debug.print("[PM] Stats: {d} scans, {d} total suspicious pipes found\n", .{ g_total_scans, g_suspicious_found });
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

test "encodePipeName creates bounded ASCII payload" {
    const pipe_name = [_]u16{ 'M', 'S', 'S', 'E', '-', '1', 0x4E2D };
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("MSSE-1", encodePipeName(&pipe_name, &buf));
}

var test_published_event: ?PipeObservation = null;
var test_published_payload: [PM_ALERT_BUF]u8 = undefined;
var test_published_len: usize = 0;

fn testPublisher(ev: PipeObservation, payload: []const u8) bool {
    test_published_event = ev;
    test_published_len = @min(payload.len, test_published_payload.len);
    @memcpy(test_published_payload[0..test_published_len], payload[0..test_published_len]);
    return true;
}

test "publishPipeObservation sends event through configured publisher" {
    setEventPublisher(testPublisher);
    defer setEventPublisher(null);
    const pipe_name = [_]u16{ 'M', 'S', 'S', 'E', '-', 'P', 'R', 'O', 'O', 'F' };
    try std.testing.expect(publishPipeObservation(&pipe_name));
    const published = test_published_event orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 40), published.kind);
    try std.testing.expectEqual(@as(u8, 5), published.source);
    try std.testing.expectEqualStrings("MSSE-PROOF", test_published_payload[0..test_published_len]);
    try std.testing.expectEqual(@as(u32, @intCast(test_published_len)), published.payload_len);
    try std.testing.expectEqual(fnv1a32("MSSE-PROOF"), published.payload_hash);
}
