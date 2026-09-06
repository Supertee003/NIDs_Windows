//! forensic_log.zig - AEGIS NIDS Persistent Forensic Logger (Phase 12)
//!
//! Provides structured NDJSON (newline-delimited JSON) logging for incident
//! response and SIEM ingestion. Writes append-only to logs/aegis_core.ndjson
//! with fsync after every Critical/Block event.
//!
//! Log schema (one JSON object per line):
//!   {"ts_ms": 1692900000000, "level": "warn", "event": "BLOCK",
//!    "rule": "SQL_INJECTION", "src_ip": "192.168.1.100", "src_port": 12345,
//!    "session_id": 42, "ruleset_version": 3, "payload_sha256": "abc123..."}

const std = @import("std");
const win = std.os.windows;

// ============================================================
// Configuration
// ============================================================

const LOG_FILE_PATH = "logs\\aegis_core.ndjson";
const LOG_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB rotation
const LOG_MAX_FILES: usize = 7; // Keep 7 rotated files

// ============================================================
// Module State
// ============================================================

var g_log_handle: ?win.HANDLE = null;
var g_log_mutex: std.Thread.Mutex = .{};
var g_session_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_initialized: bool = false;

// ============================================================
// Initialization
// ============================================================

/// Initialize the forensic logger. Call once at startup.
/// Creates logs/ directory if missing. Opens log file for append.
pub fn init() void {
    g_log_mutex.lock();
    defer g_log_mutex.unlock();

    if (g_initialized) return;

    // Ensure logs/ directory exists
    std.fs.cwd().makePath("logs") catch |err| {
        std.log.err("[FORENSIC] Failed to create logs/ dir: {}", .{err});
        return;
    };

    // Open log file for append (create if missing)
    const path_w = std.unicode.utf8ToUtf16LeStringLiteral(LOG_FILE_PATH);
    const handle = win.kernel32.CreateFileW(
        path_w,
        win.GENERIC_WRITE,
        win.FILE_SHARE_READ,
        null,
        win.OPEN_ALWAYS,
        win.FILE_ATTRIBUTE_NORMAL,
        null,
    );

    if (handle == win.INVALID_HANDLE_VALUE) {
        std.log.err("[FORENSIC] Failed to open log file: {s}", .{LOG_FILE_PATH});
        return;
    }

    // Seek to end for append
    _ = win.kernel32.SetFilePointer(handle, 0, null, win.FILE_END);

    g_log_handle = handle;
    g_initialized = true;
    std.log.info("[FORENSIC] Logger initialized: {s}", .{LOG_FILE_PATH});
}

/// Shutdown the forensic logger. Call on process exit.
pub fn shutdown() void {
    g_log_mutex.lock();
    defer g_log_mutex.unlock();

    if (g_log_handle) |handle| {
        _ = win.kernel32.FlushFileBuffers(handle);
        _ = win.CloseHandle(handle);
        g_log_handle = null;
    }
    g_initialized = false;
}

// ============================================================
// Session ID Generation (IR-03)
// ============================================================

/// Generate a unique session ID for cross-tier event correlation.
/// Returns a monotonically increasing 64-bit ID.
pub fn nextSessionId() u64 {
    return g_session_counter.fetchAdd(1, .acq_rel) + 1;
}

// ============================================================
// Log Event Structure (IR-08)
// ============================================================

pub const LogLevel = enum {
    info,
    warn,
    err,
    @"error", // alias
    critical,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .info => "info",
            .warn => "warn",
            .err, .@"error" => "error",
            .critical => "critical",
        };
    }
};

pub const LogEvent = struct {
    level: LogLevel,
    event: []const u8,
    rule: ?[]const u8 = null,
    src_ip: ?u32 = null,
    src_port: ?u16 = null,
    session_id: ?u64 = null,
    ruleset_version: ?u64 = null,
    payload_preview: ?[]const u8 = null,
    extra: ?[]const u8 = null,
};

// ============================================================
// Core Write Function
// ============================================================

/// Write a structured log event as NDJSON to the forensic log file.
/// Thread-safe via mutex. Flushes to disk after Critical/Block events.
pub fn log(event: LogEvent) void {
    if (!g_initialized) return;

    g_log_mutex.lock();
    defer g_log_mutex.unlock();

    const handle = g_log_handle orelse return;

    // Build JSON line on stack (max 2KB per entry)
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    // Get current timestamp (epoch milliseconds)
    const ts_ms: u64 = @as(u64, @intCast(@max(@as(i64, 0), std.time.milliTimestamp())));

    // Build JSON manually (avoids ArrayList allocation)
    writer.print("{{\"ts_ms\":{d},\"level\":\"{s}\"", .{ ts_ms, event.level.toString() }) catch return;
    writer.print(",\"event\":\"{s}\"", .{event.event}) catch return;

    if (event.rule) |rule| {
        // Escape basic JSON-special chars in rule name (IR-05: log injection prevention)
        writer.print(",\"rule\":\"", .{}) catch return;
        writeJsonEscaped(writer, rule);
        writer.print("\"", .{}) catch return;
    }

    if (event.src_ip) |ip| {
        const a = (ip >> 24) & 0xFF;
        const b = (ip >> 16) & 0xFF;
        const c = (ip >> 8) & 0xFF;
        const d = ip & 0xFF;
        writer.print(",\"src_ip\":\"{d}.{d}.{d}.{d}\"", .{ a, b, c, d }) catch return;
    }

    if (event.src_port) |port| {
        writer.print(",\"src_port\":{d}", .{port}) catch return;
    }

    if (event.session_id) |sid| {
        writer.print(",\"session_id\":{d}", .{sid}) catch return;
    }

    if (event.ruleset_version) |v| {
        writer.print(",\"ruleset_version\":{d}", .{v}) catch return;
    }

    if (event.payload_preview) |payload| {
        writer.print(",\"payload_len\":{d}", .{payload.len}) catch return;
    }

    if (event.extra) |extra| {
        writer.print(",\"extra\":\"", .{}) catch return;
        writeJsonEscaped(writer, extra);
        writer.print("\"", .{}) catch return;
    }

    writer.print("}}\n", .{}) catch return;

    const written = fbs.getWritten();

    // Write to file
    var bytes_written: u32 = 0;
    const ok = win.kernel32.WriteFile(handle, written.ptr, @intCast(written.len), &bytes_written, null);
    if (ok == 0) {
        std.log.warn("[FORENSIC] WriteFile failed", .{});
        return;
    }

    // Flush to disk for Critical/error events (IR-01: durability)
    if (event.level == .critical or event.level == .err or event.level == .@"error") {
        _ = win.kernel32.FlushFileBuffers(handle);
    }
}

/// Write a string with JSON escaping (IR-05: prevent log injection)
fn writeJsonEscaped(writer: anytype, s: []const u8) void {
    for (s) |c| {
        switch (c) {
            '"' => writer.print("\\\"", .{}) catch return,
            '\\' => writer.print("\\\\", .{}) catch return,
            '\n' => writer.print("\\n", .{}) catch return,
            '\r' => writer.print("\\r", .{}) catch return,
            '\t' => writer.print("\\t", .{}) catch return,
            0...8, 11, 12, 14...31 => writer.print("\\u{x:0>4}", .{c}) catch return,
            else => writer.writeByte(c) catch return,
        }
    }
}

// ============================================================
// Convenience Functions
// ============================================================

/// Log a BLOCK event (when a rule with action="Block" matches)
pub fn logBlock(rule_name: []const u8, src_ip: u32, src_port: u16, session_id: u64, ruleset_version: u64, payload: []const u8) void {
    log(.{
        .level = .critical,
        .event = "BLOCK",
        .rule = rule_name,
        .src_ip = src_ip,
        .src_port = src_port,
        .session_id = session_id,
        .ruleset_version = ruleset_version,
        .payload_preview = payload,
    });
}

/// Log a MATCH event (when any rule matches but action != Block)
pub fn logMatch(rule_name: []const u8, src_ip: u32, src_port: u16, session_id: u64, ruleset_version: u64, payload: []const u8) void {
    log(.{
        .level = .warn,
        .event = "MATCH",
        .rule = rule_name,
        .src_ip = src_ip,
        .src_port = src_port,
        .session_id = session_id,
        .ruleset_version = ruleset_version,
        .payload_preview = payload,
    });
}

/// Log a FORWARD event (unmatched packet sent to brain)
pub fn logForward(src_ip: u32, src_port: u16, session_id: u64, payload: []const u8) void {
    log(.{
        .level = .info,
        .event = "FORWARD",
        .src_ip = src_ip,
        .src_port = src_port,
        .session_id = session_id,
        .payload_preview = payload,
    });
}

/// Log an IP block action (WFP filter installed)
pub fn logIpBlocked(ip: u32, reason: []const u8) void {
    log(.{
        .level = .warn,
        .event = "IP_BLOCKED",
        .src_ip = ip,
        .extra = reason,
    });
}

/// Log a security rejection (rate limit, ACL, semaphore)
pub fn logRejection(reason: []const u8, src_ip: ?u32) void {
    log(.{
        .level = .warn,
        .event = "REJECTED",
        .src_ip = src_ip,
        .extra = reason,
    });
}

// ============================================================
// Tests
// ============================================================

test "LogLevel.toString returns correct values" {
    try std.testing.expect(std.mem.eql(u8, LogLevel.info.toString(), "info"));
    try std.testing.expect(std.mem.eql(u8, LogLevel.warn.toString(), "warn"));
    try std.testing.expect(std.mem.eql(u8, LogLevel.critical.toString(), "critical"));
}

test "nextSessionId returns increasing values" {
    const a = nextSessionId();
    const b = nextSessionId();
    try std.testing.expect(b > a);
}

test "writeJsonEscaped escapes special characters" {
    var buf: [100]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    writeJsonEscaped(writer, "hello\"world\\test\n");
    const written = fbs.getWritten();
    try std.testing.expect(std.mem.eql(u8, written, "hello\\\"world\\\\test\\n"));
}
