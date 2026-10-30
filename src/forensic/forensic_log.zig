//! forensic_log.zig - AEGIS NIDS Persistent Forensic Logger (Phase 12)
//!
//! Provides structured NDJSON (newline-delimited JSON) logging for incident
//! response and SIEM ingestion. Writes append-only to logs/aegis_core.ndjson
//! with fsync after every Critical/Block event.
//!
//! NDJSON schema v1 (one JSON object per line; readers MUST ignore unknown
//! keys so the schema stays additive — BE-EVI-097):
//!   Base (always): ts_ms, mono_ns, level (info/warn/error/critical), event,
//!     rule (decimal rule_id string), src_ip (dotted quad or full v6 text),
//!     src_port, session_id (flow identity), ruleset_version, payload_len,
//!     policy (pipeline action), policy_id, event_id, trace_id, audit_id.
//!   Receipt (only when a verified EnforcementReceipt proves the host
//!     effect): enforcement_status="enforced", host_effect_confirmed=true,
//!     filter_id, request_id, decision="block", provider="wfp",
//!     receipt_version=1. Otherwise enforcement_status="observed" and
//!     host_effect_confirmed=false with zero IDs.
//!   A line claiming enforced WITHOUT the full receipt set is malformed;
//!   readers must treat it as unconfirmed (see desktop confirmed_block,
//!   web PEP_UNVERIFIED, mouth is_confirmed_block).

const std = @import("std");
const builtin = @import("builtin");
const is_windows = builtin.os.tag == .windows;
const win = if (is_windows) std.os.windows else struct {};

// ============================================================
// Configuration
// ============================================================

const LOG_FILE_PATH = "logs\\aegis_core.ndjson";
const LOG_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB rotation
const LOG_MAX_FILES: usize = 7; // Keep 7 rotated files

// ============================================================
// Module State
// ============================================================

var g_log_handle: ?win.HANDLE = if (is_windows) null else null;
var g_log_file: ?std.fs.File = null;
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

    // Ensure logs/ directory exists (cross-platform)
    std.fs.cwd().makePath("logs") catch |err| {
        std.log.err("[FORENSIC] Failed to create logs/ dir: {}", .{err});
        return;
    };

    if (is_windows) {
        // Windows path: use Win32 API for shared-write access
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

        // Seek to end for append (SetFilePointerEx - zig 0.13 dropped SetFilePointer)
        var new_pos: i64 = 0;
        _ = win.kernel32.SetFilePointerEx(handle, 0, &new_pos, win.FILE_END);

        g_log_handle = handle;
    } else {
        // POSIX Host: use std.fs.File for append
        const file = std.fs.cwd().createFile(LOG_FILE_PATH, .{ .read = false, .truncate = false }) catch |err| {
            std.log.err("[FORENSIC] Failed to open log file: {s} ({})", .{ LOG_FILE_PATH, err });
            return;
        };
        // Seek to end for append
        file.seekFromEnd(0) catch |err| {
            std.log.err("[FORENSIC] Failed to seek: {}", .{err});
            file.close();
            return;
        };
        g_log_file = file;
    }

    g_initialized = true;
    std.log.info("[FORENSIC] Logger initialized: {s}", .{LOG_FILE_PATH});
}

/// Shutdown the forensic logger. Call on process exit.
pub fn shutdown() void {
    g_log_mutex.lock();
    defer g_log_mutex.unlock();

    if (is_windows) {
        if (g_log_handle) |handle| {
            _ = win.kernel32.FlushFileBuffers(handle);
            _ = win.CloseHandle(handle);
            g_log_handle = null;
        }
    } else {
        if (g_log_file) |*f| {
            f.close();
            g_log_file = null;
        }
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
// IR-04: Canonical timestamp schema (epoch_ms + monotonic_ns)
// ============================================================
// Dual-clock logging: epoch for cross-system correlation, monotonic for ordering

pub const Timestamp = struct {
    /// Wall-clock epoch milliseconds (for SIEM/cross-system correlation)
    epoch_ms: i64,
    /// Monotonic nanoseconds (for in-process ordering, immune to clock skew)
    monotonic_ns: i128,

    /// Get current timestamp from both clocks
    pub fn now() Timestamp {
        return .{
            .epoch_ms = std.time.milliTimestamp(),
            .monotonic_ns = std.time.nanoTimestamp(),
        };
    }
};

// ============================================================
// IR-06: Log rotation (100MB or 24h, keep 7 files)
// ============================================================
// Note: LOG_MAX_FILE_SIZE and LOG_MAX_FILES already declared at top of file

const LOG_MAX_AGE_S: u64 = 24 * 60 * 60; // 24 hours

var g_last_rotation_check_ns: i128 = 0;
const ROTATION_CHECK_INTERVAL_NS: i128 = 60 * std.time.ns_per_s; // Check every 60s

/// Check if log file needs rotation based on size or age.
/// Called periodically from the log() function (every 60s).
fn checkRotation(handle: win.HANDLE) void {
    const now_ns = std.time.nanoTimestamp();
    if (now_ns - g_last_rotation_check_ns < ROTATION_CHECK_INTERVAL_NS) return;
    g_last_rotation_check_ns = now_ns;

    // Get current file size via std.fs (simpler than GetFileSizeEx)
    var file_size: u64 = 0;
    if (std.fs.cwd().statFile("logs\\aegis_core.ndjson")) |stat| {
        file_size = stat.size;
    } else |_| return;

    if (file_size < LOG_MAX_FILE_SIZE) return;

    // Rotate: close current handle, rename files, reopen new
    _ = win.kernel32.FlushFileBuffers(handle);
    _ = win.kernel32.CloseHandle(handle);
    g_log_handle = null;

    // Shift older files: .6 -> .7, .5 -> .6, ..., .1 -> .2
    var i: u32 = @intCast(LOG_MAX_FILES);
    while (i > 1) : (i -= 1) {
        var old_buf: [256]u8 = undefined;
        var new_buf: [256]u8 = undefined;
        const old_path = std.fmt.bufPrint(&old_buf, "logs\\aegis_core.{d}.ndjson", .{i - 1}) catch continue;
        const new_path = std.fmt.bufPrint(&new_buf, "logs\\aegis_core.{d}.ndjson", .{i}) catch continue;
        // Try rename (ignore errors if old doesn't exist)
        std.fs.cwd().rename(old_path, new_path) catch {};
    }
    // Move current to .1
    std.fs.cwd().rename("logs\\aegis_core.ndjson", "logs\\aegis_core.1.ndjson") catch {};

    // Reopen new file
    const path_w = std.unicode.utf8ToUtf16LeStringLiteral("logs\\aegis_core.ndjson");
    const new_handle = win.kernel32.CreateFileW(
        path_w,
        win.GENERIC_WRITE,
        win.FILE_SHARE_READ,
        null,
        win.OPEN_ALWAYS,
        win.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (new_handle != win.INVALID_HANDLE_VALUE) {
        g_log_handle = new_handle;
    }
    std.log.info("[FORENSIC] Log rotated (was {} bytes)", .{file_size});
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
    // FOR-V6A: full v6 text form when the producer has sidecars. Takes
    // precedence over the u32 dotted quad (which for v6 events is only
    // the /32 prefix). Additive: readers ignore unknown fields.
    src_ipv6: ?[]const u8 = null,
    dst_ipv6: ?[]const u8 = null,
    src_port: ?u16 = null,
    session_id: ?u64 = null,
    ruleset_version: ?u64 = null,
    payload_preview: ?[]const u8 = null,
    extra: ?[]const u8 = null,
    // BE-EVI-097: pipeline identity + policy + receipt projection.
    // A line is a confirmed host effect ONLY when enforcement_status is
    // "enforced" with host_effect_confirmed AND all receipt IDs nonzero.
    policy: ?[]const u8 = null,
    policy_id: ?u32 = null,
    event_id: ?u64 = null,
    trace_id: ?u64 = null,
    audit_id: ?u64 = null,
    enforcement_status: ?[]const u8 = null,
    host_effect_confirmed: bool = false,
    filter_id: u64 = 0,
    request_id: u64 = 0,
    decision: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    receipt_version: u8 = 0,
    // IDS-INT-001: recording proof only; never an enforcement claim.
    ids_receipt_version: u16 = 0,
    ids_receipt_sequence: u64 = 0,
    ids_receipt_hash: ?[]const u8 = null,
};

// ============================================================
// Core Write Function
// ============================================================

/// Pure NDJSON line formatter (no filesystem). Shared by log() and the
/// schema unit tests below so the contract readers pin is exactly what
/// the daemon writes. Timestamps are caller-supplied (write time).
pub fn formatLogLine(event: LogEvent, epoch_ms: i64, mono_ns: i128, writer: anytype) void {
    // Build JSON manually (avoids ArrayList allocation)
    writer.print("{{\"ts_ms\":{d},\"mono_ns\":{d},\"level\":\"{s}\"", .{ epoch_ms, mono_ns, event.level.toString() }) catch return;
    writer.print(",\"event\":\"{s}\"", .{event.event}) catch return;

    if (event.rule) |rule| {
        // Escape basic JSON-special chars in rule name (IR-05: log injection prevention)
        writer.print(",\"rule\":\"", .{}) catch return;
        writeJsonEscaped(writer, rule);
        writer.print("\"", .{}) catch return;
    }

    if (event.src_ip) |ip| {
        if (event.src_ipv6) |ip6| {
            writer.print(",\"src_ip\":\"{s}\"", .{ip6}) catch return;
        } else {
            const a = (ip >> 24) & 0xFF;
            const b = (ip >> 16) & 0xFF;
            const c = (ip >> 8) & 0xFF;
            const d = ip & 0xFF;
            writer.print(",\"src_ip\":\"{d}.{d}.{d}.{d}\"", .{ a, b, c, d }) catch return;
        }
    } else if (event.src_ipv6) |ip6| {
        writer.print(",\"src_ip\":\"{s}\"", .{ip6}) catch return;
    }

    if (event.dst_ipv6) |ip6| {
        writer.print(",\"dst_ip\":\"{s}\"", .{ip6}) catch return;
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

    // BE-EVI-097: pipeline identity (always) + receipt projection.
    // Numeric IDs always emit (0 when absent); readers only trust them
    // with enforcement_status="enforced" + host_effect_confirmed=true.
    if (event.policy) |pol| {
        writer.print(",\"policy\":\"{s}\"", .{pol}) catch return;
    }
    if (event.policy_id) |pid| {
        writer.print(",\"policy_id\":{d}", .{pid}) catch return;
    }
    if (event.event_id) |eid| {
        writer.print(",\"event_id\":{d}", .{eid}) catch return;
    }
    if (event.trace_id) |tid| {
        writer.print(",\"trace_id\":{d}", .{tid}) catch return;
    }
    if (event.audit_id) |aid| {
        writer.print(",\"audit_id\":{d}", .{aid}) catch return;
    }
    if (event.enforcement_status) |st| {
        writer.print(",\"enforcement_status\":\"{s}\"", .{st}) catch return;
    }
    writer.print(",\"host_effect_confirmed\":{}", .{event.host_effect_confirmed}) catch return;
    writer.print(",\"filter_id\":{d},\"request_id\":{d}", .{ event.filter_id, event.request_id }) catch return;
    if (event.decision) |dec| {
        writer.print(",\"decision\":\"{s}\"", .{dec}) catch return;
    }
    if (event.provider) |prov| {
        writer.print(",\"provider\":\"{s}\"", .{prov}) catch return;
    }
    writer.print(",\"receipt_version\":{d}", .{event.receipt_version}) catch return;
    if (event.ids_receipt_version != 0) {
        writer.print(",\"ids_receipt_version\":{d},\"ids_receipt_sequence\":{d}", .{ event.ids_receipt_version, event.ids_receipt_sequence }) catch return;
        if (event.ids_receipt_hash) |hash| {
            writer.print(",\"ids_receipt_hash\":\"{s}\"", .{hash}) catch return;
        }
    }

    writer.print("}}\n", .{}) catch return;
}

/// Write a structured log event as NDJSON to the forensic log file.
/// Thread-safe via mutex. Flushes to disk after Critical/Block events.
/// Drop-on-error: any failure returns silently — the forensic ring (not
/// this projection) is the detection record, so a full disk must never
/// fail or slow detection.
pub fn log(event: LogEvent) void {
    if (!g_initialized) return;

    g_log_mutex.lock();
    defer g_log_mutex.unlock();

    const handle = g_log_handle orelse return;

    // IR-06: Check for log rotation every 60 seconds
    checkRotation(handle);

    // Re-read handle in case rotation changed it
    const current_handle = g_log_handle orelse return;

    // Build JSON line on stack (max 2KB per entry)
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    // IR-04: Dual-clock timestamp (epoch_ms for cross-system, monotonic_ns for ordering)
    const ts = Timestamp.now();
    formatLogLine(event, ts.epoch_ms, ts.monotonic_ns, writer);

    const written = fbs.getWritten();

    // Write to file
    var bytes_written: u32 = 0;
    const ok = win.kernel32.WriteFile(current_handle, written.ptr, @intCast(written.len), &bytes_written, null);
    if (ok == 0) {
        std.log.warn("[FORENSIC] WriteFile failed", .{});
        return;
    }

    // Flush to disk for Critical/error events (IR-01: durability)
    if (event.level == .critical or event.level == .err or event.level == .@"error") {
        _ = win.kernel32.FlushFileBuffers(current_handle);
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

// ============================================================
// IR-07: Full payload capture for Block events
// Saves payload to logs/payloads/<sha256-prefix>.bin for forensic analysis
// ============================================================

/// Capture a Block-event payload to disk for forensic analysis.
/// Writes to logs/payloads/<first16-hex-of-sha256>.bin
/// Returns the filename (or null on failure).
pub fn capturePayload(payload: []const u8) ?[]const u8 {
    // Compute SHA-256
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(payload);
    var hash: [32]u8 = undefined;
    hasher.final(&hash);

    // Use first 8 bytes (16 hex chars) as filename prefix
    var name_buf: [64]u8 = undefined;
    const filename = std.fmt.bufPrint(&name_buf, "logs\\payloads\\{x:0>4}{x:0>4}{x:0>4}{x:0>4}.bin", .{
        std.mem.readInt(u16, hash[0..2], .big),
        std.mem.readInt(u16, hash[2..4], .big),
        std.mem.readInt(u16, hash[4..6], .big),
        std.mem.readInt(u16, hash[6..8], .big),
    }) catch return null;

    // Create logs/payloads/ directory if missing
    std.fs.cwd().makePath("logs\\payloads") catch {};

    // Write payload to file (only if not already exists ΓÇö dedup by hash)
    const file = std.fs.cwd().createFile(filename, .{ .exclusive = true }) catch {
        // File already exists (same payload captured before) ΓÇö that's fine
        return filename;
    };
    defer file.close();
    file.writeAll(payload) catch return null;

    return filename;
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

test "BE-EVI-097: formatLogLine emits the v1 contract readers pin" {
    // Detection line (unconfirmed): identity fields present, receipt
    // zeros, observed status. Readers must see every key they gate on.
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    formatLogLine(.{
        .level = .critical,
        .event = "signature_match",
        .rule = "4237725842",
        .src_ip = 0xC0A80164,
        .src_port = 1234,
        .session_id = 7,
        .policy = "alert",
        .policy_id = 9,
        .event_id = 101,
        .trace_id = 102,
        .audit_id = 103,
        .enforcement_status = "observed",
        .payload_preview = "abc",
    }, 1700000000000, 9000, fbs.writer());
    const line = fbs.getWritten();
    for ([_][]const u8{
        "\"ts_ms\":1700000000000",
        "\"mono_ns\":9000",
        "\"level\":\"critical\"",
        "\"event\":\"signature_match\"",
        "\"rule\":\"4237725842\"",
        "\"src_ip\":\"192.168.1.100\"",
        "\"src_port\":1234",
        "\"session_id\":7",
        "\"payload_len\":3",
        "\"policy\":\"alert\"",
        "\"policy_id\":9",
        "\"event_id\":101",
        "\"trace_id\":102",
        "\"audit_id\":103",
        "\"enforcement_status\":\"observed\"",
        "\"host_effect_confirmed\":false",
        "\"filter_id\":0",
        "\"request_id\":0",
        "\"receipt_version\":0",
    }) |key| {
        try std.testing.expect(std.mem.indexOf(u8, line, key) != null);
    }
    // No receipt keys leak onto an unconfirmed line.
    try std.testing.expect(std.mem.indexOf(u8, line, "\"decision\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, line, "\"provider\"") == null);
}

test "BE-EVI-097: formatLogLine receipt set satisfies every reader recipe" {
    // Confirmed line: the full receipt set desktop confirmed_block(),
    // web receipt_valid, and mouth is_confirmed_block() gate on.
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    formatLogLine(.{
        .level = .critical,
        .event = "signature_match",
        .rule = "4237725842",
        .src_ip = 0x0A000001,
        .policy = "block",
        .policy_id = 4,
        .event_id = 201,
        .trace_id = 202,
        .audit_id = 203,
        .enforcement_status = "enforced",
        .host_effect_confirmed = true,
        .filter_id = 301,
        .request_id = 302,
        .decision = "block",
        .provider = "wfp",
        .receipt_version = 1,
    }, 1700000000001, 9001, fbs.writer());
    const line = fbs.getWritten();
    for ([_][]const u8{
        "\"enforcement_status\":\"enforced\"",
        "\"host_effect_confirmed\":true",
        "\"filter_id\":301",
        "\"request_id\":302",
        "\"event_id\":201",
        "\"trace_id\":202",
        "\"audit_id\":203",
        "\"policy_id\":4",
        "\"decision\":\"block\"",
        "\"provider\":\"wfp\"",
        "\"receipt_version\":1",
    }) |key| {
        try std.testing.expect(std.mem.indexOf(u8, line, key) != null);
    }
}

test "RB-013: formatLogLine carries the confirmed-quarantine marker" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    formatLogLine(.{
        .level = .critical,
        .event = "action_quarantine",
        .rule = "4237725842",
        .src_ip = 0xCB00710A,
        .policy = "quarantine",
        .policy_id = 3,
        .event_id = 401,
        .trace_id = 402,
        .audit_id = 403,
        .enforcement_status = "enforced",
        .host_effect_confirmed = true,
        .filter_id = 78056,
        .request_id = 404,
        .decision = "quarantine",
        .extra = "QUARANTINED_CONFIRMED",
        .provider = "wfp",
        .receipt_version = 1,
    }, 1700000000003, 9003, fbs.writer());
    const line = fbs.getWritten();
    for ([_][]const u8{
        "\"event\":\"action_quarantine\"",
        "\"decision\":\"quarantine\"",
        "\"extra\":\"QUARANTINED_CONFIRMED\"",
        "\"enforcement_status\":\"enforced\"",
        "\"host_effect_confirmed\":true",
        "\"filter_id\":78056",
        "\"request_id\":404",
        "\"provider\":\"wfp\"",
        "\"receipt_version\":1",
    }) |key| {
        try std.testing.expect(std.mem.indexOf(u8, line, key) != null);
    }
}

test "BE-EVI-097: formatLogLine prefers v6 sidecars, escapes rule names" {
    var buf: [2048]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    // src_ipv6 carries pre-rendered text (the pipeline renders via the
    // same full-hextet formatter as the SIEM path); the /32 prefix must
    // never appear disguised as a dotted quad.
    const v6text = "2001:0db8:0000:0000:0000:0000:0000:0001";
    formatLogLine(.{
        .level = .warn,
        .event = "dns_query",
        .rule = "9003\"injected",
        .src_ip = 0x20010DB8,
        .src_ipv6 = v6text,
        .policy = "alert",
        .enforcement_status = "observed",
    }, 1700000000002, 9002, fbs.writer());
    const line = fbs.getWritten();
    // Full v6 text, never the dotted /32 prefix in disguise.
    try std.testing.expect(std.mem.indexOf(u8, line, "2001:0db8") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "32.1.13.184") == null);
    // Injection attempt in the rule name is escaped, line stays one line.
    try std.testing.expect(std.mem.indexOf(u8, line, "9003\\\"injected") != null);
    try std.testing.expect(std.mem.count(u8, line, "\n") == 1);
}
