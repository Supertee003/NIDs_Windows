//! forensic/alert_log.zig — ALERT-FILE-001 local, file-only alert writer.
//!
//! One append line per detection to a FIXED path (logs/alerts.ndjson).
//! No env var, no endpoint, no transport enum, no network code — the owner chose
//! file-based local alerting explicitly. This is deliberately NOT the SIEM
//! forwarder (which owns opt-in external transports); reusing it would inherit
//! an egress surface and a batch/spool path that cannot give an honest
//! "one line per detection" count.
//!
//! Invariants:
//!   - append() returns true only after a COMPLETE line + newline is written.
//!   - failure increments g_alerts_write_failed, never g_alerts_written.
//!   - no payload bytes, no raw packet text, no secret material is emitted.
//!   - output is JSON-escaped (IR-05 log-injection prevention).

const std = @import("std");
const builtin = @import("builtin");
const state = @import("../pipeline/runtime_state.zig");

pub const ALERT_PATH = "logs/alerts.ndjson";

pub const Alert = struct {
    ts_ms: i64,
    event_id: u64,
    rule_id: u32,
    severity: u8,
    /// Advisory label from policy evidence. Never a host-effect claim.
    action: []const u8 = "",
    /// Evidence status (observed/unconfirmed). Never BLOCKED_CONFIRMED.
    status: []const u8 = "",
    src_ip: ?[]const u8 = null,
    dst_ip: ?[]const u8 = null,
    src_port: ?u16 = null,
    dst_port: ?u16 = null,
    protocol: ?u8 = null,
    /// Short evidence note; escaped, length-bounded by the caller.
    evidence: ?[]const u8 = null,
    session_id: ?u64 = null,
    trace_id: ?u64 = null,
    audit_id: ?u64 = null,
};

/// Pure dotted-quad formatter for a big-endian u32 IPv4 address.
pub fn formatIp4(buf: *[15]u8, ip: u32) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
        (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
    }) catch "?"; // never invent a bind address in a detection alert
}

fn writeJsonEscaped(writer: anytype, s: []const u8) void {
    for (s) |c| {
        switch (c) {
            '"' => writer.writeAll("\\\"") catch return,
            '\\' => writer.writeAll("\\\\") catch return,
            '\n' => writer.writeAll("\\n") catch return,
            '\r' => writer.writeAll("\\r") catch return,
            '\t' => writer.writeAll("\\t") catch return,
            0...8, 11, 12, 14...31 => writer.print("\\u{x:0>4}", .{c}) catch return,
            else => writer.writeByte(c) catch return,
        }
    }
}

fn writeStringField(writer: anytype, key: []const u8, value: []const u8) void {
    writer.print(",\"{s}\":\"", .{key}) catch return;
    writeJsonEscaped(writer, value);
    writer.writeByte('"') catch return;
}

/// Pure NDJSON line formatter (no filesystem). Shared by append() and tests so
/// the contract pinned by E2 is exactly what the daemon writes.
pub fn formatAlertLine(alert: Alert, writer: anytype) void {
    writer.print("{{\"schema\":\"aegis.alert.v1\",\"ts_ms\":{d},\"event_id\":{d},\"rule_id\":{d},\"severity\":{d}", .{
        alert.ts_ms, alert.event_id, alert.rule_id, alert.severity,
    }) catch return;
    if (alert.action.len > 0) writeStringField(writer, "action", alert.action);
    if (alert.status.len > 0) writeStringField(writer, "status", alert.status);
    if (alert.src_ip) |ip| writeStringField(writer, "src_ip", ip);
    if (alert.dst_ip) |ip| writeStringField(writer, "dst_ip", ip);
    if (alert.src_port) |p| writer.print(",\"src_port\":{d}", .{p}) catch return;
    if (alert.dst_port) |p| writer.print(",\"dst_port\":{d}", .{p}) catch return;
    if (alert.protocol) |p| writer.print(",\"protocol\":{d}", .{p}) catch return;
    if (alert.evidence) |e| writeStringField(writer, "evidence", e);
    if (alert.session_id) |v| writer.print(",\"session_id\":{d}", .{v}) catch return;
    if (alert.trace_id) |v| writer.print(",\"trace_id\":{d}", .{v}) catch return;
    if (alert.audit_id) |v| writer.print(",\"audit_id\":{d}", .{v}) catch return;
    writer.writeByte('}') catch return;
}

var g_mutex: std.Thread.Mutex = .{};

/// Ensure the producer-owned logs/ directory exists. No env, no destination.
pub fn init() void {
    std.fs.cwd().makePath("logs") catch {};
}

/// Production append at the fixed path. Caller must pass a bounded alert.
pub fn append(alert: Alert) bool {
    return appendTo(ALERT_PATH, alert);
}

/// Test seam: explicit path override. NOT exposed via env/CLI — the production
/// path is fixed, so no config can turn this into an external transport.
pub fn appendTo(path: []const u8, alert: Alert) bool {
    g_mutex.lock();
    defer g_mutex.unlock();

    const file = std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch blk: {
        const created = std.fs.cwd().createFile(path, .{ .truncate = false, .read = false }) catch {
            _ = state.g_alerts_write_failed.fetchAdd(1, .monotonic);
            return false;
        };
        break :blk created;
    };
    defer file.close();
    file.seekFromEnd(0) catch {
        _ = state.g_alerts_write_failed.fetchAdd(1, .monotonic);
        return false;
    };

    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    formatAlertLine(alert, stream.writer());
    stream.writer().writeByte('\n') catch {
        _ = state.g_alerts_write_failed.fetchAdd(1, .monotonic);
        return false;
    };
    const line = stream.getWritten();
    file.writeAll(line) catch {
        _ = state.g_alerts_write_failed.fetchAdd(1, .monotonic);
        return false;
    };
    _ = state.g_alerts_written.fetchAdd(1, .monotonic);
    return true;
}

// ── E2 tests: pure formatter + tmp-dir append, no host effect ──────────────
const testing = std.testing;

test "formatAlertLine: schema and bounded fields, no payload key" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    formatAlertLine(.{
        .ts_ms = 1763550000123,
        .event_id = 42,
        .rule_id = 9006,
        .severity = 3,
        .action = "observe",
        .status = "unconfirmed",
        .src_ip = "10.0.0.1",
        .dst_port = 443,
        .protocol = 6,
    }, stream.writer());
    const line = stream.getWritten();
    try testing.expect(std.mem.startsWith(u8, line, "{\"schema\":\"aegis.alert.v1\""));
    try testing.expect(std.mem.indexOf(u8, line, "\"event_id\":42") != null);
    try testing.expect(std.mem.indexOf(u8, line, "\"rule_id\":9006") != null);
    try testing.expect(std.mem.indexOf(u8, line, "payload") == null);
    try testing.expect(line[line.len - 1] == '}');
}

test "formatAlertLine: escapes quotes and control chars (no log injection)" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    formatAlertLine(.{
        .ts_ms = 1,
        .event_id = 1,
        .rule_id = 1,
        .severity = 1,
        .evidence = "a\"b\\c\nd",
    }, stream.writer());
    const line = stream.getWritten();
    try testing.expect(std.mem.indexOf(u8, line, "a\\\"b\\\\c\\nd") != null);
}

test "formatIp4: dotted quad is big-endian" {
    var buf: [15]u8 = undefined;
    try testing.expectEqualStrings("10.0.0.1", formatIp4(&buf, 0x0A000001));
}

test "appendTo: two appends produce two valid NDJSON lines" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(root);
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/alerts.ndjson", .{root});
    defer testing.allocator.free(path);
    const before_written = state.g_alerts_written.load(.acquire);
    const before_failed = state.g_alerts_write_failed.load(.acquire);
    defer {
        // Restore so writer tests never become order-dependent.
        state.g_alerts_written.store(before_written, .release);
        state.g_alerts_write_failed.store(before_failed, .release);
    }

    const a = Alert{ .ts_ms = 1, .event_id = 1, .rule_id = 100, .severity = 2 };
    try testing.expect(appendTo(path, a));
    try testing.expect(appendTo(path, a));
    const data = try tmp.dir.readFileAlloc(testing.allocator, "alerts.ndjson", 4096);
    defer testing.allocator.free(data);
    var it = std.mem.splitScalar(u8, data, '\n');
    var lines: usize = 0;
    while (it.next()) |line| {
        if (line.len == 0) continue;
        lines += 1;
        try testing.expect(std.mem.indexOf(u8, line, "\"schema\":\"aegis.alert.v1\"") != null);
    }
    try testing.expectEqual(@as(usize, 2), lines);
    try testing.expectEqual(before_written + 2, state.g_alerts_written.load(.acquire));
    try testing.expectEqual(before_failed, state.g_alerts_write_failed.load(.acquire));
}
