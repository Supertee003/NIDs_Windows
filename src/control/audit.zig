//! control/audit.zig — Structured Audit Log for Control Plane
//!
//! Every command execution produces an audit entry with timing, result, and caller info.
//! The audit log is a ring buffer in memory, exported to logs/control_audit.ndjson.

const std = @import("std");
const protocol = @import("protocol.zig");

pub const AuditEntry = struct {
    timestamp_ms: i64,
    request_id: u64,
    command: protocol.Command,
    command_name: []const u8,
    caller_role: protocol.Role,
    caller_pid: u32,
    ok: bool,
    code: []const u8,
    latency_ms: u64,
    payload_len: usize,
};

const MAX_AUDIT_ENTRIES: usize = 4096;

pub const AuditLog = struct {
    entries: [MAX_AUDIT_ENTRIES]AuditEntry = undefined,
    head: usize = 0,
    count: usize = 0,
    mutex: std.Thread.Mutex = .{},
    total_commands: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    total_mutation: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn record(self: *AuditLog, entry: AuditEntry) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries[self.head] = entry;
        self.head = (self.head + 1) % MAX_AUDIT_ENTRIES;
        if (self.count < MAX_AUDIT_ENTRIES) self.count += 1;
        _ = self.total_commands.fetchAdd(1, .monotonic);
        if (!entry.ok) _ = self.total_errors.fetchAdd(1, .monotonic);
        if (protocol.contract(entry.command).is_mutation) _ = self.total_mutation.fetchAdd(1, .monotonic);
    }

    pub fn recent(self: *AuditLog, n: usize) []AuditEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        const available = if (n > self.count) self.count else n;
        const start = if (self.count >= MAX_AUDIT_ENTRIES)
            (self.head + MAX_AUDIT_ENTRIES - available) % MAX_AUDIT_ENTRIES
        else
            0;
        // Return a slice of the ring buffer (valid until next lock)
        return self.entries[start .. start + available];
    }

    pub fn toJson(self: *AuditLog, a: std.mem.Allocator) ![]u8 {
        var arr = std.ArrayList(u8).init(a);
        var writer = arr.writer();
        try writer.writeByte('[');
        self.mutex.lock();
        const n = self.count;
        const h = self.head;
        self.mutex.unlock();
        const start = if (n >= MAX_AUDIT_ENTRIES)
            (h + MAX_AUDIT_ENTRIES - n) % MAX_AUDIT_ENTRIES
        else
            0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const idx = (start + i) % MAX_AUDIT_ENTRIES;
            const e = self.entries[idx];
            if (i > 0) try writer.writeByte(',');
            try std.json.stringify(e, .{}, writer);
        }
        try writer.writeByte(']');
        return arr.toOwnedSlice();
    }
};

/// Global audit log instance.
pub var g_audit = AuditLog{};

// ============================================================
// Tests
// ============================================================

test "AuditLog ring buffer basic" {
    var log = AuditLog{};
    const entry = AuditEntry{
        .timestamp_ms = 1000,
        .request_id = 1,
        .command = .system_status,
        .command_name = "system.status",
        .caller_role = .read,
        .caller_pid = 1234,
        .ok = true,
        .code = "OK",
        .latency_ms = 5,
        .payload_len = 0,
    };
    log.record(entry);
    try std.testing.expectEqual(@as(usize, 1), log.count);
    try std.testing.expectEqual(@as(u64, 1), log.total_commands.load(.monotonic));
}

test "AuditLog wraps around" {
    var log = AuditLog{};
    var i: u64 = 0;
    while (i < MAX_AUDIT_ENTRIES + 10) : (i += 1) {
        log.record(.{
            .timestamp_ms = 0,
            .request_id = i,
            .command = .system_status,
            .command_name = "system.status",
            .caller_role = .read,
            .caller_pid = 0,
            .ok = true,
            .code = "OK",
            .latency_ms = 0,
            .payload_len = 0,
        });
    }
    try std.testing.expectEqual(MAX_AUDIT_ENTRIES, log.count);
    try std.testing.expectEqual(i, log.total_commands.load(.monotonic));
}
