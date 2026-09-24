// II02 - File Integrity Monitor (FIM)
// AEGIS NIDS v5.0+ â€” Recursive directory watcher using ReadDirectoryChangesW
// Backed by fim_native.c (the kernel-side completion routine).

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

// ============================================================================
// FIM rule model
// ============================================================================
pub const FimRule = struct {
    path: []const u8,
    recursive: bool = true,
    notify_filter: u32 = @bitCast(NotifyFilter.all),
};

pub const NotifyFilter = packed struct {
    file_name: bool = false,
    dir_name: bool = false,
    attributes: bool = false,
    size: bool = false,
    last_write: bool = false,
    last_access: bool = false,
    creation: bool = false,
    security: bool = false,
    _reserved: u24 = 0,

    pub const all = NotifyFilter{
        .file_name = true,
        .dir_name = true,
        .attributes = true,
        .size = true,
        .last_write = true,
        .creation = true,
        .security = true,
    };
};

pub const FimChangeKind = enum(u8) {
    added = 1,
    removed = 2,
    modified = 3,
    renamed_old = 4,
    renamed_new = 5,
    security_changed = 6,
};

pub const FimEvent = struct {
    kind: FimChangeKind,
    path: [512]u8 = [_]u8{0} ** 512,
    path_len: u16 = 0,
    timestamp_ns: i128 = 0,
    rule_id: u32 = 0,
};

pub const NotifyParseError = error{
    Truncated,
    InvalidRecord,
    UnsupportedAction,
    PathTooLong,
    InvalidUtf16,
};

/// Parse one Windows FILE_NOTIFY_INFORMATION record. The native helper may
/// return several records in one buffer; the returned offset is the start of
/// the next record. The normalized path is UTF-8 and relative to the watch
/// root, which is the form consumed by Rule-22 matching.
pub fn parseNotifyRecord(raw: []const u8, out: *FimEvent) NotifyParseError!usize {
    if (raw.len < 12) return error.Truncated;
    const next_offset = std.mem.readInt(u32, raw[0..4], .little);
    const action = std.mem.readInt(u32, raw[4..8], .little);
    const name_bytes = std.mem.readInt(u32, raw[8..12], .little);
    if ((name_bytes & 1) != 0 or name_bytes > raw.len - 12) return error.InvalidRecord;
    const record_len = if (next_offset == 0) raw.len else next_offset;
    if (record_len < 12 or record_len > raw.len) return error.InvalidRecord;
    out.kind = switch (action) {
        1 => .added,
        2 => .removed,
        3 => .modified,
        4 => .renamed_old,
        5 => .renamed_new,
        else => return error.UnsupportedAction,
    };
    const utf16 = raw[12 .. 12 + name_bytes];
    var i: usize = 0;
    var w: usize = 0;
    while (i < utf16.len) : (i += 2) {
        const code_unit = @as(u16, utf16[i]) | (@as(u16, utf16[i + 1]) << 8);
        if (code_unit == 0) break;
        // Proof roots and Windows system paths are normally ASCII. Rejecting
        // non-ASCII here is safer than silently corrupting a path and matching
        // the wrong file; a later revision can add full UTF-16 conversion.
        if (code_unit > 0x7f) return error.InvalidUtf16;
        if (w >= out.path.len) return error.PathTooLong;
        out.path[w] = @intCast(code_unit);
        w += 1;
    }
    out.path_len = @intCast(w);
    out.timestamp_ns = @intCast(std.time.nanoTimestamp());
    return record_len;
}

/// Convert the parser's watch-root-relative path into the canonical full path
/// required by file rules. This keeps parsing and root identity separate.
pub fn qualifyPath(root: []const u8, relative: []const u8, out: *FimEvent) NotifyParseError!void {
    const needs_separator = root.len > 0 and root[root.len - 1] != '\\' and root[root.len - 1] != '/';
    const total = root.len + (if (needs_separator and relative.len > 0) @as(usize, 1) else 0) + relative.len;
    if (total > out.path.len) return error.PathTooLong;
    var offset: usize = 0;
    if (root.len > 0) {
        @memcpy(out.path[0..root.len], root);
        offset = root.len;
    }
    if (needs_separator and relative.len > 0) {
        out.path[offset] = '\\';
        offset += 1;
    }
    if (relative.len > 0) @memcpy(out.path[offset .. offset + relative.len], relative);
    out.path_len = @intCast(total);
}

// ============================================================================
// Native FFI
// ============================================================================
extern "aegis_fim_helper" fn aegis_fim_start(path: [*:0]const u8, recursive: u32, filter: u32) ?*anyopaque;
extern "aegis_fim_helper" fn aegis_fim_stop(handle: *anyopaque) c_int;
extern "aegis_fim_helper" fn aegis_fim_poll(handle: *anyopaque, out_buf: [*]u8, out_len: usize) c_int;

pub const FimWatcher = struct {
    handles: [8]?*anyopaque = [_]?*anyopaque{null} ** 8,
    handle_rule_indices: [8]usize = [_]usize{0} ** 8,
    handle_count: usize = 0,
    rules: std.ArrayList(FimRule),
    allocator: std.mem.Allocator,
    poll_buf: [16384]u8 = undefined,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active_rule_index: usize = 0,

    pub fn init(allocator: std.mem.Allocator) FimWatcher {
        return .{
            .rules = std.ArrayList(FimRule).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FimWatcher) void {
        self.stopAll();
        for (self.rules.items) |r| {
            self.allocator.free(r.path);
        }
        self.rules.deinit();
    }

    pub fn addRule(self: *FimWatcher, path: []const u8, recursive: bool) !void {
        try self.rules.append(.{
            .path = try self.allocator.dupe(u8, path),
            .recursive = recursive,
        });
    }

    pub fn startAll(self: *FimWatcher) !void {
        if (@import("builtin").os.tag != .windows) return error.UnsupportedPlatform;
        self.handle_count = 0;
        self.handle_rule_indices = [_]usize{0} ** 8;
        var started: usize = 0;
        for (self.rules.items, 0..) |r, rule_index| {
            const path_z = try self.allocator.dupeZ(u8, r.path);
            defer self.allocator.free(path_z);
            const handle = aegis_fim_start(path_z.ptr, if (r.recursive) 1 else 0, @bitCast(NotifyFilter.all));
            if (handle == null) {
                diag.err("aegis_fim_start failed for {s}", .{r.path});
                continue;
            }
            if (self.handle_count >= self.handles.len) {
                _ = aegis_fim_stop(handle.?);
                break;
            }
            self.handles[self.handle_count] = handle;
            self.handle_rule_indices[self.handle_count] = rule_index;
            self.handle_count += 1;
            started += 1;
            diag.info("FIM watching {s} (recursive={})", .{ r.path, r.recursive });
        }
        // A worker is ready only when at least one requested watcher is live.
        // Previously every native-start failure was swallowed and the worker
        // still published running=true, producing a false healthy capability.
        if (started == 0) return error.NoWatchersStarted;
        self.running.store(true, .release);
    }

    pub fn stopAll(self: *FimWatcher) void {
        self.running.store(false, .release);
        for (self.handles[0..self.handle_count]) |maybe_handle| {
            if (maybe_handle) |h| _ = aegis_fim_stop(h);
        }
        self.handles = [_]?*anyopaque{null} ** 8;
        self.handle_rule_indices = [_]usize{0} ** 8;
        self.handle_count = 0;
    }

    pub fn poll(self: *FimWatcher) []u8 {
        for (self.handles[0..self.handle_count], 0..) |maybe_handle, index| {
            if (maybe_handle) |h| {
                const n = aegis_fim_poll(h, &self.poll_buf, self.poll_buf.len);
                if (n > 0) {
                    self.active_rule_index = index;
                    return self.poll_buf[0..@intCast(n)];
                }
            }
        }
        return &[_]u8{};
    }

    pub fn activeRoot(self: *const FimWatcher) []const u8 {
        if (self.active_rule_index < self.handle_count) {
            const rule_index = self.handle_rule_indices[self.active_rule_index];
            if (rule_index < self.rules.items.len) return self.rules.items[rule_index].path;
        }
        return &[_]u8{};
    }
};

// ============================================================================
// Tests
// ============================================================================
test "FimWatcher addRule" {
    var w = FimWatcher.init(std.testing.allocator);
    defer w.deinit();
    try w.addRule("C:\\Windows\\System32", true);
    try std.testing.expectEqual(@as(usize, 1), w.rules.items.len);
    try std.testing.expect(w.rules.items[0].recursive);
}

test "FimWatcher startAll on non-Windows fails" {
    var w = FimWatcher.init(std.testing.allocator);
    defer w.deinit();
    try w.addRule("/tmp", true);
    if (@import("builtin").os.tag == .windows) {
        // Native watcher validation belongs to the Windows acceptance harness.
        // `/tmp` is a POSIX path and is not a valid Windows fixture.
        return error.SkipZigTest;
    } else {
        try std.testing.expectError(error.UnsupportedPlatform, w.startAll());
    }
}

test "NotifyFilter all bits set" {
    const f = NotifyFilter.all;
    const bits = @as(u32, @bitCast(f));
    try std.testing.expect(bits != 0);
}

test "FILE_NOTIFY_INFORMATION record normalizes an added path" {
    var raw = [_]u8{0} ** 24;
    std.mem.writeInt(u32, raw[0..4], 0, .little);
    std.mem.writeInt(u32, raw[4..8], 1, .little);
    std.mem.writeInt(u32, raw[8..12], 10, .little);
    const name = "a.txt";
    for (name, 0..) |c, i| {
        const code_unit: u16 = c;
        raw[12 + i * 2] = @truncate(code_unit);
        raw[13 + i * 2] = @truncate(code_unit >> 8);
    }
    var out: FimEvent = .{ .kind = .modified };
    const used = try parseNotifyRecord(&raw, &out);
    try std.testing.expectEqual(@as(usize, 24), used);
    try std.testing.expectEqual(FimChangeKind.added, out.kind);
    try std.testing.expectEqualStrings("a.txt", out.path[0..out.path_len]);
}

test "FILE_NOTIFY_INFORMATION rejects truncated records" {
    var out: FimEvent = .{ .kind = .modified };
    try std.testing.expectError(error.Truncated, parseNotifyRecord(&[_]u8{ 0, 0, 0 }, &out));
}

test "qualifyPath restores watch root context" {
    var out: FimEvent = .{ .kind = .modified };
    try qualifyPath("C:\\Windows\\System32", "drivers\\aegis.sys", &out);
    try std.testing.expectEqualStrings("C:\\Windows\\System32\\drivers\\aegis.sys", out.path[0..out.path_len]);
}
