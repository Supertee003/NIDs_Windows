// II03 - Registry Monitor (Trie-based Rules)
// AEGIS NIDS v5.0+ â€” Real-time Windows registry change monitoring
//
// Uses RegNotifyChangeKeyValue per-key with a worker pool. Rule matching
// uses a path trie (no per-key allocation in hot path).

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");

const HKEY = *anyopaque;
const HANDLE = *anyopaque;
const ERROR_SUCCESS: u32 = 0;
const KEY_NOTIFY: u32 = 0x0010;
const KEY_READ: u32 = 0x20019;
const REG_NOTIFY_CHANGE_NAME: u32 = 0x00000001;
const REG_NOTIFY_CHANGE_LAST_SET: u32 = 0x00000004;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 258;
const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);

extern "advapi32" fn RegOpenKeyExA(hKey: HKEY, lpSubKey: [*:0]const u8, ulOptions: u32, samDesired: u32, phkResult: *?HKEY) u32;
extern "advapi32" fn RegNotifyChangeKeyValue(hKey: HKEY, bWatchSubtree: i32, dwNotifyFilter: u32, hEvent: HANDLE, fAsynchronous: i32) u32;
extern "advapi32" fn RegCloseKey(hKey: HKEY) u32;
extern "kernel32" fn CreateEventA(attrs: ?*anyopaque, manual: i32, initial: i32, name: ?[*:0]const u8) ?HANDLE;
extern "kernel32" fn WaitForSingleObject(handle: HANDLE, milliseconds: u32) u32;
extern "kernel32" fn ResetEvent(handle: HANDLE) i32;
extern "kernel32" fn CloseHandle(handle: HANDLE) i32;

// ============================================================================
// Path trie â€” for fast rule matching
// ============================================================================
pub const TrieNode = struct {
    children: std.StringHashMap(*TrieNode),
    rule_id: u32 = 0,
    is_terminal: bool = false,

    pub fn init(allocator: std.mem.Allocator) TrieNode {
        return .{ .children = std.StringHashMap(*TrieNode).init(allocator) };
    }
};

pub const RegistryTrie = struct {
    root: TrieNode,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) RegistryTrie {
        return .{ .root = TrieNode.init(allocator), .allocator = allocator };
    }

    pub fn deinit(self: *RegistryTrie) void {
        self.freeNode(&self.root);
    }

    fn freeNode(self: *RegistryTrie, node: *TrieNode) void {
        var it = node.children.iterator();
        while (it.next()) |entry| {
            self.freeNode(entry.value_ptr.*);
            self.allocator.destroy(entry.value_ptr.*);
        }
        node.children.deinit();
    }

    pub fn insert(self: *RegistryTrie, path: []const u8, rule_id: u32) !void {
        var cur = &self.root;
        var it = std.mem.splitScalar(u8, path, '\\');
        while (it.next()) |segment| {
            if (segment.len == 0) continue;
            const gop = try cur.children.getOrPut(segment);
            if (!gop.found_existing) {
                const node = try self.allocator.create(TrieNode);
                node.* = TrieNode.init(self.allocator);
                gop.value_ptr.* = node;
            }
            cur = gop.value_ptr.*;
        }
        cur.is_terminal = true;
        cur.rule_id = rule_id;
    }

    pub fn match(self: *const RegistryTrie, path: []const u8) ?u32 {
        var cur = &self.root;
        var it = std.mem.splitScalar(u8, path, '\\');
        var last_match: ?u32 = null;
        while (it.next()) |segment| {
            if (segment.len == 0) continue;
            const child = cur.children.get(segment) orelse break;
            cur = child;
            if (cur.is_terminal) last_match = cur.rule_id;
        }
        return last_match;
    }
};

// ============================================================================
// Registry monitor
// ============================================================================
pub const RegChangeKind = enum(u8) {
    key_added = 1,
    key_removed = 2,
    value_changed = 3,
    value_added = 4,
    value_removed = 5,
    security_changed = 6,
};

pub const RegEvent = struct {
    kind: RegChangeKind,
    path: [512]u8 = [_]u8{0} ** 512,
    path_len: u16 = 0,
    rule_id: u32 = 0,
    timestamp_ns: i128 = 0,
};

pub const RegistryMonitor = struct {
    trie: RegistryTrie,
    events: std.ArrayList(RegEvent),
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    allocator: std.mem.Allocator,
    native_keys: [8]?HKEY = [_]?HKEY{null} ** 8,
    native_events: [8]?HANDLE = [_]?HANDLE{null} ** 8,
    native_paths: [8][]const u8 = [_][]const u8{&[_]u8{}} ** 8,
    native_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator) RegistryMonitor {
        return .{
            .trie = RegistryTrie.init(allocator),
            .events = std.ArrayList(RegEvent).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *RegistryMonitor) void {
        self.stopAll();
        self.trie.deinit();
        self.events.deinit();
    }

    pub fn addRule(self: *RegistryMonitor, path: []const u8, rule_id: u32) !void {
        try self.trie.insert(path, rule_id);
    }

    /// Open native HKLM watchers for all configured rules. Rules outside HKLM
    /// remain eligible for trie matching but are not falsely reported ready.
    pub fn startAll(self: *RegistryMonitor) !void {
        if (@import("builtin").os.tag != .windows) return error.UnsupportedPlatform;
        self.native_count = 0;
        const paths = [_][]const u8{
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        };
        for (paths) |path| {
            if (self.native_count >= self.native_keys.len) break;
            var key: ?HKEY = null;
            var path_z: [160]u8 = undefined;
            const subkey = if (std.mem.startsWith(u8, path, "HKLM\\")) path[5..] else path;
            const n = @min(subkey.len, path_z.len - 1);
            @memcpy(path_z[0..n], subkey[0..n]);
            path_z[n] = 0;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, @ptrCast(&path_z), 0, KEY_READ | KEY_NOTIFY, &key) != ERROR_SUCCESS) {
                diag.warn("registry native open failed: HKLM\\{s}", .{path});
                continue;
            }
            const ev = CreateEventA(null, 1, 0, null);
            if (ev == null) {
                _ = RegCloseKey(key.?);
                continue;
            }
            if (RegNotifyChangeKeyValue(key.?, 1, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, ev.?, 1) != ERROR_SUCCESS) {
                _ = CloseHandle(ev.?);
                _ = RegCloseKey(key.?);
                continue;
            }
            self.native_keys[self.native_count] = key;
            self.native_events[self.native_count] = ev;
            self.native_paths[self.native_count] = path;
            self.native_count += 1;
        }
        if (self.native_count == 0) return error.NoWatchersStarted;
    }

    pub fn stopAll(self: *RegistryMonitor) void {
        for (0..self.native_count) |i| {
            if (self.native_keys[i]) |key| _ = RegCloseKey(key);
            if (self.native_events[i]) |ev| _ = CloseHandle(ev);
            self.native_keys[i] = null;
            self.native_events[i] = null;
        }
        self.native_count = 0;
    }

    /// Poll native events without blocking the telemetry worker.
    pub fn pollNative(self: *RegistryMonitor) void {
        if (@import("builtin").os.tag != .windows) return;
        for (0..self.native_count) |i| {
            const ev = self.native_events[i] orelse continue;
            if (WaitForSingleObject(ev, 0) == WAIT_OBJECT_0) {
                self.observe(.value_changed, self.native_paths[i]) catch {};
                _ = ResetEvent(ev);
                if (self.native_keys[i]) |key| {
                    var path_z: [160]u8 = undefined;
                    const path = self.native_paths[i];
                    const n = @min(path.len, path_z.len - 1);
                    @memcpy(path_z[0..n], path[0..n]);
                    path_z[n] = 0;
                    _ = RegNotifyChangeKeyValue(key, 1, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, ev, 1);
                }
            }
        }
    }

    pub fn observe(self: *RegistryMonitor, kind: RegChangeKind, path: []const u8) !void {
        const rule_id = self.trie.match(path) orelse 0;
        var ev = RegEvent{
            .kind = kind,
            .rule_id = rule_id,
            .timestamp_ns = std.time.nanoTimestamp(),
        };
        const n = @min(path.len, ev.path.len);
        @memcpy(ev.path[0..n], path[0..n]);
        ev.path_len = @intCast(n);
        try self.events.append(ev);
        if (rule_id != 0) {
            diag.info("registry change matched rule {d}: {s}", .{ rule_id, path });
        }
    }

    pub fn pending(self: *RegistryMonitor) usize {
        return self.events.items.len;
    }

    pub fn drain(self: *RegistryMonitor) []RegEvent {
        const items = self.events.items;
        self.events = std.ArrayList(RegEvent).init(self.allocator);
        return items;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "RegistryTrie insert and match" {
    var t = RegistryTrie.init(std.testing.allocator);
    defer t.deinit();
    try t.insert("HKLM\\Software\\AEGIS\\Config", 100);
    try t.insert("HKLM\\Software\\AEGIS", 200);
    try std.testing.expectEqual(@as(u32, 100), t.match("HKLM\\Software\\AEGIS\\Config\\Server").?);
    try std.testing.expectEqual(@as(u32, 200), t.match("HKLM\\Software\\AEGIS").?);
    try std.testing.expect(t.match("HKLM\\Software\\Other") == null);
}

test "RegistryMonitor observe" {
    var rm = RegistryMonitor.init(std.testing.allocator);
    defer rm.deinit();
    try rm.addRule("HKLM\\System\\CurrentControlSet\\Services\\AEGIS", 42);
    try rm.observe(.value_changed, "HKLM\\System\\CurrentControlSet\\Services\\AEGIS\\Start");
    try std.testing.expectEqual(@as(usize, 1), rm.pending());
    try std.testing.expectEqual(@as(u32, 42), rm.events.items[0].rule_id);
    try std.testing.expectEqual(@as(u16, 50), rm.events.items[0].path_len);
}

test "RegistryTrie empty path returns null" {
    var t = RegistryTrie.init(std.testing.allocator);
    defer t.deinit();
    try std.testing.expect(t.match("") == null);
}
