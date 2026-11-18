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
const ERROR_NO_MORE_ITEMS: u32 = 259;
const HKEY_LOCAL_MACHINE: HKEY = @ptrFromInt(0x80000002);
const HKEY_USERS: HKEY = @ptrFromInt(0x80000003);

extern "advapi32" fn RegOpenKeyExA(hKey: HKEY, lpSubKey: [*:0]const u8, ulOptions: u32, samDesired: u32, phkResult: *?HKEY) u32;
extern "advapi32" fn RegEnumKeyExA(hKey: HKEY, dwIndex: u32, lpName: [*]u8, lpcchName: *u32, lpReserved: ?*u32, lpClass: ?[*]u8, lpcchClass: ?*u32, lpftLastWriteTime: ?*anyopaque) u32;
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
            // Keys are lowercase-owned copies made by insert (registry paths
            // are case-insensitive); borrowed slices must never be freed.
            self.allocator.free(entry.key_ptr.*);
        }
        node.children.deinit();
    }

    pub fn insert(self: *RegistryTrie, path: []const u8, rule_id: u32) !void {
        var cur = &self.root;
        var it = std.mem.splitScalar(u8, path, '\\');
        while (it.next()) |segment| {
            if (segment.len == 0) continue;
            // Own a lowercase copy: Windows registry paths are
            // case-insensitive, so `...\Run` and `...\RUN` are one rule.
            // Bounded: overlong segments cannot match and are skipped.
            if (segment.len > 256) continue;
            const lower = try self.allocator.dupe(u8, segment);
            errdefer self.allocator.free(lower);
            for (lower) |*c| c.* = std.ascii.toLower(c.*);
            const gop = try cur.children.getOrPut(lower);
            if (!gop.found_existing) {
                const node = try self.allocator.create(TrieNode);
                node.* = TrieNode.init(self.allocator);
                gop.value_ptr.* = node;
            } else {
                self.allocator.free(lower);
            }
            cur = gop.value_ptr.*;
        }
        cur.is_terminal = true;
        cur.rule_id = rule_id;
    }

    pub fn match(self: *const RegistryTrie, path: []const u8) ?u32 {
        var cur = &self.root;
        var it = std.mem.splitScalar(u8, path, '\\');
        var lower_buf: [256]u8 = undefined;
        var last_match: ?u32 = null;
        while (it.next()) |segment| {
            if (segment.len == 0) continue;
            if (segment.len > lower_buf.len) break;
            for (segment, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
            const child = cur.children.get(lower_buf[0..segment.len]) orelse break;
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

pub const MAX_WATCHERS: usize = 32;

pub const RegistryMonitor = struct {
    trie: RegistryTrie,
    events: std.ArrayList(RegEvent),
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    allocator: std.mem.Allocator,
    native_keys: [MAX_WATCHERS]?HKEY = [_]?HKEY{null} ** MAX_WATCHERS,
    native_events: [MAX_WATCHERS]?HANDLE = [_]?HANDLE{null} ** MAX_WATCHERS,
    /// Event path (what actually changed, e.g. HKU\<SID>\...\Run) and the
    /// normalized path used for rule matching (e.g. HKCU\...\Run).
    native_event_paths: [MAX_WATCHERS][512]u8 = undefined,
    native_match_paths: [MAX_WATCHERS][512]u8 = undefined,
    native_event_lens: [MAX_WATCHERS]u16 = [_]u16{0} ** MAX_WATCHERS,
    native_match_lens: [MAX_WATCHERS]u16 = [_]u16{0} ** MAX_WATCHERS,
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

    /// Open native watchers for the configured registry rules:
    ///  - HKLM\SYSTEM\CurrentControlSet\Services
    ///  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    ///  - HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run for every
    ///    loaded user hive (AEGIS runs as SYSTEM, so HKCU would be SYSTEM's
    ///    hive, not the interactive user's; HKU enumeration is required).
    /// The match path for a user hive is normalized to HKCU\... so one rule
    /// covers every user, while the event path keeps the SID for attribution.
    pub fn startAll(self: *RegistryMonitor) !void {
        if (@import("builtin").os.tag != .windows) return error.UnsupportedPlatform;
        self.native_count = 0;
        self.openWatcher(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        );
        self.openWatcher(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        );
        self.watchUserHives();
        if (self.native_count == 0) return error.NoWatchersStarted;
    }

    fn watchUserHives(self: *RegistryMonitor) void {
        var users: ?HKEY = null;
        if (RegOpenKeyExA(HKEY_USERS, "", 0, KEY_READ, &users) != ERROR_SUCCESS) {
            diag.warn("registry HKEY_USERS open failed; HKCU rules have no watcher", .{});
            return;
        }
        defer _ = RegCloseKey(users.?);
        var index: u32 = 0;
        while (index < 64 and self.native_count < self.native_keys.len) : (index += 1) {
            var name_buf: [256]u8 = undefined;
            var name_len: u32 = @intCast(name_buf.len);
            const rc = RegEnumKeyExA(users.?, index, &name_buf, &name_len, null, null, null, null);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            const sid = name_buf[0..name_len];
            var sub_buf: [320]u8 = undefined;
            const subkey = std.fmt.bufPrint(
                &sub_buf,
                "{s}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                .{sid},
            ) catch continue;
            var event_buf: [512]u8 = undefined;
            const event_path = std.fmt.bufPrint(
                &event_buf,
                "HKU\\{s}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                .{sid},
            ) catch continue;
            self.openWatcher(
                HKEY_USERS,
                subkey,
                event_path,
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            );
        }
    }

    fn openWatcher(
        self: *RegistryMonitor,
        root: HKEY,
        subkey: []const u8,
        event_path: []const u8,
        match_path: []const u8,
    ) void {
        if (self.native_count >= self.native_keys.len) return;
        var key: ?HKEY = null;
        var subkey_z: [320]u8 = undefined;
        if (subkey.len >= subkey_z.len) return;
        @memcpy(subkey_z[0..subkey.len], subkey);
        subkey_z[subkey.len] = 0;
        if (RegOpenKeyExA(root, @ptrCast(&subkey_z), 0, KEY_READ | KEY_NOTIFY, &key) != ERROR_SUCCESS) return;
        const ev = CreateEventA(null, 1, 0, null);
        if (ev == null) {
            _ = RegCloseKey(key.?);
            return;
        }
        if (RegNotifyChangeKeyValue(key.?, 1, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, ev.?, 1) != ERROR_SUCCESS) {
            _ = CloseHandle(ev.?);
            _ = RegCloseKey(key.?);
            return;
        }
        const idx = self.native_count;
        self.native_keys[idx] = key;
        self.native_events[idx] = ev;
        const event_len = @min(event_path.len, self.native_event_paths[idx].len);
        @memcpy(self.native_event_paths[idx][0..event_len], event_path[0..event_len]);
        self.native_event_lens[idx] = @intCast(event_len);
        const match_len = @min(match_path.len, self.native_match_paths[idx].len);
        @memcpy(self.native_match_paths[idx][0..match_len], match_path[0..match_len]);
        self.native_match_lens[idx] = @intCast(match_len);
        self.native_count += 1;
    }

    pub fn stopAll(self: *RegistryMonitor) void {
        for (0..self.native_count) |i| {
            if (self.native_keys[i]) |key| _ = RegCloseKey(key);
            if (self.native_events[i]) |ev| _ = CloseHandle(ev);
            self.native_keys[i] = null;
            self.native_events[i] = null;
            self.native_event_lens[i] = 0;
            self.native_match_lens[i] = 0;
        }
        self.native_count = 0;
    }

    /// Poll native events without blocking the telemetry worker.
    pub fn pollNative(self: *RegistryMonitor) void {
        if (@import("builtin").os.tag != .windows) return;
        for (0..self.native_count) |i| {
            const ev = self.native_events[i] orelse continue;
            if (WaitForSingleObject(ev, 0) == WAIT_OBJECT_0) {
                const event_path = self.native_event_paths[i][0..self.native_event_lens[i]];
                const match_path = self.native_match_paths[i][0..self.native_match_lens[i]];
                self.observeMatch(.value_changed, event_path, match_path) catch {};
                _ = ResetEvent(ev);
                if (self.native_keys[i]) |key| {
                    // REG-REARM-060: a failed re-arm silently blinds this key
                    // (one-shot notification spent, no next fire). Surface it
                    // loudly instead of losing coverage without a trace.
                    const rc = RegNotifyChangeKeyValue(key, 1, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, ev, 1);
                    if (rc != ERROR_SUCCESS) {
                        diag.warn("registry re-arm failed: rc={d} - key unwatched until restart", .{rc});
                    }
                }
            }
        }
    }

    pub fn observe(self: *RegistryMonitor, kind: RegChangeKind, path: []const u8) !void {
        try self.observeMatch(kind, path, path);
    }

    /// `event_path` is what the record carries (keeps the SID for HKU);
    /// `match_path` is what the trie matches (HKCU\...). Normalizing only the
    /// match keeps attribution while one rule covers every user hive.
    fn observeMatch(self: *RegistryMonitor, kind: RegChangeKind, event_path: []const u8, match_path: []const u8) !void {
        const rule_id = self.trie.match(match_path) orelse 0;
        var ev = RegEvent{
            .kind = kind,
            .rule_id = rule_id,
            .timestamp_ns = std.time.nanoTimestamp(),
        };
        const n = @min(event_path.len, ev.path.len);
        @memcpy(ev.path[0..n], event_path[0..n]);
        ev.path_len = @intCast(n);
        try self.events.append(ev);
        if (rule_id != 0) {
            diag.info("registry change matched rule {d}: {s}", .{ rule_id, event_path });
        }
    }

    pub fn pending(self: *RegistryMonitor) usize {
        return self.events.items.len;
    }

    pub fn drain(self: *RegistryMonitor) []RegEvent {
        // Single consumer (registryThread) drains before the next poll, so
        // the backing buffer is reused instead of leaked per drain call.
        const items = self.events.items;
        self.events.clearRetainingCapacity();
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

test "REG-HKCU-001 user-hive event matches the HKCU rule and keeps the SID" {
    var rm = RegistryMonitor.init(std.testing.allocator);
    defer rm.deinit();
    try rm.addRule("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 3);
    const event_path = "HKU\\S-1-5-21-111-222-333-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const match_path = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    try rm.observeMatch(.value_changed, event_path, match_path);
    try std.testing.expectEqual(@as(usize, 1), rm.pending());
    try std.testing.expectEqual(@as(u32, 3), rm.events.items[0].rule_id);
    try std.testing.expectEqual(@as(u16, @intCast(event_path.len)), rm.events.items[0].path_len);
    try std.testing.expectEqualStrings(event_path, rm.events.items[0].path[0..rm.events.items[0].path_len]);
}

test "RegistryTrie match is case-insensitive (Windows semantics)" {
    var t = RegistryTrie.init(std.testing.allocator);
    defer t.deinit();
    try t.insert("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 1);
    try std.testing.expectEqual(@as(u32, 1), t.match("hklm\\software\\microsoft\\windows\\currentversion\\run").?);
    try std.testing.expectEqual(@as(u32, 1), t.match("HKLM\\Software\\Microsoft\\WINDOWS\\CurrentVersion\\RUN\\evil").?);
    try std.testing.expect(t.match("HKLM\\SOFTWARE\\Other") == null);
}

test "RegistryMonitor drain reuses backing without leaking" {
    var rm = RegistryMonitor.init(std.testing.allocator);
    defer rm.deinit();
    try rm.addRule("HKLM\\System", 7);
    try rm.observe(.value_changed, "HKLM\\SYSTEM\\x");
    const first = rm.drain();
    try std.testing.expectEqual(@as(usize, 1), first.len);
    try std.testing.expectEqual(@as(u32, 7), first[0].rule_id);
    try std.testing.expectEqual(@as(usize, 0), rm.pending());
    try rm.observe(.value_changed, "HKLM\\system\\y");
    try std.testing.expectEqual(@as(usize, 1), rm.pending());
}

test "RegistryTrie empty path returns null" {
    var t = RegistryTrie.init(std.testing.allocator);
    defer t.deinit();
    try std.testing.expect(t.match("") == null);
}
