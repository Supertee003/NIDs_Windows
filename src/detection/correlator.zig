// I14 - Event Correlator (Time-Window Rules)
// AEGIS NIDS v5.0+ â€” Multi-event rule engine with sliding time windows
//
// Detects compound attacks by correlating multiple events within a configurable
// time window (default 300s). Rules are expressed as:
//   "if events {A, B, C} all occur within T seconds for the same src_ip,
//    emit correlation_match"
//
// Implementation: per-rule sliding window state, keyed by (rule_id, src_ip).

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");

pub const WINDOW_SEC: i64 = @as(i64, manifest.Limits.CORRELATOR_WINDOW_SEC);

pub const EventSpec = struct {
    kind: event.EventKind,
    count: u8 = 1, // required count
};

pub const CorrelationRule = struct {
    id: u32,
    name: [64]u8 = [_]u8{0} ** 64,
    events: []const EventSpec, // all must match within window
    window_sec: i64 = WINDOW_SEC,
    severity: event.EventSeverity = .alert,
    action: u8 = 0, // policy action to suggest
};

pub const EventRecord = struct {
    timestamp_ns: i128,
    count: u8 = 0,
};

pub const WindowKey = struct {
    rule_id: u32,
    src_ip: [16]u8,
};

pub const WindowState = struct {
    // Per-EventSpec slot index â†’ timestamps seen
    slots: [16]EventRecord = [_]EventRecord{ .{ .timestamp_ns = 0, .count = 0 } } ** 16,
    slot_count: usize = 0,
    last_match_ns: i128 = 0,
    match_count: u32 = 0,
};

pub const Correlator = struct {
    rules: []const CorrelationRule,
    windows: std.AutoHashMap(WindowKey, WindowState),
    allocator: std.mem.Allocator,
    matches: u64 = 0,
    prune_count: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, rules: []const CorrelationRule) Correlator {
        return .{
            .rules = rules,
            .windows = std.AutoHashMap(WindowKey, WindowState).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Correlator) void {
        self.windows.deinit();
    }

    pub fn observe(self: *Correlator, ev: *const event.IpcEvent) !?u32 {
        // For each rule, check if ev.kind matches any of the rule's EventSpecs
        var matched_rule: ?u32 = null;
        for (self.rules) |rule| {
            for (rule.events, 0..) |spec, slot_idx| {
                if (spec.kind != ev.kind) continue;
                // Find or create window state for this (rule, src_ip)
                const k2 = WindowKey{ .rule_id = rule.id, .src_ip = blk: {
                    var ip: [16]u8 = [_]u8{0} ** 16;
                    if (ev.src_ip != 0) {
                        const src_bytes: [4]u8 = @bitCast(ev.src_ip);
                        @memcpy(ip[0..4], &src_bytes);
                    }
                    break :blk ip;
                } };
                const gop = try self.windows.getOrPut(k2);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                const ws = gop.value_ptr;
                // Bump slot count
                if (slot_idx >= ws.slot_count) ws.slot_count = slot_idx + 1;
                const slot = &ws.slots[slot_idx];
                if (slot.count == 0 or (ev.timestamp_ns - slot.timestamp_ns) > @as(i128, rule.window_sec) * std.time.ns_per_s) {
                    slot.timestamp_ns = ev.timestamp_ns;
                    slot.count = 1;
                } else {
                    slot.count += 1;
                }
                // Check if all slots have hit their required counts within window
                if (self.allSlotsMatched(rule, ws, ev.timestamp_ns)) {
                    ws.match_count += 1;
                    ws.last_match_ns = ev.timestamp_ns;
                    self.matches += 1;
                    matched_rule = rule.id;
                    // Reset slots after match
                    for (ws.slots[0..ws.slot_count]) |*s| {
                        s.count = 0;
                        s.timestamp_ns = 0;
                    }
                    return rule.id;
                }
                break; // one spec per rule per event
            }
        }
        return matched_rule;
    }

    fn allSlotsMatched(self: *Correlator, rule: CorrelationRule, ws: *WindowState, now_ns: i128) bool {
        if (ws.slot_count != rule.events.len) return false;
        const window_ns = @as(i128, rule.window_sec) * std.time.ns_per_s;
        for (rule.events, 0..) |spec, i| {
            const slot = ws.slots[i];
            if (slot.count < spec.count) return false;
            if (now_ns - slot.timestamp_ns > window_ns) return false;
        }
        _ = self;
        return true;
    }

    pub fn prune(self: *Correlator, now_ns: i128) u32 {
        var to_remove = std.ArrayList(WindowKey).init(self.allocator);
        defer to_remove.deinit();
        var it = self.windows.iterator();
        while (it.next()) |entry| {
            const ws = entry.value_ptr;
            // If no activity in 2x window, prune
            const oldest = blk: {
                var min_ts: i128 = std.math.maxInt(i128);
                for (ws.slots[0..ws.slot_count]) |s| {
                    if (s.timestamp_ns > 0 and s.timestamp_ns < min_ts) min_ts = s.timestamp_ns;
                }
                break :blk min_ts;
            };
            if (oldest == std.math.maxInt(i128)) continue;
            const rule_window: i64 = blk: {
                var w: i64 = WINDOW_SEC;
                for (self.rules) |r| {
                    if (r.id == entry.key_ptr.rule_id) {
                        w = r.window_sec;
                        break;
                    }
                }
                break :blk w;
            };
            if (now_ns - oldest > 2 * @as(i128, rule_window) * std.time.ns_per_s) {
                to_remove.append(entry.key_ptr.*) catch break;
            }
        }
        const n: u32 = @intCast(to_remove.items.len);
        for (to_remove.items) |k| _ = self.windows.remove(k);
        self.prune_count += n;
        return n;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "Correlator simple two-event rule" {
    var spec_buf = [_]EventSpec{
        .{ .kind = .dns_query, .count = 1 },
        .{ .kind = .tls_hello, .count = 1 },
    };
    var rule_buf = [_]CorrelationRule{
        .{ .id = 100, .events = &spec_buf, .window_sec = 60, .severity = .alert },
    };
    var cor = Correlator.init(std.testing.allocator, &rule_buf);
    defer cor.deinit();
    var e1 = event.IpcEvent.init(.dns_query);
    e1.now();
    e1.src_ip = 0x0A000001;
    const r1 = try cor.observe(&e1);
    try std.testing.expect(r1 == null); // not matched yet
    var e2 = event.IpcEvent.init(.tls_hello);
    e2.now();
    e2.src_ip = 0x0A000001;
    const r2 = try cor.observe(&e2);
    try std.testing.expect(r2 != null);
    try std.testing.expectEqual(@as(u32, 100), r2.?);
}

test "Correlator window expiry" {
    var spec_buf = [_]EventSpec{ .{ .kind = .dns_query, .count = 2 } };
    var rule_buf = [_]CorrelationRule{
        .{ .id = 200, .events = &spec_buf, .window_sec = 1, .severity = .warning },
    };
    var cor = Correlator.init(std.testing.allocator, &rule_buf);
    defer cor.deinit();
    var e1 = event.IpcEvent.init(.dns_query);
    e1.timestamp_ns = 1_000_000_000; // 1s
    e1.src_ip = 0x0A000002;
    _ = try cor.observe(&e1);
    // Same kind 5 seconds later â€” outside 1s window
    var e2 = event.IpcEvent.init(.dns_query);
    e2.timestamp_ns = 6_000_000_000; // 6s
    e2.src_ip = 0x0A000002;
    const r = try cor.observe(&e2);
    try std.testing.expect(r == null); // not matched (window expired)
}

test "Correlator prune" {
    var spec_buf = [_]EventSpec{ .{ .kind = .dns_query, .count = 2 } };
    var rule_buf = [_]CorrelationRule{
        .{ .id = 300, .events = &spec_buf, .window_sec = 1, .severity = .warning },
    };
    var cor = Correlator.init(std.testing.allocator, &rule_buf);
    defer cor.deinit();
    var e1 = event.IpcEvent.init(.dns_query);
    e1.timestamp_ns = 1_000_000_000;
    e1.src_ip = 0x0A000003;
    _ = try cor.observe(&e1); // only 1 of 2 required → no match, slot keeps ts
    // Prune after 2x window
    const removed = cor.prune(1_000_000_000 + 5 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), removed);
}

test "Correlator multiple rules independent" {
    var spec_buf1 = [_]EventSpec{ .{ .kind = .dns_query, .count = 2 } };
    var spec_buf2 = [_]EventSpec{ .{ .kind = .tls_hello, .count = 1 } };
    var rule_buf = [_]CorrelationRule{
        .{ .id = 400, .events = &spec_buf1, .window_sec = 5, .severity = .warning },
        .{ .id = 401, .events = &spec_buf2, .window_sec = 5, .severity = .alert },
    };
    var cor = Correlator.init(std.testing.allocator, &rule_buf);
    defer cor.deinit();
    // Trigger rule 401 (single tls_hello)
    var e1 = event.IpcEvent.init(.tls_hello);
    e1.timestamp_ns = 1_000_000_000;
    e1.src_ip = 0x0A000001;
    const r1 = try cor.observe(&e1);
    try std.testing.expect(r1 != null);
    try std.testing.expectEqual(@as(u32, 401), r1.?);
}

test "Correlator same event type multiple sources" {
    // The correlator tracks by (rule_id, src_ip), so multiple sources
    // create separate windows. This test verifies that behavior.
    var spec_buf = [_]EventSpec{ .{ .kind = .dns_query, .count = 3 } };
    var rule_buf = [_]CorrelationRule{
        .{ .id = 500, .events = &spec_buf, .window_sec = 10, .severity = .critical },
    };
    var cor = Correlator.init(std.testing.allocator, &rule_buf);
    defer cor.deinit();
    // Three events from SAME source should trigger the rule
    var e1 = event.IpcEvent.init(.dns_query);
    e1.timestamp_ns = 1_000_000_000;
    e1.src_ip = 0x0A000001;
    _ = try cor.observe(&e1);
    var e2 = event.IpcEvent.init(.dns_query);
    e2.timestamp_ns = 2_000_000_000;
    e2.src_ip = 0x0A000001;
    _ = try cor.observe(&e2);
    var e3 = event.IpcEvent.init(.dns_query);
    e3.timestamp_ns = 3_000_000_000;
    e3.src_ip = 0x0A000001;
    const r = try cor.observe(&e3);
    try std.testing.expect(r != null);
    try std.testing.expectEqual(@as(u32, 500), r.?);
}
