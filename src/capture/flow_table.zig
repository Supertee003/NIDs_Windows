// I08 - Flow Tracking Table
// AEGIS NIDS v5.0+ â€” Bidirectional flow table with 60s eviction
//
// Layout:
//   - 4096-bucket hash table (open addressing)
//   - LRU eviction by per-flow last_seen timestamp
//   - Background sweeper evicts flows idle > FLOW_EVICTION_TIMEOUT_SEC
//
// Flow key: (src_ip, dst_ip, src_port, dst_port, proto, ip_version) â€” direction-normalized.

const std = @import("std");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const FLOW_TABLE_SIZE: usize = manifest.Limits.FLOW_TABLE_ENTRIES;
pub const FLOW_EVICTION_NS: i128 = @as(i128, manifest.Limits.FLOW_EVICTION_TIMEOUT_SEC) * std.time.ns_per_s;

pub const FlowKey = extern struct {
    ip_a: [16]u8 = [_]u8{0} ** 16,
    ip_b: [16]u8 = [_]u8{0} ** 16,
    port_a: u16 = 0,
    port_b: u16 = 0,
    proto: u8 = 0,
    is_ipv6: bool = false,

    pub fn normalize(src_ip: [16]u8, dst_ip: [16]u8, src_port: u16, dst_port: u16, proto: u8, is_ipv6: bool) FlowKey {
        // Direction normalization: smaller (ip,port) tuple = 'a'
        const src_bigger = compareEndpoint(src_ip, src_port, dst_ip, dst_port) > 0;
        if (src_bigger) {
            return .{ .ip_a = dst_ip, .ip_b = src_ip, .port_a = dst_port, .port_b = src_port, .proto = proto, .is_ipv6 = is_ipv6 };
        }
        return .{ .ip_a = src_ip, .ip_b = dst_ip, .port_a = src_port, .port_b = dst_port, .proto = proto, .is_ipv6 = is_ipv6 };
    }

    fn compareEndpoint(ip1: [16]u8, p1: u16, ip2: [16]u8, p2: u16) i32 {
        const cmp = std.mem.order(u8, &ip1, &ip2);
        if (cmp != .eq) return if (cmp == .gt) 1 else -1;
        if (p1 > p2) return 1;
        if (p1 < p2) return -1;
        return 0;
    }

    pub fn hash(self: FlowKey) u32 {
        // FNV-1a 32-bit on the canonicalized key
        var h: u32 = 0x811c9dc5;
        for (&self.ip_a) |b| {
            h ^= b;
            h *%= 0x01000193;
        }
        for (&self.ip_b) |b| {
            h ^= b;
            h *%= 0x01000193;
        }
        h ^= @as(u8, @intCast(self.port_a & 0xFF));
        h *%= 0x01000193;
        h ^= @as(u8, @intCast((self.port_a >> 8) & 0xFF));
        h *%= 0x01000193;
        h ^= @as(u8, @intCast(self.port_b & 0xFF));
        h *%= 0x01000193;
        h ^= @as(u8, @intCast((self.port_b >> 8) & 0xFF));
        h *%= 0x01000193;
        h ^= self.proto;
        h *%= 0x01000193;
        h ^= @intFromBool(self.is_ipv6);
        h *%= 0x01000193;
        return h;
    }

    pub fn eql(self: FlowKey, other: FlowKey) bool {
        return std.mem.eql(u8, std.mem.asBytes(&self), std.mem.asBytes(&other));
    }
};

pub const FlowState = enum(u8) {
    new = 0,
    syn_seen = 1,
    syn_ack_seen = 2,
    established = 3,
    fin_seen = 4,
    reset = 5,
    expired = 6,
};

pub const FlowStats = struct {
    packets_a_to_b: u64 = 0,
    packets_b_to_a: u64 = 0,
    bytes_a_to_b: u64 = 0,
    bytes_b_to_a: u64 = 0,
    first_seen_ns: i128 = 0,
    last_seen_ns: i128 = 0,
    state: FlowState = .new,
    tcp_flags_seen: u16 = 0,
    threat_score: u16 = 0,
    flow_id: u64 = 0,
};

pub const FlowEntry = struct {
    key: FlowKey = .{},
    stats: FlowStats = .{},
    occupied: bool = false,
    in_use: bool = false, // ref-count hint
};

pub const FlowTable = struct {
    buckets: [FLOW_TABLE_SIZE]FlowEntry = [_]FlowEntry{.{}} ** FLOW_TABLE_SIZE,
    count: u32 = 0,
    next_flow_id: u64 = 1,
    mutex: std.Thread.Mutex = .{},

    pub fn lookupOrCreate(self: *FlowTable, key: FlowKey, now_ns: i128) *FlowEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        const h = key.hash();
        var i: usize = 0;
        while (i < FLOW_TABLE_SIZE) : (i += 1) {
            const idx = (h +% @as(u32, @intCast(i))) % FLOW_TABLE_SIZE;
            const e = &self.buckets[idx];
            if (!e.occupied) {
                e.occupied = true;
                e.key = key;
                e.stats = .{ .first_seen_ns = now_ns, .last_seen_ns = now_ns, .flow_id = self.next_flow_id };
                self.next_flow_id += 1;
                self.count += 1;
                diag.metrics.flows_active.set(@intCast(self.count));
                return e;
            }
            if (e.key.eql(key)) {
                e.stats.last_seen_ns = now_ns;
                return e;
            }
        }
        // Table full â€” caller should run eviction and retry
        @panic("FLOW_TABLE_FULL");
    }

    pub fn lookup(self: *FlowTable, key: FlowKey) ?*FlowEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        const h = key.hash();
        var i: usize = 0;
        while (i < FLOW_TABLE_SIZE) : (i += 1) {
            const idx = (h +% @as(u32, @intCast(i))) % FLOW_TABLE_SIZE;
            const e = &self.buckets[idx];
            if (!e.occupied) return null;
            if (e.key.eql(key)) return e;
        }
        return null;
    }

    pub fn evictExpired(self: *FlowTable, now_ns: i128) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var evicted: u32 = 0;
        for (&self.buckets) |*e| {
            if (!e.occupied) continue;
            if (now_ns - e.stats.last_seen_ns > FLOW_EVICTION_NS) {
                e.occupied = false;
                e.stats.state = .expired;
                evicted += 1;
            }
        }
        if (evicted > 0) {
            self.count -= evicted;
            diag.metrics.flows_active.set(@intCast(self.count));
        }
        return evicted;
    }

    pub fn updateDirectional(self: *FlowTable, key: FlowKey, src_ip: [16]u8, src_port: u16, pkt_bytes: u32, now_ns: i128) void {
        const e = self.lookupOrCreate(key, now_ns);
        if (std.mem.eql(u8, &key.ip_a, &src_ip) and key.port_a == src_port) {
            e.stats.packets_a_to_b += 1;
            e.stats.bytes_a_to_b += pkt_bytes;
        } else {
            e.stats.packets_b_to_a += 1;
            e.stats.bytes_b_to_a += pkt_bytes;
        }
        e.stats.last_seen_ns = now_ns;
    }

    pub fn count_(self: *FlowTable) u32 {
        return self.count;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "FlowKey normalization" {
    const k1 = FlowKey.normalize([_]u8{ 192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 12345, 80, 6, false);
    const k2 = FlowKey.normalize([_]u8{ 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 80, 12345, 6, false);
    try std.testing.expect(k1.eql(k2));
}

test "FlowTable create and lookup" {
    var ft = FlowTable{};
    const k = FlowKey.normalize([_]u8{ 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 1000, 2000, 6, false);
    _ = ft.lookupOrCreate(k, 1000);
    const e = ft.lookup(k);
    try std.testing.expect(e != null);
    try std.testing.expectEqual(@as(u32, 1), ft.count_());
}

test "FlowTable eviction" {
    var ft = FlowTable{};
    const k = FlowKey.normalize([_]u8{ 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 1000, 2000, 6, false);
    _ = ft.lookupOrCreate(k, 1000);
    // Evict after 61s
    const evicted = ft.evictExpired(1000 + 61 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), evicted);
    try std.testing.expectEqual(@as(u32, 0), ft.count_());
}

test "FlowTable directional stats" {
    var ft = FlowTable{};
    const src_ip = [_]u8{ 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const dst_ip = [_]u8{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const k = FlowKey.normalize(src_ip, dst_ip, 1000, 2000, 6, false);
    ft.updateDirectional(k, src_ip, 1000, 100, 2000);
    const e = ft.lookup(k).?;
    try std.testing.expectEqual(@as(u64, 1), e.stats.packets_a_to_b);
    try std.testing.expectEqual(@as(u64, 100), e.stats.bytes_a_to_b);
}
