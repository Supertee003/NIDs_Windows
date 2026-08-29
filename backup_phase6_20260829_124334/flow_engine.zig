//! flow_engine.zig - AEGIS Flow Engine (Phase 33, AEGIS-012)
//!
//! Tracks network flow state for stateful IPS decisions.
//! Required for: IPS (stateful blocking), XDR (flow correlation)
//!
//! Blueprint: "NIDS ที่จะไป IPS/XDR ต้องมี flow state"

const std = @import("std");

// ============================================================
// Flow Key (5-tuple, AEGIS-012)
// ============================================================

pub const FlowKey = struct {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,

    pub fn eql(self: FlowKey, other: FlowKey) bool {
        return self.src_ip == other.src_ip and
            self.dst_ip == other.dst_ip and
            self.src_port == other.src_port and
            self.dst_port == other.dst_port and
            self.protocol == other.protocol;
    }

    pub fn hash(self: FlowKey) u64 {
        var h: u64 = 0;
        h ^= @as(u64, self.src_ip) << 32;
        h ^= @as(u64, self.dst_ip);
        h ^= @as(u64, self.src_port) << 48;
        h ^= @as(u64, self.dst_port) << 32;
        h ^= @as(u64, self.protocol) << 56;
        return h;
    }
};

// ============================================================
// Flow State (AEGIS-012)
// ============================================================

pub const TCPState = enum(u8) {
    none = 0,
    syn = 1,
    syn_ack = 2,
    established = 3,
    fin_wait = 4,
    closed = 5,
};

pub const FlowState = struct {
    key: FlowKey,
    created_at_ms: i64,
    last_seen_ms: i64,
    packet_count: u64,
    byte_count: u64,
    tcp_state: TCPState,
    direction: u8, // 0=inbound, 1=outbound
    session_id: u64,
    risk_score: u8, // 0-255
};

// ============================================================
// Flow Table (AEGIS-012)
// ============================================================

const MAX_FLOWS: usize = 4096;
const FLOW_TIMEOUT_MS: i64 = 60_000; // 60 seconds

pub const FlowTable = struct {
    flows: [MAX_FLOWS]?FlowState,
    count: usize,
    total_created: std.atomic.Value(u64),
    total_expired: std.atomic.Value(u64),
    mutex: std.Thread.Mutex,

    pub fn init() FlowTable {
        return .{
            .flows = [_]?FlowState{null} ** MAX_FLOWS,
            .count = 0,
            .total_created = std.atomic.Value(u64).init(0),
            .total_expired = std.atomic.Value(u64).init(0),
            .mutex = .{},
        };
    }

    /// Lookup or create a flow for a given key.
    pub fn upsert(self: *FlowTable, key: FlowKey, bytes: u64, session_id: u64) *FlowState {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // Try to find existing flow
        for (0..MAX_FLOWS) |i| {
            if (self.flows[i]) |*flow| {
                if (flow.key.eql(key)) {
                    flow.last_seen_ms = now;
                    flow.packet_count += 1;
                    flow.byte_count += bytes;
                    return flow;
                }
            }
        }

        // Find free slot (or expired flow)
        for (0..MAX_FLOWS) |i| {
            const is_free = self.flows[i] == null;
            const is_expired = if (self.flows[i]) |f| (now - f.last_seen_ms > FLOW_TIMEOUT_MS) else false;
            if (is_free or is_expired) {
                if (is_expired) {
                    _ = self.total_expired.fetchAdd(1, .monotonic);
                    self.count -= 1;
                }
                self.flows[i] = .{
                    .key = key,
                    .created_at_ms = now,
                    .last_seen_ms = now,
                    .packet_count = 1,
                    .byte_count = bytes,
                    .tcp_state = .none,
                    .direction = 0,
                    .session_id = session_id,
                    .risk_score = 0,
                };
                self.count += 1;
                _ = self.total_created.fetchAdd(1, .monotonic);
                return &self.flows[i].?;
            }
        }

        // Table full — overwrite slot 0 (simple eviction)
        self.flows[0] = .{
            .key = key,
            .created_at_ms = now,
            .last_seen_ms = now,
            .packet_count = 1,
            .byte_count = bytes,
            .tcp_state = .none,
            .direction = 0,
            .session_id = session_id,
            .risk_score = 0,
        };
        _ = self.total_created.fetchAdd(1, .monotonic);
        return &self.flows[0].?;
    }

    /// Look up a flow without creating.
    pub fn lookup(self: *FlowTable, key: FlowKey) ?*FlowState {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (0..MAX_FLOWS) |i| {
            if (self.flows[i]) |*flow| {
                if (flow.key.eql(key)) return flow;
            }
        }
        return null;
    }

    /// Purge expired flows.
    pub fn purgeExpired(self: *FlowTable) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now = std.time.milliTimestamp();
        var purged: usize = 0;
        for (0..MAX_FLOWS) |i| {
            if (self.flows[i]) |flow| {
                if (now - flow.last_seen_ms > FLOW_TIMEOUT_MS) {
                    self.flows[i] = null;
                    self.count -= 1;
                    purged += 1;
                }
            }
        }
        _ = self.total_expired.fetchAdd(@intCast(purged), .monotonic);
        return purged;
    }

    /// Get current flow count.
    pub fn len(self: *FlowTable) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.count;
    }

    /// Get statistics.
    pub fn getStats(self: *FlowTable) FlowStats {
        return .{
            .active_flows = self.len(),
            .total_created = self.total_created.load(.monotonic),
            .total_expired = self.total_expired.load(.monotonic),
        };
    }
};

pub const FlowStats = struct {
    active_flows: usize,
    total_created: u64,
    total_expired: u64,
};

// ============================================================
// Tests
// ============================================================

test "FlowKey.eql matches identical keys" {
    const k1 = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    const k2 = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    try std.testing.expect(k1.eql(k2));
}

test "FlowKey.eql rejects different keys" {
    const k1 = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    const k2 = FlowKey{ .src_ip = 0x0A000003, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    try std.testing.expect(!k1.eql(k2));
}

test "FlowKey.hash produces consistent results" {
    const k1 = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    const k2 = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    try std.testing.expect(k1.hash() == k2.hash());
}

test "FlowTable init" {
    const ft = FlowTable.init();
    try std.testing.expect(ft.count == 0);
}

test "FlowTable upsert creates new flow" {
    var ft = FlowTable.init();
    const key = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    const flow = ft.upsert(key, 1024, 42);
    try std.testing.expect(flow.packet_count == 1);
    try std.testing.expect(flow.byte_count == 1024);
    try std.testing.expect(flow.session_id == 42);
    try std.testing.expect(ft.len() == 1);
}

test "FlowTable upsert updates existing flow" {
    var ft = FlowTable.init();
    const key = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    _ = ft.upsert(key, 1024, 1);
    const flow = ft.upsert(key, 2048, 1);
    try std.testing.expect(flow.packet_count == 2);
    try std.testing.expect(flow.byte_count == 3072);
    try std.testing.expect(ft.len() == 1);
}

test "FlowTable lookup returns null for unknown" {
    var ft = FlowTable.init();
    const key = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    try std.testing.expect(ft.lookup(key) == null);
}

test "FlowTable lookup finds existing flow" {
    var ft = FlowTable.init();
    const key = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    _ = ft.upsert(key, 1024, 1);
    const flow = ft.lookup(key);
    try std.testing.expect(flow != null);
    try std.testing.expect(flow.?.byte_count == 1024);
}

test "FlowTable getStats" {
    var ft = FlowTable.init();
    const key = FlowKey{ .src_ip = 0x0A000001, .dst_ip = 0x0A000002, .src_port = 80, .dst_port = 443, .protocol = 6 };
    _ = ft.upsert(key, 1024, 1);
    const stats = ft.getStats();
    try std.testing.expect(stats.active_flows == 1);
    try std.testing.expect(stats.total_created == 1);
}
