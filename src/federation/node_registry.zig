// II13 - Node Registry & Discovery
// AEGIS NIDS v5.0+ â€” Static config + dynamic discovery (mDNS-style)
//
// Maintains a list of cluster nodes, their addresses, capabilities, and
// health status. Discovery methods:
//   1. Static config (configs/cluster.json)
//   2. UDP broadcast beacon (port 5353, AEGIS_NIDSC cluster tag)
//   3. DNS-SD over mDNS (if available)

const std = @import("std");
const diag = @import("../core/diagnostics.zig");
const cluster = @import("cluster_coord.zig");

pub const DiscoveryMethod = enum(u8) {
    static = 0,
    broadcast = 1,
    mdns = 2,
};

pub const NodeInfo = struct {
    id: u32,
    hostname: [64]u8 = [_]u8{0} ** 64,
    addr: [46]u8 = [_]u8{0} ** 46, // IPv6-capable
    port: u16,
    capabilities: u32 = 0,
    last_seen_ns: i128 = 0,
    method: DiscoveryMethod = .static,
};

pub const NodeRegistry = struct {
    nodes: std.ArrayList(NodeInfo),
    allocator: std.mem.Allocator,
    self_id: u32,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, self_id: u32) NodeRegistry {
        return .{
            .nodes = std.ArrayList(NodeInfo).init(allocator),
            .allocator = allocator,
            .self_id = self_id,
        };
    }

    pub fn deinit(self: *NodeRegistry) void {
        self.nodes.deinit();
    }

    pub fn registerStatic(self: *NodeRegistry, id: u32, addr: []const u8, port: u16) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |n| {
            if (n.id == id) return; // already
        }
        var info = NodeInfo{ .id = id, .port = port, .method = .static };
        const an = @min(addr.len, info.addr.len);
        @memcpy(info.addr[0..an], addr[0..an]);
        try self.nodes.append(info);
        diag.info("Registry: registered node {d} {s}:{d} (static)", .{ id, addr, port });
    }

    pub fn registerDiscovered(self: *NodeRegistry, id: u32, addr: []const u8, port: u16, method: DiscoveryMethod) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |*n| {
            if (n.id == id) {
                n.last_seen_ns = std.time.nanoTimestamp();
                n.method = method;
                return;
            }
        }
        var info = NodeInfo{
            .id = id,
            .port = port,
            .method = method,
            .last_seen_ns = std.time.nanoTimestamp(),
        };
        const an = @min(addr.len, info.addr.len);
        @memcpy(info.addr[0..an], addr[0..an]);
        try self.nodes.append(info);
        diag.info("Registry: discovered node {d} {s}:{d} ({s})", .{ id, addr, port, @tagName(method) });
    }

    pub fn lookup(self: *NodeRegistry, id: u32) ?NodeInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |n| {
            if (n.id == id) return n;
        }
        return null;
    }

    pub fn allNodes(self: *NodeRegistry) []const NodeInfo {
        return self.nodes.items;
    }

    pub fn pruneStale(self: *NodeRegistry, now_ns: i128, max_age_ns: i128) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        var i: usize = 0;
        var removed: u32 = 0;
        while (i < self.nodes.items.len) {
            const n = self.nodes.items[i];
            if (n.method != .static and now_ns - n.last_seen_ns > max_age_ns) {
                _ = self.nodes.swapRemove(i);
                removed += 1;
            } else {
                i += 1;
            }
        }
        return removed;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "NodeRegistry registerStatic and lookup" {
    var nr = NodeRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try nr.registerStatic(2, "192.168.1.2", 8443);
    try nr.registerStatic(3, "192.168.1.3", 8443);
    try std.testing.expectEqual(@as(usize, 2), nr.allNodes().len);
    const n = nr.lookup(2).?;
    try std.testing.expectEqual(@as(u16, 8443), n.port);
}

test "NodeRegistry registerDiscovered updates existing" {
    var nr = NodeRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try nr.registerStatic(2, "192.168.1.2", 8443);
    try nr.registerDiscovered(2, "192.168.1.2", 8443, .broadcast);
    try std.testing.expectEqual(@as(usize, 1), nr.allNodes().len);
}

test "NodeRegistry pruneStale removes only dynamic" {
    var nr = NodeRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try nr.registerStatic(2, "192.168.1.2", 8443);
    try nr.registerDiscovered(3, "192.168.1.3", 8443, .broadcast);
    // Force last_seen to be old for node 3
    nr.nodes.items[1].last_seen_ns = std.time.nanoTimestamp() - 600 * std.time.ns_per_s;
    const removed = nr.pruneStale(std.time.nanoTimestamp(), 300 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), removed);
    try std.testing.expectEqual(@as(usize, 1), nr.allNodes().len);
}
