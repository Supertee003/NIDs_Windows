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

// FED-P1A: DiscoveryRegistry (this file) is the *discovery* table
// (static/broadcast/mDNS rows + stale pruning). The *coordination*
// registry (peers, heartbeats, leader election) is
// cluster_coord.zig::NodeRegistry. The shared name was a collision;
// this rename keeps both importable side by side.

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

pub const DiscoveryRegistry = struct {
    nodes: std.ArrayList(NodeInfo),
    allocator: std.mem.Allocator,
    self_id: u32,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, self_id: u32) DiscoveryRegistry {
        return .{
            .nodes = std.ArrayList(NodeInfo).init(allocator),
            .allocator = allocator,
            .self_id = self_id,
        };
    }

    pub fn deinit(self: *DiscoveryRegistry) void {
        self.nodes.deinit();
    }

    pub fn registerStatic(self: *DiscoveryRegistry, id: u32, addr: []const u8, port: u16, hostname: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |n| {
            if (n.id == id) return; // already
        }
        if (hostname.len > 64) return error.BadName;
        var info = NodeInfo{ .id = id, .port = port, .method = .static };
        const an = @min(addr.len, info.addr.len);
        @memcpy(info.addr[0..an], addr[0..an]);
        @memcpy(info.hostname[0..hostname.len], hostname);
        try self.nodes.append(info);
        diag.info("Registry: registered node {d} {s}:{d} (static)", .{ id, addr, port });
    }

    pub fn registerDiscovered(self: *DiscoveryRegistry, id: u32, addr: []const u8, port: u16, method: DiscoveryMethod) !void {
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

    pub fn lookup(self: *DiscoveryRegistry, id: u32) ?NodeInfo {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.nodes.items) |n| {
            if (n.id == id) return n;
        }
        return null;
    }

    pub fn allNodes(self: *DiscoveryRegistry) []const NodeInfo {
        return self.nodes.items;
    }

    pub fn pruneStale(self: *DiscoveryRegistry, now_ns: i128, max_age_ns: i128) u32 {
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

    /// Load static peers from a canonical `configs/cluster.json` file.
    /// Schema v1: {"version": 1, "nodes": [{"id": u32, "addr": str,
    /// "port": u16}]}. u32 ids match the wire (ClusterNode.node_id) per
    /// the owner verdict — string ids are rejected, not coerced.
    /// Fail-closed and atomic: unknown versions, empty node lists,
    /// id 0 (broadcast-reserved), port 0, empty/oversize addrs, or any
    /// malformed JSON registers NOTHING and returns an error. Returns
    /// the number of entries accepted. The live file is operator-local
    /// (gitignored); the tracked example is the schema reference.
    pub fn loadStaticFile(self: *DiscoveryRegistry, allocator: std.mem.Allocator, path: []const u8) !usize {
        const bytes = std.fs.cwd().readFileAlloc(allocator, path, 65536) catch return error.FileNotFound;
        defer allocator.free(bytes);
        return self.loadStaticBytes(allocator, bytes);
    }

    pub fn loadStaticBytes(self: *DiscoveryRegistry, allocator: std.mem.Allocator, bytes: []const u8) !usize {
        const Entry = struct {
            id: u32,
            addr: []const u8,
            port: u16,
            // Optional human label (FED-P3B): authority stays numeric (id),
            // the name is display-only. Missing = unlabeled, never an error.
            name: ?[]const u8 = null,
        };
        const File = struct {
            version: u8,
            nodes: []Entry,
        };
        const parsed = std.json.parseFromSlice(File, allocator, bytes, .{}) catch return error.BadShape;
        defer parsed.deinit();
        if (parsed.value.version != 1) return error.UnknownVersion;
        if (parsed.value.nodes.len == 0) return error.EmptyCluster;
        // Validate everything before registering anything (atomic).
        for (parsed.value.nodes) |e| {
            if (e.id == 0) return error.ReservedId;
            if (e.port == 0) return error.BadPort;
            if (e.addr.len == 0 or e.addr.len > 45) return error.BadAddr;
            if (e.name) |nm| {
                if (nm.len == 0 or nm.len > 64) return error.BadName;
            }
        }
        for (parsed.value.nodes) |e| {
            try self.registerStatic(e.id, e.addr, e.port, e.name orelse "");
        }
        return parsed.value.nodes.len;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "DiscoveryRegistry registerStatic and lookup" {
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try nr.registerStatic(2, "192.168.1.2", 8443, "");
    try nr.registerStatic(3, "192.168.1.3", 8443, "");
    try std.testing.expectEqual(@as(usize, 2), nr.allNodes().len);
    const n = nr.lookup(2).?;
    try std.testing.expectEqual(@as(u16, 8443), n.port);
}

test "DiscoveryRegistry registerDiscovered updates existing" {
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try nr.registerStatic(2, "192.168.1.2", 8443, "");
    try nr.registerDiscovered(2, "192.168.1.2", 8443, .broadcast);
    try std.testing.expectEqual(@as(usize, 1), nr.allNodes().len);
}

test "DiscoveryRegistry pruneStale removes only dynamic" {
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try nr.registerStatic(2, "192.168.1.2", 8443, "");
    try nr.registerDiscovered(3, "192.168.1.3", 8443, .broadcast);
    // Force last_seen to be old for node 3
    nr.nodes.items[1].last_seen_ns = std.time.nanoTimestamp() - 600 * std.time.ns_per_s;
    const removed = nr.pruneStale(std.time.nanoTimestamp(), 300 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(u32, 1), removed);
    try std.testing.expectEqual(@as(usize, 1), nr.allNodes().len);
}

test "DiscoveryRegistry loadStaticBytes accepts canonical v1" {
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    const n = try nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [
        \\  {"id": 7, "addr": "192.168.126.7", "port": 9001},
        \\  {"id": 9, "addr": "192.168.126.9", "port": 9002}
        \\]}
    );
    try std.testing.expectEqual(@as(usize, 2), n);
    const got = nr.lookup(7).?;
    try std.testing.expectEqual(@as(u16, 9001), got.port);
    try std.testing.expectEqual(DiscoveryMethod.static, got.method);
}

test "DiscoveryRegistry loadStaticBytes rejects non-v1" {
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try std.testing.expectError(error.UnknownVersion, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 2, "nodes": [{"id": 7, "addr": "x", "port": 1}]}
    ));
    try std.testing.expectEqual(@as(usize, 0), nr.allNodes().len);
}

test "DiscoveryRegistry loadStaticBytes rejects reserved id port and empty" {
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try std.testing.expectError(error.ReservedId, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [{"id": 0, "addr": "x", "port": 1}]}
    ));
    try std.testing.expectError(error.BadPort, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [{"id": 7, "addr": "x", "port": 0}]}
    ));
    try std.testing.expectError(error.EmptyCluster, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": []}
    ));
    try std.testing.expectError(error.BadShape, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [{"id": 7, "addr": "x"}]}
    ));
    try std.testing.expectEqual(@as(usize, 0), nr.allNodes().len);
}

test "DiscoveryRegistry loadStaticBytes stores optional name labels" {
    // FED-P3B: numeric id stays the authority; the name is display-only.
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    const n = try nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [
        \\  {"id": 7, "addr": "192.168.126.7", "port": 9001, "name": "nids-07"},
        \\  {"id": 9, "addr": "192.168.126.9", "port": 9001}
        \\]}
    );
    try std.testing.expectEqual(@as(usize, 2), n);
    const named = nr.lookup(7).?;
    try std.testing.expectEqualStrings("nids-07", named.hostname[0..7]);
    const unnamed = nr.lookup(9).?;
    try std.testing.expectEqual(@as(u8, 0), unnamed.hostname[0]);
    // Overlong names fail closed (never silently truncated): 70 > 64.
    try std.testing.expectError(error.BadName, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [{"id": 8, "addr": "x", "port": 1, "name": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqr"}]}
    ));
    try std.testing.expectEqual(@as(usize, 2), nr.allNodes().len);
}

test "DiscoveryRegistry loadStaticBytes never coerces string ids" {    // Owner verdict: u32 ids. A string id is malformed input, not a
    // value to hash or index into a number.
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    try std.testing.expectError(error.BadShape, nr.loadStaticBytes(std.testing.allocator,
        \\{"version": 1, "nodes": [{"id": "node-01", "addr": "x", "port": 1}]}
    ));
    try std.testing.expectEqual(@as(usize, 0), nr.allNodes().len);
}

test "DiscoveryRegistry tracked example matches the canonical schema" {
    // The example is the schema reference: if it drifts from what the
    // loader accepts, this fails (same standing as the Rules mirror pin).
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    const n = try nr.loadStaticFile(std.testing.allocator, "configs/cluster.example.json");
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expect(nr.lookup(7) != null);
    try std.testing.expect(nr.lookup(9) != null);
    try std.testing.expectEqualStrings("nids-07", nr.lookup(7).?.hostname[0..7]);
}

test "DiscoveryRegistry loadStaticFile round-trips a scratch file" {    const scratch = "zig-test-cluster.json";
    {
        const f = try std.fs.cwd().createFile(scratch, .{});
        defer f.close();
        try f.writeAll(
            \\{"version": 1, "nodes": [{"id": 11, "addr": "10.0.0.11", "port": 9001}]}
        );
    }
    defer std.fs.cwd().deleteFile(scratch) catch {};
    var nr = DiscoveryRegistry.init(std.testing.allocator, 1);
    defer nr.deinit();
    const n = try nr.loadStaticFile(std.testing.allocator, scratch);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expect(nr.lookup(11) != null);
}
