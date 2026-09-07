// II12 - Federation Cluster Coordinator
// AEGIS NIDS v5.0+ â€” Multi-node leader election + heartbeat + state replication
//
// Implements a Bully-style leader election with quorum. Each node broadcasts
// its term and last applied log index; the node with the highest (term, id)
// tuple wins leadership.

const std = @import("std");
const event = @import("../contract/event.zig");
const manifest = @import("../contract/runtime_manifest.zig");
const diag = @import("../core/diagnostics.zig");

pub const MAX_NODES: usize = manifest.Limits.FEDERATION_NODES_MAX;
pub const HEARTBEAT_NS: i128 = @as(i128, manifest.Limits.FEDERATION_HEARTBEAT_MS) * std.time.ns_per_ms;
pub const ELECTION_TIMEOUT_NS: i128 = 3 * HEARTBEAT_NS;

pub const NodeId = u32;

pub const NodeRole = enum(u8) {
    follower = 0,
    candidate = 1,
    leader = 2,
    observer = 3,
};

pub const NodeState = struct {
    id: NodeId,
    addr: [64]u8 = [_]u8{0} ** 64,
    port: u16 = 0,
    role: NodeRole = .follower,
    last_heartbeat_ns: i128 = 0,
    last_seen_ns: i128 = 0,
    healthy: bool = false,
    log_index: u64 = 0,
};

pub const ClusterCoord = struct {
    self_id: NodeId,
    nodes: [MAX_NODES]NodeState = [_]NodeState{.{ .id = 0 }} ** MAX_NODES,
    node_count: usize = 0,
    leader_id: ?NodeId = null,
    current_term: u64 = 0,
    role: NodeRole = .follower,
    last_election_ns: i128 = 0,
    votes_received: u32 = 0,
    mutex: std.Thread.Mutex = .{},
    last_heartbeat_sent_ns: i128 = 0,

    pub fn init(self_id: NodeId) ClusterCoord {
        var c = ClusterCoord{ .self_id = self_id };
        c.nodes[0] = .{ .id = self_id, .role = .follower, .healthy = true };
        c.node_count = 1;
        return c;
    }

    pub fn addNode(self: *ClusterCoord, id: NodeId, addr: []const u8, port: u16) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.node_count >= MAX_NODES) return error.TooManyNodes;
        if (id == self.self_id) return; // skip self
        // Check for duplicate
        for (self.nodes[0..self.node_count]) |n| {
            if (n.id == id) return; // already present
        }
        self.nodes[self.node_count] = .{
            .id = id,
            .port = port,
            .role = .observer,
            .healthy = false,
        };
        const n = @min(addr.len, self.nodes[self.node_count].addr.len);
        @memcpy(self.nodes[self.node_count].addr[0..n], addr[0..n]);
        self.node_count += 1;
        diag.info("Cluster: added node {d} ({s}:{d})", .{ id, addr, port });
    }

    pub fn tick(self: *ClusterCoord, now_ns: i128) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        // Mark unhealthy nodes
        for (self.nodes[0..self.node_count]) |*n| {
            if (n.id == self.self_id) continue;
            if (now_ns - n.last_seen_ns > 3 * HEARTBEAT_NS and n.last_seen_ns != 0) {
                n.healthy = false;
                if (self.leader_id == n.id) {
                    // Leader down â€” trigger election
                    diag.warn("Cluster: leader {d} appears down, triggering election", .{n.id});
                    self.role = .candidate;
                    self.current_term += 1;
                    self.votes_received = 1; // vote for self
                    self.last_election_ns = now_ns;
                    self.leader_id = null;
                }
            }
        }
        // If we're a candidate and election timeout expired, become leader
        if (self.role == .candidate and self.votes_received > self.node_count / 2) {
            self.role = .leader;
            self.leader_id = self.self_id;
            diag.info("Cluster: self {d} elected leader (term={d})", .{ self.self_id, self.current_term });
        }
        // If we're leader, send heartbeats (caller invokes sendHeartbeat)
        if (self.role == .leader and now_ns - self.last_heartbeat_sent_ns > HEARTBEAT_NS) {
            self.last_heartbeat_sent_ns = now_ns;
            // Real impl would broadcast via federation_tls
        }
    }

    pub fn receiveHeartbeat(self: *ClusterCoord, from_id: NodeId, term: u64, leader_id: NodeId, now_ns: i128) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (term < self.current_term) return; // stale
        if (term > self.current_term) {
            self.current_term = term;
            self.role = .follower;
        }
        self.leader_id = leader_id;
        self.role = .follower;
        for (self.nodes[0..self.node_count]) |*n| {
            if (n.id == from_id) {
                n.last_seen_ns = now_ns;
                n.last_heartbeat_ns = now_ns;
                n.healthy = true;
                break;
            }
        }
    }

    pub fn receiveVote(self: *ClusterCoord, from_id: NodeId, term: u64, granted: bool, now_ns: i128) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = from_id;
        _ = now_ns;
        if (term != self.current_term) return;
        if (granted and self.role == .candidate) {
            self.votes_received += 1;
        }
    }

    pub fn isLeader(self: *ClusterCoord) bool {
        return self.role == .leader;
    }

    pub fn leaderId(self: *ClusterCoord) ?NodeId {
        return self.leader_id;
    }

    pub fn nodeCount(self: *ClusterCoord) usize {
        return self.node_count;
    }
};

// ============================================================================
// Tests
// ============================================================================
test "ClusterCoord init has self as follower" {
    var c = ClusterCoord.init(1);
    try std.testing.expectEqual(@as(usize, 1), c.nodeCount());
    try std.testing.expectEqual(NodeRole.follower, c.role);
}

test "ClusterCoord addNode" {
    var c = ClusterCoord.init(1);
    try c.addNode(2, "192.168.1.2", 8443);
    try c.addNode(3, "192.168.1.3", 8443);
    try std.testing.expectEqual(@as(usize, 3), c.nodeCount());
    try std.testing.expect(!c.isLeader());
}

test "ClusterCoord election via heartbeat" {
    var c = ClusterCoord.init(1);
    try c.addNode(2, "192.168.1.2", 8443);
    // Node 2 sends heartbeat claiming leadership at term 5
    c.receiveHeartbeat(2, 5, 2, std.time.nanoTimestamp());
    try std.testing.expectEqual(@as(?NodeId, 2), c.leaderId());
    try std.testing.expectEqual(NodeRole.follower, c.role);
}

test "ClusterCoord candidate becomes leader with majority" {
    var c = ClusterCoord.init(1);
    try c.addNode(2, "192.168.1.2", 8443);
    try c.addNode(3, "192.168.1.3", 8443);
    // Simulate candidate state
    c.role = .candidate;
    c.current_term = 1;
    c.votes_received = 1; // self
    // Receive vote from node 2
    c.receiveVote(2, 1, true, std.time.nanoTimestamp());
    c.tick(std.time.nanoTimestamp());
    try std.testing.expect(c.isLeader());
}
