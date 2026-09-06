// federation.zig - AEGIS NIDS G17: Federation / Cluster
// Node registry, heartbeat, leader election, cross-node incident sharing
// Built on Phase 39 design; integrated into repository for G17.

const std = @import("std");

pub const MAX_NODES: usize = 64;
pub const HEARTBEAT_TIMEOUT_MS: i64 = 15_000;
pub const HEARTBEAT_DEAD_THRESHOLD: u8 = 3;
pub const LEADER_ELECTION_INTERVAL_MS: i64 = 30_000;

pub const NodeRole = enum(u8) {
    sensor = 0,
    coordinator = 1,
    aggregator = 2,
    pub fn toString(self: NodeRole) []const u8 {
        return switch (self) { .sensor => "SENSOR", .coordinator => "COORDINATOR", .aggregator => "AGGREGATOR" };
    }
};

pub const NodeHealth = enum(u8) {
    healthy = 0, degraded = 1, unhealthy = 2, dead = 3,
    pub fn toString(self: NodeHealth) []const u8 {
        return switch (self) { .healthy => "HEALTHY", .degraded => "DEGRADED", .unhealthy => "UNHEALTHY", .dead => "DEAD" };
    }
    pub fn isActive(self: NodeHealth) bool { return self == .healthy or self == .degraded; }
};

pub const MessageType = enum(u8) {
    heartbeat = 0, node_join = 1, node_leave = 2,
    incident_report = 3, threat_intel_share = 4,
    leader_announce = 5, leader_request = 6,
    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .heartbeat => "HEARTBEAT", .node_join => "NODE_JOIN", .node_leave => "NODE_LEAVE",
            .incident_report => "INCIDENT_REPORT", .threat_intel_share => "THREAT_INTEL_SHARE",
            .leader_announce => "LEADER_ANNOUNCE", .leader_request => "LEADER_REQUEST",
        };
    }
};

pub const IncidentSeverity = enum(u8) {
    info = 0, low = 1, medium = 2, high = 3, critical = 4,
    pub fn toString(self: IncidentSeverity) []const u8 {
        return switch (self) { .info => "INFO", .low => "LOW", .medium => "MEDIUM", .high => "HIGH", .critical => "CRITICAL" };
    }
};

pub const ClusterNode = struct {
    node_id: u32 = 0,
    name: [64]u8 = [_]u8{0} ** 64, name_len: u8 = 0,
    role: NodeRole = .sensor,
    health: NodeHealth = .healthy,
    last_seen_ns: i64 = 0,
    joined_ns: i64 = 0,
    heartbeat_misses: u8 = 0,
    incidents_reported: u64 = 0,
    is_self: bool = false,
    pub fn nameStr(self: *const ClusterNode) []const u8 { return self.name[0..self.name_len]; }
};

pub const NodeRegistry = struct {
    nodes: std.AutoHashMap(u32, ClusterNode),
    max_nodes: usize, self_id: u32,
    total_joins: u64 = 0, total_leaves: u64 = 0,
    pub fn init(allocator: std.mem.Allocator, max_nodes: usize, self_id: u32) NodeRegistry {
        return .{ .nodes = std.AutoHashMap(u32, ClusterNode).init(allocator), .max_nodes = max_nodes, .self_id = self_id };
    }
    pub fn deinit(self: *NodeRegistry) void { self.nodes.deinit(); }
    pub fn upsert(self: *NodeRegistry, node: ClusterNode) bool {
        if (self.nodes.count() >= self.max_nodes and !self.nodes.contains(node.node_id)) return false;
        const existed = self.nodes.contains(node.node_id);
        self.nodes.put(node.node_id, node) catch return false;
        if (!existed) self.total_joins += 1;
        return true;
    }
    pub fn remove(self: *NodeRegistry, node_id: u32) bool {
        const removed = self.nodes.remove(node_id);
        if (removed) self.total_leaves += 1;
        return removed;
    }
    pub fn get(self: *const NodeRegistry, node_id: u32) ?ClusterNode { return self.nodes.get(node_id); }
    pub fn count(self: *const NodeRegistry) usize { return self.nodes.count(); }
};

pub const HeartbeatMonitor = struct {
    timeout_ms: i64, dead_threshold: u8,
    total_beats: u64 = 0, total_timeouts: u64 = 0, total_dead: u64 = 0,
    pub fn init(timeout_ms: i64, dead_threshold: u8) HeartbeatMonitor {
        return .{ .timeout_ms = timeout_ms, .dead_threshold = dead_threshold };
    }
    pub fn onHeartbeat(self: *HeartbeatMonitor, node: *ClusterNode, now_ns: i64) void {
        node.last_seen_ns = now_ns; node.heartbeat_misses = 0;
        if (node.health != .healthy) node.health = .healthy;
        self.total_beats += 1;
    }
    pub fn checkTimeout(self: *HeartbeatMonitor, node: *ClusterNode, now_ns: i64) NodeHealth {
        const elapsed_ms = @divFloor(now_ns - node.last_seen_ns, 1_000_000);
        if (elapsed_ms < self.timeout_ms) return node.health;
        node.heartbeat_misses += 1; self.total_timeouts += 1;
        if (node.heartbeat_misses >= self.dead_threshold) {
            node.health = .dead; self.total_dead += 1;
        } else if (node.heartbeat_misses >= self.dead_threshold / 2 + 1) {
            node.health = .unhealthy;
        } else { node.health = .degraded; }
        return node.health;
    }
};

pub const LeaderElection = struct {
    current_leader: u32 = 0, leader_since_ns: i64 = 0,
    election_count: u64 = 0, last_election_ns: i64 = 0, election_interval_ms: i64,
    pub const ElectionResult = struct { leader: u32, changed: bool };
    pub fn init(election_interval_ms: i64) LeaderElection { return .{ .election_interval_ms = election_interval_ms }; }
    pub fn elect(self: *LeaderElection, registry: *const NodeRegistry, now_ns: i64) ElectionResult {
        var winner: u32 = 0;
        var it = registry.nodes.valueIterator();
        while (it.next()) |n| { if (n.isActive() and n.node_id > winner) winner = n.node_id; }
        const changed = winner != self.current_leader;
        if (changed) { self.current_leader = winner; self.leader_since_ns = now_ns; }
        self.last_election_ns = now_ns; self.election_count += 1;
        return .{ .leader = winner, .changed = changed };
    }
    pub fn shouldRunElection(self: *const LeaderElection, now_ns: i64) bool {
        return @divFloor(now_ns - self.last_election_ns, 1_000_000) >= self.election_interval_ms;
    }
    pub fn isLeader(self: *const LeaderElection, node_id: u32) bool { return self.current_leader == node_id and self.current_leader != 0; }
};

pub const ClusterIncident = struct {
    incident_id: u64 = 0, timestamp_ns: i64 = 0,
    source_ip: [4]u8 = .{0,0,0,0}, remote_port: u16 = 0, proto: u8 = 6,
    severity: IncidentSeverity = .info,
    reporting_node_ids: [8]u32 = [_]u32{0} ** 8, reporting_count: u8 = 0,
    first_seen_ns: i64 = 0, last_seen_ns: i64 = 0,
    score: f32 = 0.0,
    pub fn addReportingNode(self: *ClusterIncident, node_id: u32) bool {
        if (self.reporting_count >= 8) return false;
        var i: u8 = 0;
        while (i < self.reporting_count) : (i += 1) { if (self.reporting_node_ids[i] == node_id) return false; }
        self.reporting_node_ids[self.reporting_count] = node_id; self.reporting_count += 1;
        return true;
    }
};

pub const CrossNodeIncidentAggregator = struct {
    allocator: std.mem.Allocator,
    incidents: std.AutoHashMap(u64, ClusterIncident),
    max_incidents: usize, window_ms: i64,
    escalate_at: u8, critical_at: u8,
    next_incident_id: u64 = 1,
    total_reports: u64 = 0, total_aggregated: u64 = 0, total_escalated: u64 = 0, total_critical: u64 = 0,
    pub fn init(allocator: std.mem.Allocator, max_incidents: usize, window_ms: i64, escalate_at: u8, critical_at: u8) CrossNodeIncidentAggregator {
        return .{ .allocator = allocator, .incidents = std.AutoHashMap(u64, ClusterIncident).init(allocator), .max_incidents = max_incidents, .window_ms = window_ms, .escalate_at = escalate_at, .critical_at = critical_at };
    }
    pub fn deinit(self: *CrossNodeIncidentAggregator) void { self.incidents.deinit(); }
    fn aggregateKey(src_ip: [4]u8, port: u16, proto: u8) u64 {
        return @as(u64, src_ip[0]) << 56 | @as(u64, src_ip[1]) << 48 | @as(u64, src_ip[2]) << 40 | @as(u64, src_ip[3]) << 32 | @as(u64, port) << 16 | proto;
    }
    pub fn report(self: *CrossNodeIncidentAggregator, src_ip: [4]u8, port: u16, proto: u8, node_id: u32, sev: IncidentSeverity, score: f32, now_ns: i64) !u64 {
        self.total_reports += 1;
        const key = aggregateKey(src_ip, port, proto);
        if (self.incidents.getPtr(key)) |existing| {
            if (@divFloor(now_ns - existing.last_seen_ns, 1_000_000) <= self.window_ms) {
                _ = existing.addReportingNode(node_id); existing.last_seen_ns = now_ns;
                existing.score = @max(existing.score, score); self.escalate(existing);
                return existing.incident_id;
            }
        }
        const id = self.next_incident_id; self.next_incident_id += 1;
        var inc = ClusterIncident{ .incident_id = id, .timestamp_ns = now_ns, .source_ip = src_ip, .remote_port = port, .proto = proto, .severity = sev, .score = score, .first_seen_ns = now_ns, .last_seen_ns = now_ns };
        _ = inc.addReportingNode(node_id); self.escalate(&inc);
        try self.incidents.put(key, inc); return id;
    }
    fn escalate(self: *CrossNodeIncidentAggregator, inc: *ClusterIncident) void {
        if (inc.reporting_count >= self.critical_at) { inc.severity = .critical; self.total_critical += 1; }
        else if (inc.reporting_count >= self.escalate_at) { if (@intFromEnum(inc.severity) < @intFromEnum(IncidentSeverity.high)) inc.severity = .high; self.total_escalated += 1; }
    }
    pub fn getIncident(self: *const CrossNodeIncidentAggregator, src_ip: [4]u8, port: u16, proto: u8) ?ClusterIncident {
        return self.incidents.get(aggregateKey(src_ip, port, proto));
    }
};

pub const ClusterConfig = struct {
    enabled: bool = false,
    node_id: u32 = 0,
    role: NodeRole = .sensor,
    heartbeat_interval_ms: i64 = 5_000,
    heartbeat_timeout_ms: i64 = HEARTBEAT_TIMEOUT_MS,
    heartbeat_dead_threshold: u8 = HEARTBEAT_DEAD_THRESHOLD,
    cross_node_window_ms: i64 = 30_000,
    escalate_at_node_count: u8 = 2,
    critical_node_count: u8 = 3,
    election_interval_ms: i64 = LEADER_ELECTION_INTERVAL_MS,
    max_nodes: usize = MAX_NODES,
    max_incidents: usize = 512,
};

pub const ClusterCoord = struct {
    allocator: std.mem.Allocator, config: ClusterConfig,
    registry: NodeRegistry, heartbeat: HeartbeatMonitor,
    aggregator: CrossNodeIncidentAggregator, election: LeaderElection,
    initialized: bool = false,
    var _instance: ?ClusterCoord = null;
    pub fn instance() ?*ClusterCoord { return if (_instance) |*i| i else null; }
    pub fn init(allocator: std.mem.Allocator, config: ClusterConfig) !*ClusterCoord {
        if (_instance != null) return &_instance.?;
        _instance = ClusterCoord{
            .allocator = allocator, .config = config,
            .registry = NodeRegistry.init(allocator, config.max_nodes, config.node_id),
            .heartbeat = HeartbeatMonitor.init(config.heartbeat_timeout_ms, config.heartbeat_dead_threshold),
            .aggregator = CrossNodeIncidentAggregator.init(allocator, config.max_incidents, config.cross_node_window_ms, config.escalate_at_node_count, config.critical_node_count),
            .election = LeaderElection.init(config.election_interval_ms),
        };
        var self = &_instance.?;
        var self_node = ClusterNode{ .node_id = config.node_id, .role = config.role, .health = .healthy, .is_self = true, .joined_ns = @intCast(std.time.nanoTimestamp()), .last_seen_ns = @intCast(std.time.nanoTimestamp()) };
        _ = self.registry.upsert(self_node);
        self.initialized = true;
        return self;
    }
    pub fn shutdown(self: *ClusterCoord) void {
        if (!self.initialized) return;
        self.registry.deinit(); self.aggregator.deinit(); self.initialized = false; _instance = null;
    }
    pub fn isAvailable(self: *const ClusterCoord) bool { return self.initialized and self.config.enabled; }
    pub fn currentLeader(self: *const ClusterCoord) u32 { return self.election.current_leader; }
    pub fn isLeader(self: *const ClusterCoord) bool { return self.election.isLeader(self.config.node_id); }
};

test "G17: NodeRegistry upsert and lookup" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();
    try std.testing.expect(reg.upsert(.{ .node_id = 5, .health = .healthy }));
    try std.testing.expectEqual(@as(usize, 1), reg.count());
    try std.testing.expectEqual(@as(u32, 5), reg.get(5).?.node_id);
}
test "G17: HeartbeatMonitor degrades on timeout" {
    var hm = HeartbeatMonitor.init(15_000, 3);
    var node = ClusterNode{ .node_id = 5, .health = .healthy, .last_seen_ns = 0 };
    var h = hm.checkTimeout(&node, 20_000_000_000);
    try std.testing.expectEqual(NodeHealth.degraded, h);
    h = hm.checkTimeout(&node, 40_000_000_000);
    try std.testing.expectEqual(NodeHealth.unhealthy, h);
    h = hm.checkTimeout(&node, 60_000_000_000);
    try std.testing.expectEqual(NodeHealth.dead, h);
}
test "G17: CrossNodeIncidentAggregator escalates at 3 nodes" {
    var agg = CrossNodeIncidentAggregator.init(std.testing.allocator, .{});
    defer agg.deinit();
    _ = try agg.report(.{198,51,100,42}, 4444, 6, 1, .medium, 0.85, 1_000_000_000);
    _ = try agg.report(.{198,51,100,42}, 4444, 6, 2, .medium, 0.85, 1_100_000_000);
    _ = try agg.report(.{198,51,100,42}, 4444, 6, 3, .medium, 0.85, 1_200_000_000);
    const inc = agg.getIncident(.{198,51,100,42}, 4444, 6).?;
    try std.testing.expectEqual(@as(u8, 3), inc.reporting_count);
    try std.testing.expectEqual(IncidentSeverity.critical, inc.severity);
}
test "G17: LeaderElection picks highest active NodeId" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();
    _ = reg.upsert(.{ .node_id = 1, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 5, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 10, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 20, .health = .dead });
    var le = LeaderElection.init(30_000);
    const r = le.elect(&reg, 1_000_000_000);
    try std.testing.expectEqual(@as(u32, 10), r.leader);
    try std.testing.expect(r.changed);
}
test "G17: ClusterCoord singleton init/shutdown" {
    const alloc = std.testing.allocator;
    var c = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer c.shutdown();
    try std.testing.expect(c.isAvailable());
    try std.testing.expectEqual(@as(usize, 1), c.registry.count());
}
