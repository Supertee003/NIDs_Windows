//! cluster_coord.zig - AEGIS NIDS Phase 39: Distributed Cluster Coordination
//!
//! Extends AEGIS from single-node NIDS to a coordinated multi-sensor cluster.
//! A single sensor sees only its own network segment; Phase 39 lets multiple
//! sensors share state so that an attacker hitting several segments is
//! recognized as one campaign rather than N isolated incidents.
//!
//! Five coordinated capabilities:
//!   1. ClusterNode registry (peer discovery + capacity + role)
//!   2. HeartbeatMonitor (liveness: last_seen, miss count, health state)
//!   3. CrossNodeIncidentAggregator (same source IP across N nodes within
//!      window_ms -> severity escalation)
//!   4. ThreatIntelBroadcast (IP/hash signatures shared across nodes)
//!   5. LeaderElection (deterministic ring election by NodeId)
//!
//! Design principles (mirrors Phase 32 Npcap + Phase 36 ML + Phase 37 HIDS):
//!   - Pure Zig, host-testable on Linux (no real network sockets in this
//!     module; adapters for gRPC/ZeroMQ/REST feed messages via ingest())
//!   - Additive only - enforcement stays in WFP kernel driver per node
//!   - Kill switch OFF by default; ClusterConfig{.enabled=true} opts in
//!   - Singleton facade (init/shutdown/instance/isAvailable) - project style
//!   - Bounded memory, fixed caps (no unbounded growth under attack)
//!
//! Build:
//!   zig test cluster_coord.zig -lc
//!   zig build-exe cluster_cli.zig -lc   (uses this module)
//!
//! Integration:
//!   const cc = @import("cluster_coord.zig");
//!   try cc.ClusterCoord.instance().?.init(allocator, .{ .node_id = 1 });
//!   defer cc.ClusterCoord.instance().?.shutdown();
//!   cc.ClusterCoord.instance().?.ingest(msg);

const std = @import("std");

// ============================================================
// Constants & limits
// ============================================================

pub const MAX_NODES: usize = 64;
pub const MAX_INCIDENTS: usize = 512;
pub const MAX_THREAT_INTEL: usize = 1024;
pub const MAX_NODE_NAME: usize = 64;
pub const MAX_NODE_ENDPOINT: usize = 128;
pub const MAX_INCIDENT_REASONS: usize = 6;
pub const MAX_INCIDENT_LABEL: usize = 24;
pub const HEARTBEAT_TIMEOUT_MS: i64 = 15_000;
pub const HEARTBEAT_DEAD_THRESHOLD: u8 = 3;
pub const CROSS_NODE_WINDOW_MS: i64 = 30_000;
pub const LEADER_ELECTION_INTERVAL_MS: i64 = 30_000;

// ============================================================
// Enums
// ============================================================

pub const NodeRole = enum(u8) {
    sensor = 0,
    coordinator = 1,
    aggregator = 2,

    pub fn toString(self: NodeRole) []const u8 {
        return switch (self) {
            .sensor => "SENSOR",
            .coordinator => "COORDINATOR",
            .aggregator => "AGGREGATOR",
        };
    }
};

pub const NodeHealth = enum(u8) {
    healthy = 0,
    degraded = 1,
    unhealthy = 2,
    dead = 3,

    pub fn toString(self: NodeHealth) []const u8 {
        return switch (self) {
            .healthy => "HEALTHY",
            .degraded => "DEGRADED",
            .unhealthy => "UNHEALTHY",
            .dead => "DEAD",
        };
    }

    pub fn isActive(self: NodeHealth) bool {
        return self == .healthy or self == .degraded;
    }
};

pub const MessageType = enum(u8) {
    heartbeat = 0,
    node_join = 1,
    node_leave = 2,
    incident_report = 3,
    threat_intel_share = 4,
    leader_announce = 5,
    leader_request = 6,

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .heartbeat => "HEARTBEAT",
            .node_join => "NODE_JOIN",
            .node_leave => "NODE_LEAVE",
            .incident_report => "INCIDENT_REPORT",
            .threat_intel_share => "THREAT_INTEL_SHARE",
            .leader_announce => "LEADER_ANNOUNCE",
            .leader_request => "LEADER_REQUEST",
        };
    }
};

pub const IncidentSeverity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn toString(self: IncidentSeverity) []const u8 {
        return switch (self) {
            .info => "INFO",
            .low => "LOW",
            .medium => "MEDIUM",
            .high => "HIGH",
            .critical => "CRITICAL",
        };
    }
};

// ============================================================
// ClusterConfig (kill switch + cluster parameters)
// ============================================================

pub const ClusterConfig = struct {
    /// Master kill switch. OFF by default - cluster coordination is a
    /// no-op until explicitly enabled. Per-node enforcement stays in the
    /// WFP kernel driver; this module is detection/attribution only.
    enabled: bool = false,
    /// Identity of THIS node (must be unique within the cluster).
    node_id: u32 = 0,
    /// Cluster display name (for logging / UI).
    cluster_name: [MAX_NODE_NAME]u8 = [_]u8{0} ** MAX_NODE_NAME,
    cluster_name_len: u8 = 0,
    /// Role this node plays in the cluster.
    role: NodeRole = .sensor,
    /// Heartbeat parameters
    heartbeat_interval_ms: i64 = 5_000,
    heartbeat_timeout_ms: i64 = HEARTBEAT_TIMEOUT_MS,
    heartbeat_dead_threshold: u8 = HEARTBEAT_DEAD_THRESHOLD,
    /// Cross-node incident aggregation window (same source IP seen at
    /// multiple nodes within this window -> severity escalation)
    cross_node_window_ms: i64 = CROSS_NODE_WINDOW_MS,
    /// Threat intel broadcast limits
    max_threat_intel: usize = MAX_THREAT_INTEL,
    max_nodes: usize = MAX_NODES,
    max_incidents: usize = MAX_INCIDENTS,
    /// Leader election
    election_interval_ms: i64 = LEADER_ELECTION_INTERVAL_MS,
    /// Escalation thresholds: incident reported by N nodes -> bump severity
    escalate_at_node_count: u8 = 2,
    /// When cross-node count >= this, severity becomes CRITICAL
    critical_node_count: u8 = 3,
};

// ============================================================
// ClusterNode (peer registry entry)
// ============================================================

pub const ClusterNode = struct {
    node_id: u32 = 0,
    name: [MAX_NODE_NAME]u8 = [_]u8{0} ** MAX_NODE_NAME,
    name_len: u8 = 0,
    endpoint: [MAX_NODE_ENDPOINT]u8 = [_]u8{0} ** MAX_NODE_ENDPOINT,
    endpoint_len: u8 = 0,
    role: NodeRole = .sensor,
    health: NodeHealth = .healthy,
    capacity: u16 = 1000,
    last_seen_ns: i64 = 0,
    joined_ns: i64 = 0,
    heartbeat_misses: u8 = 0,
    incidents_reported: u64 = 0,
    threat_intel_contributed: u64 = 0,
    is_self: bool = false,

    pub fn nameStr(self: *const ClusterNode) []const u8 {
        return self.name[0..self.name_len];
    }
    pub fn endpointStr(self: *const ClusterNode) []const u8 {
        return self.endpoint[0..self.endpoint_len];
    }
    pub fn isActive(self: *const ClusterNode) bool {
        return self.health.isActive();
    }
};

// ============================================================
// NodeRegistry (peers + self; bounded by MAX_NODES)
// ============================================================

pub const NodeRegistry = struct {
    allocator: std.mem.Allocator,
    nodes: std.AutoHashMap(u32, ClusterNode),
    max_nodes: usize,
    self_id: u32 = 0,
    total_joins: u64 = 0,
    total_leaves: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_nodes: usize, self_id: u32) NodeRegistry {
        return .{
            .allocator = allocator,
            .nodes = std.AutoHashMap(u32, ClusterNode).init(allocator),
            .max_nodes = max_nodes,
            .self_id = self_id,
        };
    }

    pub fn deinit(self: *NodeRegistry) void {
        self.nodes.deinit();
    }

    /// Register or refresh a peer. If new and at capacity, evict the
    /// oldest dead node (LRU-ish under contention).
    pub fn upsert(self: *NodeRegistry, node: ClusterNode) bool {
        if (self.nodes.count() >= self.max_nodes and !self.nodes.contains(node.node_id)) {
            self.evictOneDead() orelse return false;
        }
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

    pub fn get(self: *const NodeRegistry, node_id: u32) ?ClusterNode {
        return self.nodes.get(node_id);
    }

    pub fn getMut(self: *NodeRegistry, node_id: u32) ?*ClusterNode {
        return self.nodes.getPtr(node_id);
    }

    pub fn count(self: *const NodeRegistry) usize {
        return self.nodes.count();
    }

    pub fn activeCount(self: *const NodeRegistry) usize {
        var c: usize = 0;
        var it = self.nodes.valueIterator();
        while (it.next()) |n| {
            if (n.isActive()) c += 1;
        }
        return c;
    }

    /// Snapshot all node IDs to a caller-provided buffer (sorted ascending).
    pub fn listIds(self: *const NodeRegistry, out: []u32) usize {
        var n: usize = 0;
        var it = self.nodes.keyIterator();
        while (it.next()) |id| {
            if (n >= out.len) break;
            out[n] = id.*;
            n += 1;
        }
        // Bubble sort (small N, no alloc)
        var i: usize = 0;
        while (i + 1 < n) : (i += 1) {
            var j: usize = 0;
            while (j + 1 < n - i) : (j += 1) {
                if (out[j] > out[j + 1]) {
                    const t = out[j];
                    out[j] = out[j + 1];
                    out[j + 1] = t;
                }
            }
        }
        return n;
    }

    fn evictOneDead(self: *NodeRegistry) ?void {
        var victim: ?u32 = null;
        var oldest: i64 = std.math.maxInt(i64);
        var it = self.nodes.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.health == .dead) {
                if (entry.value_ptr.last_seen_ns < oldest) {
                    oldest = entry.value_ptr.last_seen_ns;
                    victim = entry.key_ptr.*;
                }
            }
        }
        if (victim) |v| {
            _ = self.nodes.remove(v);
            self.total_leaves += 1;
            return {};
        }
        return null;
    }

    pub fn resetStats(self: *NodeRegistry) void {
        self.total_joins = 0;
        self.total_leaves = 0;
    }
};

// ============================================================
// HeartbeatMonitor (liveness: healthy -> degraded -> unhealthy -> dead)
// ============================================================

pub const HeartbeatMonitor = struct {
    timeout_ms: i64,
    dead_threshold: u8,
    total_beats: u64 = 0,
    total_timeouts: u64 = 0,
    total_dead: u64 = 0,

    pub fn init(timeout_ms: i64, dead_threshold: u8) HeartbeatMonitor {
        return .{
            .timeout_ms = timeout_ms,
            .dead_threshold = dead_threshold,
        };
    }

    /// Apply a heartbeat: refresh last_seen + reset misses + set healthy.
    pub fn onHeartbeat(self: *HeartbeatMonitor, node: *ClusterNode, now_ns: i64) void {
        node.last_seen_ns = now_ns;
        node.heartbeat_misses = 0;
        if (node.health != .healthy) node.health = .healthy;
        self.total_beats += 1;
    }

    /// Check one node for timeout; if missed, bump misses and degrade.
    /// Returns the new health state.
    pub fn checkTimeout(self: *HeartbeatMonitor, node: *ClusterNode, now_ns: i64) NodeHealth {
        const elapsed_ms = @divFloor(now_ns - node.last_seen_ns, 1_000_000);
        if (elapsed_ms < self.timeout_ms) {
            return node.health; // still fresh
        }
        node.heartbeat_misses += 1;
        self.total_timeouts += 1;
        if (node.heartbeat_misses >= self.dead_threshold) {
            node.health = .dead;
            self.total_dead += 1;
        } else if (node.heartbeat_misses >= self.dead_threshold / 2 + 1) {
            node.health = .unhealthy;
        } else {
            node.health = .degraded;
        }
        return node.health;
    }

    pub fn resetStats(self: *HeartbeatMonitor) void {
        self.total_beats = 0;
        self.total_timeouts = 0;
        self.total_dead = 0;
    }
};

// ============================================================
// ClusterIncident (report from a node; may aggregate across nodes)
// ============================================================

pub const ClusterIncident = struct {
    incident_id: u64 = 0,
    timestamp_ns: i64 = 0,
    source_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dest_ip: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,
    proto: u8 = 6, // TCP
    severity: IncidentSeverity = .info,
    label: [MAX_INCIDENT_LABEL]u8 = [_]u8{0} ** MAX_INCIDENT_LABEL,
    label_len: u8 = 0,
    score: f32 = 0.0,
    reporting_node_ids: [8]u32 = [_]u32{0} ** 8,
    reporting_count: u8 = 0,
    first_seen_ns: i64 = 0,
    last_seen_ns: i64 = 0,
    reasons: [MAX_INCIDENT_REASONS][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** MAX_INCIDENT_REASONS,
    reason_lens: [MAX_INCIDENT_REASONS]u8 = [_]u8{0} ** MAX_INCIDENT_REASONS,
    reason_count: u8 = 0,

    pub fn labelStr(self: *const ClusterIncident) []const u8 {
        return self.label[0..self.label_len];
    }

    pub fn addReportingNode(self: *ClusterIncident, node_id: u32) bool {
        if (self.reporting_count >= 8) return false;
        var i: u8 = 0;
        while (i < self.reporting_count) : (i += 1) {
            if (self.reporting_node_ids[i] == node_id) return false; // dedup
        }
        self.reporting_node_ids[self.reporting_count] = node_id;
        self.reporting_count += 1;
        return true;
    }

    pub fn addReason(self: *ClusterIncident, reason: []const u8) void {
        if (self.reason_count >= MAX_INCIDENT_REASONS) return;
        const n = @min(reason.len, 32);
        @memcpy(self.reasons[self.reason_count][0..n], reason[0..n]);
        self.reason_lens[self.reason_count] = @intCast(n);
        self.reason_count += 1;
    }

    pub fn reasonStr(self: *const ClusterIncident, idx: u8) []const u8 {
        if (idx >= self.reason_count) return "";
        return self.reasons[idx][0..self.reason_lens[idx]];
    }
};

// ============================================================
// CrossNodeIncidentAggregator (same source IP across N nodes -> escalate)
// ============================================================

pub const CrossNodeIncidentAggregator = struct {
    allocator: std.mem.Allocator,
    incidents: std.AutoHashMap(u64, ClusterIncident),
    max_incidents: usize,
    window_ms: i64,
    escalate_at: u8,
    critical_at: u8,
    next_incident_id: u64 = 1,
    total_reports: u64 = 0,
    total_aggregated: u64 = 0,
    total_escalated: u64 = 0,
    total_critical: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, config: ClusterConfig) CrossNodeIncidentAggregator {
        return .{
            .allocator = allocator,
            .incidents = std.AutoHashMap(u64, ClusterIncident).init(allocator),
            .max_incidents = config.max_incidents,
            .window_ms = config.cross_node_window_ms,
            .escalate_at = config.escalate_at_node_count,
            .critical_at = config.critical_node_count,
        };
    }

    pub fn deinit(self: *CrossNodeIncidentAggregator) void {
        self.incidents.deinit();
    }

    /// Stable aggregation key: source_ip + remote_port + proto. Two
    /// nodes reporting the same source hitting the same dest:port join.
    fn aggregateKey(source_ip: [4]u8, remote_port: u16, proto: u8) u64 {
        var k: u64 = 0;
        k |= @as(u64, source_ip[0]) << 56;
        k |= @as(u64, source_ip[1]) << 48;
        k |= @as(u64, source_ip[2]) << 40;
        k |= @as(u64, source_ip[3]) << 32;
        k |= @as(u64, remote_port) << 16;
        k |= @as(u64, proto);
        return k;
    }

    /// Report an incident from a node. Returns the (possibly aggregated)
    /// incident ID. Severity escalates as reporting_count grows.
    pub fn report(self: *CrossNodeIncidentAggregator, src_ip: [4]u8, remote_port: u16, proto: u8, reporting_node_id: u32, severity: IncidentSeverity, score: f32, label: []const u8, now_ns: i64) !u64 {
        if (self.incidents.count() >= self.max_incidents) {
            self.evictOneExpired(now_ns);
        }
        const key = aggregateKey(src_ip, remote_port, proto);
        self.total_reports += 1;

        if (self.incidents.getPtr(key)) |existing| {
            // Existing incident - aggregate if within window
            const elapsed_ms = @divFloor(now_ns - existing.last_seen_ns, 1_000_000);
            if (elapsed_ms <= self.window_ms) {
                if (existing.addReportingNode(reporting_node_id)) {
                    self.total_aggregated += 1;
                }
                existing.last_seen_ns = now_ns;
                existing.score = @max(existing.score, score);
                self.escalate(existing);
                return existing.incident_id;
            } else {
                // Window expired - reset
                existing.reporting_count = 0;
                _ = existing.addReportingNode(reporting_node_id);
                existing.first_seen_ns = now_ns;
                existing.last_seen_ns = now_ns;
                existing.severity = severity;
                existing.score = score;
                self.escalate(existing);
                return existing.incident_id;
            }
        }

        // New incident
        const id = self.next_incident_id;
        self.next_incident_id += 1;
        var inc = ClusterIncident{
            .incident_id = id,
            .timestamp_ns = now_ns,
            .source_ip = src_ip,
            .remote_port = remote_port,
            .proto = proto,
            .severity = severity,
            .score = score,
            .first_seen_ns = now_ns,
            .last_seen_ns = now_ns,
        };
        const n = @min(label.len, MAX_INCIDENT_LABEL);
        @memcpy(inc.label[0..n], label[0..n]);
        inc.label_len = @intCast(n);
        _ = inc.addReportingNode(reporting_node_id);
        self.escalate(&inc);
        try self.incidents.put(key, inc);
        return id;
    }

    fn escalate(self: *CrossNodeIncidentAggregator, inc: *ClusterIncident) void {
        const c = inc.reporting_count;
        if (c >= self.critical_at) {
            inc.severity = .critical;
            self.total_critical += 1;
        } else if (c >= self.escalate_at) {
            if (@intFromEnum(inc.severity) < @intFromEnum(IncidentSeverity.high)) {
                inc.severity = .high;
            }
            self.total_escalated += 1;
        }
    }

    fn evictOneExpired(self: *CrossNodeIncidentAggregator, now_ns: i64) void {
        var victim_key: ?u64 = null;
        var oldest: i64 = std.math.maxInt(i64);
        var it = self.incidents.iterator();
        while (it.next()) |entry| {
            // Expire if outside window OR older than 5x window (stale)
            const elapsed_ms = @divFloor(now_ns - entry.value_ptr.last_seen_ns, 1_000_000);
            if (elapsed_ms > self.window_ms * 5 and entry.value_ptr.last_seen_ns < oldest) {
                oldest = entry.value_ptr.last_seen_ns;
                victim_key = entry.key_ptr.*;
            }
        }
        if (victim_key) |k| {
            _ = self.incidents.remove(k);
        } else if (self.incidents.count() > 0) {
            // No expired - evict oldest by last_seen
            it = self.incidents.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.last_seen_ns < oldest) {
                    oldest = entry.value_ptr.last_seen_ns;
                    victim_key = entry.key_ptr.*;
                }
            }
            if (victim_key) |k| _ = self.incidents.remove(k);
        }
    }

    pub fn getIncident(self: *const CrossNodeIncidentAggregator, src_ip: [4]u8, remote_port: u16, proto: u8) ?ClusterIncident {
        const key = aggregateKey(src_ip, remote_port, proto);
        return self.incidents.get(key);
    }

    pub fn incidentCount(self: *const CrossNodeIncidentAggregator) usize {
        return self.incidents.count();
    }

    pub fn resetStats(self: *CrossNodeIncidentAggregator) void {
        self.total_reports = 0;
        self.total_aggregated = 0;
        self.total_escalated = 0;
        self.total_critical = 0;
    }
};

// ============================================================
// ThreatIntelEntry (shared IoC: malicious IP / hash / domain)
// ============================================================

pub const ThreatIntelKind = enum(u8) {
    malicious_ip = 0,
    malicious_hash = 1,
    malicious_domain = 2,
    c2_server = 3,

    pub fn toString(self: ThreatIntelKind) []const u8 {
        return switch (self) {
            .malicious_ip => "MALICIOUS_IP",
            .malicious_hash => "MALICIOUS_HASH",
            .malicious_domain => "MALICIOUS_DOMAIN",
            .c2_server => "C2_SERVER",
        };
    }
};

pub const ThreatIntelEntry = struct {
    kind: ThreatIntelKind = .malicious_ip,
    // IP form (when kind is malicious_ip / c2_server)
    ip: [4]u8 = .{ 0, 0, 0, 0 },
    // Hash form (when kind is malicious_hash) - SHA-256 first 16 bytes
    hash: [16]u8 = [_]u8{0} ** 16,
    // Domain form (when kind is malicious_domain)
    domain: [64]u8 = [_]u8{0} ** 64,
    domain_len: u8 = 0,
    source_node_id: u32 = 0,
    first_seen_ns: i64 = 0,
    confidence: u8 = 50, // 0-100
    hits: u32 = 0,
};

pub const ThreatIntelBroadcast = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(ThreatIntelEntry),
    max_entries: usize,
    total_received: u64 = 0,
    total_shared: u64 = 0,
    total_hits: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) ThreatIntelBroadcast {
        return .{
            .allocator = allocator,
            .entries = std.ArrayList(ThreatIntelEntry).init(allocator),
            .max_entries = max_entries,
        };
    }

    pub fn deinit(self: *ThreatIntelBroadcast) void {
        self.entries.deinit();
    }

    /// Receive a threat intel entry from a peer. Deduplicates by (kind, key).
    /// Returns true if added (new), false if duplicate or full.
    pub fn receive(self: *ThreatIntelBroadcast, entry: ThreatIntelEntry) bool {
        for (self.entries.items) |*e| {
            if (e.kind != entry.kind) continue;
            switch (entry.kind) {
                .malicious_ip, .c2_server => {
                    if (std.mem.eql(u8, &e.ip, &entry.ip)) {
                        e.hits += 1;
                        return false;
                    }
                },
                .malicious_hash => {
                    if (std.mem.eql(u8, &e.hash, &entry.hash)) {
                        e.hits += 1;
                        return false;
                    }
                },
                .malicious_domain => {
                    if (std.mem.eql(u8, e.domain[0..e.domain_len], entry.domain[0..entry.domain_len])) {
                        e.hits += 1;
                        return false;
                    }
                },
            }
        }
        if (self.entries.items.len >= self.max_entries) {
            // Evict lowest-confidence
            var min_idx: usize = 0;
            var min_conf: u8 = 255;
            for (self.entries.items, 0..) |e, i| {
                if (e.confidence < min_conf) {
                    min_conf = e.confidence;
                    min_idx = i;
                }
            }
            _ = self.entries.swapRemove(min_idx);
        }
        self.entries.append(entry) catch return false;
        self.total_received += 1;
        return true;
    }

    /// Check if an IP is in the threat intel list. Bumps hit counter
    /// when matched (so source nodes can see how often their IoC was useful).
    pub fn checkIp(self: *ThreatIntelBroadcast, ip: [4]u8) ?*ThreatIntelEntry {
        for (self.entries.items) |*e| {
            if (e.kind == .malicious_ip or e.kind == .c2_server) {
                if (std.mem.eql(u8, &e.ip, &ip)) {
                    e.hits += 1;
                    self.total_hits += 1;
                    return e;
                }
            }
        }
        return null;
    }

    pub fn checkHash(self: *ThreatIntelBroadcast, hash: [16]u8) ?*ThreatIntelEntry {
        for (self.entries.items) |*e| {
            if (e.kind == .malicious_hash) {
                if (std.mem.eql(u8, &e.hash, &hash)) {
                    e.hits += 1;
                    self.total_hits += 1;
                    return e;
                }
            }
        }
        return null;
    }

    pub fn entryCount(self: *const ThreatIntelBroadcast) usize {
        return self.entries.items.len;
    }

    pub fn resetStats(self: *ThreatIntelBroadcast) void {
        self.total_received = 0;
        self.total_shared = 0;
        self.total_hits = 0;
    }
};

// ============================================================
// LeaderElection (deterministic ring: highest active NodeId wins)
// ============================================================

pub const LeaderElection = struct {
    current_leader: u32 = 0,
    leader_since_ns: i64 = 0,
    election_count: u64 = 0,
    last_election_ns: i64 = 0,
    election_interval_ms: i64,

    pub fn init(election_interval_ms: i64) LeaderElection {
        return .{ .election_interval_ms = election_interval_ms };
    }

    /// Run an election across the registry. Picks the highest active
    /// NodeId (deterministic, no Paxos/Raft complexity needed for NIDS).
    /// Returns the elected leader ID; if the leader changed,
    /// `changed` is true (caller can emit a LEADER_ANNOUNCE).
    pub const ElectionResult = struct {
        leader: u32,
        changed: bool,
    };

    pub fn elect(self: *LeaderElection, registry: *const NodeRegistry, now_ns: i64) ElectionResult {
        var winner: u32 = 0;
        var it = registry.nodes.valueIterator();
        while (it.next()) |n| {
            if (!n.isActive()) continue;
            if (n.node_id > winner) winner = n.node_id;
        }
        const changed = winner != self.current_leader;
        if (changed) {
            self.current_leader = winner;
            self.leader_since_ns = now_ns;
        }
        self.last_election_ns = now_ns;
        self.election_count += 1;
        return .{ .leader = winner, .changed = changed };
    }

    /// Should we run an election now? (interval elapsed)
    pub fn shouldRunElection(self: *const LeaderElection, now_ns: i64) bool {
        const elapsed_ms = @divFloor(now_ns - self.last_election_ns, 1_000_000);
        return elapsed_ms >= self.election_interval_ms;
    }

    pub fn isLeader(self: *const LeaderElection, node_id: u32) bool {
        return self.current_leader == node_id and self.current_leader != 0;
    }

    pub fn resetStats(self: *LeaderElection) void {
        self.election_count = 0;
    }
};

// ============================================================
// ClusterMessage (federation protocol envelope)
// ============================================================

pub const ClusterMessage = struct {
    msg_type: MessageType,
    from_node_id: u32,
    to_node_id: u32 = 0, // 0 = broadcast
    timestamp_ns: i64 = 0,
    // Payloads (only one relevant per msg_type)
    node: ?ClusterNode = null,
    incident_source_ip: [4]u8 = .{ 0, 0, 0, 0 },
    incident_remote_port: u16 = 0,
    incident_proto: u8 = 6,
    incident_severity: IncidentSeverity = .info,
    incident_score: f32 = 0.0,
    incident_label: [MAX_INCIDENT_LABEL]u8 = [_]u8{0} ** MAX_INCIDENT_LABEL,
    incident_label_len: u8 = 0,
    threat_intel: ?ThreatIntelEntry = null,
    leader_node_id: u32 = 0,
};

// ============================================================
// ClusterCoord facade (singleton, project style)
// ============================================================

pub const ClusterCoord = struct {
    allocator: std.mem.Allocator,
    config: ClusterConfig,
    registry: NodeRegistry,
    heartbeat: HeartbeatMonitor,
    aggregator: CrossNodeIncidentAggregator,
    threat_intel: ThreatIntelBroadcast,
    election: LeaderElection,
    initialized: bool = false,

    var _instance: ?ClusterCoord = null;

    pub fn instance() ?*ClusterCoord {
        if (_instance) |*i| return i;
        return null;
    }

    pub fn init(allocator: std.mem.Allocator, config: ClusterConfig) !*ClusterCoord {
        if (_instance != null) return &_instance.?;
        _instance = ClusterCoord{
            .allocator = allocator,
            .config = config,
            .registry = NodeRegistry.init(allocator, config.max_nodes, config.node_id),
            .heartbeat = HeartbeatMonitor.init(config.heartbeat_timeout_ms, config.heartbeat_dead_threshold),
            .aggregator = CrossNodeIncidentAggregator.init(allocator, config),
            .threat_intel = ThreatIntelBroadcast.init(allocator, config.max_threat_intel),
            .election = LeaderElection.init(config.election_interval_ms),
        };
        var self = &_instance.?;
        // Self-register
        var self_node = ClusterNode{
            .node_id = config.node_id,
            .role = config.role,
            .health = .healthy,
            .is_self = true,
            .joined_ns = @intCast(std.time.nanoTimestamp()),
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        };
        const cname = config.cluster_name[0..config.cluster_name_len];
        @memcpy(self_node.name[0..cname.len], cname);
        self_node.name_len = config.cluster_name_len;
        _ = self.registry.upsert(self_node);
        self.initialized = true;
        return self;
    }

    pub fn shutdown(self: *ClusterCoord) void {
        if (!self.initialized) return;
        self.registry.deinit();
        self.aggregator.deinit();
        self.threat_intel.deinit();
        self.initialized = false;
        _instance = null;
    }

    pub fn isAvailable(self: *const ClusterCoord) bool {
        return self.initialized and self.config.enabled;
    }

    /// Ingest a cluster message (heartbeat, incident, threat intel, etc).
    /// All federation protocol traffic flows through this single entry point.
    pub fn ingest(self: *ClusterCoord, msg: ClusterMessage) void {
        if (!self.config.enabled) return;
        const now_ns = msg.timestamp_ns;
        switch (msg.msg_type) {
            .heartbeat => {
                if (self.registry.getMut(msg.from_node_id)) |n| {
                    self.heartbeat.onHeartbeat(n, now_ns);
                } else {
                    var new_node = ClusterNode{
                        .node_id = msg.from_node_id,
                        .health = .healthy,
                        .last_seen_ns = now_ns,
                        .joined_ns = now_ns,
                    };
                    if (msg.node) |src| {
                        @memcpy(new_node.name[0..src.name_len], src.name[0..src.name_len]);
                        new_node.name_len = src.name_len;
                        @memcpy(new_node.endpoint[0..src.endpoint_len], src.endpoint[0..src.endpoint_len]);
                        new_node.endpoint_len = src.endpoint_len;
                        new_node.role = src.role;
                    }
                    _ = self.registry.upsert(new_node);
                    self.heartbeat.onHeartbeat(self.registry.getMut(msg.from_node_id).?, now_ns);
                }
            },
            .node_join => {
                if (msg.node) |n| {
                    var joined = n;
                    joined.joined_ns = now_ns;
                    joined.last_seen_ns = now_ns;
                    joined.health = .healthy;
                    _ = self.registry.upsert(joined);
                }
            },
            .node_leave => {
                _ = self.registry.remove(msg.from_node_id);
            },
            .incident_report => {
                const inc_label = msg.incident_label[0..msg.incident_label_len];
                _ = self.aggregator.report(
                    msg.incident_source_ip,
                    msg.incident_remote_port,
                    msg.incident_proto,
                    msg.from_node_id,
                    msg.incident_severity,
                    msg.incident_score,
                    inc_label,
                    now_ns,
                ) catch {};
                if (self.registry.getMut(msg.from_node_id)) |n| {
                    n.incidents_reported += 1;
                }
            },
            .threat_intel_share => {
                if (msg.threat_intel) |ti| {
                    _ = self.threat_intel.receive(ti);
                    if (self.registry.getMut(msg.from_node_id)) |n| {
                        n.threat_intel_contributed += 1;
                    }
                }
            },
            .leader_announce => {
                // Trust the announced leader (no Byzantine defense; deterministic
                // election would produce the same answer)
                self.election.current_leader = msg.leader_node_id;
                self.election.leader_since_ns = now_ns;
            },
            .leader_request => {
                // Trigger election now if interval allows
                if (self.election.shouldRunElection(now_ns)) {
                    _ = self.election.elect(&self.registry, now_ns);
                }
            },
        }
    }

    /// Check if a remote IP is in the shared threat intel list.
    pub fn checkThreatIp(self: *ClusterCoord, ip: [4]u8) ?*ThreatIntelEntry {
        if (!self.config.enabled) return null;
        return self.threat_intel.checkIp(ip);
    }

    /// Check if a file hash is in the shared threat intel list.
    pub fn checkThreatHash(self: *ClusterCoord, hash: [16]u8) ?*ThreatIntelEntry {
        if (!self.config.enabled) return null;
        return self.threat_intel.checkHash(hash);
    }

    /// Periodic tick: run heartbeat-timeout checks + leader election.
    pub fn tick(self: *ClusterCoord, now_ns: i64) void {
        if (!self.config.enabled) return;
        var it = self.registry.nodes.valueIterator();
        while (it.next()) |n| {
            if (n.is_self) continue;
            _ = self.heartbeat.checkTimeout(n, now_ns);
        }
        if (self.election.shouldRunElection(now_ns)) {
            _ = self.election.elect(&self.registry, now_ns);
        }
    }

    /// Get the current leader (0 if no active nodes)
    pub fn currentLeader(self: *const ClusterCoord) u32 {
        return self.election.current_leader;
    }

    /// Is THIS node the leader?
    pub fn isLeader(self: *const ClusterCoord) bool {
        return self.election.isLeader(self.config.node_id);
    }
};

// ============================================================
// Tests
// ============================================================

test "ClusterConfig defaults - kill switch OFF" {
    const c = ClusterConfig{};
    try std.testing.expect(!c.enabled);
    try std.testing.expectEqual(@as(i64, 5_000), c.heartbeat_interval_ms);
    try std.testing.expectEqual(@as(u8, 2), c.escalate_at_node_count);
    try std.testing.expectEqual(@as(u8, 3), c.critical_node_count);
}

test "NodeRole toString" {
    try std.testing.expectEqualStrings("SENSOR", NodeRole.sensor.toString());
    try std.testing.expectEqualStrings("COORDINATOR", NodeRole.coordinator.toString());
    try std.testing.expectEqualStrings("AGGREGATOR", NodeRole.aggregator.toString());
}

test "NodeHealth isActive" {
    try std.testing.expect(NodeHealth.healthy.isActive());
    try std.testing.expect(NodeHealth.degraded.isActive());
    try std.testing.expect(!NodeHealth.unhealthy.isActive());
    try std.testing.expect(!NodeHealth.dead.isActive());
}

test "MessageType toString" {
    try std.testing.expectEqualStrings("HEARTBEAT", MessageType.heartbeat.toString());
    try std.testing.expectEqualStrings("INCIDENT_REPORT", MessageType.incident_report.toString());
    try std.testing.expectEqualStrings("THREAT_INTEL_SHARE", MessageType.threat_intel_share.toString());
}

test "IncidentSeverity toString" {
    try std.testing.expectEqualStrings("INFO", IncidentSeverity.info.toString());
    try std.testing.expectEqualStrings("CRITICAL", IncidentSeverity.critical.toString());
}

test "ClusterNode basic fields" {
    var n = ClusterNode{ .node_id = 5, .role = .sensor, .health = .healthy };
    const name = "node-5";
    @memcpy(n.name[0..name.len], name);
    n.name_len = name.len;
    try std.testing.expectEqualStrings("node-5", n.nameStr());
    try std.testing.expect(n.isActive());
}

test "NodeRegistry upsert and lookup" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();

    const n = ClusterNode{ .node_id = 5, .role = .sensor, .health = .healthy };
    try std.testing.expect(reg.upsert(n));
    try std.testing.expectEqual(@as(usize, 1), reg.count());
    try std.testing.expectEqual(@as(u32, 5), reg.get(5).?.node_id);
    try std.testing.expectEqual(@as(u64, 1), reg.total_joins);

    // Upsert existing -> no new join
    try std.testing.expect(reg.upsert(n));
    try std.testing.expectEqual(@as(u64, 1), reg.total_joins);

    try std.testing.expect(reg.remove(5));
    try std.testing.expectEqual(@as(usize, 0), reg.count());
    try std.testing.expectEqual(@as(u64, 1), reg.total_leaves);
}

test "NodeRegistry listIds sorted ascending" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();
    _ = reg.upsert(.{ .node_id = 30, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 5, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 20, .health = .healthy });

    var ids: [8]u32 = undefined;
    const n = reg.listIds(&ids);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u32, 5), ids[0]);
    try std.testing.expectEqual(@as(u32, 20), ids[1]);
    try std.testing.expectEqual(@as(u32, 30), ids[2]);
}

test "NodeRegistry activeCount skips dead" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();
    _ = reg.upsert(.{ .node_id = 1, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 2, .health = .dead });
    _ = reg.upsert(.{ .node_id = 3, .health = .degraded });
    try std.testing.expectEqual(@as(usize, 3), reg.count());
    try std.testing.expectEqual(@as(usize, 2), reg.activeCount());
}

test "NodeRegistry evicts dead nodes when at capacity" {
    var reg = NodeRegistry.init(std.testing.allocator, 3, 1);
    defer reg.deinit();
    _ = reg.upsert(.{ .node_id = 1, .health = .dead, .last_seen_ns = 100 });
    _ = reg.upsert(.{ .node_id = 2, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 3, .health = .healthy });
    // At capacity (3); adding #4 should evict the dead node #1
    _ = reg.upsert(.{ .node_id = 4, .health = .healthy });
    try std.testing.expect(reg.get(1) == null);
    try std.testing.expect(reg.get(4) != null);
    try std.testing.expectEqual(@as(usize, 3), reg.count());
}

test "HeartbeatMonitor refreshes on heartbeat" {
    var hm = HeartbeatMonitor.init(15_000, 3);
    var node = ClusterNode{ .node_id = 5, .health = .unhealthy, .heartbeat_misses = 2, .last_seen_ns = 0 };
    hm.onHeartbeat(&node, 100_000_000);
    try std.testing.expectEqual(NodeHealth.healthy, node.health);
    try std.testing.expectEqual(@as(u8, 0), node.heartbeat_misses);
    try std.testing.expectEqual(@as(i64, 100_000_000), node.last_seen_ns);
    try std.testing.expectEqual(@as(u64, 1), hm.total_beats);
}

test "HeartbeatMonitor degrades on timeout" {
    var hm = HeartbeatMonitor.init(15_000, 3); // 15s timeout, dead after 3 misses
    var node = ClusterNode{ .node_id = 5, .health = .healthy, .last_seen_ns = 0 };

    // First missed beat (>15s after last_seen=0)
    var h = hm.checkTimeout(&node, 20_000_000_000); // 20s later
    try std.testing.expectEqual(NodeHealth.degraded, h);
    try std.testing.expectEqual(@as(u8, 1), node.heartbeat_misses);

    // Second missed beat
    h = hm.checkTimeout(&node, 40_000_000_000);
    try std.testing.expectEqual(NodeHealth.unhealthy, h);
    try std.testing.expectEqual(@as(u8, 2), node.heartbeat_misses);

    // Third missed beat -> dead
    h = hm.checkTimeout(&node, 60_000_000_000);
    try std.testing.expectEqual(NodeHealth.dead, h);
    try std.testing.expectEqual(@as(u8, 3), node.heartbeat_misses);
    try std.testing.expectEqual(@as(u64, 1), hm.total_dead);
}

test "ClusterIncident addReportingNode dedups" {
    var inc = ClusterIncident{};
    try std.testing.expect(inc.addReportingNode(1));
    try std.testing.expect(inc.addReportingNode(2));
    try std.testing.expect(!inc.addReportingNode(1)); // dup
    try std.testing.expectEqual(@as(u8, 2), inc.reporting_count);
}

test "ClusterIncident addReason bounded" {
    var inc = ClusterIncident{};
    inc.addReason("port_scan");
    inc.addReason("syn_flood");
    try std.testing.expectEqual(@as(u8, 2), inc.reason_count);
    try std.testing.expectEqualStrings("port_scan", inc.reasonStr(0));
    try std.testing.expectEqualStrings("syn_flood", inc.reasonStr(1));
    try std.testing.expectEqualStrings("", inc.reasonStr(99));
}

test "CrossNodeIncidentAggregator creates new incident" {
    var agg = CrossNodeIncidentAggregator.init(std.testing.allocator, .{});
    defer agg.deinit();

    const id = try agg.report(.{ 198, 51, 100, 5 }, 4444, 6, 1, .medium, 0.75, "malicious", 1_000_000_000);
    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(usize, 1), agg.incidentCount());
}

test "CrossNodeIncidentAggregator aggregates same source across nodes" {
    var agg = CrossNodeIncidentAggregator.init(std.testing.allocator, .{});
    defer agg.deinit();

    // Node 1 reports incident
    _ = try agg.report(.{ 198, 51, 100, 5 }, 4444, 6, 1, .medium, 0.75, "malicious", 1_000_000_000);
    // Node 2 reports same source IP+port+proto within window
    _ = try agg.report(.{ 198, 51, 100, 5 }, 4444, 6, 2, .medium, 0.80, "malicious", 1_100_000_000);

    const inc = agg.getIncident(.{ 198, 51, 100, 5 }, 4444, 6).?;
    try std.testing.expectEqual(@as(u8, 2), inc.reporting_count);
    try std.testing.expectEqual(IncidentSeverity.high, inc.severity); // escalated at 2 nodes
    try std.testing.expectEqual(@as(f32, 0.80), inc.score); // max of 0.75, 0.80
    try std.testing.expectEqual(@as(u64, 1), agg.total_aggregated);
    try std.testing.expectEqual(@as(u64, 1), agg.total_escalated);
}

test "CrossNodeIncidentAggregator escalates to critical at 3 nodes" {
    var agg = CrossNodeIncidentAggregator.init(std.testing.allocator, .{});
    defer agg.deinit();

    _ = try agg.report(.{ 203, 0, 113, 10 }, 4444, 6, 1, .low, 0.6, "c2", 1_000_000_000);
    _ = try agg.report(.{ 203, 0, 113, 10 }, 4444, 6, 2, .low, 0.7, "c2", 1_100_000_000);
    _ = try agg.report(.{ 203, 0, 113, 10 }, 4444, 6, 3, .low, 0.8, "c2", 1_200_000_000);

    const inc = agg.getIncident(.{ 203, 0, 113, 10 }, 4444, 6).?;
    try std.testing.expectEqual(@as(u8, 3), inc.reporting_count);
    try std.testing.expectEqual(IncidentSeverity.critical, inc.severity);
    try std.testing.expectEqual(@as(u64, 1), agg.total_critical);
}

test "CrossNodeIncidentAggregator expires outside window" {
    var agg = CrossNodeIncidentAggregator.init(std.testing.allocator, .{ .cross_node_window_ms = 1_000 });
    defer agg.deinit();

    _ = try agg.report(.{ 198, 51, 100, 5 }, 4444, 6, 1, .medium, 0.7, "x", 1_000_000_000);
    // 2 seconds later (>1s window) - resets
    _ = try agg.report(.{ 198, 51, 100, 5 }, 4444, 6, 2, .medium, 0.8, "x", 3_000_000_000);

    const inc = agg.getIncident(.{ 198, 51, 100, 5 }, 4444, 6).?;
    try std.testing.expectEqual(@as(u8, 1), inc.reporting_count); // reset, not aggregated
    try std.testing.expectEqual(@as(f32, 0.8), inc.score);
}

test "ThreatIntelBroadcast dedups by IP" {
    var ti = ThreatIntelBroadcast.init(std.testing.allocator, 16);
    defer ti.deinit();

    const e1 = ThreatIntelEntry{ .kind = .malicious_ip, .ip = .{ 198, 51, 100, 5 }, .source_node_id = 1, .confidence = 80 };
    const e2 = ThreatIntelEntry{ .kind = .malicious_ip, .ip = .{ 198, 51, 100, 5 }, .source_node_id = 2, .confidence = 90 };
    try std.testing.expect(ti.receive(e1));
    try std.testing.expect(!ti.receive(e2)); // dedup
    try std.testing.expectEqual(@as(usize, 1), ti.entryCount());
    try std.testing.expectEqual(@as(u64, 1), ti.total_received);
}

test "ThreatIntelBroadcast checkIp bumps hits" {
    var ti = ThreatIntelBroadcast.init(std.testing.allocator, 16);
    defer ti.deinit();

    _ = ti.receive(.{ .kind = .c2_server, .ip = .{ 198, 51, 100, 7 }, .source_node_id = 1, .confidence = 95 });
    try std.testing.expectEqual(@as(usize, 1), ti.entryCount());

    const m = ti.checkIp(.{ 198, 51, 100, 7 });
    try std.testing.expect(m != null);
    try std.testing.expectEqual(@as(u32, 1), m.?.hits);
    try std.testing.expectEqual(@as(u64, 1), ti.total_hits);

    // Non-matching IP returns null
    try std.testing.expect(ti.checkIp(.{ 1, 2, 3, 4 }) == null);
}

test "ThreatIntelBroadcast evicts lowest-confidence when full" {
    var ti = ThreatIntelBroadcast.init(std.testing.allocator, 3);
    defer ti.deinit();

    _ = ti.receive(.{ .kind = .malicious_ip, .ip = .{ 10, 0, 0, 1 }, .confidence = 90 });
    _ = ti.receive(.{ .kind = .malicious_ip, .ip = .{ 10, 0, 0, 2 }, .confidence = 50 }); // lowest
    _ = ti.receive(.{ .kind = .malicious_ip, .ip = .{ 10, 0, 0, 3 }, .confidence = 80 });
    _ = ti.receive(.{ .kind = .malicious_ip, .ip = .{ 10, 0, 0, 4 }, .confidence = 70 }); // forces eviction

    try std.testing.expectEqual(@as(usize, 3), ti.entryCount());
    try std.testing.expect(ti.checkIp(.{ 10, 0, 0, 2 }) == null); // evicted
    try std.testing.expect(ti.checkIp(.{ 10, 0, 0, 4 }) != null); // survived
}

test "LeaderElection picks highest active NodeId" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();
    _ = reg.upsert(.{ .node_id = 1, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 5, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 10, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 20, .health = .dead }); // not active

    var le = LeaderElection.init(30_000);
    const r = le.elect(&reg, 1_000_000_000);
    try std.testing.expectEqual(@as(u32, 10), r.leader);
    try std.testing.expect(r.changed);
    try std.testing.expectEqual(@as(u32, 10), le.current_leader);
}

test "LeaderElection detects change" {
    var reg = NodeRegistry.init(std.testing.allocator, 32, 1);
    defer reg.deinit();
    _ = reg.upsert(.{ .node_id = 1, .health = .healthy });
    _ = reg.upsert(.{ .node_id = 5, .health = .healthy });

    var le = LeaderElection.init(30_000);
    var r = le.elect(&reg, 1_000_000_000);
    try std.testing.expectEqual(@as(u32, 5), r.leader);
    try std.testing.expect(r.changed);

    // Re-elect, no change
    r = le.elect(&reg, 2_000_000_000);
    try std.testing.expectEqual(@as(u32, 5), r.leader);
    try std.testing.expect(!r.changed);

    // Kill node 5, re-elect
    if (reg.getMut(5)) |n| n.health = .dead;
    r = le.elect(&reg, 3_000_000_000);
    try std.testing.expectEqual(@as(u32, 1), r.leader);
    try std.testing.expect(r.changed);
}

test "LeaderElection shouldRunElection respects interval" {
    var le = LeaderElection.init(30_000); // 30s interval (ms units)
    le.last_election_ns = 1_000_000_000; // t=1s
    try std.testing.expect(!le.shouldRunElection(2_000_000_000)); // 1s later, 1s < 30s
    try std.testing.expect(le.shouldRunElection(31_000_000_000)); // 30s later, 30s >= 30s
}

test "LeaderElection isLeader" {
    var le = LeaderElection.init(30_000);
    le.current_leader = 7;
    try std.testing.expect(le.isLeader(7));
    try std.testing.expect(!le.isLeader(5));
    le.current_leader = 0;
    try std.testing.expect(!le.isLeader(0)); // 0 = no leader
}

test "ClusterCoord singleton init/shutdown" {
    const alloc = std.testing.allocator;
    {
        var cc = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
        defer cc.shutdown();
        try std.testing.expect(cc.isAvailable());
        try std.testing.expectEqual(@as(usize, 1), cc.registry.count()); // self-registered
    }
    try std.testing.expect(ClusterCoord.instance() == null);
}

test "ClusterCoord kill switch: ingest is no-op when disabled" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{ .enabled = false, .node_id = 1 });
    defer cc.shutdown();

    cc.ingest(.{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 1_000_000_000,
    });
    try std.testing.expectEqual(@as(usize, 1), cc.registry.count()); // only self
}

test "ClusterCoord ingest heartbeat registers new peer" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer cc.shutdown();

    cc.ingest(.{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 1_000_000_000,
    });
    try std.testing.expectEqual(@as(usize, 2), cc.registry.count()); // self + peer
    try std.testing.expect(cc.registry.get(5) != null);
}

test "ClusterCoord ingest node_join adds peer" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer cc.shutdown();

    var n = ClusterNode{ .node_id = 7, .role = .aggregator, .health = .healthy };
    const name = "aggregator-7";
    @memcpy(n.name[0..name.len], name);
    n.name_len = name.len;
    const ep = "10.0.0.7:9090";
    @memcpy(n.endpoint[0..ep.len], ep);
    n.endpoint_len = ep.len;

    cc.ingest(.{
        .msg_type = .node_join,
        .from_node_id = 7,
        .timestamp_ns = 1_000_000_000,
        .node = n,
    });
    const got = cc.registry.get(7).?;
    try std.testing.expectEqualStrings("aggregator-7", got.nameStr());
    try std.testing.expectEqualStrings("10.0.0.7:9090", got.endpointStr());
    try std.testing.expectEqual(NodeRole.aggregator, got.role);
}

test "ClusterCoord ingest incident_report aggregates across nodes" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer cc.shutdown();

    // Two nodes report same source IP incident within window
    cc.ingest(.{
        .msg_type = .incident_report,
        .from_node_id = 1,
        .timestamp_ns = 1_000_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .medium,
        .incident_score = 0.75,
        .incident_label_len = 9,
        .incident_label = blk: {
            var b = [_]u8{0} ** MAX_INCIDENT_LABEL;
            @memcpy(b[0..9], "malicious");
            break :blk b;
        },
    });
    cc.ingest(.{
        .msg_type = .incident_report,
        .from_node_id = 2,
        .timestamp_ns = 1_100_000_000,
        .incident_source_ip = .{ 198, 51, 100, 5 },
        .incident_remote_port = 4444,
        .incident_proto = 6,
        .incident_severity = .medium,
        .incident_score = 0.80,
        .incident_label_len = 9,
        .incident_label = blk: {
            var b = [_]u8{0} ** MAX_INCIDENT_LABEL;
            @memcpy(b[0..9], "malicious");
            break :blk b;
        },
    });

    // Note: node 2 hasn't sent a heartbeat so isn't registered, but
    // the aggregator still records its report.
    const inc = cc.aggregator.getIncident(.{ 198, 51, 100, 5 }, 4444, 6).?;
    try std.testing.expectEqual(@as(u8, 2), inc.reporting_count);
    try std.testing.expectEqual(IncidentSeverity.high, inc.severity);
}

test "ClusterCoord ingest threat_intel_share adds entry" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer cc.shutdown();

    cc.ingest(.{
        .msg_type = .threat_intel_share,
        .from_node_id = 2,
        .timestamp_ns = 1_000_000_000,
        .threat_intel = .{
            .kind = .c2_server,
            .ip = .{ 198, 51, 100, 7 },
            .source_node_id = 2,
            .confidence = 95,
        },
    });
    try std.testing.expectEqual(@as(usize, 1), cc.threat_intel.entryCount());

    const m = cc.checkThreatIp(.{ 198, 51, 100, 7 });
    try std.testing.expect(m != null);
    try std.testing.expectEqual(ThreatIntelKind.c2_server, m.?.kind);
}

test "ClusterCoord tick runs heartbeat timeout + leader election" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{
        .enabled = true,
        .node_id = 1,
        .heartbeat_timeout_ms = 1_000,
        .heartbeat_dead_threshold = 1, // 1 miss = dead
        .election_interval_ms = 500,
    });
    defer cc.shutdown();

    // Register a peer (last_seen = 0)
    cc.ingest(.{
        .msg_type = .heartbeat,
        .from_node_id = 5,
        .timestamp_ns = 0,
    });
    try std.testing.expect(cc.registry.get(5).?.health == .healthy);

    // Tick at 2s later: peer 5 missed heartbeat (1s timeout, 1 miss = dead)
    cc.tick(2_000_000_000);
    try std.testing.expect(cc.registry.get(5).?.health == .dead);

    // Election should have run (500ms interval), self node 1 wins (5 is dead)
    try std.testing.expectEqual(@as(u32, 1), cc.currentLeader());
    try std.testing.expect(cc.isLeader());
}

test "ClusterCoord end-to-end: 3 nodes report same C2 -> critical escalation" {
    const alloc = std.testing.allocator;
    var cc = try ClusterCoord.init(alloc, .{ .enabled = true, .node_id = 1 });
    defer cc.shutdown();

    // Three nodes see the same C2 IP (198.51.100.42:4444 TCP) within 30s
    for ([_]u32{ 1, 2, 3 }) |nid| {
        cc.ingest(.{
            .msg_type = .incident_report,
            .from_node_id = nid,
            .timestamp_ns = @as(i64, @intCast(nid)) * 100_000_000,
            .incident_source_ip = .{ 198, 51, 100, 42 },
            .incident_remote_port = 4444,
            .incident_proto = 6,
            .incident_severity = .medium,
            .incident_score = 0.85,
            .incident_label_len = 2,
            .incident_label = blk: {
                var b = [_]u8{0} ** MAX_INCIDENT_LABEL;
                @memcpy(b[0..2], "c2");
                break :blk b;
            },
        });
    }

    const inc = cc.aggregator.getIncident(.{ 198, 51, 100, 42 }, 4444, 6).?;
    try std.testing.expectEqual(@as(u8, 3), inc.reporting_count);
    try std.testing.expectEqual(IncidentSeverity.critical, inc.severity);
    try std.testing.expectEqual(@as(u64, 1), cc.aggregator.total_critical);
}
