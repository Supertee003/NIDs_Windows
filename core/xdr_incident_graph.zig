//! xdr_incident_graph.zig - AEGIS XDR Entity/Incident Graph (P3 Phase U)
//!
//! Entity graph + incident linking for cross-domain correlation.
//! Complements xdr_harden.zig (which aggregates forensic records into
//! incidents) by adding the ENTITY dimension:
//!
//!   - EntityNode: ip / host / process / file / user / domain
//!   - EntityEdge: directed relation with weight + first/last seen
//!   - IncidentLink: connects graph entities to XDR incident IDs
//!   - BFS path query: "how is entity A related to entity B"
//!
//! Phase U exit condition:
//!   Incidents are linked to entities, entities are linked to each
//!   other, and the graph answers pivot queries deterministically.
//!
//! Design notes:
//!   - Fixed-capacity tables (no allocation). Overflow is counted,
//!     never panics (fail-soft, same policy as the rest of AEGIS).
//!   - Deterministic: BFS scans edges in insertion order, so the same
//!     graph always yields the same shortest path.
//!   - Self-contained: imports only std, so it can be unit-tested in
//!     isolation. Severity mirrors xdr_harden.XdrSeverity (0-4 scale).

const std = @import("std");

// ============================================================
// Capacity constants
// ============================================================

/// Maximum entities tracked in the graph.
pub const MAX_NODES: usize = 512;
/// Maximum directed edges tracked in the graph.
pub const MAX_EDGES: usize = 2048;
/// Maximum incident links tracked in the graph.
pub const MAX_INCIDENTS: usize = 256;
/// Maximum length of an entity key (e.g. "192.168.1.10", "svchost.exe").
pub const MAX_KEY_LEN: usize = 64;
/// Maximum entities attached to one incident.
pub const MAX_INCIDENT_ENTITIES: usize = 8;
/// Maximum event ids stored per incident link.
pub const MAX_INCIDENT_EVENTS: usize = 16;
/// Maximum neighbors returned by one neighbors() call.
pub const MAX_NEIGHBORS: usize = 32;

// ============================================================
// Entity kinds and relations
// ============================================================

pub const EntityKind = enum(u8) {
    ip = 0,
    host = 1,
    process = 2,
    file = 3,
    user = 4,
    domain = 5,

    pub fn toString(self: EntityKind) []const u8 {
        return switch (self) {
            .ip => "ip",
            .host => "host",
            .process => "process",
            .file => "file",
            .user => "user",
            .domain => "domain",
        };
    }
};

pub const Relation = enum(u8) {
    talked_to = 0,
    executed = 1,
    wrote = 2,
    read = 3,
    logged_in_as = 4,
    resolved_to = 5,
    downloaded = 6,
    spawned = 7,

    pub fn toString(self: Relation) []const u8 {
        return switch (self) {
            .talked_to => "talked_to",
            .executed => "executed",
            .wrote => "wrote",
            .read => "read",
            .logged_in_as => "logged_in_as",
            .resolved_to => "resolved_to",
            .downloaded => "downloaded",
            .spawned => "spawned",
        };
    }
};

/// Incident severity. Mirrors xdr_harden.XdrSeverity (0-4 scale) so the
/// two modules stay consistent without a cross-module import.
pub const IncidentSeverity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn toString(self: IncidentSeverity) []const u8 {
        return switch (self) {
            .info => "Info",
            .low => "Low",
            .medium => "Medium",
            .high => "High",
            .critical => "Critical",
        };
    }
};

// ============================================================
// Entity key
// ============================================================

pub const EntityKey = struct {
    buf: [MAX_KEY_LEN]u8 = undefined,
    len: u8 = 0,

    pub fn set(self: *EntityKey, s: []const u8) void {
        const n = @min(s.len, MAX_KEY_LEN);
        @memcpy(self.buf[0..n], s[0..n]);
        self.len = @intCast(n);
    }

    pub fn slice(self: *const EntityKey) []const u8 {
        return self.buf[0..self.len];
    }
};

// ============================================================
// Graph records
// ============================================================

pub const EntityNode = struct {
    id: u32,
    kind: EntityKind,
    key: EntityKey,
    first_seen_ns: i128,
    last_seen_ns: i128,
    event_count: u64,
    incident_count: u32,
    active: bool,
};

pub const EntityEdge = struct {
    src_id: u32,
    dst_id: u32,
    relation: Relation,
    weight: u64,
    first_seen_ns: i128,
    last_seen_ns: i128,
    active: bool,
};

pub const IncidentLink = struct {
    /// XDR incident id (from xdr_harden, or producer-defined).
    incident_id: u64,
    severity: IncidentSeverity,
    entity_ids: [MAX_INCIDENT_ENTITIES]u32,
    entity_count: u8,
    event_ids: [MAX_INCIDENT_EVENTS]u64,
    event_count: u16,
    created_ns: i128,
    updated_ns: i128,
    active: bool,
};

// ============================================================
// High-level ingest spec
// ============================================================

pub const IngestSpec = struct {
    src_kind: EntityKind,
    src_key: []const u8,
    dst_kind: EntityKind,
    dst_key: []const u8,
    relation: Relation,
    ts_ns: i128,
    /// 0 = do not link to any incident.
    incident_id: u64 = 0,
};

// ============================================================
// IncidentGraph
// ============================================================

pub const IncidentGraph = struct {
    nodes: [MAX_NODES]EntityNode,
    node_count: usize,
    edges: [MAX_EDGES]EntityEdge,
    edge_count: usize,
    incidents: [MAX_INCIDENTS]IncidentLink,
    incident_count: usize,

    // Lifetime counters (monotonic, reset only by reset()).
    total_ingest_events: u64,
    total_edge_upserts: u64,
    dropped_nodes: u64,
    dropped_edges: u64,
    dropped_incidents: u64,

    pub fn init() IncidentGraph {
        var g: IncidentGraph = undefined;
        g.node_count = 0;
        g.edge_count = 0;
        g.incident_count = 0;
        g.total_ingest_events = 0;
        g.total_edge_upserts = 0;
        g.dropped_nodes = 0;
        g.dropped_edges = 0;
        g.dropped_incidents = 0;
        var i: usize = 0;
        while (i < MAX_NODES) : (i += 1) {
            g.nodes[i] = .{
                .id = 0,
                .kind = .ip,
                .key = .{},
                .first_seen_ns = 0,
                .last_seen_ns = 0,
                .event_count = 0,
                .incident_count = 0,
                .active = false,
            };
        }
        i = 0;
        while (i < MAX_EDGES) : (i += 1) {
            g.edges[i] = .{
                .src_id = 0,
                .dst_id = 0,
                .relation = .talked_to,
                .weight = 0,
                .first_seen_ns = 0,
                .last_seen_ns = 0,
                .active = false,
            };
        }
        i = 0;
        while (i < MAX_INCIDENTS) : (i += 1) {
            g.incidents[i] = .{
                .incident_id = 0,
                .severity = .info,
                .entity_ids = [_]u32{0} ** MAX_INCIDENT_ENTITIES,
                .entity_count = 0,
                .event_ids = [_]u64{0} ** MAX_INCIDENT_EVENTS,
                .event_count = 0,
                .created_ns = 0,
                .updated_ns = 0,
                .active = false,
            };
        }
        return g;
    }

    // --------------------------------------------------------
    // Entity upsert
    // --------------------------------------------------------

    /// Find an entity by kind + key. Returns node id or null.
    pub fn findEntity(self: *const IncidentGraph, kind: EntityKind, key_slice: []const u8) ?u32 {
        var i: usize = 0;
        while (i < self.node_count) : (i += 1) {
            const n = &self.nodes[i];
            if (n.active and n.kind == kind and std.mem.eql(u8, n.key.slice(), key_slice)) {
                return n.id;
            }
        }
        return null;
    }

    /// Create or refresh an entity. Returns node id, or null if the
    /// key is invalid or the node table is full (fail-soft).
    pub fn upsertEntity(self: *IncidentGraph, kind: EntityKind, key_slice: []const u8, ts_ns: i128) ?u32 {
        if (key_slice.len == 0 or key_slice.len > MAX_KEY_LEN) return null;
        if (self.findEntity(kind, key_slice)) |id| {
            const n = &self.nodes[id];
            n.last_seen_ns = ts_ns;
            n.event_count += 1;
            return id;
        }
        if (self.node_count >= MAX_NODES) {
            self.dropped_nodes += 1;
            return null;
        }
        const idx = self.node_count;
        const n = &self.nodes[idx];
        n.id = @intCast(idx);
        n.kind = kind;
        n.key.set(key_slice);
        n.first_seen_ns = ts_ns;
        n.last_seen_ns = ts_ns;
        n.event_count = 1;
        n.incident_count = 0;
        n.active = true;
        self.node_count += 1;
        return n.id;
    }

    // --------------------------------------------------------
    // Edge upsert
    // --------------------------------------------------------

    /// Create or refresh a directed edge. Returns false if either
    /// endpoint is unknown or the edge table is full (fail-soft).
    pub fn linkEntities(self: *IncidentGraph, src_id: u32, dst_id: u32, relation: Relation, ts_ns: i128) bool {
        if (src_id >= self.node_count or dst_id >= self.node_count) return false;
        var i: usize = 0;
        while (i < self.edge_count) : (i += 1) {
            const e = &self.edges[i];
            if (e.active and e.src_id == src_id and e.dst_id == dst_id and e.relation == relation) {
                e.weight += 1;
                e.last_seen_ns = ts_ns;
                self.total_edge_upserts += 1;
                return true;
            }
        }
        if (self.edge_count >= MAX_EDGES) {
            self.dropped_edges += 1;
            return false;
        }
        const idx = self.edge_count;
        const e = &self.edges[idx];
        e.src_id = src_id;
        e.dst_id = dst_id;
        e.relation = relation;
        e.weight = 1;
        e.first_seen_ns = ts_ns;
        e.last_seen_ns = ts_ns;
        e.active = true;
        self.edge_count += 1;
        self.total_edge_upserts += 1;
        return true;
    }

    // --------------------------------------------------------
    // Incident links
    // --------------------------------------------------------

    /// Find the slot index of an incident link by incident id.
    pub fn findIncidentIndex(self: *const IncidentGraph, incident_id: u64) ?usize {
        var i: usize = 0;
        while (i < self.incident_count) : (i += 1) {
            if (self.incidents[i].active and self.incidents[i].incident_id == incident_id) {
                return i;
            }
        }
        return null;
    }

    /// Create or refresh an incident link. Returns slot index or null
    /// if the incident table is full (fail-soft).
    pub fn attachIncident(self: *IncidentGraph, incident_id: u64, severity: IncidentSeverity, entity_ids: []const u32, ts_ns: i128) ?usize {
        if (incident_id == 0) return null;
        if (self.findIncidentIndex(incident_id)) |idx| {
            const inc = &self.incidents[idx];
            inc.severity = severity;
            inc.updated_ns = ts_ns;
            for (entity_ids) |eid| {
                _ = self.addEntityToIncident(idx, eid);
            }
            return idx;
        }
        if (self.incident_count >= MAX_INCIDENTS) {
            self.dropped_incidents += 1;
            return null;
        }
        const idx = self.incident_count;
        const inc = &self.incidents[idx];
        inc.incident_id = incident_id;
        inc.severity = severity;
        inc.entity_count = 0;
        inc.event_count = 0;
        inc.created_ns = ts_ns;
        inc.updated_ns = ts_ns;
        inc.active = true;
        self.incident_count += 1;
        for (entity_ids) |eid| {
            _ = self.addEntityToIncident(idx, eid);
        }
        return idx;
    }

    /// Attach one entity to an incident slot (no-op if already present
    /// or full). Bumps the node's incident_count on first attach.
    pub fn addEntityToIncident(self: *IncidentGraph, inc_idx: usize, entity_id: u32) bool {
        if (inc_idx >= self.incident_count) return false;
        if (entity_id >= self.node_count) return false;
        const inc = &self.incidents[inc_idx];
        var i: usize = 0;
        while (i < inc.entity_count) : (i += 1) {
            if (inc.entity_ids[i] == entity_id) return false;
        }
        if (inc.entity_count >= MAX_INCIDENT_ENTITIES) return false;
        inc.entity_ids[inc.entity_count] = entity_id;
        inc.entity_count += 1;
        self.nodes[entity_id].incident_count += 1;
        return true;
    }

    /// Append an event id to an incident's timeline. Returns false if
    /// the incident is unknown or its timeline is full.
    pub fn addEventToIncident(self: *IncidentGraph, incident_id: u64, event_id: u64, ts_ns: i128) bool {
        const idx = self.findIncidentIndex(incident_id) orelse return false;
        const inc = &self.incidents[idx];
        if (inc.event_count >= MAX_INCIDENT_EVENTS) return false;
        inc.event_ids[inc.event_count] = event_id;
        inc.event_count += 1;
        inc.updated_ns = ts_ns;
        return true;
    }

    /// Incident indices that reference the given entity.
    /// Returns the number of indices written into out.
    pub fn incidentsForEntity(self: *const IncidentGraph, entity_id: u32, out: []usize) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.incident_count) : (i += 1) {
            const inc = &self.incidents[i];
            if (!inc.active) continue;
            var j: usize = 0;
            while (j < inc.entity_count) : (j += 1) {
                if (inc.entity_ids[j] == entity_id) {
                    if (count < out.len) {
                        out[count] = i;
                        count += 1;
                    }
                    break;
                }
            }
        }
        return count;
    }

    // --------------------------------------------------------
    // High-level ingest
    // --------------------------------------------------------

    /// Ingest one observed interaction: upserts both entities, links
    /// them, and (optionally) attaches both to an incident.
    pub fn ingest(self: *IncidentGraph, spec: IngestSpec) bool {
        self.total_ingest_events += 1;
        const src = self.upsertEntity(spec.src_kind, spec.src_key, spec.ts_ns) orelse return false;
        const dst = self.upsertEntity(spec.dst_kind, spec.dst_key, spec.ts_ns) orelse return false;
        if (src == dst) return false;
        if (!self.linkEntities(src, dst, spec.relation, spec.ts_ns)) return false;
        if (spec.incident_id != 0) {
            const idx = self.findIncidentIndex(spec.incident_id);
            if (idx) |ii| {
                _ = self.addEntityToIncident(ii, src);
                _ = self.addEntityToIncident(ii, dst);
            }
        }
        return true;
    }

    // --------------------------------------------------------
    // Queries
    // --------------------------------------------------------

    /// Distinct nodes directly connected to entity_id (either
    /// direction, any relation). Returns count written into out.
    pub fn neighbors(self: *const IncidentGraph, entity_id: u32, out: []u32) usize {
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.edge_count) : (i += 1) {
            const e = &self.edges[i];
            if (!e.active) continue;
            var other: u32 = 0;
            if (e.src_id == entity_id) {
                other = e.dst_id;
            } else if (e.dst_id == entity_id) {
                other = e.src_id;
            } else {
                continue;
            }
            var seen = false;
            var j: usize = 0;
            while (j < count) : (j += 1) {
                if (out[j] == other) {
                    seen = true;
                    break;
                }
            }
            if (!seen and count < out.len and count < MAX_NEIGHBORS) {
                out[count] = other;
                count += 1;
            }
        }
        return count;
    }

    /// Deterministic BFS shortest path between two entities.
    /// Edges are traversed in both directions, in insertion order.
    /// Writes node ids (from_id ... to_id) into out_path and returns
    /// the number of nodes written (0 = no path or buffer too small).
    pub fn findPath(self: *const IncidentGraph, from_id: u32, to_id: u32, out_path: []u32) usize {
        if (out_path.len == 0) return 0;
        if (from_id >= self.node_count or to_id >= self.node_count) return 0;
        if (from_id == to_id) {
            out_path[0] = from_id;
            return 1;
        }
        var visited = [_]bool{false} ** MAX_NODES;
        var prev = [_]u32{0} ** MAX_NODES;
        var queue = [_]u32{0} ** MAX_NODES;
        var head: usize = 0;
        var tail: usize = 0;
        visited[from_id] = true;
        queue[tail] = from_id;
        tail += 1;
        var found = false;
        while (head < tail and !found) {
            const cur = queue[head];
            head += 1;
            var i: usize = 0;
            while (i < self.edge_count) : (i += 1) {
                const e = &self.edges[i];
                if (!e.active) continue;
                var nxt: u32 = 0;
                if (e.src_id == cur) {
                    nxt = e.dst_id;
                } else if (e.dst_id == cur) {
                    nxt = e.src_id;
                } else {
                    continue;
                }
                if (visited[nxt]) continue;
                visited[nxt] = true;
                prev[nxt] = cur;
                if (nxt == to_id) {
                    found = true;
                    break;
                }
                if (tail < MAX_NODES) {
                    queue[tail] = nxt;
                    tail += 1;
                }
            }
        }
        if (!found) return 0;
        // Reconstruct the path by walking the prev chain backwards.
        var rev: [MAX_NODES]u32 = undefined;
        var n: usize = 0;
        var cur = to_id;
        while (true) {
            rev[n] = cur;
            n += 1;
            if (cur == from_id) break;
            cur = prev[cur];
        }
        var i: usize = 0;
        while (i < n and i < out_path.len) : (i += 1) {
            out_path[i] = rev[n - 1 - i];
        }
        return i;
    }

    // --------------------------------------------------------
    // Maintenance
    // --------------------------------------------------------

    pub fn node(self: *const IncidentGraph, id: u32) ?*const EntityNode {
        if (id >= self.node_count) return null;
        return &self.nodes[id];
    }

    pub fn reset(self: *IncidentGraph) void {
        self.* = IncidentGraph.init();
    }
};

// ============================================================
// Tests (P3.1 - Phase U)
// ============================================================

test "P3.1: EntityKind and Relation toString" {
    try std.testing.expectEqualStrings("ip", EntityKind.ip.toString());
    try std.testing.expectEqualStrings("process", EntityKind.process.toString());
    try std.testing.expectEqualStrings("talked_to", Relation.talked_to.toString());
    try std.testing.expectEqualStrings("logged_in_as", Relation.logged_in_as.toString());
}

test "P3.1: upsertEntity creates then reuses node" {
    var g = IncidentGraph.init();
    const id1 = g.upsertEntity(.ip, "10.0.0.5", 1000).?;
    const id2 = g.upsertEntity(.ip, "10.0.0.5", 2000).?;
    try std.testing.expectEqual(id1, id2);
    const n = g.node(id1).?;
    try std.testing.expectEqual(@as(u64, 2), n.event_count);
    try std.testing.expectEqual(@as(i128, 1000), n.first_seen_ns);
    try std.testing.expectEqual(@as(i128, 2000), n.last_seen_ns);
    try std.testing.expectEqual(@as(usize, 1), g.node_count);
}

test "P3.1: same key different kind is a different entity" {
    var g = IncidentGraph.init();
    const ip_id = g.upsertEntity(.ip, "10.0.0.5", 1000).?;
    const host_id = g.upsertEntity(.host, "10.0.0.5", 1000).?;
    try std.testing.expect(ip_id != host_id);
    try std.testing.expectEqual(@as(usize, 2), g.node_count);
}

test "P3.1: upsertEntity rejects empty and oversized keys" {
    var g = IncidentGraph.init();
    try std.testing.expect(g.upsertEntity(.ip, "", 1000) == null);
    try std.testing.expect(g.upsertEntity(.ip, "x" ** (MAX_KEY_LEN + 1), 1000) == null);
    try std.testing.expect(g.upsertEntity(.ip, "10.0.0.9", 1000) != null);
}

test "P3.1: linkEntities upserts weight on repeat" {
    var g = IncidentGraph.init();
    const a = g.upsertEntity(.ip, "10.0.0.1", 1000).?;
    const b = g.upsertEntity(.ip, "10.0.0.2", 1000).?;
    try std.testing.expect(g.linkEntities(a, b, .talked_to, 1100));
    try std.testing.expect(g.linkEntities(a, b, .talked_to, 1200));
    try std.testing.expectEqual(@as(usize, 1), g.edge_count);
    try std.testing.expectEqual(@as(u64, 2), g.edges[0].weight);
    try std.testing.expectEqual(@as(i128, 1200), g.edges[0].last_seen_ns);
}

test "P3.1: linkEntities rejects unknown endpoints" {
    var g = IncidentGraph.init();
    try std.testing.expect(!g.linkEntities(0, 1, .talked_to, 1000));
    _ = g.upsertEntity(.ip, "10.0.0.1", 1000);
    try std.testing.expect(!g.linkEntities(0, 7, .talked_to, 1000));
}

test "P3.1: ingest creates two nodes and one edge" {
    var g = IncidentGraph.init();
    const ok = g.ingest(.{
        .src_kind = .ip,
        .src_key = "10.0.0.1",
        .dst_kind = .host,
        .dst_key = "win11-a",
        .relation = .talked_to,
        .ts_ns = 1000,
    });
    try std.testing.expect(ok);
    try std.testing.expectEqual(@as(usize, 2), g.node_count);
    try std.testing.expectEqual(@as(usize, 1), g.edge_count);
    try std.testing.expectEqual(@as(u64, 1), g.total_ingest_events);
}

test "P3.1: neighbors returns both directions deduped" {
    var g = IncidentGraph.init();
    const a = g.upsertEntity(.ip, "10.0.0.1", 1000).?;
    const b = g.upsertEntity(.ip, "10.0.0.2", 1000).?;
    const c = g.upsertEntity(.ip, "10.0.0.3", 1000).?;
    _ = g.linkEntities(a, b, .talked_to, 1100);
    _ = g.linkEntities(c, a, .talked_to, 1100);
    _ = g.linkEntities(a, b, .talked_to, 1200);
    var out: [MAX_NEIGHBORS]u32 = undefined;
    const count = g.neighbors(a, &out);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "P3.1: findPath direct and 2-hop" {
    var g = IncidentGraph.init();
    const a = g.upsertEntity(.ip, "10.0.0.1", 1000).?;
    const b = g.upsertEntity(.ip, "10.0.0.2", 1000).?;
    const c = g.upsertEntity(.ip, "10.0.0.3", 1000).?;
    _ = g.linkEntities(a, b, .talked_to, 1100);
    _ = g.linkEntities(b, c, .downloaded, 1200);
    var path: [8]u32 = undefined;
    // Direct edge a -> b.
    const direct = g.findPath(a, b, &path);
    try std.testing.expectEqual(@as(usize, 2), direct);
    try std.testing.expectEqual(a, path[0]);
    try std.testing.expectEqual(b, path[1]);
    // Two-hop path a -> b -> c (edges are traversed both directions).
    const two_hop = g.findPath(a, c, &path);
    try std.testing.expectEqual(@as(usize, 3), two_hop);
    try std.testing.expectEqual(a, path[0]);
    try std.testing.expectEqual(c, path[2]);
}

test "P3.1: findPath unreachable returns 0" {
    var g = IncidentGraph.init();
    const a = g.upsertEntity(.ip, "10.0.0.1", 1000).?;
    const b = g.upsertEntity(.ip, "10.0.0.2", 1000).?;
    const c = g.upsertEntity(.ip, "10.0.0.3", 1000).?;
    // a - b connected, c isolated.
    _ = g.linkEntities(a, b, .talked_to, 1100);
    var path: [8]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), g.findPath(a, c, &path));
}

test "P3.1: attachIncident links entities and events" {
    var g = IncidentGraph.init();
    const a = g.upsertEntity(.ip, "10.0.0.1", 1000).?;
    const b = g.upsertEntity(.ip, "10.0.0.2", 1000).?;
    const idx = g.attachIncident(5001, .high, &[_]u32{ a, b }, 1500).?;
    try std.testing.expectEqual(@as(usize, 0), idx);
    try std.testing.expectEqual(@as(u8, 2), g.incidents[idx].entity_count);
    try std.testing.expectEqual(@as(u32, 1), g.nodes[a].incident_count);
    try std.testing.expect(g.addEventToIncident(5001, 9001, 1600));
    try std.testing.expectEqual(@as(u16, 1), g.incidents[idx].event_count);
    // attachIncident on the same id refreshes instead of duplicating.
    const idx2 = g.attachIncident(5001, .critical, &[_]u32{}, 1700).?;
    try std.testing.expectEqual(idx, idx2);
    try std.testing.expectEqual(IncidentSeverity.critical, g.incidents[idx].severity);
    try std.testing.expectEqual(@as(usize, 1), g.incident_count);
}

test "P3.1: incidentsForEntity finds linked incidents" {
    var g = IncidentGraph.init();
    const a = g.upsertEntity(.ip, "10.0.0.1", 1000).?;
    const b = g.upsertEntity(.ip, "10.0.0.2", 1000).?;
    _ = g.attachIncident(5001, .medium, &[_]u32{a}, 1500);
    _ = g.attachIncident(5002, .low, &[_]u32{b}, 1600);
    var out: [8]usize = undefined;
    const found = g.incidentsForEntity(a, &out);
    try std.testing.expectEqual(@as(usize, 1), found);
    try std.testing.expectEqual(@as(u64, 5001), g.incidents[out[0]].incident_id);
}

test "P3.1: ingest with incident id attaches both endpoints" {
    var g = IncidentGraph.init();
    _ = g.attachIncident(7001, .high, &[_]u32{}, 1000);
    const ok = g.ingest(.{
        .src_kind = .ip,
        .src_key = "10.0.0.1",
        .dst_kind = .file,
        .dst_key = "malware.exe",
        .relation = .downloaded,
        .ts_ns = 2000,
        .incident_id = 7001,
    });
    try std.testing.expect(ok);
    var out: [8]usize = undefined;
    const a = g.findEntity(.ip, "10.0.0.1").?;
    const f = g.findEntity(.file, "malware.exe").?;
    _ = f;
    try std.testing.expectEqual(@as(usize, 1), g.incidentsForEntity(a, &out));
}

test "P3.1: capacity guards count drops instead of panicking" {
    var g = IncidentGraph.init();
    g.node_count = MAX_NODES;
    try std.testing.expect(g.upsertEntity(.ip, "overflow-key", 1000) == null);
    try std.testing.expectEqual(@as(u64, 1), g.dropped_nodes);
    g.node_count = 1;
    g.edge_count = MAX_EDGES;
    try std.testing.expect(!g.linkEntities(0, 0, .talked_to, 1000));
    try std.testing.expectEqual(@as(u64, 1), g.dropped_edges);
    g.incident_count = MAX_INCIDENTS;
    try std.testing.expect(g.attachIncident(9999, .low, &[_]u32{}, 1000) == null);
    try std.testing.expectEqual(@as(u64, 1), g.dropped_incidents);
}

test "P3.1: reset clears all state" {
    var g = IncidentGraph.init();
    _ = g.ingest(.{
        .src_kind = .ip,
        .src_key = "10.0.0.1",
        .dst_kind = .ip,
        .dst_key = "10.0.0.2",
        .relation = .talked_to,
        .ts_ns = 1000,
    });
    g.reset();
    try std.testing.expectEqual(@as(usize, 0), g.node_count);
    try std.testing.expectEqual(@as(usize, 0), g.edge_count);
    try std.testing.expectEqual(@as(u64, 0), g.total_ingest_events);
}
