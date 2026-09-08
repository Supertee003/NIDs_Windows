//! xdr_incident_fabric.zig - AEGIS XDR Multi-Source Incident Fabric (T18 / Step 55)
//!
//! Combines nine source categories into a single evidence fabric:
//!
//!   Network, Host, Process, File, Registry, Identity, Threat Intel,
//!   Historical, Federation
//!
//! Pipeline: Entity -> Evidence -> Incident -> Decision -> Action.
//!   Entity    = pivoting key (ip / host / process / file / registry key /
//!               identity / indicator / historical indicator / node)
//!   Evidence  = one observation tagged with its source category + severity
//!   Incident  = aggregate keyed by entity: distinct-source bitmask, evidence
//!               event list, severest severity
//!   Decision  = severity aggregation into an enforcement action
//!   Action    = the decided action, dispatched to the Rust PEP (dispatched_to_pep)
//!
//! A single incident MUST hold evidence from multiple source categories
//! (AC3): distinctSources() >= 2 is the XDR criterion exercised by tests.
//!
//! Self-contained: imports std only. Fixed-capacity tables, fails soft.

const std = @import("std");

pub const CATEGORY_COUNT = 9;

pub const SourceCategory = enum(u8) {
    network = 0,
    host = 1,
    process = 2,
    file = 3,
    registry = 4,
    identity = 5,
    threat_intel = 6,
    historical = 7,
    federation = 8,

    pub fn label(self: SourceCategory) []const u8 {
        return switch (self) {
            .network => "network",
            .host => "host",
            .process => "process",
            .file => "file",
            .registry => "registry",
            .identity => "identity",
            .threat_intel => "threat_intel",
            .historical => "historical",
            .federation => "federation",
        };
    }

    pub fn bit(self: SourceCategory) u64 {
        return @as(u64, 1) << @intCast(@intFromEnum(self));
    }
};

pub const SOURCE_CATEGORIES = [CATEGORY_COUNT]SourceCategory{
    .network,
    .host,
    .process,
    .file,
    .registry,
    .identity,
    .threat_intel,
    .historical,
    .federation,
};

pub const MAX_KEY_LEN: usize = 64;
pub const MAX_EVIDENCE: usize = 32;
pub const MAX_INCIDENTS: usize = 128;

pub const Evidence = struct {
    source: SourceCategory = .network,
    entity: [MAX_KEY_LEN]u8 = undefined,
    entity_len: usize = 0,
    event_id: u64 = 0,
    ts_ms: i64 = 0,
    severity: u8 = 0,
    detail: []const u8 = "",

    pub fn entitySlice(self: *const Evidence) []const u8 {
        return self.entity[0..self.entity_len];
    }
};

pub const DecisionAction = enum(u8) {
    monitor = 0,
    allow = 1,
    rate_limit = 2,
    quarantine = 3,
    block = 4,

    pub fn label(self: DecisionAction) []const u8 {
        return switch (self) {
            .monitor => "monitor",
            .allow => "allow",
            .rate_limit => "rate_limit",
            .quarantine => "quarantine",
            .block => "block",
        };
    }

    pub fn isEnforcement(self: DecisionAction) bool {
        return self == .rate_limit or self == .quarantine or self == .block;
    }
};

pub const Decision = struct {
    made_ms: i64 = 0,
    action: DecisionAction = .monitor,
    confidence: u8 = 0,
    source_categories_used: u8 = 0,
    dispatched_to_pep: bool = false,
};

pub const Incident = struct {
    incident_id: u64 = 0,
    entity: [MAX_KEY_LEN]u8 = undefined,
    entity_len: usize = 0,
    opened_ms: i64 = 0,
    last_seen_ms: i64 = 0,
    severest: u8 = 0,
    sources: u64 = 0,
    evidence_event_ids: [MAX_EVIDENCE]u64 = undefined,
    evidence_count: usize = 0,
    decision: ?Decision = null,

    pub fn entitySlice(self: *const Incident) []const u8 {
        return self.entity[0..self.entity_len];
    }

    pub fn distinctSources(self: *const Incident) u8 {
        var n: u8 = 0;
        var m = self.sources;
        while (m != 0) : (m >>= 1) {
            if ((m & 1) != 0) n += 1;
        }
        return n;
    }

    pub fn hasSource(self: *const Incident, cat: SourceCategory) bool {
        return (self.sources & cat.bit()) != 0;
    }
};

pub const Fabric = struct {
    incidents: [MAX_INCIDENTS]Incident = undefined,
    incident_count: usize = 0,
    next_id: u64 = 1,

    pub fn ingest(self: *Fabric, ev: Evidence) u64 {
        if (self.findEntity(ev.entitySlice())) |idx| {
            self.fold(idx, &ev);
            return self.incidents[idx].incident_id;
        }
        if (self.incident_count >= MAX_INCIDENTS) return 0; // overflow: fail soft
        const idx = self.incident_count;
        self.incident_count += 1;
        const inc = &self.incidents[idx];
        inc.* = .{};
        inc.incident_id = self.next_id;
        self.next_id += 1;
        @memcpy(inc.entity[0..ev.entity_len], ev.entity[0..ev.entity_len]);
        inc.entity_len = ev.entity_len;
        inc.opened_ms = ev.ts_ms;
        inc.last_seen_ms = ev.ts_ms;
        self.fold(idx, &ev);
        return inc.incident_id;
    }

    pub fn incidentCount(self: *const Fabric) usize {
        return self.incident_count;
    }

    pub fn distinctSources(self: *const Fabric, idx: usize) u8 {
        if (idx >= self.incident_count) return 0;
        return self.incidents[idx].distinctSources();
    }

    pub fn evidenceCount(self: *const Fabric, idx: usize) usize {
        if (idx >= self.incident_count) return 0;
        return self.incidents[idx].evidence_count;
    }

    pub fn severest(self: *const Fabric, idx: usize) u8 {
        if (idx >= self.incident_count) return 0;
        return self.incidents[idx].severest;
    }

    pub fn hasSource(self: *const Fabric, idx: usize, cat: SourceCategory) bool {
        if (idx >= self.incident_count) return false;
        return self.incidents[idx].hasSource(cat);
    }

    pub fn decide(self: *Fabric, idx: usize, now_ms: i64) ?Decision {
        if (idx >= self.incident_count) return null;
        const inc = &self.incidents[idx];
        const d: DecisionAction = switch (inc.severest) {
            0, 1 => .monitor,
            2 => .rate_limit,
            3 => .quarantine,
            else => .block,
        };
        const srcs = inc.distinctSources();
        const confidence: u8 = @intCast(@min(@as(u32, 100), 50 + @as(u32, srcs) * 10));
        inc.decision = .{
            .made_ms = now_ms,
            .action = d,
            .confidence = confidence,
            .source_categories_used = srcs,
            .dispatched_to_pep = d.isEnforcement(),
        };
        return inc.decision;
    }

    fn fold(self: *Fabric, idx: usize, ev: *const Evidence) void {
        const inc = &self.incidents[idx];
        inc.last_seen_ms = ev.ts_ms;
        if (ev.severity > inc.severest) inc.severest = ev.severity;
        inc.sources |= ev.source.bit();
        for (inc.evidence_event_ids[0..inc.evidence_count]) |id| {
            if (id == ev.event_id) return; // dedupe
        }
        if (inc.evidence_count < MAX_EVIDENCE) {
            inc.evidence_event_ids[inc.evidence_count] = ev.event_id;
            inc.evidence_count += 1;
        }
    }

    fn findEntity(self: *const Fabric, key: []const u8) ?usize {
        var i: usize = 0;
        for (self.incidents[0..self.incident_count]) |*inc| {
            if (inc.entity_len == key.len and std.mem.eql(u8, inc.entitySlice(), key)) return i;
            i += 1;
        }
        return null;
    }
};

// ============================================================
// Tests
// ============================================================

fn makeEv(
    src: SourceCategory,
    entity: []const u8,
    event_id: u64,
    ts_ms: i64,
    severity: u8,
) Evidence {
    var e = Evidence{ .source = src, .event_id = event_id, .ts_ms = ts_ms, .severity = severity };
    std.debug.assert(entity.len <= MAX_KEY_LEN);
    @memcpy(e.entity[0..entity.len], entity);
    e.entity_len = entity.len;
    return e;
}

test "nine source categories with labels and bits" {
    try std.testing.expectEqual(@as(usize, 9), CATEGORY_COUNT);
    const want = [_][]const u8{
        "network", "host",  "process",    "file",  "registry",
        "identity", "threat_intel", "historical", "federation",
    };
    for (SOURCE_CATEGORIES, want) |cat, label| {
        try std.testing.expectEqualStrings(label, cat.label());
        try std.testing.expect(@as(u64, 1) << @intCast(@intFromEnum(cat)) == cat.bit());
    }
}

test "network evidence creates an incident" {
    var f = Fabric{};
    const id = f.ingest(makeEv(.network, "203.0.113.55", 1, 1000, 3));
    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(usize, 1), f.incidentCount());
    try std.testing.expectEqual(@as(u32, 3), f.severest(0));
}

test "second source category merges into the SAME incident" {
    var f = Fabric{};
    const id1 = f.ingest(makeEv(.network, "203.0.113.55", 1, 1000, 3));
    const id2 = f.ingest(makeEv(.registry, "203.0.113.55", 2, 1100, 2));
    try std.testing.expectEqual(id1, id2);
    try std.testing.expectEqual(@as(u8, 2), f.distinctSources(0));
    try std.testing.expectEqual(@as(usize, 2), f.evidenceCount(0));
}

test "incident holds evidence from multiple source categories (XDR criterion)" {
    var f = Fabric{};
    const id = f.ingest(makeEv(.network, "host-a", 1, 1000, 3));
    _ = f.ingest(makeEv(.host, "host-a", 2, 1050, 3));
    _ = f.ingest(makeEv(.process, "host-a", 3, 1100, 2));
    _ = f.ingest(makeEv(.registry, "host-a", 4, 1150, 2));
    _ = f.ingest(makeEv(.identity, "host-a", 5, 1200, 3));
    try std.testing.expectEqual(@as(u64, 1), id);
    try std.testing.expectEqual(@as(u8, 5), f.distinctSources(0));
    try std.testing.expectEqual(true, f.hasSource(0, .host));
    try std.testing.expectEqual(true, f.hasSource(0, .registry));
    try std.testing.expectEqual(true, f.hasSource(0, .identity));
    try std.testing.expectEqual(false, f.hasSource(0, .federation));
}

test "all nine categories can converge on one entity" {
    var f = Fabric{};
    const cats = [_]SourceCategory{
        .network, .host,  .process,       .file,  .registry,
        .identity, .threat_intel, .historical, .federation,
    };
    for (cats, 1..) |c, i| {
        _ = f.ingest(makeEv(c, "203.0.113.9", i, 1000 + @as(i64, @intCast(i)), 3));
    }
    try std.testing.expectEqual(@as(u8, 9), f.distinctSources(0));
    try std.testing.expectEqual(CATEGORY_COUNT, f.evidenceCount(0));
}

test "evidence event ids are deduplicated" {
    var f = Fabric{};
    _ = f.ingest(makeEv(.network, "host-a", 42, 1000, 3));
    _ = f.ingest(makeEv(.host, "host-a", 42, 1000, 3));
    try std.testing.expectEqual(@as(usize, 1), f.evidenceCount(0));
}

test "different entities get different incidents" {
    var f = Fabric{};
    const id1 = f.ingest(makeEv(.network, "10.0.0.1", 1, 1000, 3));
    const id2 = f.ingest(makeEv(.registry, "10.0.0.2", 2, 1000, 3));
    try std.testing.expect(id1 != id2);
    try std.testing.expectEqual(@as(usize, 2), f.incidentCount());
}

test "severest severity is tracked across sources" {
    var f = Fabric{};
    _ = f.ingest(makeEv(.network, "host-a", 1, 1000, 1));
    _ = f.ingest(makeEv(.federation, "host-a", 2, 1100, 4));
    try std.testing.expectEqual(@as(u32, 4), f.severest(0));
}

test "decision for critical multi-source incident is block, dispatched to PEP" {
    var f = Fabric{};
    _ = f.ingest(makeEv(.network, "203.0.113.55", 1, 1000, 4));
    _ = f.ingest(makeEv(.threat_intel, "203.0.113.55", 2, 1050, 4));
    _ = f.ingest(makeEv(.identity, "203.0.113.55", 3, 1100, 4));
    const d = f.decide(0, 2000).?;
    try std.testing.expectEqual(DecisionAction.block, d.action);
    try std.testing.expectEqual(true, d.dispatched_to_pep);
    try std.testing.expectEqual(@as(u8, 3), d.source_categories_used);
    try std.testing.expect(d.confidence > 50);
}

test "decision for high-severity two-source incident is quarantine" {
    var f = Fabric{};
    _ = f.ingest(makeEv(.file, "host-a", 1, 1000, 3));
    _ = f.ingest(makeEv(.host, "host-a", 2, 1050, 3));
    const d = f.decide(0, 2000).?;
    try std.testing.expectEqual(DecisionAction.quarantine, d.action);
    try std.testing.expectEqual(true, d.dispatched_to_pep);
}

test "decision for suspicious two-source incident is rate-limit" {
    var f = Fabric{};
    _ = f.ingest(makeEv(.process, "host-a", 1, 1000, 2));
    _ = f.ingest(makeEv(.historical, "host-a", 2, 1050, 2));
    const d = f.decide(0, 2000).?;
    try std.testing.expectEqual(DecisionAction.rate_limit, d.action);
    try std.testing.expectEqual(true, d.dispatched_to_pep);
}

test "decision for low-severity single-source incident is monitor, not dispatched" {
    var f = Fabric{};
    _ = f.ingest(makeEv(.network, "host-a", 1, 1000, 1));
    const d = f.decide(0, 2000).?;
    try std.testing.expectEqual(DecisionAction.monitor, d.action);
    try std.testing.expectEqual(false, d.dispatched_to_pep);
}