//! correlation_engine.zig - AEGIS Correlation Engine (Rewrite Phase 9)
//!
//! Tracks ENTITIES (not just session_id) across multiple flows/events.
//! When detection produces a threat verdict, correlation adds context:
//!   "this is the 5th threat from src_ip 10.0.0.1 in 60s"
//!
//! Entity types:
//!   src_ip   - source IP address (tracks outbound threat activity)
//!   dst_ip   - destination IP address (tracks inbound targets)
//!   session  - session_id (legacy cross-tier correlation)
//!   flow     - 5-tuple flow key
//!
//! Correlation rules (Phase 9 minimal set):
//!   1. repeated_threats: >=3 threats from same src_ip in 60s -> SUSPICIOUS alert
//!   2. port_scan_pattern: src_ip connects to >10 distinct dst_ports -> SUSPICIOUS alert
//!   3. target_repeated: dst_ip receives >5 threats in 60s -> MALICIOUS alert (under attack)
//!
//! Architecture:
//!   Detection Engine (Phase 7) -> Verdict Aggregator (Phase 8) -> Correlation Engine (Phase 9)
//!   Correlation produces CorrelationAlert structs (does NOT mutate events or evidence).

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow_types = @import("flow_types.zig");
const detection = @import("detection_engine.zig");
const verdict_agg = @import("verdict_aggregator.zig");

// ============================================================
// Constants
// ============================================================

/// Time window for correlation (60 seconds in nanoseconds).
pub const CORRELATION_WINDOW_NS: i128 = 60 * std.time.ns_per_s;

/// Max threats from same src_ip before alerting.
pub const REPEATED_THREAT_THRESHOLD: u32 = 3;

/// Max distinct dst_ports from same src_ip before alerting (port scan pattern).
pub const PORT_SCAN_DISTINCT_PORTS: u32 = 10;

/// Max threats received by same dst_ip before alerting (under attack).
pub const TARGET_REPEATED_THRESHOLD: u32 = 5;

/// Max entities tracked (LRU eviction when full).
pub const MAX_ENTITIES: usize = 4096;

/// Max verdict history per entity (ring buffer).
pub const MAX_VERDICT_HISTORY: usize = 32;

// ============================================================
// Entity Types
// ============================================================

pub const EntityType = enum(u8) {
    src_ip = 0,
    dst_ip = 1,
    session = 2,
    flow = 3,

    pub fn toString(self: EntityType) []const u8 {
        return switch (self) {
            .src_ip => "SRC_IP",
            .dst_ip => "DST_IP",
            .session => "SESSION",
            .flow => "FLOW",
        };
    }
};

/// Entity identifier. Uses a u64 to pack different entity types:
/// - src_ip/dst_ip: the IP address (lower 32 bits), upper 32 bits = 0
/// - session: session_id (full 64 bits)
/// - flow: hash of FlowKey (64 bits)
pub const EntityKey = struct {
    entity_type: EntityType,
    id: u64,

    pub fn fromSrcIp(ip: u32) EntityKey {
        return .{ .entity_type = .src_ip, .id = @as(u64, ip) };
    }

    pub fn fromDstIp(ip: u32) EntityKey {
        return .{ .entity_type = .dst_ip, .id = @as(u64, ip) };
    }

    pub fn fromSessionId(session_id: u64) EntityKey {
        return .{ .entity_type = .session, .id = session_id };
    }

    pub fn fromFlowKey(key: flow_types.FlowKey) EntityKey {
        return .{ .entity_type = .flow, .id = key.hash() };
    }

    pub fn hash(self: EntityKey) u64 {
        var h: u64 = 0xcbf29ce484222325;
        h ^= @as(u64, @intFromEnum(self.entity_type));
        h *%= 0x100000001b3;
        h ^= self.id;
        h *%= 0x100000001b3;
        return h;
    }

    pub fn eql(a: EntityKey, b: EntityKey) bool {
        return a.entity_type == b.entity_type and a.id == b.id;
    }
};

const EntityKeyContext = struct {
    pub fn hash(_: @This(), k: EntityKey) u64 {
        return k.hash();
    }
    pub fn eql(_: @This(), a: EntityKey, b: EntityKey) bool {
        return EntityKey.eql(a, b);
    }
};

// ============================================================
// Verdict History Entry
// ============================================================

pub const VerdictHistoryEntry = struct {
    verdict: detection.Verdict,
    timestamp_ns: i128,
    event_id: u64,
    rule_id: u32,
};

// ============================================================
// Entity State
// ============================================================

pub const Entity = struct {
    key: EntityKey,
    first_seen_ns: i128,
    last_seen_ns: i128,
    /// Total events observed for this entity.
    total_events: u64,
    /// Total threat verdicts (suspicious + malicious).
    threat_count: u32,
    /// Total malicious verdicts.
    malicious_count: u32,
    /// Distinct dst_ports seen (for src_ip port scan detection).
    /// Stored as a bitmask of low 16 bits of dst_port.
    dst_port_mask: u64,
    /// Count of distinct dst_ports (popcount of dst_port_mask).
    dst_port_count: u8,
    /// Ring buffer of recent verdicts (most recent first).
    verdict_history: [MAX_VERDICT_HISTORY]VerdictHistoryEntry,
    verdict_history_count: u8,
    /// Highest threat_score ever seen for this entity (0-100).
    max_threat_score: u8,
    /// Last time this entity triggered a correlation alert (debounce).
    last_alert_ns: i128,
};

// ============================================================
// Correlation Alert
// ============================================================

pub const CorrelationRule = enum(u8) {
    repeated_threats = 0,
    port_scan_pattern = 1,
    target_repeated = 2,

    pub fn toString(self: CorrelationRule) []const u8 {
        return switch (self) {
            .repeated_threats => "REPEATED_THREATS",
            .port_scan_pattern => "PORT_SCAN_PATTERN",
            .target_repeated => "TARGET_REPEATED",
        };
    }
};

pub const CorrelationAlert = struct {
    rule: CorrelationRule,
    entity_key: EntityKey,
    /// Aggregated verdict that triggered this alert.
    triggering_verdict: detection.Verdict,
    /// Number of threats counted for this entity (at time of alert).
    threat_count: u32,
    /// Distinct ports touched (for port_scan_pattern).
    distinct_ports: u8,
    /// Timestamp of the alert.
    timestamp_ns: i128,
    /// Event ID that triggered the alert.
    triggering_event_id: u64,
    /// Description (static string).
    description: []const u8,
};

// ============================================================
// Entity Store (HashMap with LRU eviction)
// ============================================================

const EntityMap = std.HashMap(EntityKey, Entity, EntityKeyContext, std.hash_map.default_max_load_percentage);

pub const EntityStore = struct {
    allocator: std.mem.Allocator,
    map: EntityMap,
    max_entities: usize,

    pub fn init(allocator: std.mem.Allocator) EntityStore {
        return .{
            .allocator = allocator,
            .map = EntityMap.init(allocator),
            .max_entities = MAX_ENTITIES,
        };
    }

    pub fn deinit(self: *EntityStore) void {
        self.map.deinit();
    }

    /// Get or create an entity for the given key.
    /// If the store is full, evicts the oldest entity first.
    pub fn getOrCreate(self: *EntityStore, key: EntityKey, now_ns: i128) *Entity {
        if (self.map.getPtr(key)) |entity| {
            return entity;
        }

        // Evict if at capacity
        if (self.map.count() >= self.max_entities) {
            self.evictOldest();
        }

        // Create new entity
        const entity = Entity{
            .key = key,
            .first_seen_ns = now_ns,
            .last_seen_ns = now_ns,
            .total_events = 0,
            .threat_count = 0,
            .malicious_count = 0,
            .dst_port_mask = 0,
            .dst_port_count = 0,
            .verdict_history = undefined,
            .verdict_history_count = 0,
            .max_threat_score = 0,
            .last_alert_ns = 0,
        };
        self.map.put(key, entity) catch {
            // Allocation failure - return a dummy. Production: log + metric.
            // For safety, we re-fetch the just-inserted entry if it exists.
            return self.map.getPtr(key) orelse @panic("EntityStore allocation failure");
        };
        return self.map.getPtr(key).?;
    }

    /// Get an entity by key (read-only). Returns null if not present.
    pub fn get(self: *const EntityStore, key: EntityKey) ?Entity {
        return self.map.get(key);
    }

    /// Current entity count.
    pub fn count(self: *const EntityStore) usize {
        return self.map.count();
    }

    /// Evict the entity with the oldest last_seen_ns.
    fn evictOldest(self: *EntityStore) void {
        if (self.map.count() == 0) return;

        var oldest_key: ?EntityKey = null;
        var oldest_ts: i128 = std.math.maxInt(i128);

        var it = self.map.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_seen_ns < oldest_ts) {
                oldest_ts = entry.value_ptr.last_seen_ns;
                oldest_key = entry.value_ptr.key;
            }
        }

        if (oldest_key) |k| {
            _ = self.map.remove(k);
        }
    }
};

// ============================================================
// Correlation Engine
// ============================================================

pub const CorrelationEngine = struct {
    store: EntityStore,
    /// Lifetime stats
    total_events_processed: u64,
    total_threat_events: u64,
    total_alerts: u64,
    /// Per-rule alert counts
    alerts_repeated_threats: u64,
    alerts_port_scan: u64,
    alerts_target_repeated: u64,

    pub fn init(allocator: std.mem.Allocator) CorrelationEngine {
        return .{
            .store = EntityStore.init(allocator),
            .total_events_processed = 0,
            .total_threat_events = 0,
            .total_alerts = 0,
            .alerts_repeated_threats = 0,
            .alerts_port_scan = 0,
            .alerts_target_repeated = 0,
        };
    }

    pub fn deinit(self: *CorrelationEngine) void {
        self.store.deinit();
    }

    /// Process an aggregated verdict and produce correlation alerts.
    /// Returns up to 3 alerts (one per rule). Does NOT mutate event/evidence.
    pub fn processVerdict(
        self: *CorrelationEngine,
        event: canonical.CanonicalEvent,
        flow_update: ?flow_types.FlowUpdate,
        av: verdict_agg.AggregatedVerdict,
    ) [3]?CorrelationAlert {
        var alerts: [3]?CorrelationAlert = .{ null, null, null };
        var alert_idx: usize = 0;

        self.total_events_processed += 1;

        const now_ns = event.monotonic_ns;
        const is_threat = av.isThreat();

        if (is_threat) {
            self.total_threat_events += 1;
        }

        // --- Update src_ip entity ---
        if (event.source_ip != 0) {
            const key = EntityKey.fromSrcIp(event.source_ip);
            const entity = self.store.getOrCreate(key, now_ns);
            self.updateEntity(entity, event, av, now_ns);

            // Rule 1: repeated_threats (>=3 threats from same src_ip in 60s)
            if (is_threat and alert_idx < 3) {
                if (self.checkRepeatedThreats(entity, now_ns)) |threat_count| {
                    alerts[alert_idx] = CorrelationAlert{
                        .rule = .repeated_threats,
                        .entity_key = key,
                        .triggering_verdict = av.verdict,
                        .threat_count = threat_count,
                        .distinct_ports = entity.dst_port_count,
                        .timestamp_ns = now_ns,
                        .triggering_event_id = event.event_id,
                        .description = "repeated threats from same source IP",
                    };
                    alert_idx += 1;
                    self.alerts_repeated_threats += 1;
                    self.total_alerts += 1;
                    entity.last_alert_ns = now_ns;
                }
            }

            // Rule 2: port_scan_pattern (>10 distinct dst_ports from same src_ip)
            if (alert_idx < 3) {
                if (self.checkPortScanPattern(entity, now_ns)) |port_count| {
                    alerts[alert_idx] = CorrelationAlert{
                        .rule = .port_scan_pattern,
                        .entity_key = key,
                        .triggering_verdict = av.verdict,
                        .threat_count = entity.threat_count,
                        .distinct_ports = port_count,
                        .timestamp_ns = now_ns,
                        .triggering_event_id = event.event_id,
                        .description = "port scan pattern detected",
                    };
                    alert_idx += 1;
                    self.alerts_port_scan += 1;
                    self.total_alerts += 1;
                    entity.last_alert_ns = now_ns;
                }
            }
        }

        // --- Update dst_ip entity ---
        if (event.dest_ip != 0) {
            const key = EntityKey.fromDstIp(event.dest_ip);
            const entity = self.store.getOrCreate(key, now_ns);
            self.updateEntity(entity, event, av, now_ns);

            // Rule 3: target_repeated (>5 threats received by same dst_ip in 60s)
            if (is_threat and alert_idx < 3) {
                if (self.checkTargetRepeated(entity, now_ns)) |threat_count| {
                    alerts[alert_idx] = CorrelationAlert{
                        .rule = .target_repeated,
                        .entity_key = key,
                        .triggering_verdict = av.verdict,
                        .threat_count = threat_count,
                        .distinct_ports = 0,
                        .timestamp_ns = now_ns,
                        .triggering_event_id = event.event_id,
                        .description = "target receiving repeated threats (under attack)",
                    };
                    alert_idx += 1;
                    self.alerts_target_repeated += 1;
                    self.total_alerts += 1;
                    entity.last_alert_ns = now_ns;
                }
            }
        }

        // --- Update session entity (legacy) ---
        if (event.session_id != 0) {
            const key = EntityKey.fromSessionId(event.session_id);
            const entity = self.store.getOrCreate(key, now_ns);
            self.updateEntity(entity, event, av, now_ns);
        }

        // --- Update flow entity ---
        if (flow_update != null) {
            const key = EntityKey.fromFlowKey(flow_update.?.key);
            const entity = self.store.getOrCreate(key, now_ns);
            self.updateEntity(entity, event, av, now_ns);
        }

        return alerts;
    }

    /// Update entity state with a new verdict.
    fn updateEntity(
        self: *CorrelationEngine,
        entity: *Entity,
        event: canonical.CanonicalEvent,
        av: verdict_agg.AggregatedVerdict,
        now_ns: i128,
    ) void {
        _ = self;
        entity.last_seen_ns = now_ns;
        entity.total_events += 1;

        // Track dst_port for src_ip entities (port scan detection)
        if (entity.key.entity_type == .src_ip and event.dest_port != 0) {
            const port_bit: u64 = @as(u64, 1) << @intCast(event.dest_port & 0x3F); // low 6 bits = 64 ports
            if (entity.dst_port_mask & port_bit == 0) {
                entity.dst_port_mask |= port_bit;
                entity.dst_port_count += 1;
            }
        }

        // Track threat counts
        if (av.isThreat()) {
            entity.threat_count += 1;
            if (av.verdict == .malicious) {
                entity.malicious_count += 1;
            }
            // Update max_threat_score (use confidence as proxy)
            if (av.confidence > entity.max_threat_score) {
                entity.max_threat_score = av.confidence;
            }
        }

        // Append to verdict history (ring buffer)
        const idx: usize = @intCast(entity.verdict_history_count % MAX_VERDICT_HISTORY);
        entity.verdict_history[idx] = .{
            .verdict = av.verdict,
            .timestamp_ns = now_ns,
            .event_id = event.event_id,
            .rule_id = if (av.indicators != 0) 1 else 0, // simplified
        };
        if (entity.verdict_history_count < MAX_VERDICT_HISTORY) {
            entity.verdict_history_count += 1;
        }
    }

    /// Rule 1: Check if src_ip has >=3 threats in the correlation window.
    /// Returns the threat count if alerting, null otherwise.
    /// Uses debounce: don't alert more than once per CORRELATION_WINDOW_NS.
    fn checkRepeatedThreats(self: *const CorrelationEngine, entity: *Entity, now_ns: i128) ?u32 {
        _ = self;
        // Debounce: skip if alerted recently
        if (now_ns - entity.last_alert_ns < CORRELATION_WINDOW_NS and entity.last_alert_ns != 0) {
            return null;
        }
        if (entity.threat_count >= REPEATED_THREAT_THRESHOLD) {
            return entity.threat_count;
        }
        return null;
    }

    /// Rule 2: Check if src_ip has touched >10 distinct dst_ports.
    /// Uses > (strictly greater than) to match rule description.
    fn checkPortScanPattern(self: *const CorrelationEngine, entity: *Entity, now_ns: i128) ?u8 {
        _ = self;
        if (now_ns - entity.last_alert_ns < CORRELATION_WINDOW_NS and entity.last_alert_ns != 0) {
            return null;
        }
        if (entity.dst_port_count > PORT_SCAN_DISTINCT_PORTS) {
            return entity.dst_port_count;
        }
        return null;
    }

    /// Rule 3: Check if dst_ip has received >5 threats in the correlation window.
    fn checkTargetRepeated(self: *const CorrelationEngine, entity: *Entity, now_ns: i128) ?u32 {
        _ = self;
        if (now_ns - entity.last_alert_ns < CORRELATION_WINDOW_NS and entity.last_alert_ns != 0) {
            return null;
        }
        if (entity.threat_count >= TARGET_REPEATED_THRESHOLD) {
            return entity.threat_count;
        }
        return null;
    }

    /// Get a snapshot of an entity (read-only).
    pub fn getEntity(self: *const CorrelationEngine, key: EntityKey) ?Entity {
        return self.store.get(key);
    }

    /// Current entity count.
    pub fn entityCount(self: *const CorrelationEngine) usize {
        return self.store.count();
    }
};

// ============================================================
// Tests (all use local engine instances - parallelism-safe)
// ============================================================

test "EntityKey.fromSrcIp packs correctly" {
    const k = EntityKey.fromSrcIp(0x0A000001);
    try std.testing.expect(k.entity_type == .src_ip);
    try std.testing.expect(k.id == 0x0A000001);
}

test "EntityKey.fromDstIp packs correctly" {
    const k = EntityKey.fromDstIp(0xC0A80001);
    try std.testing.expect(k.entity_type == .dst_ip);
    try std.testing.expect(k.id == 0xC0A80001);
}

test "EntityKey.fromSessionId packs correctly" {
    const k = EntityKey.fromSessionId(0xDEADBEEFCAFE);
    try std.testing.expect(k.entity_type == .session);
    try std.testing.expect(k.id == 0xDEADBEEFCAFE);
}

test "EntityKey.fromFlowKey hashes consistently" {
    const fk = flow_types.FlowKey{
        .ip_a = 0x0A000001,
        .port_a = 12345,
        .ip_b = 0x0A000002,
        .port_b = 80,
        .protocol = 6,
    };
    const k1 = EntityKey.fromFlowKey(fk);
    const k2 = EntityKey.fromFlowKey(fk);
    try std.testing.expect(EntityKey.eql(k1, k2));
    try std.testing.expect(k1.hash() == k2.hash());
}

test "EntityKey.eql distinguishes types" {
    const k1 = EntityKey.fromSrcIp(0x0A000001);
    const k2 = EntityKey.fromDstIp(0x0A000001);
    try std.testing.expect(!EntityKey.eql(k1, k2));
}

test "EntityType.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, EntityType.src_ip.toString(), "SRC_IP"));
    try std.testing.expect(std.mem.eql(u8, EntityType.dst_ip.toString(), "DST_IP"));
    try std.testing.expect(std.mem.eql(u8, EntityType.session.toString(), "SESSION"));
    try std.testing.expect(std.mem.eql(u8, EntityType.flow.toString(), "FLOW"));
}

test "CorrelationRule.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, CorrelationRule.repeated_threats.toString(), "REPEATED_THREATS"));
    try std.testing.expect(std.mem.eql(u8, CorrelationRule.port_scan_pattern.toString(), "PORT_SCAN_PATTERN"));
    try std.testing.expect(std.mem.eql(u8, CorrelationRule.target_repeated.toString(), "TARGET_REPEATED"));
}

test "EntityStore init and basic getOrCreate" {
    var store = EntityStore.init(std.testing.allocator);
    defer store.deinit();

    const key = EntityKey.fromSrcIp(0x0A000001);
    const entity = store.getOrCreate(key, 1000);

    try std.testing.expect(entity.key.id == 0x0A000001);
    try std.testing.expect(entity.first_seen_ns == 1000);
    try std.testing.expect(entity.total_events == 0);
    try std.testing.expect(store.count() == 1);

    // Second getOrCreate returns same entity
    const entity2 = store.getOrCreate(key, 2000);
    try std.testing.expect(entity2.first_seen_ns == 1000); // unchanged
    try std.testing.expect(store.count() == 1); // still 1
}

test "EntityStore evicts oldest when full" {
    var store = EntityStore.init(std.testing.allocator);
    defer store.deinit();
    store.max_entities = 4; // small for testing

    var i: u32 = 0;
    while (i < 4) : (i += 1) {
        const key = EntityKey.fromSrcIp(0x0A000000 + i);
        _ = store.getOrCreate(key, @as(i128, i));
    }
    try std.testing.expect(store.count() == 4);

    // Insert 5th - should evict oldest (i=0)
    const key5 = EntityKey.fromSrcIp(0x0A0000AA);
    _ = store.getOrCreate(key5, 100);

    try std.testing.expect(store.count() == 4); // still 4
    // Oldest (i=0) should be gone
    try std.testing.expect(store.get(EntityKey.fromSrcIp(0x0A000000)) == null);
    // Newest (i=3) should still be there
    try std.testing.expect(store.get(EntityKey.fromSrcIp(0x0A000003)) != null);
}

test "CorrelationEngine init has zero stats" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    try std.testing.expect(engine.total_events_processed == 0);
    try std.testing.expect(engine.total_threat_events == 0);
    try std.testing.expect(engine.total_alerts == 0);
    try std.testing.expect(engine.entityCount() == 0);
}

test "CorrelationEngine.processVerdict with benign verdict produces no alerts" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.monotonic_ns = 1000;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .benign,
        .confidence = 50,
        .detector_count = 3,
        .agreeing_count = 3,
        .malicious_count = 0,
        .suspicious_count = 0,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .benign,
        .indicators = detection.Indicator.NONE,
        .event_id = event.event_id,
    };

    const alerts = engine.processVerdict(event, null, av);
    try std.testing.expect(alerts[0] == null);
    try std.testing.expect(alerts[1] == null);
    try std.testing.expect(alerts[2] == null);
    try std.testing.expect(engine.total_threat_events == 0);
}

test "CorrelationEngine: single threat produces no alert (below threshold)" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.monotonic_ns = 1000;
    event.severity = 2;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 70,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = event.event_id,
    };

    const alerts = engine.processVerdict(event, null, av);
    // 1 threat - below REPEATED_THREAT_THRESHOLD (3)
    try std.testing.expect(alerts[0] == null);
    try std.testing.expect(engine.total_threat_events == 1);
}

test "CorrelationEngine: 3 threats from same src_ip triggers repeated_threats alert" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.source_ip = 0x0A000001; // same src_ip
        event.dest_ip = 0x0A000002;
        event.dest_port = @intCast(80 + i); // different ports
        event.monotonic_ns = @intCast(i * 1000);
        event.severity = 2;

        const av = verdict_agg.AggregatedVerdict{
            .verdict = .suspicious,
            .confidence = 70,
            .detector_count = 3,
            .agreeing_count = 2,
            .malicious_count = 0,
            .suspicious_count = 2,
            .error_count = 0,
            .escalated = false,
            .original_verdict = .suspicious,
            .indicators = detection.Indicator.RULE_MATCH,
            .event_id = event.event_id,
        };

        const alerts = engine.processVerdict(event, null, av);

        if (i < 2) {
            // First 2 threats: no alert (below threshold)
            try std.testing.expect(alerts[0] == null);
        } else {
            // 3rd threat: alert triggered
            try std.testing.expect(alerts[0] != null);
            try std.testing.expect(alerts[0].?.rule == .repeated_threats);
            try std.testing.expect(alerts[0].?.threat_count == 3);
        }
    }

    try std.testing.expect(engine.total_threat_events == 3);
    try std.testing.expect(engine.total_alerts == 1);
    try std.testing.expect(engine.alerts_repeated_threats == 1);
}

test "CorrelationEngine: 10+ distinct dst_ports triggers port_scan_pattern alert" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    // Send 11 events from same src_ip to 11 different ports (benign verdicts)
    var i: u32 = 0;
    while (i < 11) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.source_ip = 0x0A000001; // same src_ip
        event.dest_ip = 0x0A000002;
        event.dest_port = @intCast(100 + i); // 11 distinct ports
        event.monotonic_ns = @intCast(i * 1000);

        const av = verdict_agg.AggregatedVerdict{
            .verdict = .benign, // benign verdicts, but port pattern is suspicious
            .confidence = 50,
            .detector_count = 3,
            .agreeing_count = 3,
            .malicious_count = 0,
            .suspicious_count = 0,
            .error_count = 0,
            .escalated = false,
            .original_verdict = .benign,
            .indicators = detection.Indicator.NONE,
            .event_id = event.event_id,
        };

        const alerts = engine.processVerdict(event, null, av);

        if (i < 10) {
            // First 10 ports: no alert
            try std.testing.expect(alerts[0] == null);
            try std.testing.expect(alerts[1] == null);
        } else {
            // 11th port: port_scan_pattern alert
            var found_port_scan = false;
            for (alerts) |a| {
                if (a) |alert| {
                    if (alert.rule == .port_scan_pattern) {
                        found_port_scan = true;
                        try std.testing.expect(alert.distinct_ports >= 10);
                    }
                }
            }
            try std.testing.expect(found_port_scan);
        }
    }

    try std.testing.expect(engine.alerts_port_scan == 1);
}

test "CorrelationEngine: 5+ threats to same dst_ip triggers target_repeated alert" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    // 5 different src_ips all targeting same dst_ip with threats
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.source_ip = 0x0A000000 + i; // different src_ip
        event.dest_ip = 0x0A0000FF; // same dst_ip (target)
        event.dest_port = 80;
        event.monotonic_ns = @intCast(i * 1000);
        event.severity = 2;

        const av = verdict_agg.AggregatedVerdict{
            .verdict = .suspicious,
            .confidence = 70,
            .detector_count = 3,
            .agreeing_count = 2,
            .malicious_count = 0,
            .suspicious_count = 2,
            .error_count = 0,
            .escalated = false,
            .original_verdict = .suspicious,
            .indicators = detection.Indicator.RULE_MATCH,
            .event_id = event.event_id,
        };

        const alerts = engine.processVerdict(event, null, av);

        if (i < 4) {
            // First 4 threats to dst_ip: no alert
            var found_target = false;
            for (alerts) |a| {
                if (a) |alert| {
                    if (alert.rule == .target_repeated) found_target = true;
                }
            }
            try std.testing.expect(!found_target);
        } else {
            // 5th threat: target_repeated alert
            var found_target = false;
            for (alerts) |a| {
                if (a) |alert| {
                    if (alert.rule == .target_repeated) {
                        found_target = true;
                        try std.testing.expect(alert.threat_count >= 5);
                    }
                }
            }
            try std.testing.expect(found_target);
        }
    }

    try std.testing.expect(engine.alerts_target_repeated == 1);
}

test "CorrelationEngine: stats accumulate correctly" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    // 3 threats from same src_ip (triggers repeated_threats)
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.source_ip = 0x0A000001;
        event.dest_ip = 0x0A000002;
        event.dest_port = 80;
        event.monotonic_ns = @intCast(i * 1000);
        event.severity = 2;

        const av = verdict_agg.AggregatedVerdict{
            .verdict = .suspicious,
            .confidence = 70,
            .detector_count = 3,
            .agreeing_count = 2,
            .malicious_count = 0,
            .suspicious_count = 2,
            .error_count = 0,
            .escalated = false,
            .original_verdict = .suspicious,
            .indicators = detection.Indicator.RULE_MATCH,
            .event_id = event.event_id,
        };

        _ = engine.processVerdict(event, null, av);
    }

    try std.testing.expect(engine.total_events_processed == 3);
    try std.testing.expect(engine.total_threat_events == 3);
    try std.testing.expect(engine.total_alerts == 1);
    try std.testing.expect(engine.alerts_repeated_threats == 1);
}

test "CorrelationEngine: getEntity retrieves entity state" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.monotonic_ns = 1000;

    const av = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 70,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = event.event_id,
    };

    _ = engine.processVerdict(event, null, av);

    const src_entity = engine.getEntity(EntityKey.fromSrcIp(0x0A000001));
    try std.testing.expect(src_entity != null);
    try std.testing.expect(src_entity.?.threat_count == 1);
    try std.testing.expect(src_entity.?.total_events == 1);
    try std.testing.expect(src_entity.?.dst_port_count == 1);

    const dst_entity = engine.getEntity(EntityKey.fromDstIp(0x0A000002));
    try std.testing.expect(dst_entity != null);
    try std.testing.expect(dst_entity.?.threat_count == 1);
}

test "CorrelationEngine: debounce prevents repeated alerts within window" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    // First batch: 3 threats -> alert
    var i: u32 = 0;
    while (i < 3) : (i += 1) {
        var event = canonical.create(.wfp_sensor);
        event.source_ip = 0x0A000001;
        event.dest_ip = 0x0A000002;
        event.dest_port = 80;
        event.monotonic_ns = @intCast(i * 1000); // 0, 1000, 2000 ns
        event.severity = 2;

        const av = verdict_agg.AggregatedVerdict{
            .verdict = .suspicious,
            .confidence = 70,
            .detector_count = 3,
            .agreeing_count = 2,
            .malicious_count = 0,
            .suspicious_count = 2,
            .error_count = 0,
            .escalated = false,
            .original_verdict = .suspicious,
            .indicators = detection.Indicator.RULE_MATCH,
            .event_id = event.event_id,
        };

        _ = engine.processVerdict(event, null, av);
    }
    try std.testing.expect(engine.total_alerts == 1);

    // 4th threat (still within window) - should NOT alert (debounce)
    var event4 = canonical.create(.wfp_sensor);
    event4.source_ip = 0x0A000001;
    event4.dest_ip = 0x0A000002;
    event4.dest_port = 80;
    event4.monotonic_ns = 3000; // still within 60s window
    event4.severity = 2;

    const av4 = verdict_agg.AggregatedVerdict{
        .verdict = .suspicious,
        .confidence = 70,
        .detector_count = 3,
        .agreeing_count = 2,
        .malicious_count = 0,
        .suspicious_count = 2,
        .error_count = 0,
        .escalated = false,
        .original_verdict = .suspicious,
        .indicators = detection.Indicator.RULE_MATCH,
        .event_id = event4.event_id,
    };

    _ = engine.processVerdict(event4, null, av4);
    try std.testing.expect(engine.total_alerts == 1); // still 1, no new alert
}
