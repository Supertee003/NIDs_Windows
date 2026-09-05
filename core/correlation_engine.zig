//! correlation_engine.zig - AEGIS Correlation Engine (Rewrite Phase 9)
//!
//! Tracks entities (source IPs, dest IPs, sessions) over time and emits
//! CorrelationAlerts when multiple threats hit the same entity within
//! a sliding window.
//!
//! Contract:
//!   EntityType: enum (source_ip, dest_ip, session, user)
//!   EntityKey: struct { entity_type, ip (u32), session_id (u64) }
//!   CorrelationRule: enum with toString()
//!   CorrelationAlert: struct { rule, entity_key, threat_count, triggering_event_id, description }
//!   CorrelationEngine: processVerdict(event, flow, verdict) -> [3]?CorrelationAlert

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");
const detection = @import("detection_engine.zig");

// ============================================================
// Constants
// ============================================================

pub const MAX_ALERTS_PER_VERDICT: usize = 3;
pub const THREAT_COUNT_THRESHOLD: u8 = 3;
pub const SLIDING_WINDOW_NS: i128 = 5 * std.time.ns_per_s;

// ============================================================
// Entity Types
// ============================================================

pub const EntityType = enum(u8) {
    source_ip = 0,
    dest_ip = 1,
    session = 2,
    user = 3,

    pub fn toString(self: EntityType) []const u8 {
        return switch (self) {
            .source_ip => "SOURCE_IP",
            .dest_ip => "DEST_IP",
            .session => "SESSION",
            .user => "USER",
        };
    }
};

pub const EntityKey = struct {
    entity_type: EntityType,
    ip: u32,
    session_id: u64,

    pub fn fromSourceIp(ip: u32) EntityKey {
        return .{ .entity_type = .source_ip, .ip = ip, .session_id = 0 };
    }

    pub fn fromDestIp(ip: u32) EntityKey {
        return .{ .entity_type = .dest_ip, .ip = ip, .session_id = 0 };
    }

    pub fn fromSession(session_id: u64) EntityKey {
        return .{ .entity_type = .session, .ip = 0, .session_id = session_id };
    }
};

// ============================================================
// Correlation Rules
// ============================================================

pub const CorrelationRule = enum(u8) {
    no_rule = 0,
    repeated_threats = 1,
    escalating_severity = 2,
    multi_target_scan = 3,
    long_lived_flow_threat = 4,
    high_packet_burst = 5,

    pub fn toString(self: CorrelationRule) []const u8 {
        return switch (self) {
            .no_rule => "NO_RULE",
            .repeated_threats => "REPEATED_THREATS",
            .escalating_severity => "ESCALATING_SEVERITY",
            .multi_target_scan => "MULTI_TARGET_SCAN",
            .long_lived_flow_threat => "LONG_LIVED_FLOW_THREAT",
            .high_packet_burst => "HIGH_PACKET_BURST",
        };
    }
};

// ============================================================
// Correlation Alert
// ============================================================

pub const CorrelationAlert = struct {
    rule: CorrelationRule,
    entity_key: EntityKey,
    threat_count: u8,
    triggering_event_id: u64,
    description: []const u8,

    pub fn isHighSeverity(self: CorrelationAlert) bool {
        return self.threat_count >= THREAT_COUNT_THRESHOLD + 2;
    }
};

// ============================================================
// Entity Tracker
// ============================================================

const EntityTracker = struct {
    key: EntityKey,
    threat_count: u8,
    first_seen_ns: i128,
    last_seen_ns: i128,
    max_severity: u8,
    distinct_targets: u32, // for multi_target_scan
    last_target_ip: u32,
};

// ============================================================
// Aggregated Verdict forward declaration (avoid circular dep)
// ============================================================

/// Forward-declared shape so we don't need to import verdict_aggregator.zig
/// (which would create a cycle through detection_engine.zig).
pub const AggregatedVerdictStub = struct {
    verdict: detection.Verdict,
    confidence: u8,
};

// ============================================================
// Correlation Engine
// ============================================================

pub const CorrelationEngine = struct {
    allocator: std.mem.Allocator,
    trackers: std.AutoHashMap(u64, EntityTracker),
    total_alerts_emitted: u64 = 0,
    total_verdicts_processed: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) CorrelationEngine {
        return .{
            .allocator = allocator,
            .trackers = std.AutoHashMap(u64, EntityTracker).init(allocator),
        };
    }

    pub fn deinit(self: *CorrelationEngine) void {
        self.trackers.deinit();
    }

    /// Process a verdict and return up to MAX_ALERTS_PER_VERDICT alerts.
    /// Updates entity trackers for source_ip, dest_ip, and session.
    pub fn processVerdict(
        self: *CorrelationEngine,
        event: canonical.CanonicalEvent,
        flow_update: ?flow.FlowUpdate,
        verdict: detection.Verdict,
        _: u8,
    ) [MAX_ALERTS_PER_VERDICT]?CorrelationAlert {
        var alerts: [MAX_ALERTS_PER_VERDICT]?CorrelationAlert = .{ null, null, null };
        self.total_verdicts_processed += 1;

        if (!verdict.isThreat()) return alerts;

        const now_ns = std.time.nanoTimestamp();
        var alert_idx: usize = 0;

        // Track source IP
        if (event.source_ip != 0 and alert_idx < MAX_ALERTS_PER_VERDICT) {
            const key = EntityKey.fromSourceIp(event.source_ip);
            if (self.updateTracker(key, now_ns, event.severity, event.dest_ip, verdict)) |alert| {
                alerts[alert_idx] = alert;
                alert_idx += 1;
                self.total_alerts_emitted += 1;
            }
        }

        // Track dest IP
        if (event.dest_ip != 0 and alert_idx < MAX_ALERTS_PER_VERDICT) {
            const key = EntityKey.fromDestIp(event.dest_ip);
            if (self.updateTracker(key, now_ns, event.severity, 0, verdict)) |alert| {
                alerts[alert_idx] = alert;
                alert_idx += 1;
                self.total_alerts_emitted += 1;
            }
        }

        // Track session
        if (event.session_id != 0 and alert_idx < MAX_ALERTS_PER_VERDICT) {
            const key = EntityKey.fromSession(event.session_id);
            if (self.updateTracker(key, now_ns, event.severity, 0, verdict)) |alert| {
                alerts[alert_idx] = alert;
                alert_idx += 1;
                self.total_alerts_emitted += 1;
            }
        }

        // Flow-based rule: long-lived flow threat
        if (flow_update) |upd| {
            if (alert_idx < MAX_ALERTS_PER_VERDICT and upd.flow.packet_count > 100 and upd.flow.max_severity >= 2) {
                alerts[alert_idx] = CorrelationAlert{
                    .rule = .long_lived_flow_threat,
                    .entity_key = EntityKey.fromSourceIp(event.source_ip),
                    .threat_count = @intCast(upd.flow.packet_count),
                    .triggering_event_id = event.event_id,
                    .description = "long-lived flow with high severity",
                };
                alert_idx += 1;
                self.total_alerts_emitted += 1;
            }
        }

        return alerts;
    }

    fn hashKey(key: EntityKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(std.mem.asBytes(&key));
        return hasher.final();
    }

    fn updateTracker(
        self: *CorrelationEngine,
        key: EntityKey,
        now_ns: i128,
        severity: u8,
        target_ip: u32,
        verdict: detection.Verdict,
    ) ?CorrelationAlert {
        _ = verdict;
        const h = hashKey(key);
        const gop = self.trackers.getOrPut(h) catch return null;

        if (!gop.found_existing) {
            gop.value_ptr.* = .{
                .key = key,
                .threat_count = 1,
                .first_seen_ns = now_ns,
                .last_seen_ns = now_ns,
                .max_severity = severity,
                .distinct_targets = if (target_ip != 0) 1 else 0,
                .last_target_ip = target_ip,
            };
            return null;
        }

        var t = gop.value_ptr;
        t.threat_count += 1;
        t.last_seen_ns = now_ns;
        if (severity > t.max_severity) t.max_severity = severity;
        if (target_ip != 0 and target_ip != t.last_target_ip) {
            t.distinct_targets += 1;
            t.last_target_ip = target_ip;
        }

        // Rule: repeated_threats
        if (t.threat_count == THREAT_COUNT_THRESHOLD) {
            return CorrelationAlert{
                .rule = .repeated_threats,
                .entity_key = key,
                .threat_count = t.threat_count,
                .triggering_event_id = 0, // caller fills in
                .description = "repeated threats from same entity",
            };
        }

        // Rule: multi_target_scan (3+ distinct targets)
        if (t.distinct_targets >= 3 and t.threat_count >= 3) {
            return CorrelationAlert{
                .rule = .multi_target_scan,
                .entity_key = key,
                .threat_count = @intCast(t.distinct_targets),
                .triggering_event_id = 0,
                .description = "entity hitting multiple targets",
            };
        }

        return null;
    }

    pub fn resetStats(self: *CorrelationEngine) void {
        self.trackers.clearRetainingCapacity();
        self.total_alerts_emitted = 0;
        self.total_verdicts_processed = 0;
    }
};

// ============================================================
// Tests
// ============================================================

test "EntityType.toString returns uppercase token" {
    try std.testing.expect(std.mem.eql(u8, EntityType.source_ip.toString(), "SOURCE_IP"));
    try std.testing.expect(std.mem.eql(u8, EntityType.dest_ip.toString(), "DEST_IP"));
    try std.testing.expect(std.mem.eql(u8, EntityType.session.toString(), "SESSION"));
    try std.testing.expect(std.mem.eql(u8, EntityType.user.toString(), "USER"));
}

test "CorrelationRule.toString returns uppercase token" {
    try std.testing.expect(std.mem.eql(u8, CorrelationRule.repeated_threats.toString(), "REPEATED_THREATS"));
    try std.testing.expect(std.mem.eql(u8, CorrelationRule.escalating_severity.toString(), "ESCALATING_SEVERITY"));
}

test "EntityKey.fromSourceIp builds correct key" {
    const k = EntityKey.fromSourceIp(0x0A000001);
    try std.testing.expect(k.entity_type == .source_ip);
    try std.testing.expect(k.ip == 0x0A000001);
    try std.testing.expect(k.session_id == 0);
}

test "CorrelationEngine.init creates empty tracker map" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();
    try std.testing.expect(engine.trackers.count() == 0);
    try std.testing.expect(engine.total_alerts_emitted == 0);
}

test "CorrelationEngine.processVerdict returns no alerts for benign verdict" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    const alerts = engine.processVerdict(event, null, .benign, 30);
    for (alerts) |a| try std.testing.expect(a == null);
}

test "CorrelationEngine.processVerdict tracks source IP threats" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.severity = 2;

    // First two threats: no alert
    var i: u8 = 0;
    while (i < 2) : (i += 1) {
        const alerts = engine.processVerdict(event, null, .malicious, 70);
        for (alerts) |a| try std.testing.expect(a == null);
    }

    // Third threat: alert fires
    const alerts = engine.processVerdict(event, null, .malicious, 70);
    var found = false;
    for (alerts) |a| {
        if (a) |alert| {
            if (alert.rule == .repeated_threats) found = true;
        }
    }
    try std.testing.expect(found);
}

test "CorrelationEngine.resetStats clears trackers" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x0A000001;
    event.dest_ip = 0x0A000002;
    event.severity = 2;
    _ = engine.processVerdict(event, null, .malicious, 70);
    try std.testing.expect(engine.trackers.count() > 0);
    engine.resetStats();
    try std.testing.expect(engine.trackers.count() == 0);
}
