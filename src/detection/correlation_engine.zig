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
const canonical = @import("../contract/canonical_event.zig");
const flow = @import("../capture/flow_engine.zig");
const detection = @import("detection_engine.zig");

// ============================================================
// Constants
// ============================================================

pub const MAX_ALERTS_PER_VERDICT: usize = 3;
pub const THREAT_COUNT_THRESHOLD: u8 = 3;
pub const SLIDING_WINDOW_NS: i128 = 5 * std.time.ns_per_s;
pub const MAX_EVIDENCE_PER_INCIDENT: usize = 8;
pub const INCIDENT_MIN_CATEGORIES: u8 = 2;
pub const INCIDENT_CATEGORY_BONUS: u8 = 10;

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
// Source Categories (T4: combine multiple source categories into one incident)
// ============================================================

/// T4: canonical source category for incident correlation. Derived from the
/// event's EventSource via SourceKind.classify (network/host/process/file/
/// registry/historical). "identity" is reserved for user/identity signals.
pub const SourceCategory = enum(u8) {
    network = 1,
    host = 2,
    process = 3,
    file = 4,
    registry = 5,
    identity = 6,
    historical = 7,

    pub fn fromEventSource(source: canonical.EventSource) SourceCategory {
        return switch (canonical.SourceKind.classify(source)) {
            .network => .network,
            .host => .host,
            .process => .process,
            .file => .file,
            .registry => .registry,
            .ml, .federation, .replay => .historical,
            .core, .external => .network,
        };
    }

    /// Map an Evidence.signal_type (0=unknown, 1=network, 2=host, 3=flow)
    /// onto the incident category vocabulary.
    pub fn fromSignalType(signal_type: u8) SourceCategory {
        return switch (signal_type) {
            1 => .network,
            2 => .host,
            else => .historical,
        };
    }

    pub fn toString(self: SourceCategory) []const u8 {
        return switch (self) {
            .network => "NETWORK",
            .host => "HOST",
            .process => "PROCESS",
            .file => "FILE",
            .registry => "REGISTRY",
            .identity => "IDENTITY",
            .historical => "HISTORICAL",
        };
    }
};

// ============================================================
// Incident (T4: incident_id + entity + evidence graph + confidence)
// ============================================================

/// T4: a correlated incident. Owns an in-line evidence graph (value copies)
/// rather than pointers, so it can live in a HashMap and be returned/copied
/// freely. incident_id is assigned monotonically by CorrelationEngine.
pub const Incident = struct {
    incident_id: u64,
    entity_key: EntityKey,
    verdict: detection.Verdict,
    confidence: u8,
    category_mask: u32,
    evidence: [MAX_EVIDENCE_PER_INCIDENT]detection.Evidence = undefined,
    evidence_count: u8 = 0,
    first_seen_ns: i128,
    last_seen_ns: i128,

    pub fn categoryCount(self: Incident) u8 {
        return @as(u8, @intCast(@popCount(self.category_mask)));
    }

    pub fn hasCategory(self: Incident, cat: SourceCategory) bool {
        const bit = @as(u32, 1) << @intCast(@intFromEnum(cat) - 1);
        return (self.category_mask & bit) != 0;
    }

    pub fn addCategory(self: *Incident, cat: SourceCategory) void {
        self.category_mask |= @as(u32, 1) << @intCast(@intFromEnum(cat) - 1);
    }

    pub fn isMultiCategory(self: Incident) bool {
        return self.categoryCount() >= INCIDENT_MIN_CATEGORIES;
    }

    pub fn addEvidence(self: *Incident, e: detection.Evidence) void {
        if (self.evidence_count >= MAX_EVIDENCE_PER_INCIDENT) return;
        self.evidence[self.evidence_count] = e;
        self.evidence_count += 1;
    }

    pub fn evidenceSlice(self: *const Incident) []const detection.Evidence {
        return self.evidence[0..self.evidence_count];
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
    incidents: std.AutoHashMap(u64, Incident),
    total_alerts_emitted: u64 = 0,
    total_verdicts_processed: u64 = 0,
    total_incidents: u64 = 0,
    total_evidence_seen: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) CorrelationEngine {
        return .{
            .allocator = allocator,
            .trackers = std.AutoHashMap(u64, EntityTracker).init(allocator),
            .incidents = std.AutoHashMap(u64, Incident).init(allocator),
        };
    }

    pub fn deinit(self: *CorrelationEngine) void {
        self.trackers.deinit();
        self.incidents.deinit();
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
            if (self.updateTracker(key, now_ns, event.severity, event.dest_ip, event.event_id)) |alert| {
                alerts[alert_idx] = alert;
                alert_idx += 1;
                self.total_alerts_emitted += 1;
            }
        }

        // Track dest IP
        if (event.dest_ip != 0 and alert_idx < MAX_ALERTS_PER_VERDICT) {
            const key = EntityKey.fromDestIp(event.dest_ip);
            if (self.updateTracker(key, now_ns, event.severity, 0, event.event_id)) |alert| {
                alerts[alert_idx] = alert;
                alert_idx += 1;
                self.total_alerts_emitted += 1;
            }
        }

        // Track session
        if (event.session_id != 0 and alert_idx < MAX_ALERTS_PER_VERDICT) {
            const key = EntityKey.fromSession(event.session_id);
            if (self.updateTracker(key, now_ns, event.severity, 0, event.event_id)) |alert| {
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
        var hasher = std.hash.Wyhash.init(0xCE4D);
        hasher.update(std.mem.asBytes(&key.entity_type));
        hasher.update(std.mem.asBytes(&key.ip));
        hasher.update(std.mem.asBytes(&key.session_id));
        return hasher.final();
    }

    fn updateTracker(
        self: *CorrelationEngine,
        key: EntityKey,
        now_ns: i128,
        severity: u8,
        target_ip: u32,
        event_id: u64,
    ) ?CorrelationAlert {
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
                .triggering_event_id = event_id,
                .description = "repeated threats from same entity",
            };
        }

        // Rule: multi_target_scan (3+ distinct targets)
        if (t.distinct_targets >= 3 and t.threat_count >= 3) {
            return CorrelationAlert{
                .rule = .multi_target_scan,
                .entity_key = key,
                .threat_count = @intCast(t.distinct_targets),
                .triggering_event_id = event_id,
                .description = "entity hitting multiple targets",
            };
        }

        return null;
    }

    /// T4: feed detection evidence directly into correlation. Evidence is the
    /// detection output (never a verdict/enforcement). An incident is emitted
    /// when the same entity accumulates threat evidence from >= 2 distinct
    /// source categories (network + host + process + ... = the evidence graph).
    /// The returned Incident is a value copy containing incident_id, entity,
    /// the evidence graph, and a confidence boosted by category agreement.
    pub fn processEvidence(
        self: *CorrelationEngine,
        event: canonical.CanonicalEvent,
        list: detection.EvidenceList,
    ) ?Incident {
        var emitted: ?Incident = null;
        const now_ns = std.time.nanoTimestamp();

        for (list.slice()) |e| {
            if (!e.isThreat()) continue;
            self.total_evidence_seen += 1;

            const key = if (event.source_ip != 0)
                EntityKey.fromSourceIp(event.source_ip)
            else if (event.session_id != 0)
                EntityKey.fromSession(event.session_id)
            else
                EntityKey.fromDestIp(event.dest_ip);

            const h = hashKey(key);
            const gop = self.incidents.getOrPut(h) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .{
                    .incident_id = 0, // assigned when fired
                    .entity_key = key,
                    .verdict = e.verdict,
                    .confidence = e.confidence,
                    .category_mask = 0,
                    .first_seen_ns = now_ns,
                    .last_seen_ns = now_ns,
                };
            }

            var inc = gop.value_ptr;
            inc.last_seen_ns = now_ns;
            if (@intFromEnum(e.verdict) > @intFromEnum(inc.verdict)) inc.verdict = e.verdict;
            if (e.confidence > inc.confidence) inc.confidence = e.confidence;
            inc.addCategory(SourceCategory.fromEventSource(event.source));
            inc.addEvidence(e);

            if (inc.incident_id == 0 and inc.isMultiCategory()) {
                self.total_incidents += 1;
                inc.incident_id = self.total_incidents;
                if (inc.confidence < 100) {
                    const bonus = (inc.categoryCount() -| INCIDENT_MIN_CATEGORIES + 1) * INCIDENT_CATEGORY_BONUS;
                    inc.confidence = @min(100, inc.confidence + bonus);
                }
                emitted = inc.*;
            }
        }

        return emitted;
    }

    pub fn resetStats(self: *CorrelationEngine) void {
        self.trackers.clearRetainingCapacity();
        self.incidents.clearRetainingCapacity();
        self.total_alerts_emitted = 0;
        self.total_verdicts_processed = 0;
        self.total_incidents = 0;
        self.total_evidence_seen = 0;
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

// ============================================================
// T4 tests: evidence -> incident correlation (incident_id, entity,
// evidence graph, confidence from multiple source categories)
// ============================================================

test "T4: SourceCategory.fromEventSource classifies canonical sources" {
    try std.testing.expect(SourceCategory.fromEventSource(.wfp_sensor) == .network);
    try std.testing.expect(SourceCategory.fromEventSource(.process_sensor) == .process);
    try std.testing.expect(SourceCategory.fromEventSource(.registry_sensor) == .registry);
    try std.testing.expect(SourceCategory.fromEventSource(.ml_detector) == .historical);
}

test "T4: Incident.categoryCount and hasCategory track a mask" {
    var inc = Incident{
        .incident_id = 0,
        .entity_key = EntityKey.fromSourceIp(0x0A000001),
        .verdict = .suspicious,
        .confidence = 50,
        .category_mask = 0,
        .first_seen_ns = 0,
        .last_seen_ns = 0,
    };
    inc.addCategory(.network);
    inc.addCategory(.network); // idempotent
    inc.addCategory(.process);
    try std.testing.expectEqual(@as(u8, 2), inc.categoryCount());
    try std.testing.expect(inc.hasCategory(.network));
    try std.testing.expect(!inc.hasCategory(.registry));
    try std.testing.expect(inc.isMultiCategory());
}

test "T4: single category accumulates evidence but does not emit an incident" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;

    var list = detection.EvidenceList.init();
    list.add(.{ .detector_id = 0, .verdict = .malicious, .rule_id = 0x02, .confidence = 70, .description = "cmd channel", .severity = 2 });
    list.add(.{ .detector_id = 1, .verdict = .suspicious, .rule_id = 0, .confidence = 50, .description = "scan", .severity = 1 });

    try std.testing.expect(engine.processEvidence(event, list) == null);
    try std.testing.expect(engine.total_evidence_seen == 2);
    try std.testing.expect(engine.total_incidents == 0);
}

test "T4: two source categories emit an incident with entity, evidence graph, confidence" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    // Category 1: network evidence from the WFP sensor
    var net_event = canonical.create(.wfp_sensor);
    net_event.source_ip = 0x0A000001;
    net_event.monotonic_ns = 1;
    var net_list = detection.EvidenceList.init();
    net_list.add(.{ .detector_id = 0, .verdict = .malicious, .rule_id = 0x2E, .confidence = 70, .description = "network beacon", .severity = 2, .signal_type = 1 });
    try std.testing.expect(engine.processEvidence(net_event, net_list) == null);

    // Category 2: host/process evidence from the process sensor for the same entity
    var proc_event = canonical.create(.process_sensor);
    proc_event.source_ip = 0x0A000001;
    proc_event.monotonic_ns = 2;
    var proc_list = detection.EvidenceList.init();
    proc_list.add(.{ .detector_id = 2, .verdict = .critical, .rule_id = 0, .confidence = 90, .description = "unsigned elevated", .severity = 3, .signal_type = 2 });

    const incident = engine.processEvidence(proc_event, proc_list) orelse return error.T4ExpectedIncident;
    try std.testing.expectEqual(@as(u64, 1), incident.incident_id);
    try std.testing.expect(incident.entity_key.entity_type == .source_ip);
    try std.testing.expectEqual(@as(u32, 0x0A000001), incident.entity_key.ip);
    try std.testing.expect(incident.verdict == .critical);
    try std.testing.expectEqual(@as(u8, 2), incident.categoryCount());
    try std.testing.expect(incident.hasCategory(.network));
    try std.testing.expect(incident.hasCategory(.process));
    // Evidence graph holds both evidence entries (value copies).
    try std.testing.expectEqual(@as(u8, 2), incident.evidence_count);
    const evs = incident.evidenceSlice();
    try std.testing.expect(evs[0].rule_id == 0x2E);
    try std.testing.expect(evs[1].verdict == .critical);
    // Confidence boosted for multi-category agreement: max(70,90) + bonus(10).
    try std.testing.expectEqual(@as(u8, 100), incident.confidence);
    try std.testing.expect(engine.total_incidents == 1);
}

test "T4: incidents are emitted once and ids are monotonic across entities" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;

    var list = detection.EvidenceList.init();
    list.add(.{ .detector_id = 0, .verdict = .malicious, .rule_id = 1, .confidence = 60, .description = "n", .severity = 2 });
    _ = engine.processEvidence(event, list);

    var proc_event = canonical.create(.process_sensor);
    proc_event.source_ip = 0x0A000001;
    var proc_list = detection.EvidenceList.init();
    proc_list.add(.{ .detector_id = 2, .verdict = .malicious, .rule_id = 0, .confidence = 70, .description = "h", .severity = 2 });
    const inc1 = engine.processEvidence(proc_event, proc_list) orelse return error.NoIncident1;
    try std.testing.expectEqual(@as(u64, 1), inc1.incident_id);

    // Further same-category evidence does not re-emit (already fired).
    var reg_event = canonical.create(.registry_sensor);
    reg_event.source_ip = 0x0A000001;
    var reg_list = detection.EvidenceList.init();
    reg_list.add(.{ .detector_id = 3, .verdict = .malicious, .rule_id = 0, .confidence = 80, .description = "r", .severity = 2 });
    try std.testing.expect(engine.processEvidence(reg_event, reg_list) == null);
    try std.testing.expectEqual(@as(u64, 1), engine.total_incidents);

    // A second entity gets butchered as a distinct incident id.
    var other = canonical.create(.wfp_sensor);
    other.source_ip = 0x0A000002;
    var other_net = detection.EvidenceList.init();
    other_net.add(.{ .detector_id = 0, .verdict = .suspicious, .rule_id = 2, .confidence = 50, .description = "n2", .severity = 1 });
    _ = engine.processEvidence(other, other_net);

    var other_proc = canonical.create(.host_telemetry);
    other_proc.source_ip = 0x0A000002;
    var other_host = detection.EvidenceList.init();
    other_host.add(.{ .detector_id = 2, .verdict = .suspicious, .rule_id = 0, .confidence = 55, .description = "h2", .severity = 1 });
    const inc2 = engine.processEvidence(other_proc, other_host) orelse return error.NoIncident2;
    try std.testing.expectEqual(@as(u64, 2), inc2.incident_id);
    try std.testing.expectEqual(@as(u32, 0x0A000002), inc2.entity_key.ip);
}

test "T4: resetStats clears incident state" {
    var engine = CorrelationEngine.init(std.testing.allocator);
    defer engine.deinit();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    var list = detection.EvidenceList.init();
    list.add(.{ .detector_id = 0, .verdict = .malicious, .rule_id = 1, .confidence = 60, .description = "n", .severity = 2 });
    _ = engine.processEvidence(event, list);
    var proc_event = canonical.create(.process_sensor);
    proc_event.source_ip = 0x0A000001;
    var proc_list = detection.EvidenceList.init();
    proc_list.add(.{ .detector_id = 2, .verdict = .malicious, .rule_id = 0, .confidence = 70, .description = "h", .severity = 2 });
    try std.testing.expect(engine.processEvidence(proc_event, proc_list) != null);

    try std.testing.expect(engine.incidents.count() > 0);
    engine.resetStats();
    try std.testing.expect(engine.incidents.count() == 0);
    try std.testing.expect(engine.total_incidents == 0);
    try std.testing.expect(engine.total_evidence_seen == 0);
}