//! xdr_correlator.zig - AEGIS XDR Cross-Tier Correlation Engine (Phase 34, AEGIS-013)
//!
//! Links network events (WFP) with host events (HIDS) via session_id
//! and FlowKey for cross-tier attack timeline reconstruction.
//!
//! Blueprint: "correlation กับ event ไหน?" — this module answers that.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");

// ============================================================
// Correlation Rule (AEGIS-013)
// ============================================================

pub const CorrelationRule = struct {
    name: []const u8,
    description: []const u8,
    // Condition: if these event types co-occur within time_window_ms,
    // escalate severity to escalation_level
    required_events: []const canonical.EventType,
    time_window_ms: i64,
    escalation_level: u8, // 0-3 severity to set
    min_events: u8,       // minimum number of matching events to trigger
};

// ============================================================
// Correlated Incident (AEGIS-013)
// ============================================================

pub const Incident = struct {
    incident_id: u64,
    first_seen_ms: i64,
    last_seen_ms: i64,
    event_count: u32,
    severity: u8,
    rule_name: []const u8,
    session_ids: [16]u64,
    session_count: usize,
    source_ips: [8]u32,
    ip_count: usize,
    event_types: u32, // bitmask of EventType values seen

    pub fn addSessionId(self: *Incident, sid: u64) void {
        if (self.session_count < 16) {
            // Check for duplicate
            for (0..self.session_count) |i| {
                if (self.session_ids[i] == sid) return;
            }
            self.session_ids[self.session_count] = sid;
            self.session_count += 1;
        }
    }

    pub fn addSourceIp(self: *Incident, ip: u32) void {
        if (self.ip_count < 8) {
            for (0..self.ip_count) |i| {
                if (self.source_ips[i] == ip) return;
            }
            self.source_ips[self.ip_count] = ip;
            self.ip_count += 1;
        }
    }

    pub fn addEventType(self: *Incident, event_type: canonical.EventType) void {
        const bit = @as(u32, 1) << @intCast(@intFromEnum(event_type) & 31);
        self.event_types |= bit;
    }

    pub fn hasEventType(self: Incident, event_type: canonical.EventType) bool {
        const bit = @as(u32, 1) << @intCast(@intFromEnum(event_type) & 31);
        return (self.event_types & bit) != 0;
    }
};

// ============================================================
// XDR Correlator (AEGIS-013)
// ============================================================

const MAX_INCIDENTS: usize = 256;
const MAX_EVENTS_PER_INCIDENT: usize = 64;

pub const XDRCorrelator = struct {
    incidents: [MAX_INCIDENTS]?Incident,
    incident_count: usize,
    total_correlations: std.atomic.Value(u64),
    total_escalations: std.atomic.Value(u64),
    mutex: std.Thread.Mutex,
    next_incident_id: std.atomic.Value(u64),

    pub fn init() XDRCorrelator {
        return .{
            .incidents = [_]?Incident{null} ** MAX_INCIDENTS,
            .incident_count = 0,
            .total_correlations = std.atomic.Value(u64).init(0),
            .total_escalations = std.atomic.Value(u64).init(0),
            .mutex = .{},
            .next_incident_id = std.atomic.Value(u64).init(1),
        };
    }

    /// Submit an event for correlation.
    /// Links events by session_id — events with same session_id belong to same incident.
    pub fn submitEvent(self: *XDRCorrelator, event: canonical.CanonicalEvent) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.milliTimestamp();

        // Try to find existing incident with same session_id
        if (event.session_id != 0) {
            for (0..MAX_INCIDENTS) |i| {
                if (self.incidents[i]) |*inc| {
                    for (0..inc.session_count) |j| {
                        if (inc.session_ids[j] == event.session_id) {
                            // Found existing incident — update it
                            inc.last_seen_ms = now;
                            inc.event_count += 1;
                            inc.addSourceIp(event.source_ip);
                            inc.addEventType(event.event_type);
                            _ = self.total_correlations.fetchAdd(1, .monotonic);

                            // Check if event is high severity → escalate
                            if (event.severity >= 2 and inc.severity < event.severity) {
                                inc.severity = event.severity;
                                _ = self.total_escalations.fetchAdd(1, .monotonic);
                            }
                            return i;
                        }
                    }
                }
            }
        }

        // No existing incident — create new one
        for (0..MAX_INCIDENTS) |i| {
            if (self.incidents[i] == null) {
                self.incidents[i] = .{
                    .incident_id = self.next_incident_id.fetchAdd(1, .monotonic),
                    .first_seen_ms = now,
                    .last_seen_ms = now,
                    .event_count = 1,
                    .severity = event.severity,
                    .rule_name = "auto-correlated",
                    .session_ids = [_]u64{0} ** 16,
                    .session_count = 0,
                    .source_ips = [_]u32{0} ** 8,
                    .ip_count = 0,
                    .event_types = 0,
                };
                var inc = &self.incidents[i].?;
                inc.addSessionId(event.session_id);
                inc.addSourceIp(event.source_ip);
                inc.addEventType(event.event_type);
                self.incident_count += 1;
                return i;
            }
        }

        return null; // Table full
    }

    /// Get an incident by index.
    pub fn getIncident(self: *XDRCorrelator, index: usize) ?*Incident {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= MAX_INCIDENTS) return null;
        if (self.incidents[index] == null) return null;
        return &self.incidents[index].?;
    }

    /// Get total active incidents.
    pub fn activeIncidents(self: *XDRCorrelator) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.incident_count;
    }

    /// Get statistics.
    pub fn getStats(self: *XDRCorrelator) XDRStats {
        return .{
            .active_incidents = self.activeIncidents(),
            .total_correlations = self.total_correlations.load(.monotonic),
            .total_escalations = self.total_escalations.load(.monotonic),
        };
    }

    /// Purge old incidents (older than max_age_ms).
    pub fn purgeOlder(self: *XDRCorrelator, max_age_ms: i64) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const now = std.time.milliTimestamp();
        var purged: usize = 0;
        for (0..MAX_INCIDENTS) |i| {
            if (self.incidents[i]) |inc| {
                if (now - inc.last_seen_ms > max_age_ms) {
                    self.incidents[i] = null;
                    self.incident_count -= 1;
                    purged += 1;
                }
            }
        }
        return purged;
    }
};

pub const XDRStats = struct {
    active_incidents: usize,
    total_correlations: u64,
    total_escalations: u64,
};

// ============================================================
// Tests
// ============================================================

test "Incident addSessionId deduplicates" {
    var inc = Incident{
        .incident_id = 1,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
        .event_count = 0,
        .severity = 0,
        .rule_name = "test",
        .session_ids = [_]u64{0} ** 16,
        .session_count = 0,
        .source_ips = [_]u32{0} ** 8,
        .ip_count = 0,
        .event_types = 0,
    };
    inc.addSessionId(42);
    inc.addSessionId(42); // duplicate
    inc.addSessionId(100);
    try std.testing.expect(inc.session_count == 2);
}

test "Incident addSourceIp deduplicates" {
    var inc = Incident{
        .incident_id = 1, .first_seen_ms = 0, .last_seen_ms = 0, .event_count = 0,
        .severity = 0, .rule_name = "t", .session_ids = [_]u64{0} ** 16, .session_count = 0,
        .source_ips = [_]u32{0} ** 8, .ip_count = 0, .event_types = 0,
    };
    inc.addSourceIp(0x0A000001);
    inc.addSourceIp(0x0A000001);
    inc.addSourceIp(0x0A000002);
    try std.testing.expect(inc.ip_count == 2);
}

test "Incident hasEventType" {
    var inc = Incident{
        .incident_id = 1, .first_seen_ms = 0, .last_seen_ms = 0, .event_count = 0,
        .severity = 0, .rule_name = "t", .session_ids = [_]u64{0} ** 16, .session_count = 0,
        .source_ips = [_]u32{0} ** 8, .ip_count = 0, .event_types = 0,
    };
    inc.addEventType(.block);
    try std.testing.expect(inc.hasEventType(.block));
    try std.testing.expect(!inc.hasEventType(.forward));
}

test "XDRCorrelator init" {
    const corr = XDRCorrelator.init();
    try std.testing.expect(corr.incident_count == 0);
}

test "XDRCorrelator creates new incident for new session" {
    var corr = XDRCorrelator.init();
    var event = canonical.create(.wfp_sensor);
    event.session_id = 42;
    event.source_ip = 0xC0A80164;
    event.event_type = .block;
    event.severity = 3;

    const idx = corr.submitEvent(event);
    try std.testing.expect(idx != null);
    try std.testing.expect(corr.activeIncidents() == 1);

    const inc = corr.getIncident(idx.?);
    try std.testing.expect(inc != null);
    try std.testing.expect(inc.?.event_count == 1);
    try std.testing.expect(inc.?.severity == 3);
}

test "XDRCorrelator links events by session_id" {
    var corr = XDRCorrelator.init();

    // First event (network)
    var e1 = canonical.create(.wfp_sensor);
    e1.session_id = 100;
    e1.source_ip = 0x0A000001;
    e1.event_type = .forward;
    e1.severity = 0;
    const idx1 = corr.submitEvent(e1);
    try std.testing.expect(idx1 != null);

    // Second event (host, same session)
    var e2 = canonical.create(.minifilter);
    e2.session_id = 100;
    e2.source_ip = 0x0A000002;
    e2.event_type = .block;
    e2.severity = 3;
    const idx2 = corr.submitEvent(e2);
    try std.testing.expect(idx2 != null);

    // Should be same incident
    try std.testing.expect(idx1.? == idx2.?);
    try std.testing.expect(corr.activeIncidents() == 1);

    const inc = corr.getIncident(idx1.?);
    try std.testing.expect(inc.?.event_count == 2);
    try std.testing.expect(inc.?.ip_count == 2);
    try std.testing.expect(inc.?.severity == 3); // escalated
}

test "XDRCorrelator creates separate incidents for different sessions" {
    var corr = XDRCorrelator.init();

    var e1 = canonical.create(.wfp_sensor);
    e1.session_id = 1;
    const idx1 = corr.submitEvent(e1);

    var e2 = canonical.create(.wfp_sensor);
    e2.session_id = 2;
    const idx2 = corr.submitEvent(e2);

    try std.testing.expect(idx1 != null);
    try std.testing.expect(idx2 != null);
    try std.testing.expect(idx1.? != idx2.?);
    try std.testing.expect(corr.activeIncidents() == 2);
}

test "XDRCorrelator escalation tracking" {
    var corr = XDRCorrelator.init();

    var e1 = canonical.create(.wfp_sensor);
    e1.session_id = 1;
    e1.severity = 1;
    _ = corr.submitEvent(e1);

    var e2 = canonical.create(.minifilter);
    e2.session_id = 1;
    e2.severity = 3;
    _ = corr.submitEvent(e2);

    const stats = corr.getStats();
    try std.testing.expect(stats.total_correlations == 1);
    try std.testing.expect(stats.total_escalations == 1);
}

test "XDRCorrelator getStats" {
    var corr = XDRCorrelator.init();
    var e = canonical.create(.wfp_sensor);
    e.session_id = 1;
    _ = corr.submitEvent(e);

    const stats = corr.getStats();
    try std.testing.expect(stats.active_incidents == 1);
}
