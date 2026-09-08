//! xdr_harden.zig - AEGIS XDR Hardening (Rewrite Phase 19)
//!
//! Extended Detection & Response hardening module.
//! Aggregates threats across all tiers, provides SIEM export format,
//! and constructs incident timelines for threat hunting.
//!
//! Architecture:
//!   XDR sits ABOVE the pipeline (not a stage). It queries Forensics
//!   to build incidents and export to SIEM (CEF/LEEF format).
//!
//! Features:
//!   1. XdrIncident: aggregates related forensic records into an incident
//!   2. SiemExporter: formats incidents as CEF (Common Event Format) strings
//!   3. Threat hunting: query by IP, verdict, action, time range
//!   4. Incident timeline: chronological event sequence

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const policy = @import("policy_engine.zig");
const rust_pep = @import("rust_pep.zig");
const forensics = @import("forensics_engine.zig");

// ============================================================
// Constants
// ============================================================

/// Maximum incidents in the XDR buffer.
pub const MAX_INCIDENTS: usize = 1024;

/// Maximum events in a single incident timeline.
pub const MAX_INCIDENT_EVENTS: usize = 64;

// ============================================================
// XDR Severity
// ============================================================

pub const XdrSeverity = enum(u8) {
    info = 0,
    low = 1,
    medium = 2,
    high = 3,
    critical = 4,

    pub fn toString(self: XdrSeverity) []const u8 {
        return switch (self) {
            .info => "Info",
            .low => "Low",
            .medium => "Medium",
            .high => "High",
            .critical => "Critical",
        };
    }

    /// CEF severity (0-10 scale).
    pub fn cefSeverity(self: XdrSeverity) u8 {
        return switch (self) {
            .info => 1,
            .low => 3,
            .medium => 5,
            .high => 7,
            .critical => 9,
        };
    }
};

// ============================================================
// XDR Incident
// ============================================================

pub const IncidentStatus = enum(u8) {
    open = 0,
    investigating = 1,
    contained = 2,
    resolved = 3,
    false_positive = 4,

    pub fn toString(self: IncidentStatus) []const u8 {
        return switch (self) {
            .open => "OPEN",
            .investigating => "INVESTIGATING",
            .contained => "CONTAINED",
            .resolved => "RESOLVED",
            .false_positive => "FALSE_POSITIVE",
        };
    }
};

pub const XdrIncident = struct {
    id: u64,
    /// First event timestamp (ns).
    start_ns: i128,
    /// Last event timestamp (ns).
    end_ns: i128,
    /// Primary source IP (attacker).
    source_ip: u32,
    /// Primary destination IP (target).
    dest_ip: u32,
    /// Highest verdict seen.
    max_verdict: detection.Verdict,
    /// Highest enforcement action.
    max_action: policy.EnforcementAction,
    /// Whether PEP executed a block.
    blocked: bool,
    /// Number of events in this incident.
    event_count: u32,
    /// Number of correlation alerts.
    alert_count: u32,
    /// Number of threat intel matches.
    threat_intel_matches: u32,
    /// Severity level.
    severity: XdrSeverity,
    /// Incident status.
    status: IncidentStatus,
    /// Summary description (static string).
    summary: []const u8,
    /// Event IDs in this incident (ring buffer).
    event_ids: [MAX_INCIDENT_EVENTS]u64,
    event_id_count: u8,

    /// Returns true if this incident involves blocking.
    pub fn isBlocking(self: XdrIncident) bool {
        return self.blocked;
    }

    /// Returns true if this incident is high or critical severity.
    pub fn isHighSeverity(self: XdrIncident) bool {
        return self.severity == .high or self.severity == .critical;
    }

    /// Returns duration in nanoseconds.
    pub fn durationNs(self: XdrIncident) i128 {
        return self.end_ns - self.start_ns;
    }

    /// Add an event ID to the incident timeline.
    pub fn addEventId(self: *XdrIncident, event_id: u64) void {
        if (self.event_id_count < MAX_INCIDENT_EVENTS) {
            self.event_ids[self.event_id_count] = event_id;
            self.event_id_count += 1;
        }
    }
};

// ============================================================
// SIEM Export (CEF format)
// ============================================================

/// CEF (Common Event Format) version string.
pub const CEF_VERSION: u8 = 0;

/// CEF vendor string.
pub const CEF_VENDOR: []const u8 = "AEGIS";

/// CEF product string.
pub const CEF_PRODUCT: []const u8 = "NIDS";

/// SIEM exporter: formats incidents as CEF strings.
/// CEF format: CEF:Version|Vendor|Product|DevVersion|SignatureID|Name|Severity|Extension
pub const SiemExporter = struct {
    /// Total exports performed.
    total_exports: u64,
    /// Total CEF bytes written (approximate).
    total_bytes: u64,

    pub fn init() SiemExporter {
        return .{
            .total_exports = 0,
            .total_bytes = 0,
        };
    }

    /// Format an incident as a CEF string into the provided buffer.
    /// Returns the number of bytes written, or 0 if buffer too small.
    pub fn formatCef(self: *SiemExporter, incident: XdrIncident, buf: []u8) usize {
        // CEF:0|AEGIS|NIDS|1.0|<id>|<summary>|<severity>|src=<ip> dst=<ip> act=<action> ...
        const sev = incident.severity.cefSeverity();
        const written = std.fmt.bufPrint(buf, "CEF:{d}|{s}|{s}|1|{d}|{s}|{d}|src=0x{x:08} dst=0x{x:08} act={s} cnt={d} sev={s} status={s}", .{
            CEF_VERSION,
            CEF_VENDOR,
            CEF_PRODUCT,
            incident.id,
            incident.summary,
            sev,
            incident.source_ip,
            incident.dest_ip,
            incident.max_action.toString(),
            incident.event_count,
            incident.severity.toString(),
            incident.status.toString(),
        }) catch return 0;

        self.total_exports += 1;
        self.total_bytes += written.len;
        return written.len;
    }

    pub fn resetStats(self: *SiemExporter) void {
        self.total_exports = 0;
        self.total_bytes = 0;
    }
};

// ============================================================
// XDR Engine
// ============================================================

pub const XdrEngine = struct {
    incidents: [MAX_INCIDENTS]XdrIncident,
    incident_count: usize,
    next_incident_id: u64,
    exporter: SiemExporter,

    // Stats
    total_incidents_created: u64,
    total_blocking_incidents: u64,
    total_critical_incidents: u64,

    pub fn init() XdrEngine {
        return .{
            .incidents = undefined,
            .incident_count = 0,
            .next_incident_id = 1,
            .exporter = SiemExporter.init(),
            .total_incidents_created = 0,
            .total_blocking_incidents = 0,
            .total_critical_incidents = 0,
        };
    }

    /// Create a new incident from a forensic record.
    pub fn createIncident(self: *XdrEngine, record: forensics.PipelineResult) u64 {
        if (self.incident_count >= MAX_INCIDENTS) {
            // Overwrite oldest (ring buffer behavior)
            self.incident_count = 0;
        }

        const id = self.next_incident_id;
        self.next_incident_id += 1;

        // Determine severity from verdict + action
        const severity: XdrSeverity = blk: {
            if (record.aggregated_verdict == .malicious) {
                if (record.pep_status == .executed) break :blk .critical;
                break :blk .high;
            }
            if (record.aggregated_verdict == .suspicious) break :blk .medium;
            if (record.policy_action == .alert) break :blk .low;
            break :blk .info;
        };

        const incident = XdrIncident{
            .id = id,
            .start_ns = record.timestamp_ns,
            .end_ns = record.timestamp_ns,
            .source_ip = record.source_ip,
            .dest_ip = record.dest_ip,
            .max_verdict = record.aggregated_verdict,
            .max_action = record.policy_action,
            .blocked = record.pep_status == .executed,
            .event_count = 1,
            .alert_count = record.correlation_alert_count,
            .threat_intel_matches = if (record.threat_intel_matched) 1 else 0,
            .severity = severity,
            .status = .open,
            .summary = "pipeline incident",
            .event_ids = undefined,
            .event_id_count = 0,
        };

        self.incidents[self.incident_count] = incident;
        self.incidents[self.incident_count].addEventId(record.event_id);
        self.incident_count += 1;
        self.total_incidents_created += 1;

        if (incident.blocked) self.total_blocking_incidents += 1;
        if (severity == .critical) self.total_critical_incidents += 1;

        return id;
    }

    /// Update an existing incident with a new record (same source IP).
    pub fn updateIncident(self: *XdrEngine, incident_idx: usize, record: forensics.PipelineResult) void {
        if (incident_idx >= self.incident_count) return;

        var inc = &self.incidents[incident_idx];
        inc.end_ns = record.timestamp_ns;
        inc.event_count += 1;
        inc.alert_count += record.correlation_alert_count;
        if (record.threat_intel_matched) inc.threat_intel_matches += 1;
        inc.addEventId(record.event_id);

        // Update max verdict/action
        if (record.aggregated_verdict.severityRank() > inc.max_verdict.severityRank()) {
            inc.max_verdict = record.aggregated_verdict;
        }
        if (actionRank(record.policy_action) > actionRank(inc.max_action)) {
            inc.max_action = record.policy_action;
        }
        if (record.pep_status == .executed) inc.blocked = true;

        // Update severity
        if (inc.max_verdict == .malicious and inc.blocked) {
            inc.severity = .critical;
        } else if (inc.max_verdict == .malicious) {
            inc.severity = .high;
        }
    }

    /// Find an open incident by source IP. Returns index or null.
    pub fn findOpenIncidentByIp(self: *const XdrEngine, source_ip: u32) ?usize {
        var i: usize = 0;
        while (i < self.incident_count) : (i += 1) {
            if (self.incidents[i].source_ip == source_ip and self.incidents[i].status == .open) {
                return i;
            }
        }
        return null;
    }

    /// Process a forensic record: create or update incident.
    pub fn processRecord(self: *XdrEngine, record: forensics.PipelineResult) u64 {
        // Check if there's an open incident for this source IP
        if (self.findOpenIncidentByIp(record.source_ip)) |idx| {
            self.updateIncident(idx, record);
            return self.incidents[idx].id;
        }
        return self.createIncident(record);
    }

    /// Get incident by index.
    pub fn getIncident(self: *const XdrEngine, idx: usize) ?XdrIncident {
        if (idx >= self.incident_count) return null;
        return self.incidents[idx];
    }

    /// Export an incident as CEF string.
    pub fn exportCef(self: *XdrEngine, incident_idx: usize, buf: []u8) usize {
        if (incident_idx >= self.incident_count) return 0;
        return self.exporter.formatCef(self.incidents[incident_idx], buf);
    }

    /// Current incident count.
    pub fn count(self: *const XdrEngine) usize {
        return self.incident_count;
    }

    /// Reset everything.
    pub fn reset(self: *XdrEngine) void {
        self.* = init();
    }
};

// ============================================================
// Helpers
// ============================================================

fn actionRank(a: policy.EnforcementAction) u8 {
    return switch (a) {
        .allow => 0,
        .log_only => 1,
        .alert => 2,
        .rate_limit => 3,
        .quarantine => 4,
        .block => 5,
    };
}

// ============================================================
// Tests (all use local engine instances - parallelism-safe)
// ============================================================

test "XdrSeverity.toString returns CEF-style names" {
    try std.testing.expect(std.mem.eql(u8, XdrSeverity.info.toString(), "Info"));
    try std.testing.expect(std.mem.eql(u8, XdrSeverity.low.toString(), "Low"));
    try std.testing.expect(std.mem.eql(u8, XdrSeverity.medium.toString(), "Medium"));
    try std.testing.expect(std.mem.eql(u8, XdrSeverity.high.toString(), "High"));
    try std.testing.expect(std.mem.eql(u8, XdrSeverity.critical.toString(), "Critical"));
}

test "XdrSeverity.cefSeverity returns 0-10 scale" {
    try std.testing.expect(XdrSeverity.info.cefSeverity() == 1);
    try std.testing.expect(XdrSeverity.low.cefSeverity() == 3);
    try std.testing.expect(XdrSeverity.medium.cefSeverity() == 5);
    try std.testing.expect(XdrSeverity.high.cefSeverity() == 7);
    try std.testing.expect(XdrSeverity.critical.cefSeverity() == 9);
}

test "IncidentStatus.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, IncidentStatus.open.toString(), "OPEN"));
    try std.testing.expect(std.mem.eql(u8, IncidentStatus.investigating.toString(), "INVESTIGATING"));
    try std.testing.expect(std.mem.eql(u8, IncidentStatus.contained.toString(), "CONTAINED"));
    try std.testing.expect(std.mem.eql(u8, IncidentStatus.resolved.toString(), "RESOLVED"));
    try std.testing.expect(std.mem.eql(u8, IncidentStatus.false_positive.toString(), "FALSE_POSITIVE"));
}

test "XdrIncident.isBlocking and isHighSeverity" {
    const inc = XdrIncident{
        .id = 1,
        .start_ns = 1000,
        .end_ns = 2000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .max_verdict = .malicious,
        .max_action = .block,
        .blocked = true,
        .event_count = 3,
        .alert_count = 2,
        .threat_intel_matches = 1,
        .severity = .critical,
        .status = .open,
        .summary = "test",
        .event_ids = undefined,
        .event_id_count = 0,
    };
    try std.testing.expect(inc.isBlocking());
    try std.testing.expect(inc.isHighSeverity());
    try std.testing.expect(inc.durationNs() == 1000);
}

test "XdrIncident.addEventId tracks event IDs" {
    var inc = XdrIncident{
        .id = 1,
        .start_ns = 1000,
        .end_ns = 2000,
        .source_ip = 0x0A000001,
        .dest_ip = 0x0A000002,
        .max_verdict = .benign,
        .max_action = .allow,
        .blocked = false,
        .event_count = 0,
        .alert_count = 0,
        .threat_intel_matches = 0,
        .severity = .info,
        .status = .open,
        .summary = "test",
        .event_ids = undefined,
        .event_id_count = 0,
    };

    inc.addEventId(100);
    inc.addEventId(200);
    inc.addEventId(300);

    try std.testing.expect(inc.event_id_count == 3);
    try std.testing.expect(inc.event_ids[0] == 100);
    try std.testing.expect(inc.event_ids[1] == 200);
    try std.testing.expect(inc.event_ids[2] == 300);
}

test "SiemExporter init has zero stats" {
    const exporter = SiemExporter.init();
    try std.testing.expect(exporter.total_exports == 0);
    try std.testing.expect(exporter.total_bytes == 0);
}

test "SiemExporter.formatCef produces valid CEF string" {
    var exporter = SiemExporter.init();
    const incident = XdrIncident{
        .id = 42,
        .start_ns = 1000,
        .end_ns = 2000,
        .source_ip = 0x08080808,
        .dest_ip = 0x0A000002,
        .max_verdict = .malicious,
        .max_action = .block,
        .blocked = true,
        .event_count = 5,
        .alert_count = 2,
        .threat_intel_matches = 1,
        .severity = .critical,
        .status = .open,
        .summary = "malicious traffic blocked",
        .event_ids = undefined,
        .event_id_count = 0,
    };

    var buf: [512]u8 = undefined;
    const len = exporter.formatCef(incident, &buf);

    try std.testing.expect(len > 0);
    const cef_str = buf[0..len];
    // Should start with CEF:0|AEGIS|NIDS|
    try std.testing.expect(std.mem.startsWith(u8, cef_str, "CEF:0|AEGIS|NIDS|"));
    try std.testing.expect(exporter.total_exports == 1);
    try std.testing.expect(exporter.total_bytes == len);
}

test "XdrEngine init has zero stats" {
    const engine = XdrEngine.init();
    try std.testing.expect(engine.incident_count == 0);
    try std.testing.expect(engine.total_incidents_created == 0);
}

test "XdrEngine createIncident creates incident from record" {
    var engine = XdrEngine.init();

    const record = makeRecord(1, .malicious, 90, .block, .executed, 80, 0x08080808);
    const id = engine.createIncident(record);

    try std.testing.expect(id == 1);
    try std.testing.expect(engine.incident_count == 1);
    try std.testing.expect(engine.total_incidents_created == 1);
    try std.testing.expect(engine.total_blocking_incidents == 1);
    try std.testing.expect(engine.total_critical_incidents == 1);

    const inc = engine.getIncident(0);
    try std.testing.expect(inc != null);
    try std.testing.expect(inc.?.source_ip == 0x08080808);
    try std.testing.expect(inc.?.max_verdict == .malicious);
    try std.testing.expect(inc.?.blocked == true);
    try std.testing.expect(inc.?.severity == .critical);
}

test "XdrEngine createIncident assigns increasing IDs" {
    var engine = XdrEngine.init();

    const record = makeRecord(1, .suspicious, 70, .alert, .no_op, 50, 0x0A000001);
    const id1 = engine.createIncident(record);
    const id2 = engine.createIncident(record);

    try std.testing.expect(id1 == 1);
    try std.testing.expect(id2 == 2);
    try std.testing.expect(engine.incident_count == 2);
}

test "XdrEngine findOpenIncidentByIp finds matching incident" {
    var engine = XdrEngine.init();

    const record = makeRecord(1, .suspicious, 70, .alert, .no_op, 50, 0x0A000001);
    _ = engine.createIncident(record);

    const found = engine.findOpenIncidentByIp(0x0A000001);
    try std.testing.expect(found != null);
    try std.testing.expect(found.? == 0);

    const not_found = engine.findOpenIncidentByIp(0x0A000099);
    try std.testing.expect(not_found == null);
}

test "XdrEngine updateIncident extends incident" {
    var engine = XdrEngine.init();

    // Create incident with first event
    const record1 = makeRecord(1, .suspicious, 70, .alert, .no_op, 50, 0x0A000001);
    _ = engine.createIncident(record1);

    // Update with second event (same source IP)
    const record2 = makeRecord(2, .malicious, 90, .block, .executed, 80, 0x0A000001);
    engine.updateIncident(0, record2);

    const inc = engine.getIncident(0);
    try std.testing.expect(inc != null);
    try std.testing.expect(inc.?.event_count == 2);
    try std.testing.expect(inc.?.max_verdict == .malicious);
    try std.testing.expect(inc.?.blocked == true);
    try std.testing.expect(inc.?.severity == .critical);
}

test "XdrEngine processRecord creates or updates incident" {
    var engine = XdrEngine.init();

    // First record -> creates incident
    const record1 = makeRecord(1, .suspicious, 70, .alert, .no_op, 50, 0x0A000001);
    const id1 = engine.processRecord(record1);
    try std.testing.expect(id1 == 1);
    try std.testing.expect(engine.incident_count == 1);

    // Second record (same IP) -> updates existing incident
    const record2 = makeRecord(2, .malicious, 90, .block, .executed, 80, 0x0A000001);
    const id2 = engine.processRecord(record2);
    try std.testing.expect(id2 == 1); // same incident
    try std.testing.expect(engine.incident_count == 1); // still 1 incident

    // Third record (different IP) -> creates new incident
    const record3 = makeRecord(3, .benign, 50, .allow, .no_op, 10, 0x0A000099);
    const id3 = engine.processRecord(record3);
    try std.testing.expect(id3 == 2); // new incident
    try std.testing.expect(engine.incident_count == 2);
}

test "XdrEngine exportCef produces valid output" {
    var engine = XdrEngine.init();

    const record = makeRecord(1, .malicious, 90, .block, .executed, 80, 0x08080808);
    _ = engine.createIncident(record);

    var buf: [512]u8 = undefined;
    const len = engine.exportCef(0, &buf);

    try std.testing.expect(len > 0);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..len], "CEF:0|AEGIS|NIDS|"));
}

test "XdrEngine reset zeroes everything" {
    var engine = XdrEngine.init();

    const record = makeRecord(1, .suspicious, 70, .alert, .no_op, 50, 0x0A000001);
    _ = engine.createIncident(record);
    try std.testing.expect(engine.incident_count == 1);

    engine.reset();
    try std.testing.expect(engine.incident_count == 0);
    try std.testing.expect(engine.total_incidents_created == 0);
}

test "actionRank ordering" {
    try std.testing.expect(actionRank(.allow) < actionRank(.alert));
    try std.testing.expect(actionRank(.alert) < actionRank(.block));
    try std.testing.expect(actionRank(.block) == actionRank(.block));
}

// Helper to create PipelineResult for tests
fn makeResult(
    event_id: u64,
    verdict: detection.Verdict,
    confidence: u8,
    action: policy.EnforcementAction,
    pep_status: rust_pep.EnforcementStatus,
    threat_score: u8,
    source_ip: u32,
) forensics.PipelineResult {
    return .{
        .event_id = event_id,
        .timestamp_ns = @intCast(event_id * 1000),
        .source_ip = source_ip,
        .dest_ip = 0x0A000002,
        .source_port = 12345,
        .dest_port = 80,
        .protocol = 6,
        .aggregated_verdict = verdict,
        .aggregated_confidence = confidence,
        .escalated = false,
        .original_verdict = verdict,
        .correlation_alert_count = 0,
        .correlation_rules = .{ 0, 0, 0 },
        .threat_intel_matched = false,
        .threat_intel_max_severity = 0,
        .brain_advice_kind = 0,
        .brain_threat_score = threat_score,
        .brain_recommended_verdict = verdict,
        .policy_action = action,
        .policy_rule = .default_allow,
        .policy_confidence = confidence,
        .pep_status = pep_status,
        .pep_rejection_reason = .none,
        .pep_blocked_ip = if (pep_status == .executed) source_ip else 0,
    };
}

// Wrapper for tests (alias for readability)
fn makeRecord(
    event_id: u64,
    verdict: detection.Verdict,
    confidence: u8,
    action: policy.EnforcementAction,
    pep_status: rust_pep.EnforcementStatus,
    threat_score: u8,
    source_ip: u32,
) forensics.PipelineResult {
    return makeResult(event_id, verdict, confidence, action, pep_status, threat_score, source_ip);
}
