//! detection_engine.zig - AEGIS Detection Engine (Rewrite Phase 7)
//!
//! Multi-detector pipeline that examines each CanonicalEvent and produces
//! Evidence. Each detector is a vtable struct so detectors can be added
//! without modifying the engine core.
//!
//! Design:
//!   - Verdict: closed-set enum (unknown/benign/suspicious/malicious/critical)
//!   - Evidence: single detector result (detector_id, verdict, rule_id, confidence, description)
//!   - EvidenceList: bounded array of Evidence (max 16 per event)
//!   - DetectionEngine: owns detectors + lifetime stats

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");

// ============================================================
// Constants
// ============================================================

pub const MAX_EVIDENCE_PER_EVENT: usize = 16;
pub const MAX_DETECTORS: usize = 8;

// ============================================================
// Verdict
// ============================================================

pub const Verdict = enum(u8) {
    unknown = 0,
    benign = 1,
    suspicious = 2,
    malicious = 3,
    critical = 4,

    pub fn toString(self: Verdict) []const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .benign => "BENIGN",
            .suspicious => "SUSPICIOUS",
            .malicious => "MALICIOUS",
            .critical => "CRITICAL",
        };
    }

    /// Returns true if this verdict represents a threat
    /// (suspicious or higher).
    pub fn isThreat(self: Verdict) bool {
        return self == .suspicious or self == .malicious or self == .critical;
    }

    /// Returns true if this verdict is at or above the given threshold.
    pub fn isAtLeast(self: Verdict, threshold: Verdict) bool {
        return @intFromEnum(self) >= @intFromEnum(threshold);
    }

    /// Returns the more severe of two verdicts.
    pub fn max(a: Verdict, b: Verdict) Verdict {
        if (@intFromEnum(a) >= @intFromEnum(b)) return a;
        return b;
    }

    /// Numeric rank used by XDR engine for incident severity comparison.
    /// Higher = more severe.
    pub fn severityRank(self: Verdict) u8 {
        return @intFromEnum(self);
    }

    /// Returns the less severe of two verdicts.
    pub fn min(a: Verdict, b: Verdict) Verdict {
        if (@intFromEnum(a) <= @intFromEnum(b)) return a;
        return b;
    }
};

// ============================================================
// Evidence
// ============================================================

pub const Evidence = struct {
    detector_id: u8,
    verdict: Verdict,
    rule_id: u32,
    confidence: u8,
    description: []const u8,

    pub fn isThreat(self: Evidence) bool {
        return self.verdict.isThreat();
    }

    pub fn isHighConfidence(self: Evidence) bool {
        return self.confidence >= 70;
    }
};

// ============================================================
// Evidence List (bounded array)
// ============================================================

pub const EvidenceList = struct {
    items: [MAX_EVIDENCE_PER_EVENT]Evidence = undefined,
    count: usize = 0,

    pub fn init() EvidenceList {
        return .{};
    }

    pub fn add(self: *EvidenceList, e: Evidence) void {
        if (self.count >= MAX_EVIDENCE_PER_EVENT) return;
        self.items[self.count] = e;
        self.count += 1;
    }

    pub fn slice(self: *const EvidenceList) []const Evidence {
        return self.items[0..self.count];
    }

    pub fn maxVerdict(self: *const EvidenceList) Verdict {
        var v: Verdict = .unknown;
        for (self.slice()) |e| {
            v = Verdict.max(v, e.verdict);
        }
        return v;
    }

    pub fn maxConfidence(self: *const EvidenceList) u8 {
        var c: u8 = 0;
        for (self.slice()) |e| {
            if (e.confidence > c) c = e.confidence;
        }
        return c;
    }

    pub fn hasThreat(self: *const EvidenceList) bool {
        for (self.slice()) |e| {
            if (e.isThreat()) return true;
        }
        return false;
    }
};

// ============================================================
// Detector Interface (vtable)
// ============================================================

pub const DetectorVTable = struct {
    name: []const u8,
    id: u8,
    analyze: *const fn (event: canonical.CanonicalEvent, flow_update: ?flow.FlowUpdate) Evidence,
};

// ============================================================
// Built-in Detectors
// ============================================================

/// Detector 0: Rule match detector - escalates by rule_id presence.
fn ruleMatchDetector(event: canonical.CanonicalEvent, _: ?flow.FlowUpdate) Evidence {
    if (event.rule_id != 0 and event.event_type == .match_) {
        return .{
            .detector_id = 0,
            .verdict = .suspicious,
            .rule_id = event.rule_id,
            .confidence = 60,
            .description = "rule match",
        };
    }
    return .{
        .detector_id = 0,
        .verdict = .benign,
        .rule_id = 0,
        .confidence = 30,
        .description = "no rule match",
    };
}

/// Detector 1: Block event detector - critical if event_type == .block.
fn blockEventDetector(event: canonical.CanonicalEvent, _: ?flow.FlowUpdate) Evidence {
    if (event.event_type == .block) {
        return .{
            .detector_id = 1,
            .verdict = .critical,
            .rule_id = event.rule_id,
            .confidence = 90,
            .description = "block event",
        };
    }
    return .{
        .detector_id = 1,
        .verdict = .benign,
        .rule_id = 0,
        .confidence = 30,
        .description = "no block event",
    };
}

/// Detector 2: Severity detector - escalates by event.severity.
fn severityDetector(event: canonical.CanonicalEvent, _: ?flow.FlowUpdate) Evidence {
    return switch (event.severity) {
        0 => .{ .detector_id = 2, .verdict = .benign, .rule_id = 0, .confidence = 20, .description = "severity 0" },
        1 => .{ .detector_id = 2, .verdict = .suspicious, .rule_id = 0, .confidence = 40, .description = "severity 1" },
        2 => .{ .detector_id = 2, .verdict = .malicious, .rule_id = 0, .confidence = 70, .description = "severity 2" },
        3 => .{ .detector_id = 2, .verdict = .critical, .rule_id = 0, .confidence = 90, .description = "severity 3" },
        else => .{ .detector_id = 2, .verdict = .unknown, .rule_id = 0, .confidence = 0, .description = "severity out of range" },
    };
}

/// Detector 3: Flow anomaly detector - examines flow_update for high packet rate.
fn flowAnomalyDetector(_: canonical.CanonicalEvent, flow_update: ?flow.FlowUpdate) Evidence {
    if (flow_update) |upd| {
        if (upd.flow.packet_count > 1000) {
            return .{
                .detector_id = 3,
                .verdict = .suspicious,
                .rule_id = 0,
                .confidence = 50,
                .description = "high packet rate",
            };
        }
        if (upd.flow.max_severity >= 2) {
            return .{
                .detector_id = 3,
                .verdict = .malicious,
                .rule_id = upd.flow.last_rule_id,
                .confidence = 65,
                .description = "flow already saw high severity",
            };
        }
    }
    return .{
        .detector_id = 3,
        .verdict = .benign,
        .rule_id = 0,
        .confidence = 20,
        .description = "no flow anomaly",
    };
}

const BUILTIN_DETECTORS = [_]DetectorVTable{
    .{ .name = "rule_match", .id = 0, .analyze = ruleMatchDetector },
    .{ .name = "block_event", .id = 1, .analyze = blockEventDetector },
    .{ .name = "severity", .id = 2, .analyze = severityDetector },
    .{ .name = "flow_anomaly", .id = 3, .analyze = flowAnomalyDetector },
};

// ============================================================
// Detection Engine
// ============================================================

pub const DetectionEngine = struct {
    detectors: [MAX_DETECTORS]?DetectorVTable = .{null} ** MAX_DETECTORS,
    detector_count: usize = 0,
    total_events_analyzed: u64 = 0,
    total_threats_found: u64 = 0,

    pub fn init() DetectionEngine {
        var engine = DetectionEngine{};
        // Register built-in detectors
        for (BUILTIN_DETECTORS) |det| {
            engine.registerDetector(det) catch {};
        }
        return engine;
    }

    pub fn registerDetector(self: *DetectionEngine, det: DetectorVTable) !void {
        if (self.detector_count >= MAX_DETECTORS) return error.DetectorTableFull;
        self.detectors[self.detector_count] = det;
        self.detector_count += 1;
    }

    /// Run all detectors against an event and return the EvidenceList.
    pub fn analyze(
        self: *DetectionEngine,
        event: canonical.CanonicalEvent,
        flow_update: ?flow.FlowUpdate,
    ) EvidenceList {
        var list = EvidenceList.init();
        self.total_events_analyzed += 1;

        var i: usize = 0;
        while (i < self.detector_count) : (i += 1) {
            const det = self.detectors[i] orelse continue;
            const evidence = det.analyze(event, flow_update);
            list.add(evidence);
            if (evidence.isThreat()) self.total_threats_found += 1;
        }
        return list;
    }

    pub fn resetStats(self: *DetectionEngine) void {
        self.total_events_analyzed = 0;
        self.total_threats_found = 0;
    }
};

// ============================================================
// Tests
// ============================================================

test "Verdict.toString returns uppercase token" {
    try std.testing.expect(std.mem.eql(u8, Verdict.unknown.toString(), "UNKNOWN"));
    try std.testing.expect(std.mem.eql(u8, Verdict.benign.toString(), "BENIGN"));
    try std.testing.expect(std.mem.eql(u8, Verdict.suspicious.toString(), "SUSPICIOUS"));
    try std.testing.expect(std.mem.eql(u8, Verdict.malicious.toString(), "MALICIOUS"));
    try std.testing.expect(std.mem.eql(u8, Verdict.critical.toString(), "CRITICAL"));
}

test "Verdict.isThreat classifies correctly" {
    try std.testing.expect(!Verdict.unknown.isThreat());
    try std.testing.expect(!Verdict.benign.isThreat());
    try std.testing.expect(Verdict.suspicious.isThreat());
    try std.testing.expect(Verdict.malicious.isThreat());
    try std.testing.expect(Verdict.critical.isThreat());
}

test "Verdict.max returns more severe" {
    try std.testing.expect(Verdict.max(.benign, .suspicious) == .suspicious);
    try std.testing.expect(Verdict.max(.malicious, .suspicious) == .malicious);
    try std.testing.expect(Verdict.max(.critical, .critical) == .critical);
    try std.testing.expect(Verdict.max(.benign, .benign) == .benign);
}

test "Verdict.min returns less severe" {
    try std.testing.expect(Verdict.min(.benign, .suspicious) == .benign);
    try std.testing.expect(Verdict.min(.malicious, .suspicious) == .suspicious);
}

test "Verdict.isAtLeast threshold check" {
    try std.testing.expect(Verdict.malicious.isAtLeast(.suspicious));
    try std.testing.expect(Verdict.critical.isAtLeast(.malicious));
    try std.testing.expect(!Verdict.benign.isAtLeast(.suspicious));
}

test "EvidenceList starts empty" {
    const list = EvidenceList.init();
    try std.testing.expect(list.count == 0);
    try std.testing.expect(list.maxVerdict() == .unknown);
    try std.testing.expect(!list.hasThreat());
}

test "EvidenceList.add appends up to MAX_EVIDENCE_PER_EVENT" {
    var list = EvidenceList.init();
    var i: usize = 0;
    while (i < MAX_EVIDENCE_PER_EVENT + 5) : (i += 1) {
        list.add(.{
            .detector_id = @intCast(i),
            .verdict = .suspicious,
            .rule_id = 0,
            .confidence = 50,
            .description = "test",
        });
    }
    try std.testing.expect(list.count == MAX_EVIDENCE_PER_EVENT);
}

test "EvidenceList.maxVerdict returns highest" {
    var list = EvidenceList.init();
    list.add(.{ .detector_id = 0, .verdict = .benign, .rule_id = 0, .confidence = 30, .description = "" });
    list.add(.{ .detector_id = 1, .verdict = .malicious, .rule_id = 0, .confidence = 70, .description = "" });
    list.add(.{ .detector_id = 2, .verdict = .suspicious, .rule_id = 0, .confidence = 50, .description = "" });
    try std.testing.expect(list.maxVerdict() == .malicious);
}

test "EvidenceList.maxConfidence returns highest" {
    var list = EvidenceList.init();
    list.add(.{ .detector_id = 0, .verdict = .benign, .rule_id = 0, .confidence = 30, .description = "" });
    list.add(.{ .detector_id = 1, .verdict = .malicious, .rule_id = 0, .confidence = 85, .description = "" });
    list.add(.{ .detector_id = 2, .verdict = .suspicious, .rule_id = 0, .confidence = 50, .description = "" });
    try std.testing.expect(list.maxConfidence() == 85);
}

test "EvidenceList.hasThreat returns true when any threat present" {
    var list = EvidenceList.init();
    list.add(.{ .detector_id = 0, .verdict = .benign, .rule_id = 0, .confidence = 30, .description = "" });
    try std.testing.expect(!list.hasThreat());
    list.add(.{ .detector_id = 1, .verdict = .suspicious, .rule_id = 0, .confidence = 50, .description = "" });
    try std.testing.expect(list.hasThreat());
}

test "DetectionEngine.init registers 4 built-in detectors" {
    const engine = DetectionEngine.init();
    try std.testing.expect(engine.detector_count == 4);
    try std.testing.expect(engine.total_events_analyzed == 0);
}

test "DetectionEngine.analyze runs all detectors for benign event" {
    var engine = DetectionEngine.init();
    var event = canonical.create(.zig_core);
    event.event_type = .forward;
    event.severity = 0;
    const list = engine.analyze(event, null);
    try std.testing.expect(list.count == 4);
    try std.testing.expect(!list.hasThreat());
    try std.testing.expect(engine.total_events_analyzed == 1);
}

test "DetectionEngine.analyze flags block events as critical" {
    var engine = DetectionEngine.init();
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    event.severity = 3;
    event.rule_id = 0xDEAD;
    const list = engine.analyze(event, null);
    try std.testing.expect(list.count == 4);
    try std.testing.expect(list.hasThreat());
    try std.testing.expect(list.maxVerdict() == .critical);
    try std.testing.expect(engine.total_threats_found > 0);
}

test "DetectionEngine.analyze escalates by severity" {
    var engine = DetectionEngine.init();
    var event = canonical.create(.zig_core);
    event.event_type = .forward;
    event.severity = 2;
    const list = engine.analyze(event, null);
    try std.testing.expect(list.maxVerdict() == .malicious);
}

test "DetectionEngine.resetStats zeroes counters" {
    var engine = DetectionEngine.init();
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    event.severity = 3;
    _ = engine.analyze(event, null);
    try std.testing.expect(engine.total_events_analyzed > 0);
    engine.resetStats();
    try std.testing.expect(engine.total_events_analyzed == 0);
    try std.testing.expect(engine.total_threats_found == 0);
}

test "ruleMatchDetector returns suspicious on rule match" {
    var event = canonical.create(.zig_core);
    event.event_type = .match_;
    event.rule_id = 0xBEEF;
    const e = ruleMatchDetector(event, null);
    try std.testing.expect(e.verdict == .suspicious);
    try std.testing.expect(e.rule_id == 0xBEEF);
}

test "blockEventDetector returns critical on block event" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    const e = blockEventDetector(event, null);
    try std.testing.expect(e.verdict == .critical);
    try std.testing.expect(e.confidence == 90);
}

test "severityDetector maps severity to verdict" {
    var event = canonical.create(.zig_core);
    event.severity = 0;
    try std.testing.expect(severityDetector(event, null).verdict == .benign);
    event.severity = 1;
    try std.testing.expect(severityDetector(event, null).verdict == .suspicious);
    event.severity = 2;
    try std.testing.expect(severityDetector(event, null).verdict == .malicious);
    event.severity = 3;
    try std.testing.expect(severityDetector(event, null).verdict == .critical);
}

test "flowAnomalyDetector flags high packet count" {
    const upd = flow.FlowUpdate{
        .kind = .flow_updated,
        .key = .{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 },
        .flow = .{
            .key = .{ .ip_a = 1, .port_a = 1, .ip_b = 2, .port_b = 2, .protocol = 6 },
            .state = .established,
            .packet_count = 2000,
            .byte_count = 200000,
            .start_ns = 0,
            .last_seen_ns = 1000,
            .max_severity = 0,
            .rule_matched = false,
            .last_rule_id = 0,
        },
    };
    const event = canonical.create(.zig_core);
    const e = flowAnomalyDetector(event, upd);
    try std.testing.expect(e.verdict == .suspicious);
    try std.testing.expect(e.confidence == 50);
}
