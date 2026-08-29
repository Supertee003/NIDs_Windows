//! detection_engine.zig - AEGIS Detection Engine (Rewrite Phase 7)
//!
//! Detection = EVIDENCE PRODUCER (not event mutation).
//! Each detector analyzes (event, flow) and produces DetectionEvidence.
//! Multiple detectors run in parallel, each producing independent evidence.
//! Original event is NOT modified.
//!
//! Verdict model (6 states, from Master Plan):
//!   BENIGN      - definitely not malicious
//!   OBSERVE     - not enough info, keep watching
//!   SUSPICIOUS  - indicators present but not conclusive
//!   MALICIOUS   - definitely malicious
//!   UNKNOWN     - detector could not determine
//!   ERROR       - detector failed (fail-open: treat as UNKNOWN)
//!
//! Architecture:
//!   Event Fabric -> Dispatcher -> Flow Engine -> Detection Engine -> (future Correlation)
//!                                                    |
//!                                                    v
//!                                          []DetectionEvidence
//!                                          (one per detector)

const std = @import("std");
const canonical = @import("canonical_event.zig");
const flow = @import("flow_engine.zig");

// ============================================================
// Verdict (6-state model, formalized in Phase 8)
// ============================================================

pub const Verdict = enum(u8) {
    benign = 0,
    observe = 1,
    suspicious = 2,
    malicious = 3,
    unknown = 4,
    error_ = 255,

    pub fn toString(self: Verdict) []const u8 {
        return switch (self) {
            .benign => "BENIGN",
            .observe => "OBSERVE",
            .suspicious => "SUSPICIOUS",
            .malicious => "MALICIOUS",
            .unknown => "UNKNOWN",
            .error_ => "ERROR",
        };
    }

    /// Returns true if this verdict indicates a threat (suspicious or malicious).
    pub fn isThreat(self: Verdict) bool {
        return self == .suspicious or self == .malicious;
    }

    /// Returns true if this verdict is conclusive (benign or malicious).
    pub fn isConclusive(self: Verdict) bool {
        return self == .benign or self == .malicious;
    }

    /// Numeric severity ranking (higher = more severe).
    /// Used by correlation/policy to compare evidence from multiple detectors.
    pub fn severityRank(self: Verdict) u8 {
        return switch (self) {
            .benign => 0,
            .observe => 1,
            .unknown => 2,
            .suspicious => 3,
            .malicious => 4,
            .error_ => 0, // fail-open
        };
    }
};

// ============================================================
// Detection Evidence (produced by detectors)
// ============================================================

/// Bitfield indicators for what triggered a detector.
pub const Indicator = struct {
    pub const NONE: u32 = 0;
    pub const PORT_SCAN: u32 = 1 << 0;
    pub const HIGH_RATE: u32 = 1 << 1;
    pub const RULE_MATCH: u32 = 1 << 2;
    pub const PAYLOAD_ANOMALY: u32 = 1 << 3;
    pub const FLOW_DURATION: u32 = 1 << 4;
    pub const REPEATED_CONNECTIONS: u32 = 1 << 5;
    pub const UNUSUAL_PROTOCOL: u32 = 1 << 6;
    pub const KNOWN_MALWARE_IP: u32 = 1 << 7;
};

/// Evidence produced by a single detector for a single event.
/// Pass-by-value (~96 bytes, safe to copy).
pub const DetectionEvidence = struct {
    verdict: Verdict,
    detector_id: u32,
    rule_id: u32,
    confidence: u8, // 0-100 (0=none, 100=certain)
    severity: u8, // 0-3 (matches CanonicalEvent.severity)
    description: []const u8, // static string, no allocation
    indicators: u32, // bitfield of Indicator flags
    flow_key: ?flow.FlowKey, // null if not flow-related
    event_id: u64,
    timestamp_ns: i128,

    /// Create a benign evidence (no threat detected).
    pub fn benign(detector_id: u32, event_id: u64, ts: i128) DetectionEvidence {
        return .{
            .verdict = .benign,
            .detector_id = detector_id,
            .rule_id = 0,
            .confidence = 50,
            .severity = 0,
            .description = "no threat indicators",
            .indicators = Indicator.NONE,
            .flow_key = null,
            .event_id = event_id,
            .timestamp_ns = ts,
        };
    }

    /// Create an error evidence (detector failed).
    pub fn err(detector_id: u32, event_id: u64, ts: i128) DetectionEvidence {
        return .{
            .verdict = .error_,
            .detector_id = detector_id,
            .rule_id = 0,
            .confidence = 0,
            .severity = 0,
            .description = "detector error",
            .indicators = Indicator.NONE,
            .flow_key = null,
            .event_id = event_id,
            .timestamp_ns = ts,
        };
    }
};

// ============================================================
// Detector VTable (comptime polymorphism pattern)
// ============================================================

/// Each detector implements this vtable. The DetectionEngine calls analyze_fn
/// for each registered detector, collecting all evidence.
pub const DetectorVTable = struct {
    id: u32,
    name: []const u8,
    /// Analyze an event + optional flow context, return evidence.
    /// MUST NOT mutate the event or flow.
    analyze_fn: *const fn (
        event: canonical.CanonicalEvent,
        flow_update: ?flow.FlowUpdate,
    ) DetectionEvidence,
};

// ============================================================
// Built-in Detectors (Phase 7 minimal set)
// ============================================================

/// Detector IDs (must be unique and stable for correlation).
pub const DetectorId = struct {
    pub const rule_match: u32 = 1;
    pub const port_scan: u32 = 2;
    pub const high_rate: u32 = 3;
};

// ---- Detector 1: Rule Match (legacy bridge) ----
// Passes through rule_id from event.rule_id. If event has a rule match,
// produces SUSPICIOUS evidence with the matched rule_id.

pub fn ruleMatchAnalyze(
    event: canonical.CanonicalEvent,
    flow_update: ?flow.FlowUpdate,
) DetectionEvidence {
    _ = flow_update; // rule match doesn't use flow context

    if (event.rule_id != 0) {
        return .{
            .verdict = if (event.severity >= 3) .malicious else .suspicious,
            .detector_id = DetectorId.rule_match,
            .rule_id = event.rule_id,
            .confidence = 80,
            .severity = event.severity,
            .description = "rule matched",
            .indicators = Indicator.RULE_MATCH,
            .flow_key = flow.FlowKey.fromEvent(event),
            .event_id = event.event_id,
            .timestamp_ns = event.monotonic_ns,
        };
    }
    return DetectionEvidence.benign(DetectorId.rule_match, event.event_id, event.monotonic_ns);
}

pub const rule_match_detector = DetectorVTable{
    .id = DetectorId.rule_match,
    .name = "RuleMatch",
    .analyze_fn = &ruleMatchAnalyze,
};

// ---- Detector 2: Port Scan ----
// Tracks unique destination ports per source IP. If a single source
// connects to > PORT_SCAN_THRESHOLD distinct ports, flags as SUSPICIOUS.
//
// Phase 7: stateless per-event check based on flow.packet_count.
// Future Phase 9 (Correlation) will track cross-flow port history.

const PORT_SCAN_PACKET_THRESHOLD: u64 = 20;

pub fn portScanAnalyze(
    event: canonical.CanonicalEvent,
    flow_update: ?flow.FlowUpdate,
) DetectionEvidence {
    // Need flow context to check packet count
    const upd = flow_update orelse {
        return DetectionEvidence.benign(DetectorId.port_scan, event.event_id, event.monotonic_ns);
    };

    if (upd.flow.packet_count >= PORT_SCAN_PACKET_THRESHOLD and upd.flow.state == .new) {
        return .{
            .verdict = .suspicious,
            .detector_id = DetectorId.port_scan,
            .rule_id = 0,
            .confidence = 60,
            .severity = 2,
            .description = "high packet count on new flow (possible port scan)",
            .indicators = Indicator.PORT_SCAN,
            .flow_key = upd.key,
            .event_id = event.event_id,
            .timestamp_ns = event.monotonic_ns,
        };
    }
    return DetectionEvidence.benign(DetectorId.port_scan, event.event_id, event.monotonic_ns);
}

pub const port_scan_detector = DetectorVTable{
    .id = DetectorId.port_scan,
    .name = "PortScan",
    .analyze_fn = &portScanAnalyze,
};

// ---- Detector 3: High Rate ----
// Flags flows with packet_count > HIGH_RATE_THRESHOLD as OBSERVE.
// Uses flow.byte_count to compute average payload size.

const HIGH_RATE_PACKET_THRESHOLD: u64 = 100;

pub fn highRateAnalyze(
    event: canonical.CanonicalEvent,
    flow_update: ?flow.FlowUpdate,
) DetectionEvidence {
    const upd = flow_update orelse {
        return DetectionEvidence.benign(DetectorId.high_rate, event.event_id, event.monotonic_ns);
    };

    if (upd.flow.packet_count >= HIGH_RATE_PACKET_THRESHOLD) {
        return .{
            .verdict = .observe,
            .detector_id = DetectorId.high_rate,
            .rule_id = 0,
            .confidence = 50,
            .severity = 1,
            .description = "high packet rate on flow",
            .indicators = Indicator.HIGH_RATE,
            .flow_key = upd.key,
            .event_id = event.event_id,
            .timestamp_ns = event.monotonic_ns,
        };
    }
    return DetectionEvidence.benign(DetectorId.high_rate, event.event_id, event.monotonic_ns);
}

pub const high_rate_detector = DetectorVTable{
    .id = DetectorId.high_rate,
    .name = "HighRate",
    .analyze_fn = &highRateAnalyze,
};

// ============================================================
// Detection Engine (orchestrates multiple detectors)
// ============================================================

pub const MAX_DETECTORS: usize = 16;

/// Fixed-size evidence collection (no allocation in hot path).
pub const EvidenceList = struct {
    items: [MAX_DETECTORS]DetectionEvidence,
    count: usize,

    pub fn init() EvidenceList {
        return .{
            .items = undefined, // caller must check count
            .count = 0,
        };
    }

    pub fn append(self: *EvidenceList, evidence: DetectionEvidence) void {
        if (self.count < MAX_DETECTORS) {
            self.items[self.count] = evidence;
            self.count += 1;
        }
        // If full, silently drop (production: log + metric)
    }

    pub fn slice(self: *const EvidenceList) []const DetectionEvidence {
        return self.items[0..self.count];
    }

    /// Returns the highest-severity verdict across all evidence.
    /// Used by dispatcher/policy to get a quick summary.
    pub fn maxVerdict(self: *const EvidenceList) Verdict {
        if (self.count == 0) return .unknown;
        var best: Verdict = .benign;
        var best_rank: u8 = 0;
        for (self.items[0..self.count]) |e| {
            const rank = e.verdict.severityRank();
            if (rank > best_rank) {
                best_rank = rank;
                best = e.verdict;
            }
        }
        return best;
    }

    /// Count evidence with a specific verdict.
    pub fn countByVerdict(self: *const EvidenceList, v: Verdict) usize {
        var n: usize = 0;
        for (self.items[0..self.count]) |e| {
            if (e.verdict == v) n += 1;
        }
        return n;
    }
};

pub const DetectionEngine = struct {
    detectors: [MAX_DETECTORS]DetectorVTable,
    count: usize,
    /// Lifetime stats (non-atomic; engine is single-threaded per dispatcher call).
    total_analyzed: u64,
    total_evidence: u64,
    total_threats: u64, // suspicious + malicious
    total_errors: u64,

    pub fn init() DetectionEngine {
        return .{
            .detectors = undefined,
            .count = 0,
            .total_analyzed = 0,
            .total_evidence = 0,
            .total_threats = 0,
            .total_errors = 0,
        };
    }

    /// Register a detector. Returns false if at capacity.
    pub fn register(self: *DetectionEngine, vtable: DetectorVTable) bool {
        if (self.count >= MAX_DETECTORS) return false;
        self.detectors[self.count] = vtable;
        self.count += 1;
        return true;
    }

    /// Analyze an event using all registered detectors.
    /// Returns ALL evidence (one per detector). Does NOT mutate event.
    pub fn analyze(
        self: *DetectionEngine,
        event: canonical.CanonicalEvent,
        flow_update: ?flow.FlowUpdate,
    ) EvidenceList {
        var list = EvidenceList.init();
        self.total_analyzed += 1;

        for (0..self.count) |i| {
            const evidence = self.detectors[i].analyze_fn(event, flow_update);
            list.append(evidence);
            self.total_evidence += 1;
            if (evidence.verdict == .error_) {
                self.total_errors += 1;
            } else if (evidence.verdict.isThreat()) {
                self.total_threats += 1;
            }
        }

        return list;
    }

    /// Register all built-in detectors (convenience).
    pub fn registerBuiltins(self: *DetectionEngine) void {
        _ = self.register(rule_match_detector);
        _ = self.register(port_scan_detector);
        _ = self.register(high_rate_detector);
    }
};

// ============================================================
// Tests
// ============================================================

test "Verdict.toString returns readable names" {
    // Pure function, safe to run in parallel.
    try std.testing.expect(std.mem.eql(u8, Verdict.benign.toString(), "BENIGN"));
    try std.testing.expect(std.mem.eql(u8, Verdict.observe.toString(), "OBSERVE"));
    try std.testing.expect(std.mem.eql(u8, Verdict.suspicious.toString(), "SUSPICIOUS"));
    try std.testing.expect(std.mem.eql(u8, Verdict.malicious.toString(), "MALICIOUS"));
    try std.testing.expect(std.mem.eql(u8, Verdict.unknown.toString(), "UNKNOWN"));
    try std.testing.expect(std.mem.eql(u8, Verdict.error_.toString(), "ERROR"));
}

test "Verdict.isThreat and isConclusive" {
    // Pure function, safe to run in parallel.
    try std.testing.expect(!Verdict.benign.isThreat());
    try std.testing.expect(!Verdict.observe.isThreat());
    try std.testing.expect(Verdict.suspicious.isThreat());
    try std.testing.expect(Verdict.malicious.isThreat());
    try std.testing.expect(!Verdict.unknown.isThreat());
    try std.testing.expect(!Verdict.error_.isThreat());

    try std.testing.expect(Verdict.benign.isConclusive());
    try std.testing.expect(!Verdict.observe.isConclusive());
    try std.testing.expect(!Verdict.suspicious.isConclusive());
    try std.testing.expect(Verdict.malicious.isConclusive());
    try std.testing.expect(!Verdict.unknown.isConclusive());
}

test "Verdict.severityRank ordering" {
    // Pure function, safe to run in parallel.
    try std.testing.expect(Verdict.benign.severityRank() < Verdict.observe.severityRank());
    try std.testing.expect(Verdict.observe.severityRank() < Verdict.unknown.severityRank());
    try std.testing.expect(Verdict.unknown.severityRank() < Verdict.suspicious.severityRank());
    try std.testing.expect(Verdict.suspicious.severityRank() < Verdict.malicious.severityRank());
}

test "DetectionEvidence.benign creates correct evidence" {
    const e = DetectionEvidence.benign(42, 100, 12345);
    try std.testing.expect(e.verdict == .benign);
    try std.testing.expect(e.detector_id == 42);
    try std.testing.expect(e.event_id == 100);
    try std.testing.expect(e.timestamp_ns == 12345);
    try std.testing.expect(e.confidence == 50);
    try std.testing.expect(e.indicators == Indicator.NONE);
}

test "DetectionEvidence.err creates error verdict" {
    const e = DetectionEvidence.err(99, 200, 99999);
    try std.testing.expect(e.verdict == .error_);
    try std.testing.expect(e.detector_id == 99);
    try std.testing.expect(e.confidence == 0);
}

test "EvidenceList init and append" {
    var list = EvidenceList.init();
    try std.testing.expect(list.count == 0);
    try std.testing.expect(list.slice().len == 0);

    list.append(DetectionEvidence.benign(1, 10, 0));
    try std.testing.expect(list.count == 1);
    try std.testing.expect(list.slice().len == 1);
    try std.testing.expect(list.slice()[0].detector_id == 1);

    list.append(DetectionEvidence.benign(2, 11, 0));
    try std.testing.expect(list.count == 2);
    try std.testing.expect(list.slice()[1].detector_id == 2);
}

test "EvidenceList append at capacity silently drops" {
    var list = EvidenceList.init();
    var i: u32 = 0;
    while (i < MAX_DETECTORS + 5) : (i += 1) {
        list.append(DetectionEvidence.benign(i, 0, 0));
    }
    try std.testing.expect(list.count == MAX_DETECTORS);
}

test "EvidenceList.maxVerdict returns highest severity" {
    var list = EvidenceList.init();
    try std.testing.expect(list.maxVerdict() == .unknown); // empty = unknown

    list.append(DetectionEvidence.benign(1, 0, 0)); // rank 0
    try std.testing.expect(list.maxVerdict() == .benign);

    // Add suspicious (rank 3)
    list.append(.{
        .verdict = .suspicious,
        .detector_id = 2,
        .rule_id = 0,
        .confidence = 60,
        .severity = 2,
        .description = "test",
        .indicators = Indicator.PORT_SCAN,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    try std.testing.expect(list.maxVerdict() == .suspicious);

    // Add malicious (rank 4) - should win
    list.append(.{
        .verdict = .malicious,
        .detector_id = 3,
        .rule_id = 0,
        .confidence = 90,
        .severity = 3,
        .description = "test",
        .indicators = Indicator.RULE_MATCH,
        .flow_key = null,
        .event_id = 0,
        .timestamp_ns = 0,
    });
    try std.testing.expect(list.maxVerdict() == .malicious);
}

test "EvidenceList.countByVerdict" {
    var list = EvidenceList.init();
    list.append(DetectionEvidence.benign(1, 0, 0));
    list.append(DetectionEvidence.benign(2, 0, 0));
    list.append(DetectionEvidence.err(3, 0, 0));

    try std.testing.expect(list.countByVerdict(.benign) == 2);
    try std.testing.expect(list.countByVerdict(.error_) == 1);
    try std.testing.expect(list.countByVerdict(.malicious) == 0);
}

test "DetectionEngine init and register" {
    var engine = DetectionEngine.init();
    try std.testing.expect(engine.count == 0);

    try std.testing.expect(engine.register(rule_match_detector));
    try std.testing.expect(engine.count == 1);

    try std.testing.expect(engine.register(port_scan_detector));
    try std.testing.expect(engine.count == 2);
}

test "DetectionEngine registerBuiltins adds all 3 detectors" {
    var engine = DetectionEngine.init();
    engine.registerBuiltins();
    try std.testing.expect(engine.count == 3);
}

test "DetectionEngine.analyze runs all detectors and returns evidence" {
    var engine = DetectionEngine.init();
    engine.registerBuiltins();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xDEAD;
    event.severity = 2;

    const list = engine.analyze(event, null);

    // 3 detectors -> 3 evidence
    try std.testing.expect(list.count == 3);
    try std.testing.expect(engine.total_analyzed == 1);
    try std.testing.expect(engine.total_evidence == 3);

    // At least one should be suspicious (rule match with rule_id != 0)
    try std.testing.expect(list.maxVerdict() == .suspicious);
    try std.testing.expect(list.countByVerdict(.suspicious) >= 1);
}

test "DetectionEngine.analyze with benign event produces all benign" {
    var engine = DetectionEngine.init();
    engine.registerBuiltins();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0; // no rule match
    event.severity = 0;

    const list = engine.analyze(event, null);

    try std.testing.expect(list.count == 3);
    // Without flow context, port_scan and high_rate return benign.
    // rule_match returns benign (rule_id == 0).
    try std.testing.expect(list.countByVerdict(.benign) == 3);
    try std.testing.expect(list.maxVerdict() == .benign);
}

test "DetectionEngine.analyze with high-packet-count flow triggers port_scan" {
    var engine = DetectionEngine.init();
    engine.registerBuiltins();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;

    // Create a flow update with high packet count
    const upd = flow.FlowUpdate{
        .kind = .flow_updated,
        .key = flow.FlowKey.fromEvent(event),
        .flow = .{
            .key = flow.FlowKey.fromEvent(event),
            .state = .new,
            .start_ns = 0,
            .last_seen_ns = 1000,
            .packet_count = PORT_SCAN_PACKET_THRESHOLD, // 20
            .byte_count = 2000,
            .session_id_set = 1,
            .last_session_id = 1,
            .initial_direction = 0,
            .max_severity = 0,
            .rule_matched = false,
            .last_rule_id = 0,
        },
        .triggering_event_id = event.event_id,
    };

    const list = engine.analyze(event, upd);

    // port_scan detector should flag as suspicious
    var found_suspicious: bool = false;
    for (list.slice()) |e| {
        if (e.detector_id == DetectorId.port_scan and e.verdict == .suspicious) {
            found_suspicious = true;
            try std.testing.expect(e.indicators & Indicator.PORT_SCAN != 0);
        }
    }
    try std.testing.expect(found_suspicious);
}

test "DetectionEngine.analyze with very-high-packet-count flow triggers high_rate" {
    var engine = DetectionEngine.init();
    engine.registerBuiltins();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;

    const upd = flow.FlowUpdate{
        .kind = .flow_updated,
        .key = flow.FlowKey.fromEvent(event),
        .flow = .{
            .key = flow.FlowKey.fromEvent(event),
            .state = .established,
            .start_ns = 0,
            .last_seen_ns = 1000,
            .packet_count = HIGH_RATE_PACKET_THRESHOLD + 50, // 150
            .byte_count = 15000,
            .session_id_set = 1,
            .last_session_id = 1,
            .initial_direction = 0,
            .max_severity = 0,
            .rule_matched = false,
            .last_rule_id = 0,
        },
        .triggering_event_id = event.event_id,
    };

    const list = engine.analyze(event, upd);

    var found_observe: bool = false;
    for (list.slice()) |e| {
        if (e.detector_id == DetectorId.high_rate and e.verdict == .observe) {
            found_observe = true;
            try std.testing.expect(e.indicators & Indicator.HIGH_RATE != 0);
        }
    }
    try std.testing.expect(found_observe);
}

test "DetectionEngine stats accumulate correctly" {
    var engine = DetectionEngine.init();
    engine.registerBuiltins();

    var event = canonical.create(.wfp_sensor);
    event.rule_id = 1;
    event.severity = 3;

    // Run analyze 5 times
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        _ = engine.analyze(event, null);
    }

    try std.testing.expect(engine.total_analyzed == 5);
    try std.testing.expect(engine.total_evidence == 15); // 5 * 3 detectors
    // Each run: rule_match produces malicious (severity 3 >= 3), port_scan/high_rate benign
    try std.testing.expect(engine.total_threats == 5);
}

test "DetectionEngine register at capacity returns false" {
    var engine = DetectionEngine.init();

    // Register MAX_DETECTORS detectors
    var i: u32 = 0;
    while (i < MAX_DETECTORS) : (i += 1) {
        // Create a unique vtable for each (reuse rule_match for simplicity)
        try std.testing.expect(engine.register(rule_match_detector));
    }
    try std.testing.expect(engine.count == MAX_DETECTORS);

    // Next register should fail
    try std.testing.expect(!engine.register(rule_match_detector));
}

test "ruleMatchAnalyze returns benign for no rule" {
    var event = canonical.create(.wfp_sensor);
    event.rule_id = 0;

    const e = ruleMatchAnalyze(event, null);
    try std.testing.expect(e.verdict == .benign);
    try std.testing.expect(e.detector_id == DetectorId.rule_match);
}

test "ruleMatchAnalyze returns suspicious for low-severity rule" {
    var event = canonical.create(.wfp_sensor);
    event.rule_id = 0x1234;
    event.severity = 1;

    const e = ruleMatchAnalyze(event, null);
    try std.testing.expect(e.verdict == .suspicious);
    try std.testing.expect(e.rule_id == 0x1234);
}

test "ruleMatchAnalyze returns malicious for critical rule" {
    var event = canonical.create(.wfp_sensor);
    event.rule_id = 0xDEAD;
    event.severity = 3;

    const e = ruleMatchAnalyze(event, null);
    try std.testing.expect(e.verdict == .malicious);
    try std.testing.expect(e.confidence == 80);
}
