//! rag_intelligence.zig - AEGIS RAG Intelligence Layer (Phase 35, AEGIS-014)
//!
//! Retrieval-Augmented Generation for threat intelligence enrichment.
//! Enriches CanonicalEvent with context_flags from threat intel DB.
//!
//! Blueprint principle: "RAG ไม่ควรเป็น Source of Truth ของ Security Decision"
//! RAG enriches events with context — it does NOT override deterministic policy.
//!
//! Contract:
//!   1. PolicyEngine calls RAG to enrich PolicyContext before evaluate()
//!   2. RAG sets context_flags (threat_intel_match, correlation_match, etc.)
//!   3. RAG returns enrichment result, NOT a policy decision
//!   4. RAG responses include provenance (source, confidence)

const std = @import("std");
const canonical = @import("canonical_event.zig");

// ============================================================
// Threat Intelligence Entry (AEGIS-014)
// ============================================================

pub const ThreatEntry = struct {
    ip: u32,
    severity: u8,       // 0-3
    confidence: u8,     // 0-100
    source: []const u8, // e.g., "abuseipdb", "internal", "misp"
    category: ThreatCategory,
    first_seen_ms: i64,
    last_seen_ms: i64,
};

pub const ThreatCategory = enum(u8) {
    clean = 0,
    suspicious = 1,
    malicious = 2,
    apt = 3,        // Advanced Persistent Threat
    botnet = 4,
    scanner = 5,
    spammer = 6,
    unknown = 255,

    pub fn toString(self: ThreatCategory) []const u8 {
        return switch (self) {
            .clean => "clean",
            .suspicious => "suspicious",
            .malicious => "malicious",
            .apt => "apt",
            .botnet => "botnet",
            .scanner => "scanner",
            .spammer => "spammer",
            .unknown => "unknown",
        };
    }
};

// ============================================================
// RAG Enrichment Result (AEGIS-014)
// ============================================================

pub const EnrichmentResult = struct {
    threat_intel_match: bool,
    threat_category: ThreatCategory,
    confidence: u8,       // 0-100
    risk_score_delta: i16, // -100 to +100 (adjusts flow risk_score)
    context_flags: u32,   // Bitfield to set on CanonicalEvent
    provenance: []const u8,

    pub fn noMatch() EnrichmentResult {
        return .{
            .threat_intel_match = false,
            .threat_category = .clean,
            .confidence = 0,
            .risk_score_delta = 0,
            .context_flags = 0,
            .provenance = "none",
        };
    }

    pub fn isHighConfidence(self: EnrichmentResult) bool {
        return self.confidence >= 70;
    }
};

// ============================================================
// RAG Intelligence Engine (AEGIS-014)
// ============================================================

const MAX_THREAT_ENTRIES: usize = 1024;

pub const RAGEngine = struct {
    threat_db: [MAX_THREAT_ENTRIES]?ThreatEntry,
    db_count: usize,
    total_queries: std.atomic.Value(u64),
    total_matches: std.atomic.Value(u64),
    total_high_confidence: std.atomic.Value(u64),
    mutex: std.Thread.Mutex,

    pub fn init() RAGEngine {
        return .{
            .threat_db = [_]?ThreatEntry{null} ** MAX_THREAT_ENTRIES,
            .db_count = 0,
            .total_queries = std.atomic.Value(u64).init(0),
            .total_matches = std.atomic.Value(u64).init(0),
            .total_high_confidence = std.atomic.Value(u64).init(0),
            .mutex = .{},
        };
    }

    /// Add a threat intelligence entry to the local DB.
    pub fn addThreat(self: *RAGEngine, entry: ThreatEntry) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.db_count >= MAX_THREAT_ENTRIES) return false;
        // Check for duplicate
        for (0..self.db_count) |i| {
            if (self.threat_db[i]) |e| {
                if (e.ip == entry.ip) {
                    // Update existing
                    self.threat_db[i] = entry;
                    return true;
                }
            }
        }
        self.threat_db[self.db_count] = entry;
        self.db_count += 1;
        return true;
    }

    /// Query threat intelligence for an IP address.
    /// Returns enrichment result (does NOT make policy decisions).
    pub fn enrich(self: *RAGEngine, ip: u32) EnrichmentResult {
        _ = self.total_queries.fetchAdd(1, .monotonic);

        self.mutex.lock();
        defer self.mutex.unlock();

        for (0..self.db_count) |i| {
            if (self.threat_db[i]) |entry| {
                if (entry.ip == ip) {
                    _ = self.total_matches.fetchAdd(1, .monotonic);
                    if (entry.confidence >= 70) {
                        _ = self.total_high_confidence.fetchAdd(1, .monotonic);
                    }

                    // Set context_flags based on category
                    var flags: u32 = 0;
                    if (entry.severity >= 2) flags |= 0x01; // bit0 = threat_intel_match
                    if (entry.category == .apt) flags |= 0x02; // bit1 = apt_match
                    if (entry.category == .botnet) flags |= 0x04; // bit2 = botnet_match
                    if (entry.confidence >= 80) flags |= 0x08; // bit3 = high_confidence

                    // Risk score delta: higher severity = higher risk
                    const risk_delta: i16 = @intCast(entry.severity * 25);

                    return .{
                        .threat_intel_match = entry.severity >= 2,
                        .threat_category = entry.category,
                        .confidence = entry.confidence,
                        .risk_score_delta = risk_delta,
                        .context_flags = flags,
                        .provenance = entry.source,
                    };
                }
            }
        }

        return EnrichmentResult.noMatch();
    }

    /// Remove a threat entry by IP.
    pub fn removeThreat(self: *RAGEngine, ip: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (0..self.db_count) |i| {
            if (self.threat_db[i]) |entry| {
                if (entry.ip == ip) {
                    self.threat_db[i] = null;
                    // Compact: move last to deleted slot
                    if (self.db_count > 1 and i < self.db_count - 1) {
                        self.threat_db[i] = self.threat_db[self.db_count - 1];
                        self.threat_db[self.db_count - 1] = null;
                    }
                    self.db_count -= 1;
                    return true;
                }
            }
        }
        return false;
    }

    /// Get statistics.
    pub fn getStats(self: *RAGEngine) RAGStats {
        return .{
            .db_entries = self.db_count,
            .total_queries = self.total_queries.load(.monotonic),
            .total_matches = self.total_matches.load(.monotonic),
            .total_high_confidence = self.total_high_confidence.load(.monotonic),
        };
    }
};

pub const RAGStats = struct {
    db_entries: usize,
    total_queries: u64,
    total_matches: u64,
    total_high_confidence: u64,
};

// ============================================================
// Tests
// ============================================================

test "ThreatCategory.toString" {
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.malicious.toString(), "malicious"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.apt.toString(), "apt"));
    try std.testing.expect(std.mem.eql(u8, ThreatCategory.clean.toString(), "clean"));
}

test "EnrichmentResult.noMatch" {
    const r = EnrichmentResult.noMatch();
    try std.testing.expect(!r.threat_intel_match);
    try std.testing.expect(r.threat_category == .clean);
    try std.testing.expect(r.confidence == 0);
    try std.testing.expect(r.risk_score_delta == 0);
}

test "EnrichmentResult.isHighConfidence" {
    var r = EnrichmentResult.noMatch();
    try std.testing.expect(!r.isHighConfidence());
    r.confidence = 80;
    try std.testing.expect(r.isHighConfidence());
}

test "RAGEngine init" {
    const rag = RAGEngine.init();
    try std.testing.expect(rag.db_count == 0);
}

test "RAGEngine addThreat and enrich" {
    var rag = RAGEngine.init();
    try std.testing.expect(rag.addThreat(.{
        .ip = 0xC0A80164,
        .severity = 3,
        .confidence = 85,
        .source = "test",
        .category = .malicious,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    }));

    const result = rag.enrich(0xC0A80164);
    try std.testing.expect(result.threat_intel_match);
    try std.testing.expect(result.threat_category == .malicious);
    try std.testing.expect(result.confidence == 85);
    try std.testing.expect(result.risk_score_delta == 75);
    try std.testing.expect(result.isHighConfidence());
}

test "RAGEngine enrich returns noMatch for unknown IP" {
    var rag = RAGEngine.init();
    const result = rag.enrich(0x0A000001);
    try std.testing.expect(!result.threat_intel_match);
    try std.testing.expect(result.threat_category == .clean);
}

test "RAGEngine addThreat updates existing" {
    var rag = RAGEngine.init();
    _ = rag.addThreat(.{
        .ip = 0x0A000001,
        .severity = 1,
        .confidence = 50,
        .source = "test1",
        .category = .suspicious,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });
    // Update with higher severity
    _ = rag.addThreat(.{
        .ip = 0x0A000001,
        .severity = 3,
        .confidence = 90,
        .source = "test2",
        .category = .apt,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });

    const result = rag.enrich(0x0A000001);
    try std.testing.expect(result.threat_category == .apt);
    try std.testing.expect(result.confidence == 90);
}

test "RAGEngine removeThreat" {
    var rag = RAGEngine.init();
    _ = rag.addThreat(.{
        .ip = 0x0A000002,
        .severity = 2,
        .confidence = 70,
        .source = "test",
        .category = .botnet,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });
    try std.testing.expect(rag.db_count == 1);

    try std.testing.expect(rag.removeThreat(0x0A000002));
    try std.testing.expect(rag.db_count == 0);

    const result = rag.enrich(0x0A000002);
    try std.testing.expect(!result.threat_intel_match);
}

test "RAGEngine getStats" {
    var rag = RAGEngine.init();
    _ = rag.addThreat(.{
        .ip = 0x0A000003,
        .severity = 3,
        .confidence = 85,
        .source = "test",
        .category = .malicious,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });
    _ = rag.enrich(0x0A000003);
    _ = rag.enrich(0x0A000099); // no match

    const stats = rag.getStats();
    try std.testing.expect(stats.db_entries == 1);
    try std.testing.expect(stats.total_queries == 2);
    try std.testing.expect(stats.total_matches == 1);
    try std.testing.expect(stats.total_high_confidence == 1);
}

test "RAGEngine context_flags for APT" {
    var rag = RAGEngine.init();
    _ = rag.addThreat(.{
        .ip = 0x0A000004,
        .severity = 3,
        .confidence = 90,
        .source = "intel",
        .category = .apt,
        .first_seen_ms = 0,
        .last_seen_ms = 0,
    });

    const result = rag.enrich(0x0A000004);
    // bit0 = threat_intel_match, bit1 = apt_match, bit3 = high_confidence
    try std.testing.expect((result.context_flags & 0x01) != 0); // threat_intel
    try std.testing.expect((result.context_flags & 0x02) != 0); // apt
    try std.testing.expect((result.context_flags & 0x08) != 0); // high_confidence
}
