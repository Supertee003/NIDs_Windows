//! rag_engine.zig - AEGIS RAG Engine (Rewrite Phase 22 / Manual Phase 13)
//!
//! Retrieval Augmented Generation context layer.
//! RAG enriches verdict context with retrieved intelligence.
//!
//! Architecture (Manual Section 21):
//!   Canonical Event -> Threat Intel -> Detection -> Correlation -> RAG
//!   RAG returns: context, references, confidence, provenance
//!
//! Critical rules (Manual Section 21):
//!   - RAG must NOT block (Section 21: "RAG -> block" is forbidden)
//!   - System must work when RAG is unavailable (fail-soft)
//!   - RAG enriches, it does not authorize
//!
//! Design:
//!   - In-memory knowledge base (static entries for Phase 22)
//!   - Retrieval by IP, domain, hash, category
//!   - Returns RagContext with references + confidence + provenance
//!   - Fail-soft: returns empty context if unavailable

const std = @import("std");
const canonical = @import("canonical_event.zig");
const detection = @import("detection_engine.zig");
const threat_intel = @import("threat_intel.zig");

// ============================================================
// Constants
// ============================================================

pub const MAX_RAG_ENTRIES: usize = 1024;
pub const MAX_REFERENCES: usize = 8;
pub const RAG_CONFIDENCE_THRESHOLD: u8 = 50;

// ============================================================
// RAG Knowledge Entry
// ============================================================

pub const KnowledgeCategory = enum(u8) {
    unknown = 0,
    malware_signature = 1,
    attack_pattern = 2,
    threat_actor = 3,
    vulnerability = 4,
    mitigation = 5,
    false_positive_indicator = 6,
    contextual_benign = 7,

    pub fn toString(self: KnowledgeCategory) []const u8 {
        return switch (self) {
            .unknown => "UNKNOWN",
            .malware_signature => "MALWARE_SIGNATURE",
            .attack_pattern => "ATTACK_PATTERN",
            .threat_actor => "THREAT_ACTOR",
            .vulnerability => "VULNERABILITY",
            .mitigation => "MITIGATION",
            .false_positive_indicator => "FALSE_POSITIVE_INDICATOR",
            .contextual_benign => "CONTEXTUAL_BENIGN",
        };
    }
};

pub const RagEntry = struct {
    id: u32,
    category: KnowledgeCategory,
    /// IP address this entry applies to (0 = any).
    ip: u32,
    /// Rule ID this entry relates to (0 = general).
    rule_id: u32,
    /// Context text (static string).
    context: []const u8,
    /// Reference source (static string, e.g. "MITRE ATT&CK T1059").
    reference: []const u8,
    /// Confidence in this knowledge (0-100).
    confidence: u8,
    /// Provenance: where this knowledge came from.
    provenance: []const u8,
};

// ============================================================
// RAG Context (result of retrieval)
// ============================================================

pub const RagReference = struct {
    reference: []const u8,
    provenance: []const u8,
    confidence: u8,
};

pub const RagContext = struct {
    /// Was RAG available (false = fail-soft, empty context).
    available: bool,
    /// Number of matching entries found.
    match_count: u8,
    /// Retrieved context summary (static string).
    context_summary: []const u8,
    /// Retrieved references (up to MAX_REFERENCES).
    references: [MAX_REFERENCES]RagReference,
    reference_count: u8,
    /// Overall confidence in retrieved context (0-100).
    confidence: u8,
    /// Category of the primary match.
    primary_category: KnowledgeCategory,
    /// Event ID that was enriched.
    event_id: u64,

    /// Returns true if RAG found any matching context.
    pub fn hasContext(self: RagContext) bool {
        return self.available and self.match_count > 0;
    }

    /// Returns true if RAG confidence is high enough to be useful.
    pub fn isConfident(self: RagContext) bool {
        return self.confidence >= RAG_CONFIDENCE_THRESHOLD;
    }

    /// Returns true if this context indicates a false positive.
    pub fn indicatesFalsePositive(self: RagContext) bool {
        return self.primary_category == .false_positive_indicator or
            self.primary_category == .contextual_benign;
    }

    /// Returns the references slice.
    pub fn referencesSlice(self: *const RagContext) []const RagReference {
        return self.references[0..self.reference_count];
    }
};

// ============================================================
// RAG Engine
// ============================================================

const RagMap = struct {
    entries: [MAX_RAG_ENTRIES]RagEntry,
    count: usize,

    fn init() RagMap {
        return .{
            .entries = undefined,
            .count = 0,
        };
    }

    fn add(self: *RagMap, entry: RagEntry) void {
        if (self.count < MAX_RAG_ENTRIES) {
            self.entries[self.count] = entry;
            self.count += 1;
        }
    }

    /// Find entries matching IP and/or rule_id.
    /// Returns up to max_results matches into the output buffer.
    fn findMatches(self: *const RagMap, ip: u32, rule_id: u32, out: []RagEntry) usize {
        var found: usize = 0;
        for (0..self.count) |i| {
            if (found >= out.len) break;
            const entry = self.entries[i];
            // Match if IP matches (or entry IP is 0 = wildcard) AND
            // rule_id matches (or entry rule_id is 0 = general)
            const ip_match = entry.ip == 0 or entry.ip == ip;
            const rule_match = entry.rule_id == 0 or entry.rule_id == rule_id;
            if (ip_match and rule_match) {
                out[found] = entry;
                found += 1;
            }
        }
        return found;
    }
};

pub const RagEngine = struct {
    knowledge: RagMap,
    /// Total queries (lifetime).
    total_queries: u64,
    /// Total matches found.
    total_matches: u64,
    /// Total fail-soft (no matches).
    total_misses: u64,
    /// Total false positive indicators found.
    total_fp_indicators: u64,
    /// Whether RAG is available (can be disabled for fail-soft testing).
    available: bool,

    pub fn init() RagEngine {
        return .{
            .knowledge = RagMap.init(),
            .total_queries = 0,
            .total_matches = 0,
            .total_misses = 0,
            .total_fp_indicators = 0,
            .available = true,
        };
    }

    /// Load built-in knowledge entries.
    pub fn loadBuiltinEntries(self: *RagEngine) void {
        const entries = [_]RagEntry{
            .{
                .id = 1,
                .category = .malware_signature,
                .ip = 0x0A0000A1, // 10.0.0.161 (builtin malware_c2)
                .rule_id = 0,
                .context = "known C2 server, Emotet-related",
                .reference = "MITRE ATT&CK T1071",
                .confidence = 95,
                .provenance = "builtin-rag",
            },
            .{
                .id = 2,
                .category = .attack_pattern,
                .ip = 0,
                .rule_id = 0xDEAD,
                .context = "port scan pattern, vertical scan detected",
                .reference = "MITRE ATT&CK T1046",
                .confidence = 80,
                .provenance = "builtin-rag",
            },
            .{
                .id = 3,
                .category = .attack_pattern,
                .ip = 0,
                .rule_id = 0xBEEF,
                .context = "critical severity rule match, likely exploit attempt",
                .reference = "MITRE ATT&CK T1203",
                .confidence = 85,
                .provenance = "builtin-rag",
            },
            .{
                .id = 4,
                .category = .false_positive_indicator,
                .ip = 0x0A000001, // 10.0.0.1 (private, likely benign)
                .rule_id = 0,
                .context = "private network source, likely internal traffic",
                .reference = "RFC 1918",
                .confidence = 70,
                .provenance = "builtin-rag",
            },
            .{
                .id = 5,
                .category = .threat_actor,
                .ip = 0x0A0000B2, // 10.0.0.178 (builtin botnet)
                .rule_id = 0,
                .context = "known botnet node, Mirai variant",
                .reference = "MITRE ATT&CK T1480",
                .confidence = 90,
                .provenance = "builtin-rag",
            },
            .{
                .id = 6,
                .category = .mitigation,
                .ip = 0,
                .rule_id = 0xCAFE,
                .context = "brute force attempt, recommend rate limiting",
                .reference = "MITRE ATT&CK T1110",
                .confidence = 75,
                .provenance = "builtin-rag",
            },
            .{
                .id = 7,
                .category = .contextual_benign,
                .ip = 0x0A000099, // 10.0.0.153 (not in threat intel)
                .rule_id = 0,
                .context = "no known threat indicators for this IP",
                .reference = "internal-rag",
                .confidence = 60,
                .provenance = "builtin-rag",
            },
            .{
                .id = 8,
                .category = .vulnerability,
                .ip = 0,
                .rule_id = 0,
                .context = "general vulnerability context: CVE-2024-XXXX",
                .reference = "CVE-2024-XXXX",
                .confidence = 65,
                .provenance = "builtin-rag",
            },
        };

        for (entries) |entry| {
            self.knowledge.add(entry);
        }
    }

    /// Query RAG for context about an event.
    /// Returns RagContext with retrieved information.
    /// Fail-soft: if not available, returns empty context.
    pub fn query(self: *RagEngine, event: canonical.CanonicalEvent) RagContext {
        self.total_queries += 1;

        // Fail-soft: return empty context if not available
        if (!self.available) {
            return .{
                .available = false,
                .match_count = 0,
                .context_summary = "RAG unavailable (fail-soft)",
                .references = undefined,
                .reference_count = 0,
                .confidence = 0,
                .primary_category = .unknown,
                .event_id = event.event_id,
            };
        }

        // Search knowledge base by IP and rule_id
        var matches: [MAX_REFERENCES]RagEntry = undefined;
        const match_count = self.knowledge.findMatches(event.source_ip, event.rule_id, &matches);

        if (match_count == 0) {
            self.total_misses += 1;
            return .{
                .available = true,
                .match_count = 0,
                .context_summary = "no RAG context found",
                .references = undefined,
                .reference_count = 0,
                .confidence = 0,
                .primary_category = .unknown,
                .event_id = event.event_id,
            };
        }

        self.total_matches += 1;

        // Build context from matches
        var refs: [MAX_REFERENCES]RagReference = undefined;
        var ref_count: u8 = 0;
        var best_confidence: u8 = 0;
        var primary_cat: KnowledgeCategory = .unknown;

        for (matches[0..match_count]) |entry| {
            if (ref_count < MAX_REFERENCES) {
                refs[ref_count] = .{
                    .reference = entry.reference,
                    .provenance = entry.provenance,
                    .confidence = entry.confidence,
                };
                ref_count += 1;
            }
            if (entry.confidence > best_confidence) {
                best_confidence = entry.confidence;
                primary_cat = entry.category;
            }
        }

        // Track false positive indicators
        if (primary_cat == .false_positive_indicator or primary_cat == .contextual_benign) {
            self.total_fp_indicators += 1;
        }

        // Use first match's context as summary
        const summary = matches[0].context;

        return .{
            .available = true,
            .match_count = @intCast(match_count),
            .context_summary = summary,
            .references = refs,
            .reference_count = ref_count,
            .confidence = best_confidence,
            .primary_category = primary_cat,
            .event_id = event.event_id,
        };
    }

    /// Set availability (for fail-soft testing).
    pub fn setAvailable(self: *RagEngine, available: bool) void {
        self.available = available;
    }

    /// Current knowledge base size.
    pub fn knowledgeCount(self: *const RagEngine) usize {
        return self.knowledge.count;
    }

    /// Reset all stats.
    pub fn resetStats(self: *RagEngine) void {
        self.total_queries = 0;
        self.total_matches = 0;
        self.total_misses = 0;
        self.total_fp_indicators = 0;
    }
};

// ============================================================
// Tests
// ============================================================

test "KnowledgeCategory.toString returns readable names" {
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.unknown.toString(), "UNKNOWN"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.malware_signature.toString(), "MALWARE_SIGNATURE"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.attack_pattern.toString(), "ATTACK_PATTERN"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.threat_actor.toString(), "THREAT_ACTOR"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.vulnerability.toString(), "VULNERABILITY"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.mitigation.toString(), "MITIGATION"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.false_positive_indicator.toString(), "FALSE_POSITIVE_INDICATOR"));
    try std.testing.expect(std.mem.eql(u8, KnowledgeCategory.contextual_benign.toString(), "CONTEXTUAL_BENIGN"));
}

test "RagContext.hasContext returns true when matches found" {
    const ctx_with = RagContext{
        .available = true,
        .match_count = 2,
        .context_summary = "test",
        .references = undefined,
        .reference_count = 2,
        .confidence = 80,
        .primary_category = .malware_signature,
        .event_id = 1,
    };
    try std.testing.expect(ctx_with.hasContext());

    const ctx_without = RagContext{
        .available = true,
        .match_count = 0,
        .context_summary = "none",
        .references = undefined,
        .reference_count = 0,
        .confidence = 0,
        .primary_category = .unknown,
        .event_id = 1,
    };
    try std.testing.expect(!ctx_without.hasContext());
}

test "RagContext.hasContext returns false when unavailable (fail-soft)" {
    const ctx_unavailable = RagContext{
        .available = false,
        .match_count = 0,
        .context_summary = "fail-soft",
        .references = undefined,
        .reference_count = 0,
        .confidence = 0,
        .primary_category = .unknown,
        .event_id = 1,
    };
    try std.testing.expect(!ctx_unavailable.hasContext());
}

test "RagContext.isConfident threshold" {
    const ctx_confident = RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "test",
        .references = undefined,
        .reference_count = 1,
        .confidence = 80,
        .primary_category = .malware_signature,
        .event_id = 1,
    };
    try std.testing.expect(ctx_confident.isConfident());

    const ctx_low = RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "test",
        .references = undefined,
        .reference_count = 1,
        .confidence = 30,
        .primary_category = .unknown,
        .event_id = 1,
    };
    try std.testing.expect(!ctx_low.isConfident());
}

test "RagContext.indicatesFalsePositive" {
    const ctx_fp = RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "benign",
        .references = undefined,
        .reference_count = 1,
        .confidence = 70,
        .primary_category = .false_positive_indicator,
        .event_id = 1,
    };
    try std.testing.expect(ctx_fp.indicatesFalsePositive());

    const ctx_benign = RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "benign",
        .references = undefined,
        .reference_count = 1,
        .confidence = 60,
        .primary_category = .contextual_benign,
        .event_id = 1,
    };
    try std.testing.expect(ctx_benign.indicatesFalsePositive());

    const ctx_malicious = RagContext{
        .available = true,
        .match_count = 1,
        .context_summary = "malware",
        .references = undefined,
        .reference_count = 1,
        .confidence = 90,
        .primary_category = .malware_signature,
        .event_id = 1,
    };
    try std.testing.expect(!ctx_malicious.indicatesFalsePositive());
}

test "RagContext.referencesSlice returns correct count" {
    var refs: [MAX_REFERENCES]RagReference = undefined;
    refs[0] = .{ .reference = "ref1", .provenance = "src1", .confidence = 80 };
    refs[1] = .{ .reference = "ref2", .provenance = "src2", .confidence = 70 };

    const ctx = RagContext{
        .available = true,
        .match_count = 2,
        .context_summary = "test",
        .references = refs,
        .reference_count = 2,
        .confidence = 80,
        .primary_category = .malware_signature,
        .event_id = 1,
    };

    const slice = ctx.referencesSlice();
    try std.testing.expect(slice.len == 2);
    try std.testing.expect(std.mem.eql(u8, slice[0].reference, "ref1"));
    try std.testing.expect(std.mem.eql(u8, slice[1].reference, "ref2"));
}

test "RagEngine init has zero stats" {
    const engine = RagEngine.init();
    try std.testing.expect(engine.total_queries == 0);
    try std.testing.expect(engine.total_matches == 0);
    try std.testing.expect(engine.total_misses == 0);
    try std.testing.expect(engine.available == true);
}

test "RagEngine loadBuiltinEntries adds entries" {
    var engine = RagEngine.init();
    try std.testing.expect(engine.knowledgeCount() == 0);

    engine.loadBuiltinEntries();
    try std.testing.expect(engine.knowledgeCount() == 8);
}

test "RagEngine query returns context for known IP" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // 10.0.0.161 (malware_c2)

    const ctx = engine.query(event);

    try std.testing.expect(ctx.available == true);
    try std.testing.expect(ctx.hasContext());
    try std.testing.expect(ctx.match_count > 0);
    try std.testing.expect(ctx.confidence >= 90);
    try std.testing.expect(ctx.primary_category == .malware_signature);
    try std.testing.expect(engine.total_matches == 1);
}

test "RagEngine query returns context for known rule_id" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000099; // unknown IP
    event.rule_id = 0xDEAD; // known rule (port scan)

    const ctx = engine.query(event);

    try std.testing.expect(ctx.hasContext());
    try std.testing.expect(ctx.primary_category == .attack_pattern);
}

test "RagEngine query returns no context for unknown IP and rule" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000FF; // not in knowledge base
    event.rule_id = 0; // no rule

    const ctx = engine.query(event);

    try std.testing.expect(ctx.available == true);
    try std.testing.expect(!ctx.hasContext());
    try std.testing.expect(ctx.match_count == 0);
    try std.testing.expect(engine.total_misses == 1);
}

test "RagEngine query fail-soft when unavailable" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();
    engine.setAvailable(false); // disable RAG

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // would match

    const ctx = engine.query(event);

    try std.testing.expect(ctx.available == false);
    try std.testing.expect(!ctx.hasContext());
    try std.testing.expect(ctx.match_count == 0);
    // Fail-soft: should NOT count as match or miss
    try std.testing.expect(engine.total_matches == 0);
    try std.testing.expect(engine.total_misses == 0);
}

test "RagEngine query detects false positive indicators" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001; // 10.0.0.1 (private, benign)
    event.rule_id = 0;

    const ctx = engine.query(event);

    try std.testing.expect(ctx.hasContext());
    try std.testing.expect(ctx.indicatesFalsePositive());
    try std.testing.expect(engine.total_fp_indicators >= 1);
}

test "RagEngine query returns references" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // malware_c2

    const ctx = engine.query(event);

    try std.testing.expect(ctx.reference_count > 0);
    const refs = ctx.referencesSlice();
    try std.testing.expect(refs.len > 0);
    // Should contain MITRE ATT&CK reference
    var found_mitre = false;
    for (refs) |ref| {
        if (std.mem.indexOf(u8, ref.reference, "MITRE") != null) {
            found_mitre = true;
        }
    }
    try std.testing.expect(found_mitre);
}

test "RagEngine setAvailable toggles fail-soft" {
    var engine = RagEngine.init();
    try std.testing.expect(engine.available == true);

    engine.setAvailable(false);
    try std.testing.expect(engine.available == false);

    engine.setAvailable(true);
    try std.testing.expect(engine.available == true);
}

test "RagEngine stats accumulate correctly" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    // Query 1: match (malware_c2 IP)
    var event1 = canonical.create(.wfp_sensor);
    event1.source_ip = 0x0A0000A1;
    _ = engine.query(event1);

    // Query 2: miss (unknown IP)
    var event2 = canonical.create(.wfp_sensor);
    event2.source_ip = 0x0A0000FF;
    event2.rule_id = 0;
    _ = engine.query(event2);

    try std.testing.expect(engine.total_queries == 2);
    try std.testing.expect(engine.total_matches == 1);
    try std.testing.expect(engine.total_misses == 1);
}

test "RagEngine resetStats zeroes counters" {
    var engine = RagEngine.init();
    engine.loadBuiltinEntries();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1;
    _ = engine.query(event);
    try std.testing.expect(engine.total_queries == 1);

    engine.resetStats();
    try std.testing.expect(engine.total_queries == 0);
    try std.testing.expect(engine.total_matches == 0);
    try std.testing.expect(engine.total_misses == 0);
}

test "RAG does not block: query always returns (fail-soft)" {
    var engine = RagEngine.init();
    // Don't load any entries - empty knowledge base

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1;

    // Should return immediately with empty context, not hang or error
    const ctx = engine.query(event);

    try std.testing.expect(ctx.available == true);
    try std.testing.expect(!ctx.hasContext());
    try std.testing.expect(ctx.match_count == 0);
}
