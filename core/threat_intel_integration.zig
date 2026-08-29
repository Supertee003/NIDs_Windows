//! threat_intel_integration.zig - AEGIS Threat Intel Integration (Rewrite Phase 10)
//!
//! Thin facade over threat_intel.zig that owns a singleton ThreatIntelDB.
//! Mirrors the pattern of correlation_integration.zig and detection_integration.zig.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init(allocator)              -> create DB + load builtin entries
//!   enrichEvent(event)           -> ThreatIntelMatch (context enrichment)
//!   shutdown()                   -> deinit DB

const std = @import("std");
const canonical = @import("canonical_event.zig");
const threat_intel = @import("threat_intel.zig");

// ============================================================
// Singleton state
// ============================================================

var g_db: ?threat_intel.ThreatIntelDB = null;
var g_initialized: bool = false;
var g_allocator: ?std.mem.Allocator = null;

// Lifetime stats
var g_total_enrichments: u64 = 0;
var g_total_matches: u64 = 0;
var g_total_high_severity: u64 = 0;

// ============================================================
// Initialization
// ============================================================

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    g_db = threat_intel.ThreatIntelDB.init(allocator);
    if (g_db) |*db| {
        db.loadBuiltinEntries();
    }
    g_allocator = allocator;
    g_initialized = true;
    g_total_enrichments = 0;
    g_total_matches = 0;
    g_total_high_severity = 0;
    std.log.info("[THREAT-INTEL] Threat intel integration initialized (builtin entries loaded)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

/// Reset all stats (for tests).
pub fn resetStats() void {
    g_total_enrichments = 0;
    g_total_matches = 0;
    g_total_high_severity = 0;
    if (g_db) |*db| {
        db.total_lookups = 0;
        db.total_hits = 0;
        db.total_misses = 0;
    }
}

// ============================================================
// Enrichment
// ============================================================

/// Enrich an event with threat intel context.
/// Returns ThreatIntelMatch with source/destination IP matches.
/// Does NOT mutate the event.
pub fn enrichEvent(event: canonical.CanonicalEvent) threat_intel.ThreatIntelMatch {
    if (!g_initialized) {
        return .{
            .src_match = null,
            .dst_match = null,
            .event_id = event.event_id,
        };
    }
    if (g_db) |*db| {
        const match = db.enrichEvent(event);
        g_total_enrichments += 1;
        if (match.hasMatch()) {
            g_total_matches += 1;
            if (match.isHighSeverity()) {
                g_total_high_severity += 1;
            }
        }
        return match;
    }
    return .{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };
}

/// Look up a single IP (convenience for correlation engine).
pub fn lookupIp(ip: u32) ?threat_intel.ThreatIntelEntry {
    if (!g_initialized) return null;
    if (g_db) |*db| {
        return db.lookupIp(ip);
    }
    return null;
}

/// Add a threat intel entry (for runtime loading).
pub fn addEntry(entry: threat_intel.ThreatIntelEntry) void {
    if (!g_initialized) return;
    if (g_db) |*db| {
        db.addEntry(entry);
    }
}

// ============================================================
// Stats
// ============================================================

pub const ThreatIntelStats = struct {
    total_enrichments: u64,
    total_matches: u64,
    total_high_severity: u64,
    db_entries: usize,
    db_lookups: u64,
    db_hits: u64,
    db_misses: u64,
};

pub fn getStats() ThreatIntelStats {
    if (g_db) |*db| {
        return .{
            .total_enrichments = g_total_enrichments,
            .total_matches = g_total_matches,
            .total_high_severity = g_total_high_severity,
            .db_entries = db.count(),
            .db_lookups = db.total_lookups,
            .db_hits = db.total_hits,
            .db_misses = db.total_misses,
        };
    }
    return .{
        .total_enrichments = 0,
        .total_matches = 0,
        .total_high_severity = 0,
        .db_entries = 0,
        .db_lookups = 0,
        .db_hits = 0,
        .db_misses = 0,
    };
}

// ============================================================
// Shutdown
// ============================================================

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_db) |*db| {
        db.deinit();
    }
    g_db = null;
    g_allocator = null;
    g_initialized = false;
    std.log.info("[THREAT-INTEL] Threat intel integration shutdown", .{});
}

// ============================================================
// Tests (single serial test - parallelism-safe)
// ============================================================

test "threat intel integration: full lifecycle (init, enrich, stats, shutdown)" {
    // Clean slate
    if (g_initialized) shutdown();

    // --- Phase A: enrichEvent returns empty match when not initialized ---
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // known malware C2 (in builtin entries)
    event.dest_ip = 0x0A000002;

    const empty_match = enrichEvent(event);
    try std.testing.expect(!empty_match.hasMatch());
    try std.testing.expect(empty_match.event_id == event.event_id);

    // --- Phase B: init ---
    try std.testing.expect(!isInitialized());
    init(std.testing.allocator);
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.db_entries == 5); // 5 builtin entries
    try std.testing.expect(stats_init.total_enrichments == 0);

    // --- Phase C: enrichEvent with known malware C2 source IP ---
    event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1; // critical malware_c2
    event.dest_ip = 0x0A000002; // not in DB

    const match_src = enrichEvent(event);
    try std.testing.expect(match_src.hasMatch());
    try std.testing.expect(match_src.src_match != null);
    try std.testing.expect(match_src.dst_match == null);
    try std.testing.expect(match_src.src_match.?.severity == .critical);
    try std.testing.expect(match_src.src_match.?.category == .malware_c2);
    try std.testing.expect(match_src.isHighSeverity());

    const stats_after_match = getStats();
    try std.testing.expect(stats_after_match.total_enrichments == 1);
    try std.testing.expect(stats_after_match.total_matches == 1);
    try std.testing.expect(stats_after_match.total_high_severity == 1);

    // --- Phase D: enrichEvent with known botnet destination IP ---
    event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000099; // not in DB
    event.dest_ip = 0x0A0000B2; // high botnet

    const match_dst = enrichEvent(event);
    try std.testing.expect(match_dst.hasMatch());
    try std.testing.expect(match_dst.dst_match != null);
    try std.testing.expect(match_dst.dst_match.?.category == .botnet);
    try std.testing.expect(match_dst.maxSeverity() == .high);

    // --- Phase E: enrichEvent with no matches ---
    event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000099;
    event.dest_ip = 0x0A000098;

    const match_none = enrichEvent(event);
    try std.testing.expect(!match_none.hasMatch());

    const stats_final = getStats();
    try std.testing.expect(stats_final.total_enrichments == 3);
    try std.testing.expect(stats_final.total_matches == 2); // 2 hits, 1 miss
    try std.testing.expect(stats_final.total_high_severity == 2); // both critical and high

    // --- Phase F: resetStats zeroes counters ---
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_enrichments == 0);
    try std.testing.expect(stats_reset.total_matches == 0);

    // --- Phase G: lookupIp convenience function ---
    const found = lookupIp(0x0A0000A1);
    try std.testing.expect(found != null);
    try std.testing.expect(found.?.severity == .critical);

    const not_found = lookupIp(0x0A000099);
    try std.testing.expect(not_found == null);

    // --- Phase H: addEntry adds new entry ---
    addEntry(.{
        .ip = 0x0A0000FF,
        .severity = .low,
        .category = .spam,
        .confidence = 60,
        .source = "test",
        .first_seen_ms = 1000,
        .last_seen_ms = 2000,
        .report_count = 1,
    });
    const new_found = lookupIp(0x0A0000FF);
    try std.testing.expect(new_found != null);
    try std.testing.expect(new_found.?.category == .spam);

    // --- Phase I: double-init is no-op, double-shutdown is no-op ---
    init(std.testing.allocator); // no-op
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown(); // no-op
    try std.testing.expect(!isInitialized());

    // --- Phase J: after shutdown, enrichEvent returns empty match ---
    const empty_after_shutdown = enrichEvent(event);
    try std.testing.expect(!empty_after_shutdown.hasMatch());
}
