//! threat_intel_integration.zig - AEGIS Threat Intel Integration (Phase 10)
//!
//! Thin facade over threat_intel.zig that owns a singleton ThreatIntelDb.
//! Provides enrichEvent() API consumed by dispatcher.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const threat_intel = @import("threat_intel.zig");

var g_db: ?threat_intel.ThreatIntelDb = null;
var g_initialized: bool = false;
var g_allocator: std.mem.Allocator = std.heap.page_allocator;
var g_total_enriched: u64 = 0;
var g_total_matches: u64 = 0;

pub fn init(allocator: std.mem.Allocator) void {
    if (g_initialized) return;
    var db = threat_intel.ThreatIntelDb.init(allocator);
    db.loadBuiltin() catch {};
    g_db = db;
    g_allocator = allocator;
    g_initialized = true;
    g_total_enriched = 0;
    g_total_matches = 0;
    std.log.info("[THREAT-INTEL] Threat intel integration initialized", .{});
}

pub fn isInitialized() bool { return g_initialized; }

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_db) |*db| db.deinit();
    g_db = null;
    g_initialized = false;
    std.log.info("[THREAT-INTEL] Threat intel integration shutdown", .{});
}

pub fn enrichEvent(event: canonical.CanonicalEvent) threat_intel.ThreatIntelMatch {
    g_total_enriched += 1;
    if (!g_initialized) {
        return .{ .src_match = null, .dst_match = null, .event_id = event.event_id };
    }
    if (g_db) |*db| {
        const src_m = db.lookup(event.source_ip);
        const dst_m = db.lookup(event.dest_ip);
        if (src_m != null or dst_m != null) g_total_matches += 1;
        return .{
            .src_match = src_m,
            .dst_match = dst_m,
            .event_id = event.event_id,
        };
    }
    return .{ .src_match = null, .dst_match = null, .event_id = event.event_id };
}

pub fn getStats() struct { total_enriched: u64, total_matches: u64 } {
    return .{ .total_enriched = g_total_enriched, .total_matches = g_total_matches };
}

pub fn resetStats() void {
    g_total_enriched = 0;
    g_total_matches = 0;
}

test "threat_intel_integration: full lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());

    init(std.testing.allocator);
    defer shutdown();
    try std.testing.expect(isInitialized());

    var event = canonical.create(.zig_core);
    event.source_ip = 0x08080808; // builtin malware_c2
    event.dest_ip = 0x0A000002;

    const m = enrichEvent(event);
    try std.testing.expect(m.hasMatch());
    try std.testing.expect(m.src_match != null);
    try std.testing.expect(m.src_match.?.severity == .critical);
    try std.testing.expect(m.isHighSeverity());

    const stats = getStats();
    try std.testing.expect(stats.total_enriched == 1);
    try std.testing.expect(stats.total_matches == 1);
}

test "threat_intel_integration: returns no match when not initialized" {
    if (isInitialized()) shutdown();
    var event = canonical.create(.zig_core);
    event.source_ip = 0x08080808;
    const m = enrichEvent(event);
    try std.testing.expect(!m.hasMatch());
}
