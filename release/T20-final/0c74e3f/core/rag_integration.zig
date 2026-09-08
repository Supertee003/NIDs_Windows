//! rag_integration.zig - AEGIS RAG Integration (Rewrite Phase 22)
//!
//! Thin facade over rag_engine.zig that owns a singleton RagEngine.
//! Provides RAG context retrieval API for the pipeline.
//!
//! Lifecycle (owned by runtime/lifecycle.zig):
//!   init()              -> create RagEngine + load builtin entries
//!   query(event)        -> RagContext (fail-soft if not init)
//!   shutdown()          -> reset engine

const std = @import("std");
const canonical = @import("canonical_event.zig");
const rag = @import("rag_engine.zig");

var g_engine: ?rag.RagEngine = null;
var g_initialized: bool = false;

var g_total_queries: u64 = 0;
var g_total_matches: u64 = 0;
var g_total_fp_indicators: u64 = 0;

pub fn init() void {
    if (g_initialized) return;
    g_engine = rag.RagEngine.init();
    if (g_engine) |*engine| {
        engine.loadBuiltinEntries();
    }
    g_initialized = true;
    g_total_queries = 0;
    g_total_matches = 0;
    g_total_fp_indicators = 0;
    std.log.info("[RAG] RAG integration initialized (7 builtin entries)", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn resetStats() void {
    g_total_queries = 0;
    g_total_matches = 0;
    g_total_fp_indicators = 0;
    if (g_engine) |*engine| {
        engine.resetStats();
    }
}

/// Query RAG for context about an event.
/// Returns empty context (available=false) if not initialized.
pub fn query(event: canonical.CanonicalEvent) rag.RagContext {
    if (!g_initialized) {
        return .{
            .available = false,
            .match_count = 0,
            .context_summary = "RAG not initialized",
            .references = undefined,
            .reference_count = 0,
            .confidence = 0,
            .primary_category = .unknown,
            .event_id = event.event_id,
        };
    }
    if (g_engine) |*engine| {
        const ctx = engine.query(event);
        g_total_queries += 1;
        if (ctx.hasContext()) {
            g_total_matches += 1;
        }
        if (ctx.indicatesFalsePositive()) {
            g_total_fp_indicators += 1;
        }
        return ctx;
    }
    return .{
        .available = false,
        .match_count = 0,
        .context_summary = "RAG engine not available",
        .references = undefined,
        .reference_count = 0,
        .confidence = 0,
        .primary_category = .unknown,
        .event_id = event.event_id,
    };
}

/// Set RAG availability (for fail-soft testing).
pub fn setAvailable(available: bool) void {
    if (g_engine) |*engine| {
        engine.setAvailable(available);
    }
}

pub const RagStats = struct {
    total_queries: u64,
    total_matches: u64,
    total_fp_indicators: u64,
    knowledge_count: usize,
    available: bool,
};

pub fn getStats() RagStats {
    if (g_engine) |*engine| {
        return .{
            .total_queries = g_total_queries,
            .total_matches = g_total_matches,
            .total_fp_indicators = g_total_fp_indicators,
            .knowledge_count = engine.knowledgeCount(),
            .available = engine.available,
        };
    }
    return .{
        .total_queries = 0,
        .total_matches = 0,
        .total_fp_indicators = 0,
        .knowledge_count = 0,
        .available = false,
    };
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_engine = null;
    g_initialized = false;
    std.log.info("[RAG] RAG integration shutdown", .{});
}

test "rag integration: full lifecycle (init, query, stats, shutdown)" {
    if (g_initialized) shutdown();

    // Not initialized -> returns unavailable context
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A0000A1;

    const empty_ctx = query(event);
    try std.testing.expect(empty_ctx.available == false);

    // Init
    try std.testing.expect(!isInitialized());
    init();
    try std.testing.expect(isInitialized());

    const stats_init = getStats();
    try std.testing.expect(stats_init.knowledge_count == 7);
    try std.testing.expect(stats_init.available == true);

    // Query known IP -> match
    const ctx = query(event);
    try std.testing.expect(ctx.available == true);
    try std.testing.expect(ctx.hasContext());
    try std.testing.expect(ctx.primary_category == .malware_signature);

    const stats_after = getStats();
    try std.testing.expect(stats_after.total_queries == 1);
    try std.testing.expect(stats_after.total_matches == 1);

    // Query unknown IP -> miss
    var event2 = canonical.create(.wfp_sensor);
    event2.source_ip = 0x0A0000FF;
    event2.rule_id = 0;
    const ctx_miss = query(event2);
    try std.testing.expect(!ctx_miss.hasContext());

    // Fail-soft: disable RAG
    setAvailable(false);
    const ctx_disabled = query(event);
    try std.testing.expect(ctx_disabled.available == false);
    try std.testing.expect(!ctx_disabled.hasContext());

    setAvailable(true);

    // Reset
    resetStats();
    const stats_reset = getStats();
    try std.testing.expect(stats_reset.total_queries == 0);

    // Double-init/double-shutdown
    init();
    try std.testing.expect(isInitialized());
    shutdown();
    shutdown();
    try std.testing.expect(!isInitialized());

    // After shutdown
    const ctx_after_shutdown = query(event);
    try std.testing.expect(ctx_after_shutdown.available == false);
}
