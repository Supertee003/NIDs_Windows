//! rag_integration.zig - AEGIS RAG Intelligence Integration (STEP 8)
//!
//! Wires the RAG Intelligence Engine with the Detection + Correlation pipeline.
//! Before STEP 8, RAG engine existed but was never queried — events flowed
//! through detection without threat intel enrichment.
//!
//! After STEP 8, every popped event is enriched with threat intel BEFORE
//! detection runs. This gives detectors visibility into prior threat matches,
//! APT/botnet classification, and adjusts flow risk_score dynamically.
//!
//! Blueprint principle: "RAG ไม่ควรเป็น Source of Truth ของ Security Decision"
//! RAG enriches (sets context_flags, adjusts risk) — it does NOT override
//! deterministic policy decisions made by DetectionManager or PolicyEngine.
//!
//! Pipeline (full Golden Path with RAG):
//!   Sensor -> nose_int.submit (STEP 4)
//!     -> fabric.popEvent (STEP 3)
//!       -> rag_int.enrichEvent (STEP 8 — NEW: pre-detection enrichment)
//!         -> flow_int.processEvent (STEP 5)
//!           -> detection_int.processEvent (STEP 6)
//!             -> correlation_int.submitDetectionContext (STEP 7)
//!
//! Threat intel sources (seeded at startup):
//!   - Well-known Tor exit nodes (category=anonymous_proxy)
//!   - Internal blocklist (category=malicious)
//!   - AbuseIPDB-style entries (added at runtime via addThreat)

const std = @import("std");
const canonical = @import("canonical_event.zig");
pub const rag = @import("rag_intelligence.zig");
const flow_int = @import("flow_integration.zig");
const flow = @import("flow_engine.zig");
const detection_int = @import("detection_integration.zig");
const detection = @import("detection_interface.zig");
const correlation_int = @import("correlation_integration.zig");

// ============================================================
// STEP 8: Enrichment context (returned to caller)
// ============================================================

pub const EnrichmentContext = struct {
    /// Original enrichment result from RAGEngine.
    enrichment: rag.EnrichmentResult,
    /// Whether the event's source_ip matched a threat entry.
    matched: bool,
    /// Final risk_score_delta applied to flow (capped at +/- 100).
    applied_delta: i16,
    /// Whether flow risk_score was updated (false for host events).
    flow_updated: bool,
};

// ============================================================
// STEP 8: Integration state
// ============================================================

var g_rag_engine: ?rag.RAGEngine = null;
var g_initialized: bool = false;
var g_total_enriched: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_matches: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_high_confidence: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_total_flow_updates: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// ============================================================
// Initialization
// ============================================================

pub fn init() void {
    if (g_initialized) return;
    g_rag_engine = rag.RAGEngine.init();
    g_initialized = true;
    g_total_enriched.store(0, .monotonic);
    g_total_matches.store(0, .monotonic);
    g_total_high_confidence.store(0, .monotonic);
    g_total_flow_updates.store(0, .monotonic);
    seedDefaultThreats();
    std.log.info("[RAG-INT] RAG integration initialized (default threats seeded)", .{});
}

pub fn shutdown() void {
    if (!g_initialized) return;
    g_rag_engine = null;
    g_initialized = false;
    std.log.info("[RAG-INT] RAG integration shutdown", .{});
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn getEngine() ?*rag.RAGEngine {
    if (!g_initialized) return null;
    return &g_rag_engine.?;
}

// ============================================================
// Seed default threat entries (well-known bad IPs)
// ============================================================

fn seedDefaultThreats() void {
    if (!g_initialized) return;
    var engine = &g_rag_engine.?;

    // Example seed entries — production would load from JSON/CSV
    // Using well-known test ranges to avoid false positives on real traffic
    _ = engine.addThreat(.{
        .ip = 0x0A000099, // 10.0.0.99 — internal honeypot
        .severity = 3,
        .confidence = 85,
        .source = "internal_seed",
        .category = .malicious,
        .first_seen_ms = std.time.milliTimestamp(),
        .last_seen_ms = std.time.milliTimestamp(),
    });
    _ = engine.addThreat(.{
        .ip = 0xC0A8FF01, // 192.168.255.1 — test scanner
        .severity = 2,
        .confidence = 70,
        .source = "internal_seed",
        .category = .scanner,
        .first_seen_ms = std.time.milliTimestamp(),
        .last_seen_ms = std.time.milliTimestamp(),
    });
}

/// Add a threat entry at runtime (e.g., from external intel feed).
pub fn addThreat(entry: rag.ThreatEntry) bool {
    if (!g_initialized) return false;
    var engine = &g_rag_engine.?;
    return engine.addThreat(entry);
}

/// Remove a threat entry by IP.
pub fn removeThreat(ip: u32) bool {
    if (!g_initialized) return false;
    var engine = &g_rag_engine.?;
    return engine.removeThreat(ip);
}

// ============================================================
// STEP 8: Main API — enrich event with threat intel
// ============================================================

/// Enrich a CanonicalEvent with threat intelligence.
/// Mutates the event: sets context_flags, adjusts severity based on enrichment.
/// Updates flow risk_score (via flow_int) if event has a flow.
/// Returns EnrichmentContext with full enrichment details.
pub fn enrichEvent(event: *canonical.CanonicalEvent) EnrichmentContext {
    g_total_enriched.store(g_total_enriched.load(.monotonic) + 1, .monotonic);

    if (!g_initialized) {
        return .{
            .enrichment = rag.EnrichmentResult.noMatch(),
            .matched = false,
            .applied_delta = 0,
            .flow_updated = false,
        };
    }

    var engine = &g_rag_engine.?;

    // Skip host events (no source_ip to look up)
    if (event.source_ip == 0 or event.is_pipe != 0) {
        return .{
            .enrichment = rag.EnrichmentResult.noMatch(),
            .matched = false,
            .applied_delta = 0,
            .flow_updated = false,
        };
    }

    // Query threat DB
    const enrichment = engine.enrich(event.source_ip);

    if (!enrichment.threat_intel_match) {
        return .{
            .enrichment = enrichment,
            .matched = false,
            .applied_delta = 0,
            .flow_updated = false,
        };
    }

    g_total_matches.store(g_total_matches.load(.monotonic) + 1, .monotonic);
    if (enrichment.isHighConfidence()) {
        g_total_high_confidence.store(g_total_high_confidence.load(.monotonic) + 1, .monotonic);
    }

    // Apply enrichment to event:
    // 1. Set context_flags (OR with existing — don't overwrite flow patterns)
    event.context_flags |= enrichment.context_flags;

    // 2. Escalate severity if threat intel says high severity
    if (enrichment.threat_category == .apt or enrichment.threat_category == .malicious) {
        if (event.severity < 2) event.severity = 2; // at least Medium
    }
    if (enrichment.threat_category == .apt and event.severity < 3) {
        event.severity = 3; // APT = critical
    }

    // 3. Update flow risk_score (capped at +/- 100, value clamped 0..255)
    var applied_delta: i16 = enrichment.risk_score_delta;
    if (applied_delta > 100) applied_delta = 100;
    if (applied_delta < -100) applied_delta = -100;

    var flow_updated = false;
    if (flow_int.isInitialized()) {
        const key = flow.FlowKey{
            .src_ip = event.source_ip,
            .dst_ip = event.dest_ip,
            .src_port = event.source_port,
            .dst_port = event.dest_port,
            .protocol = event.protocol,
        };

        // Get current risk score, apply delta, clamp
        if (flow_int.getFlowTable()) |table| {
            if (table.lookup(key)) |flow_state| {
                const current = flow_state.risk_score;
                const new_score = blk: {
                    if (applied_delta >= 0) {
                        const new_val: u16 = @as(u16, current) + @as(u16, @intCast(applied_delta));
                        if (new_val > 255) break :blk @as(u8, 255);
                        break :blk @as(u8, @intCast(new_val));
                    } else {
                        const abs_delta: u16 = @intCast(-applied_delta);
                        if (abs_delta >= current) break :blk @as(u8, 0);
                        break :blk @as(u8, @intCast(current - abs_delta));
                    }
                };
                flow_state.risk_score = new_score;
                flow_updated = true;
                g_total_flow_updates.store(g_total_flow_updates.load(.monotonic) + 1, .monotonic);
            }
        }
    }

    return .{
        .enrichment = enrichment,
        .matched = true,
        .applied_delta = applied_delta,
        .flow_updated = flow_updated,
    };
}

// ============================================================
// STEP 8: Combined pipeline — enrich + detect + correlate
// ============================================================

/// Process an event through the full RAG-enriched pipeline:
///   1. RAG enrich (mutates event.context_flags + severity)
///   2. Detection pipeline (flow + escalation + detectors)
///   3. XDR correlation (incident linking)
///
/// Returns DetectionContext + CorrelationResult + EnrichmentContext.
pub fn processEventWithRAG(
    event: canonical.CanonicalEvent,
    det_mgr: ?*detection.DetectionManager,
    payload: []const u8,
) struct {
    det_ctx: detection_int.DetectionContext,
    corr_result: correlation_int.CorrelationResult,
    enrichment: EnrichmentContext,
} {
    var mutated_event = event;

    // Step 1: RAG enrichment (mutates event)
    const enrichment = enrichEvent(&mutated_event);

    // Step 2+3: Detection + correlation pipeline
    const result = correlation_int.processEventWithCorrelation(mutated_event, det_mgr, payload);

    return .{
        .det_ctx = result.det_ctx,
        .corr_result = result.corr_result,
        .enrichment = enrichment,
    };
}

// ============================================================
// STEP 8: Stats
// ============================================================

pub const IntegrationStats = struct {
    initialized: bool,
    db_entries: usize,
    total_enriched: u64,
    total_matches: u64,
    total_high_confidence: u64,
    total_flow_updates: u64,
    rag_queries: u64,
};

pub fn getStats() IntegrationStats {
    if (!g_initialized) {
        return .{
            .initialized = false,
            .db_entries = 0,
            .total_enriched = 0,
            .total_matches = 0,
            .total_high_confidence = 0,
            .total_flow_updates = 0,
            .rag_queries = 0,
        };
    }
    var engine = &g_rag_engine.?;
    const rstats = engine.getStats();
    return .{
        .initialized = true,
        .db_entries = rstats.db_entries,
        .total_enriched = g_total_enriched.load(.monotonic),
        .total_matches = g_total_matches.load(.monotonic),
        .total_high_confidence = g_total_high_confidence.load(.monotonic),
        .total_flow_updates = g_total_flow_updates.load(.monotonic),
        .rag_queries = rstats.total_queries,
    };
}

pub fn resetStats() void {
    g_total_enriched.store(0, .monotonic);
    g_total_matches.store(0, .monotonic);
    g_total_high_confidence.store(0, .monotonic);
    g_total_flow_updates.store(0, .monotonic);
}

// ============================================================
// Tests
// ============================================================

fn initAllLayers() void {
    flow_int.init();
    detection_int.init(detection_int.EscalationThresholds.default());
    correlation_int.init();
    init();
}

fn shutdownAllLayers() void {
    shutdown();
    correlation_int.shutdown();
    flow_int.shutdown();
    detection_int.resetStats();
    correlation_int.resetStats();
    resetStats();
}

test "EnrichmentContext is a value type" {
    const ctx = EnrichmentContext{
        .enrichment = rag.EnrichmentResult.noMatch(),
        .matched = false,
        .applied_delta = 0,
        .flow_updated = false,
    };
    const copy = ctx;
    try std.testing.expect(!copy.matched);
}

test "init and shutdown lifecycle" {
    initAllLayers();
    defer shutdownAllLayers();
    try std.testing.expect(isInitialized());
    try std.testing.expect(getEngine() != null);

    // Default seeds should be present
    const stats = getStats();
    try std.testing.expect(stats.db_entries >= 2);
}

test "enrichEvent skips host events" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    correlation_int.resetStats();
    resetStats();

    var event = canonical.create(.minifilter);
    event.event_type = .session_start;
    event.source_ip = 0; // host event
    event.is_pipe = 0;

    const ctx = enrichEvent(&event);
    try std.testing.expect(!ctx.matched);
    try std.testing.expect(ctx.applied_delta == 0);
    try std.testing.expect(!ctx.flow_updated);

    const stats = getStats();
    try std.testing.expect(stats.total_enriched == 1);
    try std.testing.expect(stats.total_matches == 0);
}

test "enrichEvent skips pipe events" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    var event = canonical.create(.pipe_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000099; // would match seed
    event.is_pipe = 1; // but pipe event

    const ctx = enrichEvent(&event);
    try std.testing.expect(!ctx.matched);
}

test "enrichEvent matches seeded threat" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000099; // matches seed (10.0.0.99)
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;

    const ctx = enrichEvent(&event);
    try std.testing.expect(ctx.matched);
    try std.testing.expect(ctx.enrichment.threat_intel_match);
    try std.testing.expect(ctx.enrichment.threat_category == .malicious);
    try std.testing.expect(ctx.applied_delta > 0);
    // Context flags should be set on event
    try std.testing.expect((event.context_flags & 0x01) != 0); // threat_intel_match bit
    // Severity should be escalated to at least 2 (malicious)
    try std.testing.expect(event.severity >= 2);

    const stats = getStats();
    try std.testing.expect(stats.total_matches == 1);
}

test "enrichEvent updates flow risk score" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000099; // matches seed
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;

    // First, create the flow so we can update its risk score
    _ = flow_int.processEvent(event);
    try std.testing.expect(flow_int.getStats().active_flows == 1);

    // Reset stats (flow already exists)
    resetStats();

    // Now enrich — should update flow risk_score
    const ctx = enrichEvent(&event);
    try std.testing.expect(ctx.matched);
    try std.testing.expect(ctx.flow_updated);

    // Verify flow risk_score was incremented
    const flow_ctx = flow_int.processEvent(event);
    try std.testing.expect(flow_ctx.risk_score > 0);

    const stats = getStats();
    try std.testing.expect(stats.total_flow_updates == 1);
}

test "enrichEvent escalates APT to critical severity" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    // Add APT threat entry
    _ = addThreat(.{
        .ip = 0x0A000098,
        .severity = 3,
        .confidence = 95,
        .source = "test_apt",
        .category = .apt,
        .first_seen_ms = std.time.milliTimestamp(),
        .last_seen_ms = std.time.milliTimestamp(),
    });

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000098;
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    event.severity = 0; // start at 0

    const ctx = enrichEvent(&event);
    try std.testing.expect(ctx.matched);
    try std.testing.expect(ctx.enrichment.threat_category == .apt);
    // APT should escalate severity to 3 (critical)
    try std.testing.expect(event.severity == 3);
    // context_flags bit1 = apt_match
    try std.testing.expect((event.context_flags & 0x02) != 0);
    // context_flags bit3 = high_confidence (confidence >= 80)
    try std.testing.expect((event.context_flags & 0x08) != 0);
}

test "enrichEvent returns no match for unknown IP" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0xC0A80164; // not in seed (192.168.1.100)
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;

    const ctx = enrichEvent(&event);
    try std.testing.expect(!ctx.matched);
    try std.testing.expect(ctx.applied_delta == 0);

    const stats = getStats();
    try std.testing.expect(stats.total_enriched == 1);
    try std.testing.expect(stats.total_matches == 0);
}

test "addThreat and removeThreat at runtime" {
    initAllLayers();
    defer shutdownAllLayers();
    resetStats();

    const initial_count = getStats().db_entries;

    // Add
    _ = addThreat(.{
        .ip = 0xC0A80202,
        .severity = 2,
        .confidence = 80,
        .source = "runtime_test",
        .category = .botnet,
        .first_seen_ms = std.time.milliTimestamp(),
        .last_seen_ms = std.time.milliTimestamp(),
    });
    try std.testing.expect(getStats().db_entries == initial_count + 1);

    // Verify it matches
    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0xC0A80202;
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;

    const ctx = enrichEvent(&event);
    try std.testing.expect(ctx.matched);
    try std.testing.expect(ctx.enrichment.threat_category == .botnet);
    // bit2 = botnet_match
    try std.testing.expect((event.context_flags & 0x04) != 0);

    // Remove
    try std.testing.expect(removeThreat(0xC0A80202));
    try std.testing.expect(getStats().db_entries == initial_count);
}

test "processEventWithRAG runs full pipeline" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    correlation_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000099; // matches seed
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    event.session_id = 42;

    const result = processEventWithRAG(event, null, &.{});

    // RAG enrichment happened
    try std.testing.expect(result.enrichment.matched);
    try std.testing.expect(result.enrichment.enrichment.threat_intel_match);

    // Detection pipeline ran (flow tracking active)
    try std.testing.expect(result.det_ctx.flow_context.packet_count >= 1);

    // Correlation happened (new incident created)
    try std.testing.expect(!result.corr_result.linked_to_existing);
    try std.testing.expect(result.corr_result.incident_index != null);

    // Event severity should be escalated
    try std.testing.expect(result.det_ctx.event.severity >= 2);
}

test "processEventWithRAG preserves event for benign traffic" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    correlation_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0xC0A80164; // not in seed
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    event.severity = 0;

    const result = processEventWithRAG(event, null, &.{});

    // No threat match
    try std.testing.expect(!result.enrichment.matched);
    // Severity unchanged
    try std.testing.expect(result.det_ctx.event.severity == 0);
    // No context flags set by RAG
    try std.testing.expect((result.det_ctx.event.context_flags & 0x0F) == 0);
}

test "getStats returns full integration state" {
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    correlation_int.resetStats();
    resetStats();

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0x0A000099; // matches seed
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    _ = flow_int.processEvent(event); // create flow first
    resetStats();

    _ = enrichEvent(&event);

    const stats = getStats();
    try std.testing.expect(stats.initialized);
    try std.testing.expect(stats.total_enriched == 1);
    try std.testing.expect(stats.total_matches == 1);
    try std.testing.expect(stats.total_flow_updates == 1);
}

test "STEP8: APT threat triggers critical escalation through full pipeline" {
    // End-to-end scenario:
    // 1. Add APT threat intel entry
    // 2. Event from APT IP goes through full pipeline
    // 3. Detection + correlation see the escalated severity
    initAllLayers();
    defer shutdownAllLayers();
    flow_int.resetStats();
    detection_int.resetStats();
    correlation_int.resetStats();
    resetStats();

    // Add APT threat
    _ = addThreat(.{
        .ip = 0xC0A80164, // 192.168.1.100
        .severity = 3,
        .confidence = 95,
        .source = "apt_intel",
        .category = .apt,
        .first_seen_ms = std.time.milliTimestamp(),
        .last_seen_ms = std.time.milliTimestamp(),
    });

    var event = canonical.create(.wfp_sensor);
    event.event_type = .forward;
    event.source_ip = 0xC0A80164; // APT
    event.dest_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_port = 445; // SMB
    event.protocol = 6;
    event.payload_length = 100;
    event.is_pipe = 0;
    event.session_id = 0xABCD0011;
    event.severity = 0; // start at 0

    const result = processEventWithRAG(event, null, &.{});

    // RAG enrichment matched APT
    try std.testing.expect(result.enrichment.matched);
    try std.testing.expect(result.enrichment.enrichment.threat_category == .apt);

    // Severity escalated to critical
    try std.testing.expect(result.det_ctx.event.severity == 3);

    // APT flag set
    try std.testing.expect((result.det_ctx.event.context_flags & 0x02) != 0);

    // High confidence flag set
    try std.testing.expect((result.det_ctx.event.context_flags & 0x08) != 0);

    // Incident created with elevated severity
    try std.testing.expect(result.corr_result.incident_index != null);
    try std.testing.expect(result.corr_result.incident_severity >= 3);
}
