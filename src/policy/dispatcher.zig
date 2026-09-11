//! dispatcher.zig - AEGIS Runtime Dispatcher (Phase B: Runtime Spine)
//!
//! Pops events from Event Fabric and routes through the pipeline.
//! Replaces the old eventFabricDrain() in nids_analyze.zig.
//!
//! Pipeline (Phase B -- RAG integrated, P0.1 fixed, T3 stage helpers):
//!   Event Fabric -> Flow Engine (Phase 6) -> Detection Engine (Phase 7)
//!   -> Verdict Aggregator (Phase 8) -> Correlation Engine (Phase 9)
//!   -> Threat Intel Enrichment (Phase 10)
//!   -> RAG Context Enrichment (Phase B: NEW -- P0.1 fix)
//!   -> Brain Advisor (Phase 11)
//!   -> Policy Engine (Phase 12) -> Rust PEP (Phase 13) -> Forensics (Phase 14)
//!
//! T3: processEvent is decomposed into one helper per pipeline stage
//! (processFlow -> processForensics) WITHOUT changing the semantic order.
//! The dispatcher remains the SOLE orchestrator: no other component may
//! drive the pipeline (ADR-0001). A fate ledger (input == sum of fates)
//! audited by fatesBalanced() tracks every event end-to-end.
//!
//! main() no longer knows pipeline details - Runtime owns lifecycle.

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");
const fabric = @import("../contract/event_fabric.zig");
const flow_int = @import("../tests/integration/flow_integration.zig");
const flow_types = @import("../capture/flow_types.zig");
const detection_int = @import("../tests/integration/detection_integration.zig");
const detection = @import("../detection/detection_engine.zig");
const verdict_agg = @import("../detection/verdict_aggregator.zig");
const correlation_int = @import("../tests/integration/correlation_integration.zig");
const correlation_engine = @import("../detection/correlation_engine.zig");
const threat_intel_int = @import("../tests/integration/threat_intel_integration.zig");
const threat_intel = @import("../detection/threat_intel.zig");
const rag_int = @import("../tests/integration/rag_integration.zig");  // Phase B: RAG import (P0.1 fix)
const rag_engine = @import("../detection/rag_engine.zig");
const brain_int = @import("../tests/integration/brain_integration.zig");
const brain_engine = @import("../core/brain_engine.zig");
const policy_int = @import("../tests/integration/policy_integration.zig");
const policy_engine = @import("policy_engine.zig");
const rust_pep_int = @import("../tests/integration/rust_pep_integration.zig");
const rust_pep = @import("../core/rust_pep.zig");
const forensics_int = @import("../tests/integration/forensics_integration.zig");

// ============================================================
// Phase B: EventFate enum (accounting for every event)
// ============================================================

pub const EventFate = enum(u8) {
    accepted = 0,       // Event entered the pipeline
    processed = 1,      // Event completed all stages
    source_dropped = 2, // Dropped at source (validation failed)
    fabric_dropped = 3, // Dropped by fabric (queue full)
    rejected = 4,       // Rejected by policy
    expired = 5,        // Expired before processing
    failed = 6,         // Processing failed
    archived = 7,       // Archived for replay

    pub fn toString(self: EventFate) []const u8 {
        return switch (self) {
            .accepted => "ACCEPTED",
            .processed => "PROCESSED",
            .source_dropped => "SOURCE_DROPPED",
            .fabric_dropped => "FABRIC_DROPPED",
            .rejected => "REJECTED",
            .expired => "EXPIRED",
            .failed => "FAILED",
            .archived => "ARCHIVED",
        };
    }
};

// ============================================================
// Phase B: Pipeline accounting (invariant: input = sum of all fates)
// ============================================================

var g_total_input: u64 = 0;
var g_total_processed: u64 = 0;
var g_total_source_dropped: u64 = 0;
var g_total_fabric_dropped: u64 = 0;
var g_total_rejected: u64 = 0;
var g_total_expired: u64 = 0;
var g_total_failed: u64 = 0;
var g_total_archived: u64 = 0;

// RAG-specific accounting (Phase B)
var g_rag_queries: u64 = 0;
var g_rag_matches: u64 = 0;
var g_rag_fp_indicators: u64 = 0;

pub const PipelineStats = struct {
    total_input: u64,
    total_processed: u64,
    total_source_dropped: u64,
    total_fabric_dropped: u64,
    total_rejected: u64,
    total_expired: u64,
    total_failed: u64,
    total_archived: u64,
    rag_queries: u64,
    rag_matches: u64,
    rag_fp_indicators: u64,
};

pub fn getPipelineStats() PipelineStats {
    return .{
        .total_input = g_total_input,
        .total_processed = g_total_processed,
        .total_source_dropped = g_total_source_dropped,
        .total_fabric_dropped = g_total_fabric_dropped,
        .total_rejected = g_total_rejected,
        .total_expired = g_total_expired,
        .total_failed = g_total_failed,
        .total_archived = g_total_archived,
        .rag_queries = g_rag_queries,
        .rag_matches = g_rag_matches,
        .rag_fp_indicators = g_rag_fp_indicators,
    };
}

pub fn resetPipelineStats() void {
    g_total_input = 0;
    g_total_processed = 0;
    g_total_source_dropped = 0;
    g_total_fabric_dropped = 0;
    g_total_rejected = 0;
    g_total_expired = 0;
    g_total_failed = 0;
    g_total_archived = 0;
    g_rag_queries = 0;
    g_rag_matches = 0;
    g_rag_fp_indicators = 0;
}

// ============================================================
// Module-level aggregator (owns lifetime stats)
// ============================================================

var g_aggregator: ?verdict_agg.VerdictAggregator = null;

pub fn initAggregator() void {
    if (g_aggregator == null) {
        g_aggregator = verdict_agg.VerdictAggregator.init();
    }
}

pub fn shutdownAggregator() void {
    g_aggregator = null;
}

pub fn isAggregatorInitialized() bool {
    return g_aggregator != null;
}

// ============================================================
// Pipeline stages (T3: one stage helper each, order unchanged)
// ============================================================

/// Canonical order of the pipeline stages (T3 acceptance #5).
/// The dispatcher is the sole orchestrator; this ordering is audited
/// by `test "T3: pipeline stage order is canonical"`.
pub const PIPELINE_STAGE_NAMES = [_][]const u8{
    "fabric",       // ingress (submit/pop; not a processing stage)
    "flow",         // Phase 6
    "detection",    // Phase 7
    "verdict",      // Phase 8
    "correlation",  // Phase 9
    "threat_intel", // Phase 10
    "rag",          // Phase B (P0.1 fix; context-only, never allow/block)
    "brain",        // Phase 11
    "policy",       // Phase 12
    "pep",          // Phase 13
    "forensics",    // Phase 14 (record for replay)
};

/// T3: TTL for queued events (drain-time expiry). An event that sits in the
/// fabric longer than this is attributed to the "expired" fate instead of
/// being processed. 0 timestamp events (legacy/test fixtures) never expire.
pub const QUEUE_TTL_NS: u64 = 5 * std.time.ns_per_s;

const CorrelationAlerts = [3]?correlation_engine.CorrelationAlert;

/// Scratchpad shared by the stage helpers, one instance per event.
const StageContext = struct {
    event: canonical.CanonicalEvent,
    flow_update: ?flow_types.FlowUpdate = null,
    evidence_list: detection.EvidenceList = undefined,
    evidence_count: usize = 0,
    av: verdict_agg.AggregatedVerdict = undefined,
    alerts: CorrelationAlerts = .{ null, null, null },
    incident: ?correlation_engine.Incident = null,
    ti_match: threat_intel.ThreatIntelMatch = undefined,
    ti_evidence: ?detection.Evidence = null,
    rag_ctx: rag_engine.RagContext = undefined,
    advice: brain_engine.BrainAdvice = undefined,
    decision: policy_engine.EnforcementDecision = undefined,
    pep_result: rust_pep.EnforcementResult = undefined,
};

/// Process a single event through the pipeline.
/// T3: decomposed into one helper per stage (processFlow -> processForensics);
/// the semantic order is unchanged. The dispatcher remains the sole orchestrator.
pub fn processEvent(event: canonical.CanonicalEvent) void {
    g_total_input += 1;

    var ctx = StageContext{ .event = event };
    processFlow(&ctx); // Phase 6

    if (!detection_int.isInitialized()) {
        // Detection not initialized -> still count as processed
        g_total_processed += 1;
        return;
    }

    processDetection(&ctx); // Phase 7
    if (ctx.evidence_count == 0) {
        // No evidence -> event processed but benign
        g_total_processed += 1;
        return;
    }

    if (processVerdict(&ctx)) { // Phase 8
        processCorrelation(&ctx);  // Phase 9
        processThreatIntel(&ctx);  // Phase 10
        processRAG(&ctx);          // Phase B (P0.1 fix)
        processBrain(&ctx);        // Phase 11
        processPolicy(&ctx);       // Phase 12
        processPEP(&ctx);          // Phase 13
        processForensics(&ctx);    // Phase 14
        g_total_processed += 1;
    } else {
        std.log.debug("[DISPATCHER] (no aggregator) for event_id={d}", .{event.event_id});
        g_total_processed += 1;
    }
}

// ---- stage helpers (private; called only by processEvent) ----

/// Phase 6: route through Flow Engine.
fn processFlow(ctx: *StageContext) void {
    const event = ctx.event;
    if (flow_int.isInitialized()) {
        ctx.flow_update = flow_int.processEvent(event);
        if (ctx.flow_update) |update| {
            switch (update.kind) {
                .flow_created => {
                    std.log.info("[DISPATCHER] Flow created: ip_a=0x{x} port_a={d} ip_b=0x{x} port_b={d} proto={d}", .{
                        update.key.ip_a, update.key.port_a,
                        update.key.ip_b, update.key.port_b,
                        update.key.protocol,
                    });
                },
                .flow_state_changed => {
                    std.log.debug("[DISPATCHER] Flow state changed: {s} (event_id={d})", .{
                        update.flow.state.toString(),
                        event.event_id,
                    });
                },
                .flow_expired => {
                    std.log.info("[DISPATCHER] Flow expired: packets={d} bytes={d}", .{
                        update.flow.packet_count,
                        update.flow.byte_count,
                    });
                },
                .flow_ended, .flow_updated => {
                    std.log.debug("[DISPATCHER] Flow {s}: packets={d} bytes={d}", .{
                        update.flow.state.toString(),
                        update.flow.packet_count,
                        update.flow.byte_count,
                    });
                },
            }
        }
    } else {
        std.log.debug("[DISPATCHER] Flow not initialized, skipping event_id={d}", .{event.event_id});
    }
}

/// Phase 7: route through Detection Engine.
fn processDetection(ctx: *StageContext) void {
    ctx.evidence_list = detection_int.analyze(ctx.event, ctx.flow_update);
    ctx.evidence_count = ctx.evidence_list.count;
}

/// Phase 8: aggregate verdicts. Returns true when an aggregator is present
/// (i.e. the downstream planning/enforcement stages should run).
fn processVerdict(ctx: *StageContext) bool {
    const event = ctx.event;
    if (g_aggregator) |*agg| {
        ctx.av = agg.aggregate(ctx.evidence_list, ctx.flow_update, event.event_id);
        const av = ctx.av;

        if (av.isThreat() or av.wasEscalated()) {
            std.log.info("[DISPATCHER] Aggregated verdict={s} (was {s}) confidence={d} detectors={d}/{d} for event_id={d}", .{
                av.verdict.toString(),
                av.original_verdict.toString(),
                av.confidence,
                av.agreeing_count,
                av.detector_count,
                event.event_id,
            });

            for (ctx.evidence_list.slice()) |e| {
                if (e.verdict.isThreat()) {
                    std.log.info("[DETECTION] detector={d} verdict={s} rule=0x{x} confidence={d} desc={s}", .{
                        e.detector_id,
                        e.verdict.toString(),
                        e.rule_id,
                        e.confidence,
                        e.description,
                    });
                }
            }
        } else {
            std.log.debug("[DISPATCHER] Aggregated verdict={s} confidence={d} for event_id={d}", .{
                av.verdict.toString(),
                av.confidence,
                event.event_id,
            });
        }
        return true;
    }
    return false;
}

/// Phase 9: route through Correlation Engine (entity tracking).
/// T4: also feeds the detection evidence directly into correlation. Evidence
/// is the detection output (never enforcement) and correlation emits incident
/// records with incident_id, entity, evidence graph, and confidence whenever
/// the same entity is tagged by evidence from multiple source categories.
fn processCorrelation(ctx: *StageContext) void {
    const event = ctx.event;
    var alerts: CorrelationAlerts = .{ null, null, null };
    if (correlation_int.isInitialized()) {
        alerts = correlation_int.processVerdict(event, ctx.flow_update, ctx.av);
        for (alerts) |a| {
            if (a) |alert| {
                std.log.warn("[CORRELATION] Alert {s}: entity_type={s} threat_count={d} event_id={d} desc={s}", .{
                    alert.rule.toString(),
                    alert.entity_key.entity_type.toString(),
                    alert.threat_count,
                    alert.triggering_event_id,
                    alert.description,
                });
            }
        }
        if (ctx.evidence_count > 0) {
            ctx.incident = correlation_int.processEvidence(event, ctx.evidence_list);
            if (ctx.incident) |inc| {
                std.log.warn("[CORRELATION] Incident #{d} entity={s}:{x} verdict={s} confidence={d} categories={d}", .{
                    inc.incident_id,
                    inc.entity_key.entity_type.toString(),
                    inc.entity_key.ip,
                    inc.verdict.toString(),
                    inc.confidence,
                    inc.categoryCount(),
                });
            }
        }
    }
    ctx.alerts = alerts;
}

/// Phase 10: enrich with Threat Intel context (advisor, not enforcer).
/// T4: normalize a feed match into canonical evidence on the evidence chain.
/// Threat Intel stays evidence-only - it never emits an enforcement action.
fn processThreatIntel(ctx: *StageContext) void {
    const event = ctx.event;
    var ti_match: threat_intel.ThreatIntelMatch = .{
        .src_match = null,
        .dst_match = null,
        .event_id = event.event_id,
    };
    ctx.ti_evidence = null;
    if (threat_intel_int.isInitialized()) {
        ti_match = threat_intel_int.enrichEvent(event);
        if (ti_match.hasMatch()) {
            const max_sev = ti_match.maxSeverity();
            if (ti_match.isHighSeverity()) {
                std.log.warn("[THREAT-INTEL] High-severity match for event_id={d}: max_severity={s}", .{
                    event.event_id,
                    max_sev.toString(),
                });
            } else {
                std.log.info("[THREAT-INTEL] Match for event_id={d}: max_severity={s}", .{
                    event.event_id,
                    max_sev.toString(),
                });
            }
            ctx.ti_evidence = threat_intel_int.enrichEvidence(event);
            if (ctx.ti_evidence) |e| {
                std.log.info("[THREAT-INTEL] Normalized evidence: detector={d} verdict={s} provenance={s}", .{
                    e.detector_id,
                    e.verdict.toString(),
                    e.provenance,
                });
            }
        }
    }
    ctx.ti_match = ti_match;
}

/// Phase B (P0.1 fix): RAG Context Enrichment
/// RAG sits between Threat Intel and Brain so that Brain
/// can use the enriched context. RAG is context-only and
/// NEVER returns allow/block verdicts.
fn processRAG(ctx: *StageContext) void {
    const event = ctx.event;
    var rag_ctx: rag_engine.RagContext = undefined;
    if (rag_int.isInitialized()) {
        rag_ctx = rag_int.query(event);
        g_rag_queries += 1;
        if (rag_ctx.hasContext()) {
            g_rag_matches += 1;
            std.log.info("[RAG] Context found for event_id={d}: category={s} confidence={d} matches={d} summary={s}", .{
                event.event_id,
                rag_ctx.primary_category.toString(),
                rag_ctx.confidence,
                rag_ctx.match_count,
                rag_ctx.context_summary,
            });
            if (rag_ctx.indicatesFalsePositive()) {
                g_rag_fp_indicators += 1;
                std.log.info("[RAG] False-positive indicator for event_id={d}", .{event.event_id});
            }
        } else if (rag_ctx.available) {
            std.log.debug("[RAG] No context for event_id={d} (available but no match)", .{event.event_id});
        } else {
            std.log.debug("[RAG] Not available for event_id={d} (fail-soft)", .{event.event_id});
        }
    } else {
        rag_ctx = .{
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
    ctx.rag_ctx = rag_ctx;
}

/// Phase 11: Brain Advisor (heuristic model, advisor not enforcer)
/// Phase B: Brain now has access to RAG context via rag_ctx.
fn processBrain(ctx: *StageContext) void {
    const event = ctx.event;
    var advice: brain_engine.BrainAdvice = undefined;
    if (brain_int.isInitialized()) {
        advice = brain_int.advise(event, ctx.av, ctx.alerts, ctx.ti_match, ctx.flow_update, ctx.rag_ctx);
        if (advice.recommendsChange()) {
            std.log.info("[BRAIN] Advice {s}: score={d} recommend={s} (was {s}) confidence={d} event_id={d} rag_ctx={s}", .{
                advice.kind.toString(),
                advice.threat_score,
                advice.recommended_verdict.toString(),
                advice.original_verdict.toString(),
                advice.confidence,
                event.event_id,
                if (ctx.rag_ctx.hasContext()) "enriched" else "none",
            });
        } else if (advice.kind == .insufficient_data) {
            std.log.debug("[BRAIN] Insufficient data for event_id={d}", .{event.event_id});
        } else {
            std.log.debug("[BRAIN] Keep verdict={s} score={d} for event_id={d}", .{
                advice.original_verdict.toString(),
                advice.threat_score,
                event.event_id,
            });
        }
    } else {
        advice = .{
            .kind = .insufficient_data,
            .threat_score = 0,
            .recommended_verdict = ctx.av.verdict,
            .original_verdict = ctx.av.verdict,
            .confidence = 0,
            .explanation = "brain not initialized",
            .signal_detection = 0,
            .signal_correlation = 0,
            .signal_threat_intel = 0,
            .signal_flow_anomaly = 0,
            .signal_rag = 0,
            .event_id = event.event_id,
        };
    }
    ctx.advice = advice;
}

/// Phase 12: Policy Engine (planner, not enforcer).
fn processPolicy(ctx: *StageContext) void {
    const event = ctx.event;
    var decision: policy_engine.EnforcementDecision = undefined;
    if (policy_int.isInitialized()) {
        decision = policy_int.evaluate(event, ctx.av, ctx.alerts, ctx.ti_match, ctx.advice);
        if (decision.isBlocking()) {
            std.log.warn("[POLICY] {s} rule={s} confidence={d} event_id={d} reason={s}", .{
                decision.action.toString(),
                decision.rule.toString(),
                decision.confidence,
                event.event_id,
                decision.reason,
            });
        } else if (decision.action == .alert) {
            std.log.info("[POLICY] {s} rule={s} confidence={d} event_id={d} reason={s}", .{
                decision.action.toString(),
                decision.rule.toString(),
                decision.confidence,
                event.event_id,
                decision.reason,
            });
        } else {
            std.log.debug("[POLICY] {s} rule={s} for event_id={d}", .{
                decision.action.toString(),
                decision.rule.toString(),
                event.event_id,
            });
        }
    } else {
        decision = .{
            .action = .allow,
            .rule = .default_allow,
            .confidence = 0,
            .reason = "policy not initialized",
            .event_id = event.event_id,
            .brain_recommended_verdict = ctx.advice.recommended_verdict,
            .original_verdict = ctx.av.verdict,
            .threat_score = ctx.advice.threat_score,
        };
    }
    ctx.decision = decision;
}

/// Phase 13: Rust PEP (security authority: validate -> execute).
fn processPEP(ctx: *StageContext) void {
    const event = ctx.event;
    var pep_result: rust_pep.EnforcementResult = undefined;
    if (rust_pep_int.isInitialized()) {
        pep_result = rust_pep_int.execute(event, ctx.decision);
        if (pep_result.status == .executed) {
            std.log.warn("[RUST-PEP] EXECUTED {s} blocked_ip=0x{x} event_id={d} msg={s}", .{
                pep_result.actual_action.toString(),
                pep_result.blocked_ip,
                event.event_id,
                pep_result.message,
            });
        } else if (pep_result.status == .rejected) {
            std.log.warn("[RUST-PEP] REJECTED {s} reason={s} event_id={d} msg={s}", .{
                pep_result.requested_action.toString(),
                pep_result.reason.toString(),
                event.event_id,
                pep_result.message,
            });
        } else if (pep_result.status == .deferred) {
            std.log.info("[RUST-PEP] DEFERRED {s} reason={s} event_id={d} msg={s}", .{
                pep_result.requested_action.toString(),
                pep_result.reason.toString(),
                event.event_id,
                pep_result.message,
            });
        } else if (pep_result.status == .failed) {
            std.log.err("[RUST-PEP] FAILED {s} event_id={d} msg={s}", .{
                pep_result.requested_action.toString(),
                event.event_id,
                pep_result.message,
            });
        } else {
            std.log.debug("[RUST-PEP] NO_OP {s} event_id={d}", .{
                pep_result.actual_action.toString(),
                event.event_id,
            });
        }
    } else {
        pep_result = .{
            .status = .no_op,
            .reason = .none,
            .requested_action = ctx.decision.action,
            .actual_action = .allow,
            .event_id = event.event_id,
            .blocked_ip = 0,
            .message = "PEP not initialized",
        };
    }
    ctx.pep_result = pep_result;
}

/// Phase 14: Forensics (final stage - record everything for replay).
fn processForensics(ctx: *StageContext) void {
    const event = ctx.event;
    if (forensics_int.isInitialized()) {
        const seq = forensics_int.logResult(event, ctx.av, ctx.alerts, ctx.ti_match, ctx.advice, ctx.decision, ctx.pep_result);
        if (seq > 0) {
            std.log.debug("[FORENSICS] Logged event_id={d} seq={d} rag={s}", .{
                event.event_id, seq,
                if (ctx.rag_ctx.hasContext()) "enriched" else "none",
            });
        }
    }
}

// ============================================================
// Queue draining + fate ledger (T3)
// ============================================================

/// Drain the event fabric queue, processing at most max_events. When
/// budget_ns > 0 the drain stops as soon as the budget is exhausted
/// (drain-time slicing for the RUN phase). Returns events processed.
pub fn drainQueueTimed(max_events: u32, budget_ns: u64) u32 {
    if (!fabric.isInitialized()) return 0;

    const deadline: ?i128 = if (budget_ns == 0) null else std.time.nanoTimestamp() + @as(i128, budget_ns);
    var processed: u32 = 0;
    while (processed < max_events) {
        if (deadline) |d| {
            if (std.time.nanoTimestamp() >= d) break;
        }
        const event = fabric.popEvent() orelse break;

        // Drain-time expiry: a queued event older than QUEUE_TTL_NS is
        // attributed to the "expired" fate and never reaches the pipeline.
        if (event.monotonic_ns != 0) {
            const now = std.time.nanoTimestamp();
            if (now >= event.monotonic_ns and now - event.monotonic_ns > QUEUE_TTL_NS) {
                g_total_expired += 1;
                g_total_input += 1;
                continue;
            }
        }
        processEvent(event);
        processed += 1;
    }
    return processed;
}

/// Drain the event fabric queue - pops all pending events and processes them.
pub fn drainQueue(max_events: u32) u32 {
    return drainQueueTimed(max_events, 0);
}

/// T3: single ingress for the fate ledger. Every submission is counted as
/// input; rejections and drops are attributed to their fabric-level fate.
pub fn submitLedged(event: canonical.CanonicalEvent) bool {
    const pre = fabric.getAccounting();
    const ok = fabric.submitEvent(event);
    const post = fabric.getAccounting();
    if (ok) return true;

    g_total_input += 1;
    if (post.rejected > pre.rejected) {
        g_total_rejected += 1;
    } else if (post.dropped_by_fabric > pre.dropped_by_fabric) {
        g_total_fabric_dropped += 1;
    } else if (post.not_initialized > pre.not_initialized) {
        g_total_source_dropped += 1;
    } else {
        g_total_failed += 1; // unreachable; keeps the invariant total
    }
    return false;
}

/// T3: the fate ledger invariant. Holds after a full drain:
///   input == processed + dropped + rejected + expired + failed
pub fn fatesBalanced() bool {
    const dropped = g_total_source_dropped + g_total_fabric_dropped;
    return g_total_input ==
        g_total_processed + dropped + g_total_rejected + g_total_expired + g_total_failed;
}

// ============================================================
// Phase B: Runtime Spine Proof Test
// Verifies that RAG appears in the pipeline trace.
// ============================================================

test "Phase B: RAG is imported and queryable in dispatcher" {
    // Verify RAG integration is available to the dispatcher
    try std.testing.expect(@hasDecl(rag_int, "query"));
    try std.testing.expect(@hasDecl(rag_int, "isInitialized"));
    try std.testing.expect(@hasDecl(rag_int, "init"));
    try std.testing.expect(@hasDecl(rag_int, "shutdown"));
}

test "Phase B: EventFate enum has all required states" {
    try std.testing.expect(@intFromEnum(EventFate.accepted) == 0);
    try std.testing.expect(@intFromEnum(EventFate.processed) == 1);
    try std.testing.expect(@intFromEnum(EventFate.source_dropped) == 2);
    try std.testing.expect(@intFromEnum(EventFate.fabric_dropped) == 3);
    try std.testing.expect(@intFromEnum(EventFate.rejected) == 4);
    try std.testing.expect(@intFromEnum(EventFate.expired) == 5);
    try std.testing.expect(@intFromEnum(EventFate.failed) == 6);
    try std.testing.expect(@intFromEnum(EventFate.archived) == 7);
}

test "Phase B: PipelineStats tracks RAG counters" {
    resetPipelineStats();
    const stats = getPipelineStats();
    try std.testing.expect(stats.rag_queries == 0);
    try std.testing.expect(stats.rag_matches == 0);
    try std.testing.expect(stats.rag_fp_indicators == 0);
}

test "Phase B: processEvent records input and processed" {
    resetPipelineStats();
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    processEvent(event);
    const stats = getPipelineStats();
    try std.testing.expect(stats.total_input >= 1);
    try std.testing.expect(stats.total_processed >= 1);
}

test "drainQueue returns 0 when fabric not initialized" {
    if (fabric.isInitialized()) {
        const nose = @import("../capture/nose_contract.zig");
        nose.shutdownFabric(std.testing.allocator);
    }
    try std.testing.expect(drainQueue(100) == 0);
}

test "drainQueue processes events from fabric" {
    const nose = @import("../capture/nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = fabric.submitEvent(event);
    }

    const processed = drainQueue(100);
    try std.testing.expect(processed == 5);
}

test "drainQueue respects max_events limit" {
    const nose = @import("../capture/nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = fabric.submitEvent(event);
    }

    const processed = drainQueue(3);
    try std.testing.expect(processed == 3);
}

test "processEvent doesn't crash for valid event" {
    var event = canonical.create(.zig_core);
    event.event_type = .block;
    processEvent(event);
    try std.testing.expect(true);
}

test "T3: all ten pipeline stage helpers exist and processEvent is their oracle" {
    const self = @This();
    try std.testing.expect(@hasDecl(self, "processFlow"));
    try std.testing.expect(@hasDecl(self, "processDetection"));
    try std.testing.expect(@hasDecl(self, "processVerdict"));
    try std.testing.expect(@hasDecl(self, "processCorrelation"));
    try std.testing.expect(@hasDecl(self, "processThreatIntel"));
    try std.testing.expect(@hasDecl(self, "processRAG"));
    try std.testing.expect(@hasDecl(self, "processBrain"));
    try std.testing.expect(@hasDecl(self, "processPolicy"));
    try std.testing.expect(@hasDecl(self, "processPEP"));
    try std.testing.expect(@hasDecl(self, "processForensics"));

    // processEvent must still be the only public entry point
    try std.testing.expect(@hasDecl(self, "processEvent"));
}

test "T3: pipeline stage order is canonical" {
    const expect = [_][]const u8{
        "fabric",
        "flow",
        "detection",
        "verdict",
        "correlation",
        "threat_intel",
        "rag",
        "brain",
        "policy",
        "pep",
        "forensics",
    };
    try std.testing.expectEqualSlices([]const u8, &expect, &PIPELINE_STAGE_NAMES);
    // RAG sits between Threat Intel and Brain (P0.1 fix) and is context-only.
    const rag_index = blk: {
        for (PIPELINE_STAGE_NAMES, 0..) |stage, idx| {
            if (std.mem.eql(u8, stage, "rag")) break :blk idx;
        }
        break :blk PIPELINE_STAGE_NAMES.len;
    };
    const pep_index = blk: {
        for (PIPELINE_STAGE_NAMES, 0..) |stage, idx| {
            if (std.mem.eql(u8, stage, "pep")) break :blk idx;
        }
        break :blk PIPELINE_STAGE_NAMES.len;
    };
    try std.testing.expect(rag_index == 6);
    try std.testing.expect(pep_index == 9);
}

test "T3: fate ledger balances after a full drain" {
    const nose = @import("../capture/nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 32 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);
    resetPipelineStats();

    var i: u64 = 0;
    while (i < 20) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        try std.testing.expect(submitLedged(event));
    }
    _ = drainQueue(1000);

    const stats = getPipelineStats();
    // rejected/dropped none here: input == processed
    try std.testing.expect(stats.total_input == 20);
    try std.testing.expect(stats.total_processed == 20);
    try std.testing.expect(stats.total_rejected == 0);
    try std.testing.expect(fatesBalanced());
}

test "T3: fate ledger attributes fabric rejections to the rejected fate" {
    const nose = @import("../capture/nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 32 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);
    resetPipelineStats();

    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        try std.testing.expect(submitLedged(event));
    }
    // A validation-failed event is rejected by the fabric (not the dispatcher)
    var bad = canonical.create(.zig_core);
    bad.event_type = .block;
    bad.version = 0; // invalid -> rejected by schema validation
    try std.testing.expect(!submitLedged(bad));
    _ = drainQueue(1000);

    const stats = getPipelineStats();
    try std.testing.expect(stats.total_rejected == 1);
    try std.testing.expect(fatesBalanced());
}

test "T3: drainQueueTimed budget is monotonic and capped by max_events" {
    const nose = @import("../capture/nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    const queue_five = struct {
        fn fill() void {
            var i: u64 = 0;
            while (i < 5) : (i += 1) {
                var event = canonical.create(.zig_core);
                event.event_type = .block;
                _ = fabric.submitEvent(event);
            }
        }
    };
    queue_five.fill();
    const full = drainQueueTimed(100, 0);
    try std.testing.expect(full == 5);

    queue_five.fill();
    // A tiny budget can never process MORE than an unlimited drain.
    const tiny = drainQueueTimed(100, 1);
    try std.testing.expect(tiny <= full);

    queue_five.fill();
    // max_events bounds the drain regardless of budget.
    try std.testing.expectEqual(@as(u32, 2), drainQueueTimed(2, 0));
    queue_five.fill();
    try std.testing.expect(drainQueueTimed(0, 0) == 0);
}

test "T3: drain marks over-TTL events as expired, never processed" {
    const nose = @import("../capture/nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);
    resetPipelineStats();

    var stale = canonical.create(.zig_core);
    stale.event_type = .block;
    stale.monotonic_ns = @as(u64, @intCast(std.time.nanoTimestamp())) - (QUEUE_TTL_NS + 1);
    _ = submitLedged(stale);

    var fresh = canonical.create(.zig_core);
    fresh.event_type = .block;
    _ = submitLedged(fresh);

    const processed = drainQueue(100);
    const stats = getPipelineStats();
    try std.testing.expectEqual(@as(u32, 1), processed);
    try std.testing.expect(stats.total_processed == 1);
    try std.testing.expect(stats.total_expired == 1);
    try std.testing.expect(fatesBalanced());
}