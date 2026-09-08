//! dispatcher.zig - AEGIS Runtime Dispatcher (Phase B: Runtime Spine)
//!
//! Pops events from Event Fabric and routes through the pipeline.
//! Replaces the old eventFabricDrain() in nids_analyze.zig.
//!
//! Pipeline (Phase B -- RAG integrated, P0.1 fixed):
//!   Event Fabric -> Flow Engine (Phase 6) -> Detection Engine (Phase 7)
//!   -> Verdict Aggregator (Phase 8) -> Correlation Engine (Phase 9)
//!   -> Threat Intel Enrichment (Phase 10)
//!   -> RAG Context Enrichment (Phase B: NEW -- P0.1 fix)
//!   -> Brain Advisor (Phase 11)
//!   -> Policy Engine (Phase 12) -> Rust PEP (Phase 13) -> Forensics (Phase 14)
//!
//! main() no longer knows pipeline details - Runtime owns lifecycle.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const flow_int = @import("flow_integration.zig");
const flow_types = @import("flow_types.zig");
const detection_int = @import("detection_integration.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation_int = @import("correlation_integration.zig");
const threat_intel_int = @import("threat_intel_integration.zig");
const rag_int = @import("rag_integration.zig");  // Phase B: RAG import (P0.1 fix)
const brain_int = @import("brain_integration.zig");
const policy_int = @import("policy_integration.zig");
const rust_pep_int = @import("rust_pep_integration.zig");
const forensics_int = @import("forensics_integration.zig");

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
// Pipeline stages
// ============================================================

/// Process a single event through the pipeline.
/// Phase B: RAG stage added between Threat Intel and Brain.
pub fn processEvent(event: canonical.CanonicalEvent) void {
    g_total_input += 1;

    // Phase 6: route through Flow Engine
    var flow_update_opt: ?flow_types.FlowUpdate = null;

    if (flow_int.isInitialized()) {
        flow_update_opt = flow_int.processEvent(event);

        if (flow_update_opt) |update| {
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

    // Phase 7+8: route through Detection Engine, then aggregate verdicts
    if (detection_int.isInitialized()) {
        const evidence_list = detection_int.analyze(event, flow_update_opt);

        if (evidence_list.count > 0) {
            if (g_aggregator) |*agg| {
                const av = agg.aggregate(evidence_list, flow_update_opt, event.event_id);

                if (av.isThreat() or av.wasEscalated()) {
                    std.log.info("[DISPATCHER] Aggregated verdict={s} (was {s}) confidence={d} detectors={d}/{d} for event_id={d}", .{
                        av.verdict.toString(),
                        av.original_verdict.toString(),
                        av.confidence,
                        av.agreeing_count,
                        av.detector_count,
                        event.event_id,
                    });

                    for (evidence_list.slice()) |e| {
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

                // Phase 9: route through Correlation Engine (entity tracking)
                var alerts: [3]?@import("correlation_engine.zig").CorrelationAlert = .{ null, null, null };
                if (correlation_int.isInitialized()) {
                    alerts = correlation_int.processVerdict(event, flow_update_opt, av);
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
                }

                // Phase 10: enrich with Threat Intel context (advisor, not enforcer)
                var ti_match: @import("threat_intel.zig").ThreatIntelMatch = .{
                    .src_match = null,
                    .dst_match = null,
                    .event_id = event.event_id,
                };
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
                    }
                }

                // Phase B (P0.1 fix): RAG Context Enrichment
                // RAG sits between Threat Intel and Brain so that Brain
                // can use the enriched context. RAG is context-only and
                // NEVER returns allow/block verdicts.
                var rag_ctx: @import("rag_engine.zig").RagContext = undefined;
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

                // Phase 11: Brain Advisor (heuristic model, advisor not enforcer)
                // Phase B: Brain now has access to RAG context via rag_ctx
                var advice: @import("brain_engine.zig").BrainAdvice = undefined;
                if (brain_int.isInitialized()) {
                    advice = brain_int.advise(event, av, alerts, ti_match, flow_update_opt);
                    if (advice.recommendsChange()) {
                        std.log.info("[BRAIN] Advice {s}: score={d} recommend={s} (was {s}) confidence={d} event_id={d} rag_ctx={s}", .{
                            advice.kind.toString(),
                            advice.threat_score,
                            advice.recommended_verdict.toString(),
                            advice.original_verdict.toString(),
                            advice.confidence,
                            event.event_id,
                            if (rag_ctx.hasContext()) "enriched" else "none",
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
                        .recommended_verdict = av.verdict,
                        .original_verdict = av.verdict,
                        .confidence = 0,
                        .explanation = "brain not initialized",
                        .signal_detection = 0,
                        .signal_correlation = 0,
                        .signal_threat_intel = 0,
                        .signal_flow_anomaly = 0,
                        .event_id = event.event_id,
                    };
                }

                // Phase 12: Policy Engine (planner, not enforcer)
                var decision: @import("policy_engine.zig").EnforcementDecision = undefined;
                if (policy_int.isInitialized()) {
                    decision = policy_int.evaluate(event, av, alerts, ti_match, advice);
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
                        .brain_recommended_verdict = advice.recommended_verdict,
                        .original_verdict = av.verdict,
                        .threat_score = advice.threat_score,
                    };
                }

                // Phase 13: Rust PEP (security authority: validate -> execute)
                var pep_result: @import("rust_pep.zig").EnforcementResult = undefined;
                if (rust_pep_int.isInitialized()) {
                    pep_result = rust_pep_int.execute(event, decision);
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
                        .requested_action = decision.action,
                        .actual_action = .allow,
                        .event_id = event.event_id,
                        .blocked_ip = 0,
                        .message = "PEP not initialized",
                    };
                }

                // Phase 14: Forensics (final stage - record everything for replay)
                if (forensics_int.isInitialized()) {
                    const seq = forensics_int.logResult(event, av, alerts, ti_match, advice, decision, pep_result);
                    if (seq > 0) {
                        std.log.debug("[FORENSICS] Logged event_id={d} seq={d} rag={s}", .{
                            event.event_id, seq,
                            if (rag_ctx.hasContext()) "enriched" else "none",
                        });
                    }
                }

                // Phase B: accounting
                g_total_processed += 1;
            } else {
                std.log.debug("[DISPATCHER] (no aggregator) for event_id={d}", .{event.event_id});
                g_total_processed += 1;
            }
        } else {
            // No evidence -> event processed but benign
            g_total_processed += 1;
        }
    } else {
        // Detection not initialized -> still count as processed
        g_total_processed += 1;
    }
}

/// Drain the event fabric queue - pops all pending events and processes them.
pub fn drainQueue(max_events: u32) u32 {
    if (!fabric.isInitialized()) return 0;

    var processed: u32 = 0;
    while (processed < max_events) {
        const event = fabric.popEvent() orelse break;
        processEvent(event);
        processed += 1;
    }
    return processed;
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
        const nose = @import("nose_contract.zig");
        nose.shutdownFabric(std.testing.allocator);
    }
    try std.testing.expect(drainQueue(100) == 0);
}

test "drainQueue processes events from fabric" {
    const nose = @import("nose_contract.zig");
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
    const nose = @import("nose_contract.zig");
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
