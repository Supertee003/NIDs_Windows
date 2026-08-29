//! runtime/dispatcher.zig - AEGIS Runtime Dispatcher (Rewrite Phase 13)
//!
//! Pops events from Event Fabric and routes through the pipeline.
//! Replaces the old eventFabricDrain() in nids_analyze.zig.
//!
//! Pipeline (current):
//!   Event Fabric -> Flow Engine (Phase 6) -> Detection Engine (Phase 7)
//!   -> Verdict Aggregator (Phase 8) -> Correlation Engine (Phase 9)
//!   -> Threat Intel Enrichment (Phase 10) -> Brain Advisor (Phase 11)
//!   -> Policy Engine (Phase 12) -> Rust PEP (Phase 13)
//!   -> [Phase 14+: Forensics]
//!
//! main() no longer knows pipeline details — Runtime owns lifecycle.

const std = @import("std");
const canonical = @import("canonical_event.zig");
const fabric = @import("event_fabric.zig");
const flow_int = @import("flow_integration.zig");
const detection_int = @import("detection_integration.zig");
const verdict_agg = @import("verdict_aggregator.zig");
const correlation_int = @import("correlation_integration.zig");
const threat_intel_int = @import("threat_intel_integration.zig");
const brain_int = @import("brain_integration.zig");
const policy_int = @import("policy_integration.zig");
const rust_pep_int = @import("rust_pep_integration.zig");

// ============================================================
// Module-level aggregator (owns lifetime stats)
// ============================================================

var g_aggregator: ?verdict_agg.VerdictAggregator = null;

/// Initialize the verdict aggregator. Called by lifecycle.start().
pub fn initAggregator() void {
    if (g_aggregator == null) {
        g_aggregator = verdict_agg.VerdictAggregator.init();
    }
}

/// Shutdown the verdict aggregator. Called by lifecycle.shutdown().
pub fn shutdownAggregator() void {
    g_aggregator = null;
}

/// Check if the aggregator is initialized.
pub fn isAggregatorInitialized() bool {
    return g_aggregator != null;
}

// ============================================================
// Pipeline stages
// ============================================================

/// Process a single event through the pipeline.
/// Phase 6: routes through Flow Engine.
/// Phase 7: routes through Detection Engine (evidence producer).
/// Future phases add: correlation -> policy -> forensics.
pub fn processEvent(event: canonical.CanonicalEvent) void {
    // Phase 6: route through Flow Engine
    var flow_update_opt: ?@import("flow_engine.zig").FlowUpdate = null;

    if (flow_int.isInitialized()) {
        flow_update_opt = flow_int.processEvent(event);

        if (flow_update_opt) |update| {
            // Log flow updates (forensics will replace this in Phase 14)
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
                    // Quietly track - logged at debug level only
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
            // Phase 8: use VerdictAggregator instead of naive maxVerdict()
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

                    // Log each threat evidence at info level
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
                            if (ti_match.src_match) |src| {
                                std.log.warn("[THREAT-INTEL]   src_ip=0x{x} severity={s} category={s} confidence={d} source={s}", .{
                                    src.ip,
                                    src.severity.toString(),
                                    src.category.toString(),
                                    src.confidence,
                                    src.source,
                                });
                            }
                            if (ti_match.dst_match) |dst| {
                                std.log.warn("[THREAT-INTEL]   dst_ip=0x{x} severity={s} category={s} confidence={d} source={s}", .{
                                    dst.ip,
                                    dst.severity.toString(),
                                    dst.category.toString(),
                                    dst.confidence,
                                    dst.source,
                                });
                            }
                        } else {
                            std.log.info("[THREAT-INTEL] Match for event_id={d}: max_severity={s}", .{
                                event.event_id,
                                max_sev.toString(),
                            });
                        }
                    }
                }

                // Phase 11: Brain Advisor (heuristic model, advisor not enforcer)
                var advice: @import("brain_engine.zig").BrainAdvice = undefined;
                if (brain_int.isInitialized()) {
                    advice = brain_int.advise(event, av, alerts, ti_match, flow_update_opt);
                    if (advice.recommendsChange()) {
                        std.log.info("[BRAIN] Advice {s}: score={d} recommend={s} (was {s}) confidence={d} event_id={d}", .{
                            advice.kind.toString(),
                            advice.threat_score,
                            advice.recommended_verdict.toString(),
                            advice.original_verdict.toString(),
                            advice.confidence,
                            event.event_id,
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
                    // Brain not initialized - create a no-op advice
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
                    // Policy not initialized - create a default allow decision
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
                if (rust_pep_int.isInitialized()) {
                    const pep_result = rust_pep_int.execute(event, decision);
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
                        // no_op: allow/log_only/alert
                        std.log.debug("[RUST-PEP] NO_OP {s} event_id={d}", .{
                            pep_result.actual_action.toString(),
                            event.event_id,
                        });
                    }
                }
            } else {
                // Aggregator not initialized - fall back to Phase 7 naive maxVerdict
                const max_verdict = evidence_list.maxVerdict();
                std.log.debug("[DISPATCHER] (no aggregator) max verdict={s} for event_id={d}", .{
                    max_verdict.toString(),
                    event.event_id,
                });
            }
        }
    }

    // Phase 14+: forensics_int.logPipelineResult(event, decision, pep_result)
}

/// Drain the event fabric queue — pops all pending events and processes them.
/// Called by worker threads.
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
// Tests
// ============================================================

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

    // Submit some events
    var i: u64 = 0;
    while (i < 5) : (i += 1) {
        var event = canonical.create(.zig_core);
        event.event_type = .block;
        _ = fabric.submitEvent(event);
    }

    // Drain
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

test "processEvent routes through Flow Engine when initialized" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // Initialize Flow Engine (idempotent - safe if already initialized by another test)
    if (!flow_int.isInitialized()) {
        flow_int.init(std.testing.allocator);
    }
    defer flow_int.shutdown();

    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.payload_length = 100;

    processEvent(event);

    // Verify the specific flow was created (robust against parallel test interference).
    // Checking flow_int.count() would be flaky if another test also created a flow.
    const flow_engine = @import("flow_engine.zig");
    const key = flow_engine.FlowKey.fromEvent(event);
    const retrieved = flow_int.getFlow(key);
    try std.testing.expect(retrieved != null);
    try std.testing.expect(retrieved.?.byte_count == 100);
    try std.testing.expect(retrieved.?.packet_count == 1);
}

test "processEvent routes through Detection Engine when initialized" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // Initialize Flow + Detection
    if (!flow_int.isInitialized()) {
        flow_int.init(std.testing.allocator);
    }
    defer flow_int.shutdown();

    if (!detection_int.isInitialized()) {
        detection_int.init();
    }
    defer detection_int.shutdown();

    // Event with rule match -> should produce suspicious evidence
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xDEAD;
    event.severity = 2;

    processEvent(event);

    // Verify detection stats accumulated
    const stats = detection_int.getStats();
    try std.testing.expect(stats.total_analyzed >= 1);
    try std.testing.expect(stats.total_threats >= 1);
}

test "processEvent uses VerdictAggregator when initialized" {
    const nose = @import("nose_contract.zig");
    nose.initFabric(std.testing.allocator, .{ .capacity_per_priority = 16 }) catch {};
    defer nose.shutdownFabric(std.testing.allocator);

    // Initialize Flow + Detection + Aggregator
    if (!flow_int.isInitialized()) {
        flow_int.init(std.testing.allocator);
    }
    defer flow_int.shutdown();

    if (!detection_int.isInitialized()) {
        detection_int.init();
    }
    defer detection_int.shutdown();

    initAggregator();
    defer shutdownAggregator();
    try std.testing.expect(isAggregatorInitialized());

    // Event with critical rule match -> should aggregate to MALICIOUS
    var event = canonical.create(.wfp_sensor);
    event.source_ip = 0x0A000001;
    event.source_port = 12345;
    event.dest_ip = 0x0A000002;
    event.dest_port = 80;
    event.protocol = 6;
    event.rule_id = 0xBEEF;
    event.severity = 3; // critical - rule_match will say MALICIOUS

    processEvent(event);

    // Verify detection ran (stats accumulated)
    const det_stats = detection_int.getStats();
    try std.testing.expect(det_stats.total_analyzed >= 1);
}
