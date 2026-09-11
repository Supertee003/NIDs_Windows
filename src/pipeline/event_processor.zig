//! Detection pipeline: event processing and the pipeline loop.
//!
//! Extracted from main.zig. processEvent() runs one queued event through
//! flow lookup, signature matching, anomaly detection, threat tracking,
//! policy evaluation, PEP enforcement, and forensic recording. pipelineLoop()
//! drains the queue until shutdown.

const std = @import("std");
const builtin = @import("builtin");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const flow = @import("../capture/flow_table.zig");
const sig = @import("../detection/signature_engine.zig");
const anom = @import("../detection/anomaly_detector.zig");
const tracker = @import("../detection/threat_tracker.zig");
const policy = @import("../policy/policy_ir.zig");
const pep = @import("../policy/pep_bindings.zig");
const forensic = @import("../forensic/forensic_pipeline.zig");
const trace_mod = @import("../forensic/decision_trace.zig");
const dispatcher = @import("../policy/action_dispatcher.zig");
const watchdog = @import("../reliability/watchdog.zig");
const hist = @import("../reliability/latency_histogram.zig");
const state = @import("runtime_state.zig");
const queue = @import("event_queue.zig");

/// Process a single event through the detection pipeline:
///   1. Flow table lookup/update
///   2. Aho-Corasick signature matching
///   3. Anomaly detection
///   4. Threat tracking
///   5. Forensic recording
fn processEvent(
    qe: *const queue.QueuedEvent,
    _: *sig.AhoCorasick, // using g_active_ac global instead
    ad: *anom.AnomalyDetector,
    ft: *flow.FlowTable,
    tt: *tracker.ThreatTracker,
    ps: *policy.PolicySet,
    pep_enf: *pep.PepEnforcer,
    forensic_ring: *forensic.ForensicRing,
    _: u32, // using g_rules_loaded global instead
    _: hist.Stage, // performance tracking (reserved for future use)
) !void {
    const ev = &qe.ev;
    state.g_pipeline_events_processed += 1;

    // Create security decision trace (128 bytes on stack)
    state.g_trace_id += 1;
    var decision_trace = trace_mod.SecurityDecisionTrace.init(state.g_trace_id, ev);

    // 1. Flow table: lookup or create flow for this event's 5-tuple
    const src_ip_bytes: [16]u8 = blk: {
        var ip: [16]u8 = [_]u8{0} ** 16;
        const src_bytes: [4]u8 = @bitCast(ev.src_ip);
        @memcpy(ip[0..4], &src_bytes);
        break :blk ip;
    };
    const dst_ip_bytes: [16]u8 = blk: {
        var ip: [16]u8 = [_]u8{0} ** 16;
        const dst_bytes: [4]u8 = @bitCast(ev.dst_ip);
        @memcpy(ip[0..4], &dst_bytes);
        break :blk ip;
    };
    const fkey = flow.FlowKey.normalize(src_ip_bytes, dst_ip_bytes, ev.src_port, ev.dst_port, ev.protocol, false);
    _ = ft.lookupOrCreate(fkey, ev.timestamp_ns);

    // 2. Aho-Corasick signature matching (if rules are loaded)
    // Use mutex-protected global AC pointer for hot-reload support
    var matched_rule_id: u32 = 0;
    if (qe.payload_len > 0) {
        state.g_ac_mutex.lock();
        const active_ac = state.g_active_ac;
        state.g_ac_mutex.unlock();
        if (active_ac) |the_ac| {
            const payload_slice = qe.payload[0..qe.payload_len];
            const matches = the_ac.match(payload_slice, std.heap.page_allocator) catch &[_]sig.AhoCorasick.Match{};
            if (matches.len > 0) {
                matched_rule_id = matches[0].rule_id;
                state.g_pipeline_detections += 1;
            }
            if (matches.len > 0) {
                std.heap.page_allocator.free(matches);
            }
        }
    }

    // 3. Anomaly detection
    const anom_key = anom.EntityKey{ .src_ip = blk: {
        var ip: [16]u8 = [_]u8{0} ** 16;
        const src_b: [4]u8 = @bitCast(ev.src_ip);
        @memcpy(ip[0..4], &src_b);
        break :blk ip;
    }, .metric_kind = 1 }; // 1 = packet rate
    _ = ad.observe(anom_key, 1.0) catch null;

    // 4. Threat tracking (if detection matched)
    // Capture incident result — escalate severity when threshold crossed
    var active_incident: ?tracker.Incident = null;
    var ev_severity = ev.severity; // track severity escalation
    if (matched_rule_id != 0) {
        if (tt.observeFlowThreat(ev, 10) catch null) |inc| {
            // Incident created: threat score crossed threshold
            active_incident = inc.*;
            // Escalate event severity to incident severity
            ev_severity = inc.severity;
            state.g_pipeline_detections += 1; // incident = significant detection
            state.g_incidents_total += 1; // track total incidents
            state.g_incidents_open += 1; // track open incidents
        }
    }

    // Record detection result in trace
    decision_trace.setDetection(
        matched_rule_id,
        if (active_incident) |inc| @as(u64, inc.id) else @as(u64, 0),
        if (active_incident) |inc| @as(u8, @intFromEnum(inc.severity)) else @as(u8, 0),
    );

    // 5. Policy evaluation — use escalated severity for policy matching
    var policy_action: policy.Action = .pass;
    var matched_policy: ?policy.Policy = null;
    var ev_copy = ev.*; // mutable copy for severity override
    ev_copy.severity = ev_severity;
    const eval_ctx = policy.EvalContext{ .ev = &ev_copy };
    if (ps.evaluate(eval_ctx)) |pol| {
        matched_policy = pol;
        policy_action = pol.action;
        // Record policy match in trace (Policy has no version field; use 1)
        decision_trace.setPolicy(pol.id, 1);
    }

    // 6. PEP enforcement (final authorization gate)
    // Only PEP call — ActionDispatcher must NOT call PEP again
    var pep_decision: pep.PepDecision = .allow;
    if (matched_policy) |pol| {
        // Unique PEP request ID (not event_id)
        state.g_pep_request_id += 1;
        pep_decision = pep_enf.enforce(&ev_copy, pol, 0, 0xFFFFFFFF, state.g_pep_request_id); // caller_pid=0, all caps
        state.g_pipeline_detections += 1; // policy matched = detection event

        // Record PEP decision in trace
        decision_trace.setPepDecision(state.g_pep_request_id, @intFromEnum(pep_decision));

        // 6a. Action dispatch (execute enforcement action)
        // dispatcher receives PEP decision — does NOT re-evaluate PEP
        dispatcher.ActionDispatcher.dispatch(&ev_copy, pol, pep_decision);
    }

    // Audit trace — every security decision gets a unique audit_id
    const audit_id = state.g_pipeline_audit_id;
    state.g_pipeline_audit_id += 1;
    decision_trace.setAuditId(audit_id);

    // Structured audit log from trace
    diag.info("AUDIT trace_id={} audit_id={} event_id={} rule={} incident={} policy={} pep_req={} decision={s} result={s} src={x}:{d} dst={x}:{d} proto={d}", .{
        decision_trace.trace_id,
        audit_id,
        ev.event_id,
        decision_trace.matched_rule_id,
        decision_trace.incident_id,
        decision_trace.policy_id,
        decision_trace.pep_request_id,
        @tagName(pep_decision),
        @tagName(@as(trace_mod.TraceResult, @enumFromInt(decision_trace.result))),
        ev.src_ip,
        ev.src_port,
        ev.dst_ip,
        ev.dst_port,
        ev.protocol,
    });

    // 7. Forensic recording (captures full pipeline result)
    _ = forensic_ring.append(ev, qe.payload[0..qe.payload_len], audit_id, if (matched_policy) |pol| pol.id else @as(u32, 0), @intFromEnum(pep_decision), @intFromEnum(ev.severity)) catch 0;
}

/// Main pipeline loop: pops events from queue and processes them.
/// Runs on its own thread in daemon mode.
pub fn pipelineLoop(
    ac: *sig.AhoCorasick,
    ad: *anom.AnomalyDetector,
    ft: *flow.FlowTable,
    tt: *tracker.ThreatTracker,
    ps: *policy.PolicySet,
    pep_enf: *pep.PepEnforcer,
    forensic_ring: *forensic.ForensicRing,
    rules_loaded: u32,
    wd_idx: usize, // watchdog thread index
) void {
    diag.info("pipeline loop started (queue size: {})", .{queue.PIPELINE_QUEUE_SIZE});

    while (!state.g_stop_requested.load(.acquire)) {
        // Watchdog heartbeat
        state.g_wd.beat(wd_idx);
        // Fault injection — maybe drop processing
        if (state.g_fi.maybeDrop()) {
            state.g_wd.beat(wd_idx); // still beat watchdog on drop
            std.time.sleep(1 * std.time.ns_per_ms);
            continue;
        }

        const maybe_qe = queue.popEvent();
        if (maybe_qe) |qe_val| {
            var qe = qe_val;
            // Fault injection — maybe corrupt event
            _ = state.g_fi.maybeCorrupt(&qe.ev);
            // Performance tracking
            const start = std.time.nanoTimestamp();
            processEvent(&qe, ac, ad, ft, tt, ps, pep_enf, forensic_ring, rules_loaded, hist.Stage.capture_to_decode) catch |err| {
                diag.warn("pipeline processing error: {}", .{err});
            };
            state.g_perf.observe(hist.Stage.capture_to_decode, @intCast(std.time.nanoTimestamp() - start));
        } else {
            // No events — yield briefly
            std.time.sleep(1 * std.time.ns_per_ms);
        }
    }

    diag.info("pipeline loop stopped: processed={}, detections={}, policies_matched={}", .{
        state.g_pipeline_events_processed,
        state.g_pipeline_detections,
        state.g_pipeline_policies_matched,
    });
}
