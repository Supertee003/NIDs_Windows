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
const corr_mod = @import("../detection/correlator.zig");
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
const siem_mod = @import("../forensic/siem_forwarder.zig");
const brain_mod = @import("../core/bridge_init.zig");

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
    corr: *corr_mod.Correlator,
    tt: *tracker.ThreatTracker,
    ps: *policy.PolicySet,
    pep_enf: *pep.PepEnforcer,
    forensic_ring: *forensic.ForensicRing,
    _: u32, // using g_rules_loaded global instead
    _: hist.Stage, // performance tracking (reserved for future use)
) !void {
    // Queue entries are immutable from the consumer's perspective. Work on a
    // local mutable copy so detector results become part of the same event
    // object used by policy, PEP, audit, and forensic stages.
    var ev_copy = qe.ev;
    const ev = &ev_copy;
    _ = state.g_pipeline_events_processed.fetchAdd(1, .monotonic);
    // CTRL-002: real liveness timestamp for the health contract (§4.1).
    state.g_last_event_ms.store(std.time.milliTimestamp(), .monotonic);

    // Create security decision trace (128 bytes on stack)
    const trace_id = state.g_trace_id.fetchAdd(1, .monotonic) + 1;
    var decision_trace = trace_mod.SecurityDecisionTrace.init(trace_id, ev);

    // 1. Flow table: lookup or create flow for this event's 5-tuple.
    // V6-FLOW-036: v2 frames carry full addresses in the queue sidecars and
    // key the flow on all 16 bytes with is_ipv6=true. v1 frames (and every
    // other producer) have null sidecars: zero-padded u32 identity with
    // is_ipv6=false, exactly as before. Detection/policy/forensic identity
    // (u32 + bit2 guard) is untouched by this change.
    const is_ipv6 = qe.src_ipv6 != null and qe.dst_ipv6 != null;
    const src_ip_bytes: [16]u8 = qe.src_ipv6 orelse blk: {
        var ip: [16]u8 = [_]u8{0} ** 16;
        const src_bytes: [4]u8 = @bitCast(ev.src_ip);
        @memcpy(ip[0..4], &src_bytes);
        break :blk ip;
    };
    const dst_ip_bytes: [16]u8 = qe.dst_ipv6 orelse blk: {
        var ip: [16]u8 = [_]u8{0} ** 16;
        const dst_bytes: [4]u8 = @bitCast(ev.dst_ip);
        @memcpy(ip[0..4], &dst_bytes);
        break :blk ip;
    };
    const fkey = flow.FlowKey.normalize(src_ip_bytes, dst_ip_bytes, ev.src_port, ev.dst_port, ev.protocol, is_ipv6);
    _ = ft.lookupOrCreate(fkey, ev.timestamp_ns);

    // 2. Aho-Corasick signature matching (if rules are loaded)
    // Use mutex-protected global AC pointer for hot-reload support
    var matched_rule_id: u32 = 0;
    // The frozen 109-byte Canonical Event carries detection metadata but not
    // raw payload bytes. Preserve that contract: an upstream classifier may
    // provide rule_id/event_type, and the Zig pipeline must carry it into
    // policy evaluation without attempting a second payload interpretation.
    if (ev.kind == .signature_match and ev.rule_id != 0) {
        matched_rule_id = ev.rule_id;
        _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
    }
    if (qe.payload_len > 0) {
        state.g_ac_mutex.lock();
        const active_ac = state.g_active_ac;
        state.g_ac_mutex.unlock();
        if (active_ac) |the_ac| {
            const payload_slice = qe.payload[0..qe.payload_len];
            const matches = the_ac.match(payload_slice, std.heap.page_allocator) catch &[_]sig.AhoCorasick.Match{};
            if (matches.len > 0) {
                matched_rule_id = matches[0].rule_id;
                // Persist the detector result onto the canonical event before
                // policy, audit, and forensic stages. Previously the local
                // variable was updated but ev.rule_id stayed zero, so the
                // audit line and forensic record lost detection identity.
                ev.rule_id = matched_rule_id;
                ev.kind = .signature_match;
                _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
            }
            if (matches.len > 0) {
                std.heap.page_allocator.free(matches);
            }
        }
    }

    // 2b. Correlation (multi-event rules). A correlation hit on an event
    // with no signature match is carried as detection identity so threat
    // tracking, policy, and forensics see one coherent result. Correlation
    // rule IDs live in the 9000 block, outside the FNV-1a signature space
    // used by rule_loader hashes. Observe-only: hits count and escalate
    // severity, they never invent host effects.
    if (corr.observe(ev) catch null) |corr_rule_id| {
        if (matched_rule_id == 0) {
            matched_rule_id = corr_rule_id;
            ev.rule_id = corr_rule_id;
            ev.kind = .correlation_match;
            ev.severity = .alert;
            _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
            _ = state.g_pipeline_correlations.fetchAdd(1, .monotonic);
        }
    }

    // 3. Anomaly detection over a real per-event signal (Tier-1 depth).
    // metric_kind=2 observes payload bytes through the EWMA baseline. A
    // z-score hit is counted only: anomalies never create incidents or
    // enforcement in observe-only mode, they enrich the metrics/forensic
    // picture that operators and the Kali probes validate against.
    // V6-DETECT-037: baseline identity follows the queue sidecars (full
    // 16B for v2, zero-padded u32 otherwise) — same rule as the flow key.
    const anom_key_bytes = anom.EntityKey{ .src_ip = anom.entityKeyBytes(qe.src_ipv6, ev.src_ip), .metric_kind = 2 }; // 2 = payload bytes
    const anom_bytes: f64 = @floatFromInt(qe.payload_len);
    if (ad.observe(anom_key_bytes, anom_bytes) catch null) |z_score| {
        _ = z_score;
        // ANOM-COUNT-035: the detector already counted this emission in
        // ad.anomalies_emitted. The only other counter touched here is the
        // live metrics feed (diag.metrics.anomalies_detected -> snapshot);
        // the write-only g_pipeline_anomalies global is gone.
        diag.metrics.anomalies_detected.inc();
    }

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
            _ = state.g_pipeline_detections.fetchAdd(1, .monotonic); // incident = significant detection
            _ = state.g_incidents_total.fetchAdd(1, .monotonic); // track total incidents
            _ = state.g_incidents_open.fetchAdd(1, .monotonic); // track open incidents
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
    ev_copy.severity = ev_severity;
    const eval_ctx = policy.EvalContext{ .ev = &ev_copy };
    if (ps.evaluate(eval_ctx)) |pol| {
        matched_policy = pol;
        policy_action = pol.action;
        _ = state.g_pipeline_policies_matched.fetchAdd(1, .monotonic);
        // Record policy match in trace (Policy has no version field; use 1)
        decision_trace.setPolicy(pol.id, 1);
    }

    // 6. PEP enforcement (final authorization gate)
    // Only PEP call — ActionDispatcher must NOT call PEP again
    var pep_decision: pep.PepDecision = .allow;
    if (matched_policy) |pol| {
        // Unique PEP request ID (not event_id)
        const pep_req_id = state.g_pep_request_id.fetchAdd(1, .monotonic) + 1;
        pep_decision = pep_enf.enforce(
            &ev_copy,
            pol,
            state.g_runtime_pid,
            state.g_runtime_capability_mask,
            pep_req_id,
        );
        _ = state.g_pipeline_detections.fetchAdd(1, .monotonic); // policy matched = detection event

        // Record PEP decision in trace
        decision_trace.setPepDecision(pep_req_id, @intFromEnum(pep_decision));

        // 6a. Action dispatch (execute enforcement action). The receipt is
        // produced by the same PEP call above; dispatcher only verifies its
        // provider postcondition and never calls enforcement again.
        dispatcher.ActionDispatcher.dispatchWithReceipt(
            &ev_copy,
            pol,
            pep_decision,
            pep_enf,
            pep_enf.lastReceipt(),
        );
    }

    // Audit trace — every security decision gets a unique audit_id
    const audit_id = state.g_pipeline_audit_id.fetchAdd(1, .monotonic);
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
    const forensic_seq = forensic_ring.append(ev, qe.payload[0..qe.payload_len], audit_id, if (matched_policy) |pol| pol.id else @as(u32, 0), @intFromEnum(pep_decision), @intFromEnum(ev_copy.severity)) catch 0;
    if (forensic_seq != 0) {
        _ = state.g_forensic_records_written.fetchAdd(1, .monotonic);
    }

    // 8. SIEM forwarding (detections only; observe path, never host effects).
    // Zero-cost when uninitialized: one bool check. The forwarder duplicates
    // all strings, so stack buffers below never escape this call.
    if (siem_mod.isEnabled()) {
        siemForward(ev, matched_rule_id, ev_severity, policy_action);
        if (siem_mod.shouldFlush()) siem_mod.flush();
    }

    // 9. Tier-2 brain inspection (detections only, AEGIS_BRAIN=1).
    // Fire-and-forget UDP offer for deep inspection; findings return via
    // the opt-in sensor pipe. Advisory only: never blocks, enforces, or
    // gates detection. Zero-cost when the loop is closed (one bool check).
    if (state.g_brain_enabled.load(.acquire)) {
        brainInspect(ev, matched_rule_id, ev_severity, policy_action);
    }
}

/// Offer one detection to the Tier-2 brain over UDP (Case-1 document:
/// the brain verifies instead of re-scanning). Detections only.
fn brainInspect(ev: *const event.IpcEvent, rule_id: u32, severity: event.EventSeverity, action: policy.Action) void {
    if (rule_id == 0) return;
    var src_buf: [16]u8 = undefined;
    const src = std.fmt.bufPrint(&src_buf, "{}.{}.{}.{}", .{
        (ev.src_ip >> 24) & 0xFF, (ev.src_ip >> 16) & 0xFF, (ev.src_ip >> 8) & 0xFF, ev.src_ip & 0xFF,
    }) catch return;
    const msg = struct {
        source: []const u8,
        src_ip: []const u8,
        attack_type: []const u8,
        policy: []const u8,
        severity: []const u8,
        rule_id: u32,
    }{
        .source = "zig_pipeline",
        .src_ip = src,
        .attack_type = @tagName(ev.kind),
        .policy = @tagName(action),
        .severity = brainSeverity(severity),
        .rule_id = rule_id,
    };
    brain_mod.sendToBrain(std.heap.page_allocator, @TypeOf(msg), msg);
}

/// Map pipeline severity onto the brain's Low/Medium/High/Critical vocabulary.
fn brainSeverity(severity: event.EventSeverity) []const u8 {
    return switch (severity) {
        .critical, .emergency => "Critical",
        .alert, .@"error" => "High",
        .warning, .notice => "Medium",
        else => "Low",
    };
}

/// Format one detection for the SIEM forwarder. Detections only
/// (matched_rule_id == 0 means no signal worth forwarding).
fn siemForward(ev: *const event.IpcEvent, rule_id: u32, severity: event.EventSeverity, action: policy.Action) void {
    if (rule_id == 0) return;
    var src_buf: [16]u8 = undefined;
    var dst_buf: [16]u8 = undefined;
    var rule_buf: [11]u8 = undefined;
    var proto_buf: [4]u8 = undefined;
    const src = std.fmt.bufPrint(&src_buf, "{}.{}.{}.{}", .{
        (ev.src_ip >> 24) & 0xFF, (ev.src_ip >> 16) & 0xFF, (ev.src_ip >> 8) & 0xFF, ev.src_ip & 0xFF,
    }) catch return;
    const dst = std.fmt.bufPrint(&dst_buf, "{}.{}.{}.{}", .{
        (ev.dst_ip >> 24) & 0xFF, (ev.dst_ip >> 16) & 0xFF, (ev.dst_ip >> 8) & 0xFF, ev.dst_ip & 0xFF,
    }) catch return;
    const rule = std.fmt.bufPrint(&rule_buf, "{}", .{rule_id}) catch return;
    const proto: []const u8 = if (ev.protocol == 6) "TCP" else if (ev.protocol == 17) "UDP" else if (ev.protocol == 1) "ICMP" else std.fmt.bufPrint(&proto_buf, "{}", .{ev.protocol}) catch return;
    siem_mod.forwardEvent(.{
        .timestamp = @as(i64, @intCast(ev.timestamp_ns / 1_000_000)),
        .attack_type = @tagName(ev.kind),
        .src_ip = src,
        .dst_ip = dst,
        .src_port = ev.src_port,
        .dst_port = ev.dst_port,
        .protocol = proto,
        .severity = @tagName(severity),
        .policy = @tagName(action),
        .rule_id = rule,
        .status = "DETECTED",
        .payload = "",
    });
}

// ============================================================
// Tests (T1-SIEM-022)
// ============================================================

test "siemForward buffers detections and ignores non-detections" {
    const dest = "siem_pipeline_probe.json";
    defer std.fs.cwd().deleteFile(dest) catch {};
    if (siem_mod.isInitialized()) siem_mod.shutdown();
    siem_mod.init(std.testing.allocator, .{ .enabled = true, .destination = dest });
    defer siem_mod.shutdown();

    var ev = event.IpcEvent.init(.packet_captured);
    ev.src_ip = 0xC0A80164;
    ev.dst_ip = 0x0A000001;
    ev.src_port = 1234;
    ev.dst_port = 80;
    ev.protocol = 6;
    siemForward(&ev, 0, .info, .pass);
    try std.testing.expectEqual(@as(u64, 0), siem_mod.getStats().total_events_read);
    siemForward(&ev, 4242, .alert, .alert);
    try std.testing.expectEqual(@as(u64, 1), siem_mod.getStats().total_events_read);
    siem_mod.flush();
    try std.testing.expectEqual(@as(u64, 1), siem_mod.getStats().total_events_forwarded);
    const body = try std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "4242") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "192.168.1.100") != null);
}

test "brainSeverity speaks the brain Low/Medium/High/Critical vocabulary" {
    try std.testing.expectEqualStrings("Critical", brainSeverity(.critical));
    try std.testing.expectEqualStrings("Critical", brainSeverity(.emergency));
    try std.testing.expectEqualStrings("High", brainSeverity(.alert));
    try std.testing.expectEqualStrings("High", brainSeverity(.@"error"));
    try std.testing.expectEqualStrings("Medium", brainSeverity(.warning));
    try std.testing.expectEqualStrings("Medium", brainSeverity(.notice));
    try std.testing.expectEqualStrings("Low", brainSeverity(.info));
    try std.testing.expectEqualStrings("Low", brainSeverity(.trace));
    try std.testing.expectEqualStrings("Low", brainSeverity(.debug));
}

test "brainInspect is a safe no-op without detections or loop" {
    var ev = event.IpcEvent.init(.packet_captured);
    ev.src_ip = 0xC0A80164;
    // Closed loop: formats nothing, sends nothing.
    state.g_brain_enabled.store(false, .release);
    brainInspect(&ev, 4242, .alert, .alert);
    // Open loop without a brain socket: UDP send fails into the bounded
    // spool (or nowhere); must never raise or block the caller.
    state.g_brain_enabled.store(true, .release);
    brainInspect(&ev, 4242, .alert, .alert);
    brainInspect(&ev, 0, .info, .pass);
    state.g_brain_enabled.store(false, .release);
}

/// Main pipeline loop: pops events from queue and processes them.
/// Runs on its own thread in daemon mode.
pub fn pipelineLoop(
    ac: *sig.AhoCorasick,
    ad: *anom.AnomalyDetector,
    ft: *flow.FlowTable,
    corr: *corr_mod.Correlator,
    tt: *tracker.ThreatTracker,
    ps: *policy.PolicySet,
    pep_enf: *pep.PepEnforcer,
    forensic_ring: *forensic.ForensicRing,
    rules_loaded: u32,
    wd_idx: usize, // watchdog thread index
) void {
    diag.info("pipeline loop started (queue size: {})", .{queue.PIPELINE_QUEUE_SIZE});
    state.g_pipeline_ready.store(true, .release);
    defer state.g_pipeline_ready.store(false, .release);

    var since_prune: u32 = 0;
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
            processEvent(&qe, ac, ad, ft, corr, tt, ps, pep_enf, forensic_ring, rules_loaded, hist.Stage.capture_to_decode) catch |err| {
                diag.warn("pipeline processing error: {}", .{err});
            };
            state.g_perf.observe(hist.Stage.capture_to_decode, @intCast(std.time.nanoTimestamp() - start));
            // Bound correlator memory: reap idle windows every 4096 events so
            // spoofed sources cannot grow the window map without bound.
            since_prune += 1;
            if (since_prune >= 4096) {
                since_prune = 0;
                _ = corr.prune(std.time.nanoTimestamp());
            }
        } else {
            // No events — yield briefly
            std.time.sleep(1 * std.time.ns_per_ms);
        }
    }

    diag.info("pipeline loop stopped: processed={}, detections={}, policies_matched={}", .{
        state.g_pipeline_events_processed.load(.acquire),
        state.g_pipeline_detections.load(.acquire),
        state.g_pipeline_policies_matched.load(.acquire),
    });
}
