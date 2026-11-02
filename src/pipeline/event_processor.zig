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
const l7_payload = @import("../capture/proto/l7_payload.zig");
const sig = @import("../detection/signature_engine.zig");
const proto_anomaly = @import("../detection/proto_anomaly.zig");
const l4 = @import("l4_matcher.zig");
const anom = @import("../detection/anomaly_detector.zig");
const corr_mod = @import("../detection/correlator.zig");
const tracker = @import("../detection/threat_tracker.zig");
const policy = @import("../policy/policy_ir.zig");
const pep = @import("../policy/pep_bindings.zig");
const forensic = @import("../forensic/forensic_pipeline.zig");
const forensic_log = @import("../forensic/forensic_log.zig");
const ids_receipt = @import("../forensic/ids_evidence_receipt.zig");
const trace_mod = @import("../forensic/decision_trace.zig");
const dispatcher = @import("../policy/action_dispatcher.zig");
const watchdog = @import("../reliability/watchdog.zig");
const hist = @import("../reliability/latency_histogram.zig");
const state = @import("runtime_state.zig");
const queue = @import("event_queue.zig");
const siem_mod = @import("../forensic/siem_forwarder.zig");
const brain_mod = @import("../core/bridge_init.zig");
const xdr_runtime = @import("../xdr/xdr_runtime.zig");

/// Host telemetry is evidence/advisory input under ADR-0009. Keep the source
/// classification explicit so even a host event labeled `signature_match`
/// cannot enter threat scoring or policy/PEP through a shared code path.
fn isHostTelemetrySource(source: event.EventSource) bool {
    return switch (source) {
        .capture_etw, .capture_fim, .capture_registry => true,
        else => false,
    };
}

/// XDR-WIRE-001 advisory entity key. Full v6 identity wins when the queue
/// sidecar carries it (never the documented prefix-as-address wart);
/// otherwise the v4 dotted source address; a zero address is refused.
fn xdrEntityKey(sidecar: ?[16]u8, v4: u32, buf: *[64]u8) []const u8 {
    if (sidecar) |full6| {
        const hex_chars = "0123456789abcdef";
        buf[0] = 'v';
        buf[1] = '6';
        buf[2] = ':';
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            buf[3 + i * 2] = hex_chars[full6[i] >> 4];
            buf[4 + i * 2] = hex_chars[full6[i] & 0x0F];
        }
        return buf[0..35];
    }
    if (v4 == 0) return "";
    return std.fmt.bufPrint(buf, "v4:{d}.{d}.{d}.{d}", .{
        (v4 >> 24) & 0xFF,
        (v4 >> 16) & 0xFF,
        (v4 >> 8) & 0xFF,
        v4 & 0xFF,
    }) catch "";
}

/// Return an upstream host-detector identity for forensic recording and an
/// IDS Evidence Receipt only. Network capture keeps its existing paths.
fn hostDetectorRuleId(ev: *const event.IpcEvent) u32 {
    if (ev.rule_id == 0) return 0;
    return if (isHostTelemetrySource(ev.source)) ev.rule_id else 0;
}

/// GAP-015 p95: record one stage interval and return now for chaining.
/// Mutex-guarded like the whole-pipeline observe (same race, same fix);
/// saturating cast keeps a clock step harmless instead of trapping.
fn markStage(stage: hist.Stage, since_ns: i128) i128 {
    const now = std.time.nanoTimestamp();
    const delta: u64 = @intCast(@max(0, now - since_ns));
    state.g_perf_mutex.lock();
    state.g_perf.observe(stage, delta);
    state.g_perf_mutex.unlock();
    return now;
}

/// Persist one queued event through the canonical forensic writer. The queue
/// rejects split IPv6 pairs, so a full pair is always recorded atomically.
fn appendForensicRecord(
    ring: *forensic.ForensicRing,
    qe: *const queue.QueuedEvent,
    ev: *const event.IpcEvent,
    audit_id: u64,
    policy_id: u32,
    pep_decision: u8,
    severity: u8,
) u64 {
    if (qe.src_ipv6) |src6| {
        if (qe.dst_ipv6) |dst6| {
            return ring.appendWithNetworkMetadata(
                ev,
                qe.payload[0..qe.payload_len],
                audit_id,
                policy_id,
                pep_decision,
                severity,
                qe.direction,
                src6,
                dst6,
            );
        }
    }
    if (qe.direction) |direction| {
        return ring.appendWithDirection(
            ev,
            qe.payload[0..qe.payload_len],
            audit_id,
            policy_id,
            pep_decision,
            severity,
            direction,
        );
    }
    return ring.append(ev, qe.payload[0..qe.payload_len], audit_id, policy_id, pep_decision, severity);
}

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
    // GAP-015 p95: per-stage latency marks (the whole-pipeline observe in
    // pipelineLoop cannot attribute the tail). Each mark is one uncontended
    // mutex hold; readers snapshot under the same mutex.
    var t_prev = std.time.nanoTimestamp();
    // CTRL-002: real liveness timestamp for the health contract (§4.1).
    const now_ms = std.time.milliTimestamp();
    state.g_last_event_ms.store(now_ms, .monotonic);

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
    // FLOW-ID-051: stamp the table's flow identity onto the event. The
    // lookup result used to be discarded, so every event kept flow_id=0
    // and the threat tracker scored the whole world on one shared Flow 0.
    assignFlowId(ft, ev, fkey);
    t_prev = markStage(.decode_to_flow, t_prev);

    // 2. Aho-Corasick signature matching (if rules are loaded)
    // Use mutex-protected global AC pointer for hot-reload support
    var matched_rule_id: u32 = 0;
    var protocol_anomaly_rule_id: u32 = 0;
    // The frozen 109-byte Canonical Event carries detection metadata but not
    // raw payload bytes. Preserve that contract: an upstream classifier may
    // provide rule_id/event_type, and the Zig pipeline must carry it into
    // policy evaluation without attempting a second payload interpretation.
    if (!isHostTelemetrySource(ev.source) and ev.kind == .signature_match and ev.rule_id != 0) {
        matched_rule_id = ev.rule_id;
        _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
    }
    var active_ac: ?*sig.AhoCorasick = null;
    var l4_rules: [l4.MAX_RULES]l4.Rule = l4.empty_rules;
    var l4_count: usize = 0;
    state.g_ac_mutex.lock();
    active_ac = state.g_active_ac;
    l4_count = @min(state.g_l4_rule_count, l4.MAX_RULES);
    if (l4_count > 0) {
        @memcpy(l4_rules[0..l4_count], state.g_l4_rules[0..l4_count]);
    }
    state.g_ac_mutex.unlock();

    if (qe.payload_len > 0) {
        if (active_ac) |the_ac| {
            const payload_slice = qe.payload[0..qe.payload_len];
            // GAP-015: matchFirst, not match. The pipeline consumes only
            // matches[0] (pinned identical by the equivalence test), so the
            // heap-allocating full enumeration is pure tail latency: one
            // page-allocator ArrayList growth plus free, per event, at
            // hundreds of events/sec on the single consumer thread.
            if (the_ac.matchFirst(payload_slice)) |first| {
                matched_rule_id = first.rule_id;
                // Persist the detector result onto the canonical event before
                // policy, audit, and forensic stages. Previously the local
                // variable was updated but ev.rule_id stayed zero, so the
                // audit line and forensic record lost detection identity.
                ev.rule_id = matched_rule_id;
                ev.kind = .signature_match;
                _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
            }
        }
    }

    // L4 predicate matching. The AC owns payload bytes; layer=="L4" rules
    // own packet metadata (protocol, exact TCP flags, target ports) and never
    // enter the AC. Both Npcap acquisition paths (direct Zig callback and
    // canonical Go Nose through the ContextFlags transport lane) supply
    // trustworthy flags; other producers leave the sidecar at 0, so a flags
    // rule cannot accidentally match their zero-filled metadata.
    if (matched_rule_id == 0 and l4_count > 0 and ev.source == .capture_npcap) {
        for (l4_rules[0..l4_count]) |rule| {
            if (!l4.matches(&rule, ev.src_port, ev.dst_port, ev.protocol, qe.tcp_flags)) continue;

            // Rate/window rules emit one detection per source/window at the
            // threshold. Per-packet rules skip this branch and retain the
            // pre-existing every-matching-packet behavior.
            if (rule.rate_mode != .none) {
                state.g_l4_rate_mutex.lock();
                const rate_hit = state.g_l4_rate.observe(
                    &rule,
                    src_ip_bytes,
                    is_ipv6,
                    ev.dst_port,
                    now_ms,
                );
                state.g_l4_rate_mutex.unlock();
                if (!rate_hit) continue;
            }

            matched_rule_id = rule.rule_id;
            ev.rule_id = matched_rule_id;
            ev.kind = .signature_match;
            _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
            break;
        }
    }

    // IDS-L7-003: direct Npcap is the only ingress with a full Ethernet
    // payload. Extract the transport payload defensively and run the existing
    // protocol checks as observe-only evidence. Do not populate
    // matched_rule_id: protocol anomalies must not enter policy, PEP, or
    // ActionDispatcher. Their stable rule ID is carried by the event and IDS
    // Evidence Receipt/forensic path only.
    if (ev.source == .capture_npcap and qe.payload_len > 0) {
        if (l7_payload.extractEthernet(qe.payload[0..qe.payload_len])) |payload| {
            var dns_name_scratch: [256]u8 = undefined;
            if (proto_anomaly.inspect(ev.protocol, ev.src_port, ev.dst_port, payload, &dns_name_scratch)) |anomaly| {
                protocol_anomaly_rule_id = proto_anomaly.ruleId(anomaly.kind);
                ev.rule_id = protocol_anomaly_rule_id;
                ev.kind = .protocol_anomaly;
                ev.severity = @enumFromInt(@min(anomaly.severity, @as(u8, 7)));
                _ = state.g_pipeline_detections.fetchAdd(1, .monotonic);
            }
        }
    }
    // IDS-HOST-004: host adapters may provide a detector rule identity on the
    // canonical event. Keep it out of matched_rule_id so host evidence cannot
    // enter policy, threat tracking, PEP, or ActionDispatcher by convenience.
    const host_detector_rule_id = hostDetectorRuleId(ev);
    t_prev = markStage(.flow_to_detection, t_prev);

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

    // 4. Threat tracking (if detection matched). Host telemetry is evidence-
    // only and must not affect threat scores or open runtime incidents.
    // Capture incident result — escalate severity when threshold crossed
    var active_incident: ?tracker.Incident = null;
    var ev_severity = ev.severity; // track severity escalation
    if (matched_rule_id != 0 and !isHostTelemetrySource(ev.source)) {
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

    // FE-DEF-095a: daemon-owned critical input. Counted once per matched
    // event at final (possibly incident-escalated) severity — never from
    // file contents. Feeds control/defcon.zig via healthJson.
    if (matched_rule_id != 0 and !isHostTelemetrySource(ev.source) and (ev_severity == .critical or ev_severity == .emergency)) {
        _ = state.g_critical_detections.fetchAdd(1, .monotonic);
    }

    const detection_rule_id = if (matched_rule_id != 0)
        matched_rule_id
    else if (protocol_anomaly_rule_id != 0)
        protocol_anomaly_rule_id
    else
        host_detector_rule_id;

    // Record detection result in trace
    decision_trace.setDetection(
        detection_rule_id,
        if (active_incident) |inc| @as(u64, inc.id) else @as(u64, 0),
        if (active_incident) |inc| @as(u8, @intFromEnum(inc.severity)) else @as(u8, 0),
    );

    // XDR-WIRE-001: advisory evidence feed. Only detection-identity events
    // (rule_id != 0) are classified into the XDR evidence fabric; the result
    // is a read-only advisory summary exposed via xdr.list. This call
    // consumes nothing and authorizes nothing: DEFCON, threat scoring,
    // policy, PEP and ActionDispatcher never read the fabric.
    if (detection_rule_id != 0) {
        if (xdr_runtime.categoryForSource(ev.source)) |xdr_cat| {
            var xdr_entity: [64]u8 = undefined;
            const entity = xdrEntityKey(qe.src_ipv6, ev.src_ip, &xdr_entity);
            if (entity.len > 0) {
                _ = xdr_runtime.observe(
                    xdr_cat,
                    entity,
                    ev.event_id,
                    @intCast(ev.timestamp_ns / std.time.ns_per_ms),
                    @intFromEnum(ev_severity),
                );
            }
        }
    }
    t_prev = markStage(.detection_to_correlation, t_prev);

    // 5. Policy evaluation — use escalated severity for policy matching.
    // Host-source detections can be recorded, but never authorize host effects.
    var policy_action: policy.Action = .pass;
    var matched_policy: ?policy.Policy = null;
    ev_copy.severity = ev_severity;
    const eval_ctx = policy.EvalContext{ .ev = &ev_copy };
    // Protocol anomalies are evidence-only. A nonzero event rule_id is useful
    // for receipts, but must not by itself authorize policy evaluation.
    if (matched_rule_id != 0 and !isHostTelemetrySource(ev.source)) {
        if (ps.evaluate(eval_ctx)) |pol| {
            matched_policy = pol;
            policy_action = pol.action;
            _ = state.g_pipeline_policies_matched.fetchAdd(1, .monotonic);
            // Record policy match in trace (Policy has no version field; use 1)
            decision_trace.setPolicy(pol.id, 1);
        }
    }
    t_prev = markStage(.correlation_to_policy, t_prev);

    // 6. Policy assessment. The normal production path is evidence-only:
    // assessment has no host-effect receipt and never reaches ActionDispatcher.
    // The separately compiled lab gate retains its isolated enforcement path.
    var pep_decision: pep.PepDecision = .allow;
    var confirmed_effect = false;
    var pep_req_id: u64 = 0;
    var receipt_filter_id: u64 = 0;
    if (matched_policy) |pol| {
        // Unique PEP request ID (not event_id)
        pep_req_id = state.g_pep_request_id.fetchAdd(1, .monotonic) + 1;
        if (state.g_prevention_gate_open) {
            // SLICE-C-LAB: only a build compiled with the opt-in lab gate may
            // enter this legacy host-effect path.
            pep_decision = pep_enf.enforce(
                &ev_copy,
                pol,
                state.g_runtime_pid,
                state.g_runtime_capability_mask,
                pep_req_id,
                true,
            );
            confirmed_effect = dispatcher.ActionDispatcher.dispatchWithReceipt(
                &ev_copy,
                pol,
                pep_decision,
                pep_enf,
                pep_enf.lastReceipt(),
            );
            if (confirmed_effect) {
                if (pep_enf.lastReceipt()) |r| {
                    receipt_filter_id = r.filter_id;
                }
            }
        } else {
            pep_decision = pep.assessmentVerdict(pep_enf.assess(
                &ev_copy,
                pol,
                state.g_runtime_pid,
                state.g_runtime_capability_mask,
                pep_req_id,
            ));
        }
        _ = state.g_pipeline_detections.fetchAdd(1, .monotonic); // policy matched = detection event

        // Record PEP decision in trace
        decision_trace.setPepDecision(pep_req_id, @intFromEnum(pep_decision));
    }
    t_prev = markStage(.policy_to_action, t_prev);

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
    const forensic_seq = appendForensicRecord(
        forensic_ring,
        qe,
        ev,
        audit_id,
        if (matched_policy) |pol| pol.id else @as(u32, 0),
        @intFromEnum(pep_decision),
        @intFromEnum(ev_copy.severity),
    );
    if (forensic_seq != 0) {
        _ = state.g_forensic_records_written.fetchAdd(1, .monotonic);
    }
    // IDS-INT-001: issue a recording-only receipt after the forensic writer
    // accepts the exact detection record and its authenticated hash is read
    // back. This never represents a host effect or an enforcement receipt.
    const ids_evidence_receipt: ?ids_receipt.Receipt = if (detection_rule_id != 0 and forensic_seq != 0)
        if (forensic_ring.recordHash(forensic_seq)) |record_hash|
            ids_receipt.issue(ev, forensic_seq, record_hash, ids_receipt.RUNTIME_DETECTOR_ID, ids_receipt.RUNTIME_DETECTOR_VERSION, 100)
        else
            null
    else
        null;
    _ = markStage(.action_to_forensic, t_prev);

    // 8. SIEM forwarding (detections only; observe path, never host effects).
    // Zero-cost when uninitialized: one bool check. The forwarder duplicates
    // all strings, so stack buffers below never escape this call.
    if (siem_mod.isEnabled()) {
        siemForward(ev, detection_rule_id, ev_severity, policy_action, qe.src_ipv6, qe.dst_ipv6);
        if (siem_mod.shouldFlush()) siem_mod.flush();
    }

    // 9. Tier-2 brain inspection (detections only, AEGIS_BRAIN=1).
    // Fire-and-forget UDP offer for deep inspection; findings return via
    // the opt-in sensor pipe. Advisory only: never blocks, enforces, or
    // gates detection. Zero-cost when the loop is closed (one bool check).
    if (state.g_brain_enabled.load(.acquire)) {
        brainInspect(ev, detection_rule_id, ev_severity, policy_action);
    }

    // 10. Evidence-log projection (detections only, on by default).
    // BE-EVI-097: appends one NDJSON line per detection to
    // logs/aegis_core.ndjson — the file the whole frontend fleet tails.
    // Drop-on-error by construction (forensic_log.log never raises); the
    // forensic ring above stays the detection record.
    if (detection_rule_id != 0 and state.g_evidence_log_enabled) {
        evidenceLog(ev, detection_rule_id, ev_severity, policy_action, matched_policy, confirmed_effect, pep_decision, receipt_filter_id, pep_req_id, decision_trace.trace_id, audit_id, qe.payload[0..qe.payload_len], qe.src_ipv6, qe.dst_ipv6, ids_evidence_receipt);
    }
}

/// Project one detection onto the evidence NDJSON log (BE-EVI-097).
/// Field contract: forensic_log.zig header (schema v1). The enforced
/// claim rides ONLY on the dispatcher's provider-read-back verdict with
/// the full receipt set; everything else is observed/unconfirmed.
fn evidenceLog(
    ev: *const event.IpcEvent,
    rule_id: u32,
    severity: event.EventSeverity,
    action: policy.Action,
    matched_policy: ?policy.Policy,
    confirmed: bool,
    decision_kind: pep.PepDecision,
    filter_id: u64,
    pep_req_id: u64,
    trace_id: u64,
    audit_id: u64,
    payload: []const u8,
    src6: ?[16]u8,
    dst6: ?[16]u8,
    ids_evidence_receipt: ?ids_receipt.Receipt,
) void {
    const log_level: forensic_log.LogLevel = switch (severity) {
        .critical, .emergency => .critical,
        .alert, .@"error" => .@"error",
        .warning, .notice => .warn,
        else => .info,
    };
    var rule_buf: [11]u8 = undefined;
    const rule = std.fmt.bufPrint(&rule_buf, "{d}", .{rule_id}) catch return;
    var src6_buf: [48]u8 = undefined;
    var dst6_buf: [48]u8 = undefined;
    var ids_hash_buf: [ids_receipt.HASH_BYTES * 2]u8 = undefined;
    const src_ip6: ?[]const u8 = if (src6) |s6| formatIp6(s6, &src6_buf) else null;
    const dst_ip6: ?[]const u8 = if (dst6) |d6| formatIp6(d6, &dst6_buf) else null;
    const ids_hash: ?[]const u8 = if (ids_evidence_receipt) |r| formatReceiptHash(r.forensic_hash, &ids_hash_buf) else null;
    forensic_log.log(.{
        .level = log_level,
        .event = evidenceEventName(ev.kind, confirmed, decision_kind),
        .rule = rule,
        .src_ip = ev.src_ip,
        .src_ipv6 = src_ip6,
        .dst_ipv6 = dst_ip6,
        .src_port = ev.src_port,
        .session_id = ev.flow_id,
        .payload_preview = payload,
        .policy = @tagName(action),
        .policy_id = if (matched_policy) |pol| pol.id else null,
        .event_id = ev.event_id,
        .trace_id = trace_id,
        .audit_id = audit_id,
        .enforcement_status = if (confirmed) "enforced" else "observed",
        .host_effect_confirmed = confirmed,
        .filter_id = filter_id,
        .request_id = pep_req_id,
        .decision = evidenceDecisionLabel(confirmed, decision_kind),
        .extra = evidenceConfirmationMarker(confirmed, decision_kind),
        .provider = if (confirmed) "wfp" else null,
        .receipt_version = if (confirmed) 1 else 0,
        .ids_receipt_version = if (ids_evidence_receipt != null) ids_receipt.VERSION else 0,
        .ids_receipt_sequence = if (ids_evidence_receipt) |r| r.forensic_sequence else 0,
        .ids_receipt_hash = ids_hash,
    });
}

fn formatReceiptHash(hash: [ids_receipt.HASH_BYTES]u8, output: []u8) []const u8 {
    if (output.len < ids_receipt.HASH_BYTES * 2) return output[0..0];
    const digits = "0123456789abcdef";
    for (hash, 0..) |byte, index| {
        output[index * 2] = digits[byte >> 4];
        output[index * 2 + 1] = digits[byte & 0x0f];
    }
    return output[0 .. ids_receipt.HASH_BYTES * 2];
}

/// The persisted evidence event name. A confirmed quarantine is its own
/// kernel action, not a detection row: operators and the web reader must be
/// able to prove the quarantine from the NDJSON file alone (RB-013).
fn evidenceEventName(kind: event.EventKind, confirmed: bool, decision: pep.PepDecision) []const u8 {
    if (confirmed and decision == .quarantine) return "action_quarantine";
    return @tagName(kind);
}

/// The receipt decision vocabulary readers validate. Never label a
/// quarantine receipt as a block; an unconfirmed action has no decision.
fn evidenceDecisionLabel(confirmed: bool, decision: pep.PepDecision) ?[]const u8 {
    if (!confirmed) return null;
    return switch (decision) {
        .block => "block",
        .quarantine => "quarantine",
        else => null,
    };
}

/// Stable grep marker for a receipt-verified quarantine. Additive to the
/// evidence schema (the generic `extra` field is ignored by old readers).
fn evidenceConfirmationMarker(confirmed: bool, decision: pep.PepDecision) ?[]const u8 {
    if (confirmed and decision == .quarantine) return "QUARANTINED_CONFIRMED";
    return null;
}

/// Stamp the flow table's identity onto the event (FLOW-ID-051).
/// The table mints a fresh id per flow incarnation (reused slots get a new
/// id on occupy), so downstream keyed state (threat tracker, PEP request)
/// never shares a scoreboard across flows. Single pipeline thread owns ft;
/// the id is immutable once occupied, so the post-unlock read is safe.
fn assignFlowId(ft: *flow.FlowTable, ev: *event.IpcEvent, key: flow.FlowKey) void {
    ev.flow_id = ft.lookupOrCreate(key, ev.timestamp_ns).stats.flow_id;
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
/// FOR-V6A: v6 sidecars (when present) render as full text form. The old
/// code printed the u32 prefix as a dotted quad, disguising a v6 source
/// as a v4 address on the only wired forensic string path.
fn formatIp6(addr: [16]u8, buf: *[48]u8) []const u8 {
    return forensic.formatIpv6(addr, buf);
}

fn siemForward(ev: *const event.IpcEvent, rule_id: u32, severity: event.EventSeverity, action: policy.Action, src6: ?[16]u8, dst6: ?[16]u8) void {
    if (rule_id == 0) return;
    var src_buf: [48]u8 = undefined;
    var dst_buf: [48]u8 = undefined;
    var rule_buf: [11]u8 = undefined;
    var proto_buf: [4]u8 = undefined;
    const src = if (src6) |s6| formatIp6(s6, &src_buf) else std.fmt.bufPrint(&src_buf, "{}.{}.{}.{}", .{
        (ev.src_ip >> 24) & 0xFF, (ev.src_ip >> 16) & 0xFF, (ev.src_ip >> 8) & 0xFF, ev.src_ip & 0xFF,
    }) catch return;
    const dst = if (dst6) |d6| formatIp6(d6, &dst_buf) else std.fmt.bufPrint(&dst_buf, "{}.{}.{}.{}", .{
        (ev.dst_ip >> 24) & 0xFF, (ev.dst_ip >> 16) & 0xFF, (ev.dst_ip >> 8) & 0xFF, ev.dst_ip & 0xFF,
    }) catch return;
    const rule = std.fmt.bufPrint(&rule_buf, "{}", .{rule_id}) catch return;
    const proto: []const u8 = if (ev.protocol == 6) "TCP" else if (ev.protocol == 17) "UDP" else if (ev.protocol == 1) "ICMP" else std.fmt.bufPrint(&proto_buf, "{}", .{ev.protocol}) catch return;
    siem_mod.forwardEvent(.{
        // GAP-016: saturating timestamp (threat_tracker rationale applies
        // here too — the cast below executes per detection even with SIEM
        // off, since the struct builds before the forward no-op).
        .timestamp = @as(i64, @intCast(@min(ev.timestamp_ns / 1_000_000, @as(u64, @intCast(std.math.maxInt(i64)))))),
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
    siemForward(&ev, 0, .info, .pass, null, null);
    try std.testing.expectEqual(@as(u64, 0), siem_mod.getStats().total_events_read);
    siemForward(&ev, 4242, .alert, .alert, null, null);
    try std.testing.expectEqual(@as(u64, 1), siem_mod.getStats().total_events_read);
    siem_mod.flush();
    try std.testing.expectEqual(@as(u64, 1), siem_mod.getStats().total_events_forwarded);
    const body = try std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "4242") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "192.168.1.100") != null);
}

test "siemForward renders v6 sidecars as text, never dotted prefix" {
    // FOR-V6A: a v6 detection used to forward its /32 prefix disguised
    // as a v4 address. With sidecars present the full text form ships.
    const dest = "siem_pipeline_probe_v6.json";
    defer std.fs.cwd().deleteFile(dest) catch {};
    if (siem_mod.isInitialized()) siem_mod.shutdown();
    siem_mod.init(std.testing.allocator, .{ .enabled = true, .destination = dest });
    defer siem_mod.shutdown();

    var ev = event.IpcEvent.init(.packet_captured);
    ev.src_ip = 0x20010DB8; // prefix only — must NOT appear dotted
    ev.dst_ip = 0x20010DB8;
    ev.src_port = 49152;
    ev.dst_port = 443;
    ev.protocol = 6;
    const src6 = [16]u8{ 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    const dst6 = [16]u8{ 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };
    siemForward(&ev, 7777, .alert, .alert, src6, dst6);
    siem_mod.flush();
    const body = try std.fs.cwd().readFileAlloc(std.testing.allocator, dest, 65536);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "2001:0db8:0000:0000:0000:0000:0000:0001") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "2001:0db8:0000:0000:0000:0000:0000:0002") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "32.1.13.184") == null);
}

test "siemForward clamps hostile timestamps instead of trapping (GAP-016)" {
    // The timestamp cast below executes per detection even with SIEM off
    // (the struct builds before the forward no-op), so a garbage
    // monotonic_ns must saturate, never int3 the pipeline thread.
    var ev = event.IpcEvent.init(.packet_captured);
    ev.timestamp_ns = std.math.maxInt(u64);
    ev.src_ip = 0xC0A80164;
    ev.dst_ip = 0x0A000001;
    siemForward(&ev, 4242, .alert, .alert, null, null);
}

test "RB-013: confirmed quarantine has its own evidence identity" {
    try std.testing.expectEqualStrings("action_quarantine", evidenceEventName(.signature_match, true, .quarantine));
    try std.testing.expectEqualStrings("quarantine", evidenceDecisionLabel(true, .quarantine).?);
    try std.testing.expectEqualStrings("QUARANTINED_CONFIRMED", evidenceConfirmationMarker(true, .quarantine).?);
    // A detection row keeps its rule-kind event and gets no quarantine mark.
    try std.testing.expectEqualStrings("signature_match", evidenceEventName(.signature_match, true, .block));
    try std.testing.expectEqualStrings("block", evidenceDecisionLabel(true, .block).?);
    try std.testing.expect(evidenceConfirmationMarker(true, .block) == null);
    // Unconfirmed actions never claim a decision or a confirmation marker.
    try std.testing.expect(evidenceDecisionLabel(false, .quarantine) == null);
    try std.testing.expect(evidenceConfirmationMarker(false, .quarantine) == null);
}

test "formatIp6 renders full hextets deterministically" {
    var buf: [48]u8 = undefined;
    const loop = [_]u8{0} ** 15 ++ [_]u8{1};
    try std.testing.expectEqualStrings("0000:0000:0000:0000:0000:0000:0000:0001", formatIp6(loop, &buf));
}

test "event processor forensic append preserves queued IPv6 sidecars" {
    var ring = try forensic.ForensicRing.initMemory(std.testing.allocator, 2 * forensic.RECORD_BYTES);
    defer ring.deinit(std.testing.allocator);
    var ev = event.IpcEvent.init(.signature_match);
    ev.event_id = 8080;
    const src6 = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst6 = [16]u8{ 0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11 };
    const body = "queued-v6-payload";
    var qe = queue.QueuedEvent{ .ev = ev };
    @memcpy(qe.payload[0..body.len], body);
    qe.payload_len = body.len;
    qe.src_ipv6 = src6;
    qe.dst_ipv6 = dst6;
    qe.direction = 1;

    _ = appendForensicRecord(&ring, &qe, &ev, 42, 0, 0, 3);
    const raw = ring.readRecord(0, std.testing.allocator) orelse return error.OutOfMemory;
    defer std.testing.allocator.free(raw);
    const view = forensic.decodeRecordPayload(raw) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, body, view.payload);
    try std.testing.expectEqual(src6, view.src_ipv6.?);
    try std.testing.expectEqual(dst6, view.dst_ipv6.?);
    try std.testing.expectEqual(@as(?u8, 1), view.direction);
    try std.testing.expect(forensic.ForensicRing.verifyRecord(raw));
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

test "assignFlowId stamps stable per-flow identity" {
    // FLOW-ID-051: the same 5-tuple keeps one nonzero id; a different tuple
    // gets another. Without the stamp every event kept flow_id=0 and the
    // threat tracker scored the whole world on shared Flow 0.
    var ft = flow.FlowTable{};
    const k1 = flow.FlowKey.normalize([_]u8{ 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 1000, 80, 6, false);
    const k2 = flow.FlowKey.normalize([_]u8{ 10, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 1000, 80, 6, false);
    var eva = event.IpcEvent.init(.packet_captured);
    var evb = event.IpcEvent.init(.packet_captured);
    var evc = event.IpcEvent.init(.packet_captured);
    try std.testing.expectEqual(@as(u64, 0), eva.flow_id);
    assignFlowId(&ft, &eva, k1);
    assignFlowId(&ft, &evb, k1);
    assignFlowId(&ft, &evc, k2);
    try std.testing.expect(eva.flow_id != 0);
    try std.testing.expectEqual(eva.flow_id, evb.flow_id);
    try std.testing.expect(evc.flow_id != eva.flow_id);
}

test "stamped flow ids isolate threat incidents per flow" {
    // FLOW-ID-051 end to end at unit level: the stamp feeds the tracker,
    // so a hot flow's incident never implicates a quiet flow — the exact
    // failure when every event carried flow_id=0 on shared Flow 0.
    var ft = flow.FlowTable{};
    var tt = tracker.ThreatTracker.init(std.testing.allocator);
    defer tt.deinit();
    const kh = flow.FlowKey.normalize([_]u8{ 10, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 10, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 5000, 443, 6, false);
    const kq = flow.FlowKey.normalize([_]u8{ 10, 9, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, [_]u8{ 10, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 5001, 443, 6, false);
    var evh = event.IpcEvent.init(.signature_match);
    evh.event_id = 101;
    evh.timestamp_ns = 1000;
    var evq = event.IpcEvent.init(.signature_match);
    evq.event_id = 102;
    evq.timestamp_ns = 1000;
    assignFlowId(&ft, &evh, kh);
    assignFlowId(&ft, &evq, kq);
    const inc = try tt.observeFlowThreat(&evh, 100);
    try std.testing.expect(inc != null);
    try std.testing.expectEqual(evh.flow_id, inc.?.flow_id);
    try std.testing.expect(try tt.observeFlowThreat(&evq, 30) == null);
    try std.testing.expectEqual(@as(u32, 1), tt.incident_count);
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

test "IDS-HOST-004: host detector identity is evidence-only" {
    inline for (.{ event.EventSource.capture_etw, .capture_fim, .capture_registry }) |source| {
        var ev = event.IpcEvent.init(.signature_match);
        ev.source = source;
        ev.rule_id = 0xA001;
        try std.testing.expect(isHostTelemetrySource(source));
        try std.testing.expectEqual(@as(u32, 0xA001), hostDetectorRuleId(&ev));
    }

    // Network detections keep their existing signature path and cannot be
    // misclassified as upstream host detector evidence.
    var network_ev = event.IpcEvent.init(.signature_match);
    network_ev.source = .capture_npcap;
    network_ev.rule_id = 0xB002;
    try std.testing.expect(!isHostTelemetrySource(network_ev.source));
    try std.testing.expectEqual(@as(u32, 0), hostDetectorRuleId(&network_ev));

    // Brain/advisory input is also outside the host detector identity channel.
    network_ev.source = .detection_brain;
    try std.testing.expectEqual(@as(u32, 0), hostDetectorRuleId(&network_ev));
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
            // A1: snapshot the event clock BEFORE fault injection can flip
            // bits in it — prune decisions must never ride corrupted time.
            const prune_now_ns = qe.ev.timestamp_ns;
            // Fault injection — maybe corrupt event
            _ = state.g_fi.maybeCorrupt(&qe.ev);
            // Performance tracking
            const start = std.time.nanoTimestamp();
            processEvent(&qe, ac, ad, ft, corr, tt, ps, pep_enf, forensic_ring, rules_loaded, hist.Stage.capture_to_decode) catch |err| {
                diag.warn("pipeline processing error: {}", .{err});
            };
            state.g_perf_mutex.lock();
            state.g_perf.observe(hist.Stage.capture_to_decode, @intCast(std.time.nanoTimestamp() - start));
            state.g_perf_mutex.unlock();
            // Bound correlator memory: reap idle windows every 4096 events so
            // spoofed sources cannot grow the window map without bound.
            since_prune += 1;
            if (since_prune >= 4096) {
                since_prune = 0;
                _ = corr.prune(std.time.nanoTimestamp());
                // A1: expire idle incidents + flow state on EVENT clock
                // (prune_now_ns, snapshotted above — the same clock as
                // first_seen/last_seen, never wall-clock, never corrupted).
                // Returns the expired count; this thread owns both the
                // tracker and g_incidents_open, so the decrement cannot
                // underflow or race.
                const expired = tt.pruneExpired(prune_now_ns);
                if (expired > 0) {
                    _ = state.g_incidents_open.fetchSub(expired, .monotonic);
                    diag.info("incident TTL: expired {} idle incidents", .{expired});
                }
                // WD-BEAT-049: drive the watchdog from the one thread that
                // always cycles. Stalls surface as critical diagnostics (and
                // stay listed in pendingAlerts for a future control drain);
                // no health-schema change in this slice.
                const stalled = state.g_wd.check(std.time.nanoTimestamp());
                if (stalled > 0) {
                    diag.critical("WATCHDOG: {d} worker thread(s) stalled past 5s timeout", .{stalled});
                }
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
