//! Lock-free-ish event queue feeding the detection pipeline.
//!
//! Extracted from main.zig. Sensors (Npcap, ETW, FIM, registry, pipe)
//! push QueuedEvents; the pipeline loop pops and processes them.

const std = @import("std");
const event = @import("../contract/event.zig");
const canonical = @import("../contract/canonical_event.zig");
const state = @import("runtime_state.zig");

pub const PIPELINE_QUEUE_SIZE: usize = 4096;
pub const MAX_PAYLOAD_BYTES: usize = 1500; // MTU-sized payload buffer

/// Queued event: wraps IpcEvent + actual packet payload bytes.
/// The payload is needed for Aho-Corasick signature matching.
/// src/dst_ipv6 carry the v2 full-address sidecars when the frame arrived
/// as a 133-byte v2 frame (nose IPv6 path); null for v1 frames and all
/// other producers. In-memory only — never on any wire.
///
/// Two-length contract (do not conflate):
///   ev.payload_len  = WIRE CLAIM (u32, unbounded, sensor-controlled).
///     Preserved verbatim for forensics/identity; never used to slice.
///   qe.payload_len  = BYTES PRESENT (u16, <= MAX_PAYLOAD_BYTES).
///     The only length any matcher/serializer may slice by. Oversize
///     payloads truncate to the 1500-byte prefix (MTU-sized); matching
///     past the prefix is a documented blind spot, not a silent promise.
pub const QueuedEvent = struct {
    ev: event.IpcEvent,
    payload: [MAX_PAYLOAD_BYTES]u8 = [_]u8{0} ** MAX_PAYLOAD_BYTES,
    payload_len: u16 = 0,
    src_ipv6: ?[16]u8 = null,
    dst_ipv6: ?[16]u8 = null,
};

var g_event_queue: [PIPELINE_QUEUE_SIZE]QueuedEvent = undefined;
var g_queue_head: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var g_queue_tail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
// GAP-015: per-source ingress accounting. Every push outcome is counted
// by legacy source ordinal, so a future queue.stats reader can say WHICH
// sensor starves instead of only how many events died globally. Counters
// only: no push/drop decision reads them, so behavior is unchanged.
pub var g_ingress_pushed: [256]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 256;
pub var g_ingress_dropped: [256]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 256;

/// Current queue occupancy (head - tail, wrapping). Control-plane readers
/// use this for queue.stats; producers/consumers never branch on it.
pub fn queueDepth() u64 {
    return g_queue_head.load(.acquire) -% g_queue_tail.load(.acquire);
}
var g_queue_mutex: std.Thread.Mutex = .{};
// A producer must reserve a head position and publish the completed slot as
// one transaction.  A load/store pair is not a reservation primitive: two
// producers can observe the same head and overwrite one another's slot.
// Keep the seam deliberately simple until a proven bounded MPMC algorithm is
// introduced; pop remains serialized by the same mutex.
var g_queue_producer_mutex: std.Thread.Mutex = .{};

/// Push an event + optional payload into the pipeline queue.
/// Returns true if accepted, false if queue is full (event dropped).
pub fn pushEvent(ev: event.IpcEvent, payload: []const u8) bool {
    return pushEventWithAddrs(ev, payload, null, null);
}

/// pushEvent with v2 full-address sidecars. The sidecars are written into
/// the slot under the same producer-mutex hold as the publish, so no
/// interleaving producer can steal or split the slot. Callers without
/// sidecars (v1 frames, ETW/FIM/registry/brain sensors, tests) use
/// pushEvent and queue exactly as before.
pub fn pushEventWithAddrs(ev: event.IpcEvent, payload: []const u8, src_ipv6: ?[16]u8, dst_ipv6: ?[16]u8) bool {
    g_queue_producer_mutex.lock();
    defer g_queue_producer_mutex.unlock();
    const head = g_queue_head.load(.monotonic);
    const tail = g_queue_tail.load(.acquire);
    const src_ord: usize = @intFromEnum(ev.source);
    if (head -% tail >= PIPELINE_QUEUE_SIZE) {
        // Queue full — drop event
        _ = state.g_queue_drops.fetchAdd(1, .monotonic);
        _ = g_ingress_dropped[src_ord].fetchAdd(1, .monotonic);
        return false;
    }
    var qe = QueuedEvent{ .ev = ev };
    const copy_len = @min(payload.len, MAX_PAYLOAD_BYTES);
    @memcpy(qe.payload[0..copy_len], payload[0..copy_len]);
    qe.payload_len = @intCast(copy_len);
    qe.src_ipv6 = src_ipv6;
    qe.dst_ipv6 = dst_ipv6;
    g_event_queue[head % PIPELINE_QUEUE_SIZE] = qe;
    g_queue_head.store(head + 1, .release);
    _ = g_ingress_pushed[src_ord].fetchAdd(1, .monotonic);
    return true;
}

/// Closest legacy pipeline source for a canonical source.
///
/// The adapter used to leave `ev.source` at its `.system` default, so every
/// network event that arrived through the canonical boundary was attributed to
/// the core: forensic records, correlation categories and XDR source bits all
/// lost the sensor that actually observed the traffic.
///
/// `event.EventSource` predates the canonical sources and cannot represent all
/// of them, so each entry names the closest legacy family. The unit test below
/// pins that every live sensor family round-trips back to itself through the
/// forensic canonicalization; a future ABI revision should carry the canonical
/// ordinal itself instead of this best-effort translation.
pub fn legacySourceFor(source: canonical.EventSource) event.EventSource {
    return switch (source) {
        .zig_core => .system,
        .wfp_sensor, .rust_shield => .policy,
        .pipe_sensor, .pipe_monitor => .capture_pipe_monitor,
        .minifilter, .file_sensor => .capture_fim,
        .python_brain, .ml_detector => .detection_anom,
        .go_aggregator, .cluster_federation => .federation,
        .npcap_sensor => .capture_npcap,
        .host_telemetry, .process_sensor => .capture_etw,
        .registry_sensor => .capture_registry,
        // No legacy sensor exists for these; attribute to the core rather than
        // to a sensor that did not produce the event.
        .cpp_bridge, .replay_sensor, .external => .system,
    };
}

/// Adapt the frozen 109-byte CanonicalEvent into the queue consumed by the
/// detector pipeline. This is the only acquisition-to-detector boundary.
/// The event_id is copied unchanged; adapters must never mint a new identity.
///
/// The frozen 109-byte wire contract contains only payload length and hash,
/// not the payload bytes. Callers that possess the original bytes must use
/// pushCanonicalEventWithPayload so payload-based detection can run without
/// changing the wire ABI.
pub fn pushCanonicalEvent(ce: *const canonical.CanonicalEvent) bool {
    return pushCanonicalEventWithPayload(ce, &[_]u8{});
}

/// Adapt a canonical event while preserving payload bytes held by the
/// acquisition adapter. The payload is bounded by MAX_PAYLOAD_BYTES in
/// pushEvent; the canonical metadata remains authoritative for identity and
/// payload_length/payload_hash. Queues with null v6 sidecars (v1-equivalent
/// identity); v2 callers must use pushDecodedFrame.
pub fn pushCanonicalEventWithPayload(ce: *const canonical.CanonicalEvent, payload: []const u8) bool {
    const frame = canonical.DecodedFrame{ .event = ce.*, .src_ipv6 = null, .dst_ipv6 = null };
    return pushDecodedFrame(&frame, payload);
}

/// Adapt a version-dispatched frame while preserving payload bytes held by
/// the acquisition adapter. v2 sidecars ride along in-memory to the flow
/// stage; v1 frames queue with null sidecars and keep the exact previous
/// behavior (u32 identity, is_ipv6=false). Sidecars are attached in the
/// same producer-mutex hold as the slot publish, so no interleaving
/// producer can steal or split the slot.
/// Two-length rule: ev.payload_len keeps the FULL wire claim (forensics/
/// identity); qe.payload_len reports the bytes actually queued (<= 1500).
/// Matchers must slice by qe.payload_len only.
/// CORR-DNS-080: classify forwarded DNS traffic by port. DNS is the
/// only protocol the pipeline names by port today; everything else
/// keeps the exact previous mapping (generic packet_captured). The
/// dns_query/dns_response kinds already exist cross-language but had
/// no producer — rule 9002 (http_request) shows dead kinds are the
/// standing pattern, and this classifier retires that class one kind
/// at a time. No production correlator rule consumed packet_captured,
/// so no rule loses inputs; SIEM/brain attack_type strings for DNS
/// detections change from "packet_captured" to the true kind.
fn classifyForward(ce: *const canonical.CanonicalEvent) event.EventKind {
    if (ce.protocol == 17) {
        if (ce.dest_port == 53) return .dns_query;
        if (ce.source_port == 53) return .dns_response;
    }
    return .packet_captured;
}

pub fn pushDecodedFrame(frame: *const canonical.DecodedFrame, payload: []const u8) bool {
    if (!canonical.validate(&frame.event)) return false;
    const ce = &frame.event;

    const kind: event.EventKind = switch (ce.event_type) {
        .block, .ip_blocked => .action_block,
        .match_ => .signature_match,
        .forward => classifyForward(ce),
        .rejected => .system_error,
        .session_start, .startup => .system_start,
        .session_end, .shutdown => .system_shutdown,
        .ruleset_reload => .policy_decision,
        .custom => .packet_captured,
    };
    const severity: event.EventSeverity = switch (ce.severity) {
        0 => .info,
        1 => .warning,
        2 => .critical,
        else => .alert,
    };

    var ev = event.IpcEvent.init(kind);
    ev.source = legacySourceFor(ce.source);
    ev.severity = severity;
    ev.event_id = ce.event_id;
    ev.timestamp_ns = ce.monotonic_ns;
    ev.src_ip = ce.source_ip;
    ev.dst_ip = ce.dest_ip;
    ev.src_port = ce.source_port;
    ev.dst_port = ce.dest_port;
    ev.protocol = ce.protocol;
    ev.rule_id = ce.rule_id;
    ev.payload_len = ce.payload_length;
    ev.payload_hash = @truncate(ce.payload_hash);
    ev.flags = ce.context_flags;
    return pushEventWithAddrs(ev, payload, frame.src_ipv6, frame.dst_ipv6);
}

test "pushCanonicalEventWithPayload attributes the observing sensor" {
    const forensic = @import("../forensic/forensic_pipeline.zig");
    var ce = canonical.create(.npcap_sensor);
    ce.event_type = .forward;
    try std.testing.expect(pushCanonicalEvent(&ce));
    const queued = popEvent().?;
    try std.testing.expectEqual(@as(event.EventSource, .capture_npcap), queued.ev.source);

    // Every live sensor family must survive the legacy space and the forensic
    // canonicalization without changing identity.
    const live = [_]canonical.EventSource{
        .npcap_sensor,
        .host_telemetry,
        .file_sensor,
        .registry_sensor,
        .pipe_monitor,
        .zig_core,
        .cluster_federation,
        .ml_detector,
    };
    for (live) |source| {
        try std.testing.expectEqual(
            source,
            forensic.canonicalSourceOf(legacySourceFor(source)),
        );
    }
}

test "pushCanonicalEvent rejects invalid canonical event" {
    var ce = canonical.create(.npcap_sensor);
    ce.magic = 0;
    try std.testing.expect(pushCanonicalEvent(&ce) == false);
}

test "pushDecodedFrame carries v2 sidecars; v1 path queues nulls" {
    // V6-FLOW-036: the queue preserves full v6 identity in-memory without
    // touching the wire ABI or the u32 detection identity.
    var ce = canonical.create(.npcap_sensor);
    ce.event_type = .forward;
    const src6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const frame = canonical.DecodedFrame{ .event = ce, .src_ipv6 = src6, .dst_ipv6 = dst6 };
    try std.testing.expect(pushDecodedFrame(&frame, &[_]u8{}));
    const queued = popEvent().?;
    try std.testing.expect(queued.src_ipv6 != null);
    try std.testing.expect(queued.dst_ipv6 != null);
    try std.testing.expectEqualSlices(u8, &src6, &queued.src_ipv6.?);
    try std.testing.expectEqualSlices(u8, &dst6, &queued.dst_ipv6.?);
    // u32 detection identity is unchanged by the sidecars.
    try std.testing.expectEqual(ce.source_ip, queued.ev.src_ip);
    try std.testing.expectEqual(ce.dest_ip, queued.ev.dst_ip);

    try std.testing.expect(pushCanonicalEvent(&ce));
    const queued_v1 = popEvent().?;
    try std.testing.expect(queued_v1.src_ipv6 == null);
    try std.testing.expect(queued_v1.dst_ipv6 == null);
}

test "classifyForward names DNS by port, keeps everything else generic" {
    // CORR-DNS-080: UDP/53 traffic gets real kinds; TCP/80, UDP/123,
    // non-forward types, and v4/v6 alike keep prior behavior exactly.
    var q = canonical.create(.npcap_sensor);
    q.event_type = .forward;
    q.protocol = 17;
    q.dest_port = 53;
    q.source_port = 45678;
    var f = canonical.DecodedFrame{ .event = q, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&f, &[_]u8{}));
    try std.testing.expectEqual(event.EventKind.dns_query, popEvent().?.ev.kind);

    q.source_port = 53;
    q.dest_port = 45678;
    f = canonical.DecodedFrame{ .event = q, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&f, &[_]u8{}));
    try std.testing.expectEqual(event.EventKind.dns_response, popEvent().?.ev.kind);

    q.protocol = 6;
    q.dest_port = 80;
    q.source_port = 45678;
    f = canonical.DecodedFrame{ .event = q, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&f, &[_]u8{}));
    try std.testing.expectEqual(event.EventKind.packet_captured, popEvent().?.ev.kind);

    q.protocol = 17;
    q.dest_port = 123;
    f = canonical.DecodedFrame{ .event = q, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&f, &[_]u8{}));
    try std.testing.expectEqual(event.EventKind.packet_captured, popEvent().?.ev.kind);

    q.event_type = .match_;
    q.dest_port = 53;
    f = canonical.DecodedFrame{ .event = q, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&f, &[_]u8{}));
    try std.testing.expectEqual(event.EventKind.signature_match, popEvent().?.ev.kind);
}

test "pushCanonicalEventWithPayload preserves bounded payload" {
    var ce = canonical.create(.npcap_sensor);
    const payload = "signature-fixture";
    ce.payload_length = payload.len;
    try std.testing.expect(pushCanonicalEventWithPayload(&ce, payload));
    const queued = popEvent().?;
    try std.testing.expectEqual(payload.len, queued.payload_len);
    try std.testing.expectEqualSlices(u8, payload, queued.payload[0..payload.len]);
}

test "LEN-CLAIM-100: oversize payload truncates to prefix, wire claim kept" {
    // A 2000-byte payload queues the 1500-byte prefix; the matcher slice
    // (qe.payload_len) and the wire claim (ev.payload_len) disagree BY
    // DESIGN — this test pins the disagreement so neither side can
    // silently change meaning.
    var big: [2000]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @truncate(i);
    const ev = event.IpcEvent.init(.packet_captured);
    try std.testing.expect(pushEvent(ev, &big));
    const queued = popEvent().?;
    try std.testing.expectEqual(@as(u16, MAX_PAYLOAD_BYTES), queued.payload_len);
    try std.testing.expectEqualSlices(u8, big[0..MAX_PAYLOAD_BYTES], queued.payload[0..MAX_PAYLOAD_BYTES]);

    // Canonical path: 9000-byte wire claim, 2000 bytes present.
    var ce = canonical.create(.npcap_sensor);
    ce.event_type = .forward;
    ce.payload_length = 9000;
    var f = canonical.DecodedFrame{ .event = ce, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&f, &big));
    const queued2 = popEvent().?;
    try std.testing.expectEqual(@as(u32, 9000), queued2.ev.payload_len);
    try std.testing.expectEqual(@as(u16, MAX_PAYLOAD_BYTES), queued2.payload_len);
}

const ProducerStressContext = struct {
    producer_id: u32,
    accepted: *std.atomic.Value(u32),
};

fn producerStressWorker(ctx: *ProducerStressContext) void {
    var i: u32 = 0;
    while (i < 400) : (i += 1) {
        var ev = event.IpcEvent.init(.packet_captured);
        ev.event_id = (@as(u64, ctx.producer_id) << 32) | i;
        if (pushEvent(ev, &[_]u8{})) {
            _ = ctx.accepted.fetchAdd(1, .monotonic);
        }
    }
}

test "multi producer reservation conserves accepted events" {
    var accepted = std.atomic.Value(u32).init(0);
    var contexts: [8]ProducerStressContext = undefined;
    var threads: [8]std.Thread = undefined;

    var i: usize = 0;
    while (i < contexts.len) : (i += 1) {
        contexts[i] = .{ .producer_id = @intCast(i), .accepted = &accepted };
        threads[i] = try std.Thread.spawn(.{}, producerStressWorker, .{&contexts[i]});
    }
    for (threads) |thread| thread.join();

    var popped: u32 = 0;
    while (popEvent()) |_| popped += 1;
    try std.testing.expectEqual(accepted.load(.acquire), popped);
}

test "GAP-015 ingress accounting counts pushes and drops by source" {
    // Delta-based: the counters are process globals shared with every test.
    var ev = event.IpcEvent.init(.packet_captured);
    ev.source = @enumFromInt(77);
    const p0 = g_ingress_pushed[77].load(.acquire);
    const d0 = g_ingress_dropped[77].load(.acquire);
    try std.testing.expect(pushEvent(ev, "abc"));
    try std.testing.expect(pushEvent(ev, "def"));
    try std.testing.expectEqual(p0 + 2, g_ingress_pushed[77].load(.acquire));
    try std.testing.expectEqual(d0, g_ingress_dropped[77].load(.acquire));
    // Drop path: push until refusal (self-calibrating to whatever the
    // earlier tests left in the queue), then drain back to balanced.
    var accepted: u32 = 0;
    var refused: u32 = 0;
    var guard: u32 = 0;
    while (guard < PIPELINE_QUEUE_SIZE * 2 + 16) : (guard += 1) {
        if (pushEvent(ev, "x")) {
            accepted += 1;
        } else {
            refused += 1;
            if (refused >= 3) break;
        }
    }
    try std.testing.expect(refused >= 3);
    try std.testing.expectEqual(d0 + refused, g_ingress_dropped[77].load(.acquire));
    var drained: u32 = 0;
    while (popEvent()) |_| drained += 1;
    try std.testing.expect(drained >= accepted + 2);
    try std.testing.expect(popEvent() == null);
    try std.testing.expectEqual(@as(u64, 0), queueDepth());
}

/// Pop the next queued event from the pipeline queue.
/// Returns null if queue is empty.
pub fn popEvent() ?QueuedEvent {
    g_queue_mutex.lock();
    defer g_queue_mutex.unlock();
    const tail = g_queue_tail.load(.monotonic);
    const head = g_queue_head.load(.acquire);
    if (tail == head) return null;
    const qe = g_event_queue[tail % PIPELINE_QUEUE_SIZE];
    g_queue_tail.store(tail + 1, .release);
    return qe;
}
