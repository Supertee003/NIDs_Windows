//! Lock-free-ish event queue feeding the detection pipeline.
//!
//! Extracted from main.zig. Sensors (Npcap, ETW, FIM, registry, pipe)
//! push QueuedEvents; the pipeline loop pops and processes them.

const std = @import("std");
const event = @import("../contract/event.zig");
const canonical = @import("../contract/canonical_event.zig");
const state = @import("runtime_state.zig");

pub const PIPELINE_QUEUE_SIZE: usize = 16384;
// GAP-015: 4096 slots held under 11 seconds at sustained ingress and the
// drop counter proved chronic overflow. 16384 absorbs bursts while the
// consumer tail is fixed; it is burst insurance, not a fix — Little's law
// still drops on a sustained mean deficit, and queue.stats now proves it.
// Memory cost: 16k slots x ~1.6KB ~= 26MB. All references are symbolic.
pub const MAX_PAYLOAD_BYTES: usize = 1500; // MTU-sized payload buffer
// IDS-QUEUE-001: reserve a bounded tail for network observations. Host
// telemetry is intentionally shed before this reserve is consumed so ETW/FIM
// storms cannot consume the kernel IDS network admission tail. This changes
// admission fairness only: the queue remains FIFO, so a network event can
// still wait behind an existing host backlog, but it is not refused while the
// reserve is free. Every refusal stays visible in the per-source counters,
// and reserved-tail sheds are counted separately from true full-queue drops.
pub const RESERVED_NETWORK_SLOTS: usize = 1024;
// QLOSS-FAIRSHARE-001: the host tail above is shared by every host sensor,
// and a FIM storm can take all of it, leaving ETW/registry blind while the
// kernel-side ring stays silent. A single host source may therefore own at
// most half of the host tail, which guarantees every other host sensor at
// least the other half no matter how hard the storm pushes. The network
// reserve above remains untouched. This is isolation, not throughput: the
// storming source still drops its own events, but it cannot blind a stream a
// detection depends on. 80/20 was measured first and failed exactly that test:
// FIM still drove total occupancy to the shared boundary, where the tail check
// refuses ETW too.
pub const SOURCE_OCCUPANCY_CAP: usize = (PIPELINE_QUEUE_SIZE - RESERVED_NETWORK_SLOTS) / 2;

// QLOSS-CRITICAL-001: not every host event is worth the same. A churn of
// temporary files must never displace a write into a protected system tree, so
// the last CRITICAL_SLOTS of the host tail are reachable only by FIM events
// whose path is under Windows\System32 or SysWOW64, and those events are exempt
// from the per-source share. Non-critical host telemetry stops CRITICAL_SLOTS
// earlier, which is why ordinary telemetry keeps working while the reserve
// waits unused.
pub const CRITICAL_SLOTS: usize = 1024;
pub const WORKING_HOST_TAIL: usize = PIPELINE_QUEUE_SIZE - RESERVED_NETWORK_SLOTS - CRITICAL_SLOTS;

// The protected prefixes are the ones configs/runtime.json already declares in
// `fim_paths`; matching is ASCII case-insensitive because NTFS is. The
// System32 prefix also covers System32\drivers\etc and every nested tree.
const CRITICAL_PATH_PREFIXES = [_][]const u8{
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
};

/// True when a FIM payload (the file path the minifilter recorded) targets a
/// protected system tree. Any other source, or any unparseable payload, is
/// non-critical: the default must be "ordinary", never "protected".
pub fn isCriticalPath(payload: []const u8) bool {
    for (CRITICAL_PATH_PREFIXES) |prefix| {
        if (payload.len < prefix.len) continue;
        var i: usize = 0;
        var matches = true;
        while (i < prefix.len) : (i += 1) {
            if (std.ascii.toLower(payload[i]) != prefix[i]) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }
    return false;
}

fn isCriticalHostEvent(ev: event.IpcEvent, payload: []const u8) bool {
    return ev.source == .capture_fim and isCriticalPath(payload);
}

fn isNetworkObservation(source: event.EventSource) bool {
    return source == .capture_npcap or source == .capture_wfp;
}

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
    /// TCP flags observed on the frame. In-memory sidecar only: the wire
    /// CanonicalEvent has no dedicated flags field. The direct Npcap path
    /// sets this from the transport header; the canonical Nose path sets
    /// the ContextFlags transport lane and pushDecodedFrame extracts it
    /// here. Producers without flag evidence leave it 0, which means "no
    /// flag evidence" (L4 flags rules do not match), not "flags are zero
    /// on the wire".
    tcp_flags: u8 = 0,
    /// Direction from a canonical network event. Null means the producer
    /// did not provide direction metadata; keep it distinct from inbound.
    direction: ?u8 = null,
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
// QLOSS-FAIRSHARE-001: how many queued events each source currently owns.
// Admission compares it against SOURCE_OCCUPANCY_CAP; queue.stats exposes it
// so an operator can see which sensor is holding the space.
pub var g_ingress_active: [256]std.atomic.Value(u64) = [_]std.atomic.Value(u64){std.atomic.Value(u64).init(0)} ** 256;

/// Current queue occupancy (head - tail, wrapping). Control-plane readers
/// use this for queue.stats; producers/consumers never branch on it.
pub fn queueDepth() u64 {
    return g_queue_head.load(.acquire) -% g_queue_tail.load(.acquire);
}

// QLOSS-QUEUE-BURST-001: high-water mark of occupancy since process start.
// A burst that sheds at the reserve boundary leaves depth already drained by
// the time anyone samples, so the instantaneous depth cannot size capacity.
// Only producers write it and they hold g_queue_producer_mutex across the
// whole reserve+publish transaction, so no update can be lost; readers treat
// it as measurement only and never branch on it.
var g_queue_peak_depth: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

/// Peak occupancy observed since the daemon started (0 until the first push).
pub fn queuePeakDepth() u64 {
    return g_queue_peak_depth.load(.acquire);
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
    return pushEventFull(ev, payload, null, null, 0, null);
}

/// pushEvent with the TCP flags observed by the direct Npcap parser.
/// The sidecar is in-memory only and is consumed by layer=="L4" matching.
pub fn pushEventWithTcpFlags(ev: event.IpcEvent, payload: []const u8, tcp_flags: u8) bool {
    return pushEventFull(ev, payload, null, null, tcp_flags, null);
}

/// pushEvent with v2 full-address sidecars. The sidecars are written into
/// the slot under the same producer-mutex hold as the publish, so no
/// interleaving producer can steal or split the slot. Callers without
/// sidecars (v1 frames, ETW/FIM/registry/brain sensors, tests) use
/// pushEvent and queue exactly as before.
pub fn pushEventWithAddrs(ev: event.IpcEvent, payload: []const u8, src_ipv6: ?[16]u8, dst_ipv6: ?[16]u8) bool {
    return pushEventFull(ev, payload, src_ipv6, dst_ipv6, 0, null);
}

fn pushEventFull(ev: event.IpcEvent, payload: []const u8, src_ipv6: ?[16]u8, dst_ipv6: ?[16]u8, tcp_flags: u8, direction: ?u8) bool {
    g_queue_producer_mutex.lock();
    defer g_queue_producer_mutex.unlock();
    const head = g_queue_head.load(.monotonic);
    const tail = g_queue_tail.load(.acquire);
    const src_ord: usize = @intFromEnum(ev.source);
    if ((src_ipv6 == null) != (dst_ipv6 == null)) {
        // A v6 endpoint pair is atomic metadata: accepting only one endpoint
        // would create a forensic record that looks complete but is not.
        _ = state.g_queue_drops.fetchAdd(1, .monotonic);
        _ = g_ingress_dropped[src_ord].fetchAdd(1, .monotonic);
        return false;
    }
    if (head -% tail >= PIPELINE_QUEUE_SIZE) {
        // Queue full — drop event
        _ = state.g_queue_drops.fetchAdd(1, .monotonic);
        _ = g_ingress_dropped[src_ord].fetchAdd(1, .monotonic);
        return false;
    }
    const depth = head -% tail;
    const host_observation = !isNetworkObservation(ev.source);
    // QLOSS-CRITICAL-001: a protected system-tree write is admitted up to the
    // full host tail and ignores the per-source share; everything else stops
    // CRITICAL_SLOTS earlier so that reserve is still free when one arrives.
    const critical = host_observation and isCriticalHostEvent(ev, payload);
    if (host_observation) {
        const host_limit = if (critical)
            PIPELINE_QUEUE_SIZE - RESERVED_NETWORK_SLOTS
        else
            WORKING_HOST_TAIL;
        if (depth >= host_limit) {
            // Preserve the reserved network tail under host-telemetry pressure.
            // Count it as an admission refusal (health must degrade), but also
            // count the cause so queue.stats can distinguish this from a full
            // queue. Callers already expose the source-specific counter.
            _ = state.g_queue_drops.fetchAdd(1, .monotonic);
            _ = state.g_reserved_tail_shed.fetchAdd(1, .monotonic);
            _ = g_ingress_dropped[src_ord].fetchAdd(1, .monotonic);
            return false;
        }
    }
    if (host_observation and !critical and
        g_ingress_active[src_ord].load(.monotonic) >= SOURCE_OCCUPANCY_CAP)
    {
        // QLOSS-FAIRSHARE-001: this source already owns its share of the host
        // tail, so its next event is refused while the other host sensors keep
        // their reachable share. Counted as a refusal (health must degrade) and
        // attributed separately so the cause is not confused with a full queue.
        _ = state.g_queue_drops.fetchAdd(1, .monotonic);
        _ = state.g_source_quota_shed.fetchAdd(1, .monotonic);
        _ = g_ingress_dropped[src_ord].fetchAdd(1, .monotonic);
        return false;
    }
    var qe = QueuedEvent{ .ev = ev };
    const copy_len = @min(payload.len, MAX_PAYLOAD_BYTES);
    @memcpy(qe.payload[0..copy_len], payload[0..copy_len]);
    qe.payload_len = @intCast(copy_len);
    qe.src_ipv6 = src_ipv6;
    qe.dst_ipv6 = dst_ipv6;
    qe.tcp_flags = tcp_flags;
    qe.direction = direction;
    g_event_queue[head % PIPELINE_QUEUE_SIZE] = qe;
    // Claim the source's occupancy BEFORE the slot is published, so a consumer
    // can never release a slot this producer has not yet counted.
    _ = g_ingress_active[src_ord].fetchAdd(1, .monotonic);
    if (critical) _ = state.g_critical_pushed.fetchAdd(1, .monotonic);
    g_queue_head.store(head + 1, .release);
    if (depth + 1 > g_queue_peak_depth.load(.monotonic)) {
        g_queue_peak_depth.store(depth + 1, .monotonic);
    }
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
        .wfp_sensor => .capture_wfp,
        .rust_shield => .policy,
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

/// Gate: canonical.validateDecodedFrame - v1 frames (null sidecars) vs v2
/// frames (version==EVENT_VERSION_V2 + both sidecars); mixed shapes fail
/// closed. V6-QUEUE-DROP: this gate used the strict event validator
/// (version==EVENT_VERSION only) and silently dropped every wire-decoded
/// v2 frame - all IPv6 acquisition (NIC-001 run3 evidence).
pub fn pushDecodedFrame(frame: *const canonical.DecodedFrame, payload: []const u8) bool {
    if (!canonical.validateDecodedFrame(frame)) return false;
    const ce = &frame.event;
    if (ce.direction > 1) return false;

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
    // RB-021-NOSE-FLAGS: wire-decoded Nose events carry the raw TCP flags
    // byte in the ContextFlags transport lane. Populate the same in-memory
    // sidecar the direct Npcap path already uses, so L4 FLAGS predicates
    // match on both acquisition paths. Absence stays 0 ("no evidence").
    const tcp_flags = canonical.getTcpFlags(ce) orelse 0;
    return pushEventFull(ev, payload, frame.src_ipv6, frame.dst_ipv6, tcp_flags, ce.direction);
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
        .wfp_sensor,
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
    // V6-QUEUE-DROP: the fixture is the exact wire-v2 shape — version 2 with
    // both sidecars and sidecar first-4 == BigEndian(u32 fields). A
    // version-1 event with sidecars is a shape no codec can emit; the
    // decoded-frame gate now rejects it (see the shape-gate test below).
    ce.version = canonical.EVENT_VERSION_V2;
    ce.direction = 1;
    const src6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    ce.source_ip = std.mem.readInt(u32, src6[0..4], .big);
    ce.dest_ip = std.mem.readInt(u32, dst6[0..4], .big);
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
    try std.testing.expectEqual(@as(?u8, 1), queued.direction);

    // v1 path: a fresh v1 event queues with null sidecars (unchanged shape).
    var ce_v1 = canonical.create(.npcap_sensor);
    try std.testing.expect(pushCanonicalEvent(&ce_v1));
    const queued_v1 = popEvent().?;
    try std.testing.expect(queued_v1.src_ipv6 == null);
    try std.testing.expect(queued_v1.dst_ipv6 == null);
    try std.testing.expectEqual(@as(?u8, 0), queued_v1.direction);
}

test "pushDecodedFrame rejects unknown direction values" {
    var ce = canonical.create(.wfp_sensor);
    ce.event_type = .forward;
    ce.direction = 2;
    const frame = canonical.DecodedFrame{ .event = ce, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(!pushDecodedFrame(&frame, &[_]u8{}));
    try std.testing.expect(popEvent() == null);
}

test "wire-decoded v2 frame survives the queue gate (V6-QUEUE-DROP regression)" {
    // NIC-001 run3 proved the live pipeline READS every IPv6 frame and then
    // silently dropped it here: decodeFields reads the wire version, so
    // deserializeDispatch yields version==EVENT_VERSION_V2, while the queue
    // gate used canonical.validate (version==EVENT_VERSION only) -> push
    // false -> nose counted frames_dropped with no log (2.75M cumulative /
    // 87.7% of frames read on the NIC-001 host). This test walks the exact
    // reader sequence - serializeV2 -> deserializeDispatch -> pushDecodedFrame
    // -> popEvent - and pins acceptance, sidecars, identity and kind.
    var ce = canonical.create(.npcap_sensor);
    ce.event_type = .forward;
    ce.protocol = 17;
    ce.source_port = 53; // DNS response (CORR-DNS-080)
    ce.dest_port = 45678;
    ce.context_flags |= canonical.CONTEXT_V6_TRUNCATED;
    const src6 = [_]u8{ 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11 };
    const dst6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x39 };
    ce.source_ip = std.mem.readInt(u32, src6[0..4], .big);
    ce.dest_ip = std.mem.readInt(u32, dst6[0..4], .big);

    var wire: [canonical.WIRE_V2_PAYLOAD_SIZE]u8 = undefined;
    const n = try canonical.serializeV2(&ce, src6, dst6, &wire);
    try std.testing.expectEqual(canonical.WIRE_V2_PAYLOAD_SIZE, n);
    const frame = canonical.deserializeDispatch(wire[0..n]).?;
    try std.testing.expectEqual(canonical.EVENT_VERSION_V2, frame.event.version);

    try std.testing.expect(pushDecodedFrame(&frame, &[_]u8{}));
    const queued = popEvent().?;
    try std.testing.expectEqualSlices(u8, &src6, &queued.src_ipv6.?);
    try std.testing.expectEqualSlices(u8, &dst6, &queued.dst_ipv6.?);
    try std.testing.expectEqual(ce.source_ip, queued.ev.src_ip);
    try std.testing.expectEqual(ce.dest_ip, queued.ev.dst_ip);
    try std.testing.expectEqual(event.EventKind.dns_response, queued.ev.kind);
}

test "decoded-frame gate rejects shapes no codec can emit (V6-QUEUE-DROP)" {
    // Shape-strict fail-closed: sidecars are present iff the frame was wire
    // v2, and wire v2 always decodes to version==EVENT_VERSION_V2 with BOTH
    // sidecars (the 24-byte tail always carries both truncated addresses).
    // A mixed shape means a codec bug and must be rejected, never queued.
    const src6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    var v2 = canonical.create(.npcap_sensor);
    v2.version = canonical.EVENT_VERSION_V2;
    const v1 = canonical.create(.npcap_sensor);
    var bad_magic = canonical.create(.npcap_sensor);
    bad_magic.magic = 0;

    const f_v2_no_sidecars = canonical.DecodedFrame{ .event = v2, .src_ipv6 = null, .dst_ipv6 = null };
    const f_v1_with_sidecars = canonical.DecodedFrame{ .event = v1, .src_ipv6 = src6, .dst_ipv6 = dst6 };
    const f_one_sided = canonical.DecodedFrame{ .event = v2, .src_ipv6 = src6, .dst_ipv6 = null };
    const f_bad_magic = canonical.DecodedFrame{ .event = bad_magic, .src_ipv6 = null, .dst_ipv6 = null };
    const r_v2_no_sidecars = pushDecodedFrame(&f_v2_no_sidecars, &[_]u8{});
    const r_v1_with_sidecars = pushDecodedFrame(&f_v1_with_sidecars, &[_]u8{});
    const r_one_sided = pushDecodedFrame(&f_one_sided, &[_]u8{});
    const r_bad_magic = pushDecodedFrame(&f_bad_magic, &[_]u8{});

    // On the buggy pre-fix binary some of these pushed; drain before the
    // asserts so a failure cannot leak events into neighbour tests.
    while (popEvent()) |_| {}

    try std.testing.expect(!r_v2_no_sidecars);
    try std.testing.expect(!r_v1_with_sidecars);
    try std.testing.expect(!r_one_sided);
    try std.testing.expect(!r_bad_magic);
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

test "tcp flag sidecar rides with the direct-capture event" {
    var ev = event.IpcEvent.init(.packet_captured);
    ev.source = .capture_npcap;
    try std.testing.expect(pushEventWithTcpFlags(ev, "frame", 0x02));
    const queued = popEvent().?;
    try std.testing.expectEqual(@as(u8, 0x02), queued.tcp_flags);

    // Producers without flag evidence use the default push and must not
    // invent SYN/FPU evidence.
    try std.testing.expect(pushEvent(ev, "frame"));
    try std.testing.expectEqual(@as(u8, 0), popEvent().?.tcp_flags);
}

test "wire-decoded Nose TCP flags reach the L4 sidecar" {
    // RB-021-NOSE-FLAGS end-to-end at unit level: serialize a canonical
    // Nose event with the ContextFlags transport lane, dispatch it exactly
    // as nose_pipe_reader does, and prove the queue carries the same flags
    // byte the direct Npcap path supplies.
    var ce = canonical.create(.npcap_sensor);
    ce.event_type = .forward;
    ce.protocol = 6;
    ce.source_port = 49152;
    ce.dest_port = 22;
    canonical.setTcpFlags(&ce, 0x02); // SYN
    var wire: [canonical.WIRE_PAYLOAD_SIZE]u8 = undefined;
    const n = try canonical.serializeToBytes(&ce, &wire);
    const frame = canonical.deserializeDispatch(wire[0..n]).?;
    try std.testing.expect(pushDecodedFrame(&frame, &[_]u8{}));
    const queued = popEvent().?;
    try std.testing.expectEqual(event.EventSource.capture_npcap, queued.ev.source);
    try std.testing.expectEqual(@as(u8, 0x02), queued.tcp_flags);

    // The queued sidecar is directly consumable by the L4 predicate that
    // R9006 uses (FLAGS:S, exact SYN).
    const l4 = @import("l4_matcher.zig");
    var rule = l4.Rule{ .rule_id = 9006, .protocol = 6, .flags_value = 0x02 };
    try std.testing.expect(l4.matches(&rule, queued.ev.src_port, queued.ev.dst_port, queued.ev.protocol, queued.tcp_flags));

    // No lane means no flag evidence; the zero-filled sidecar must not be
    // treated as an observed SYN or XMAS byte.
    var plain = canonical.create(.npcap_sensor);
    plain.event_type = .forward;
    plain.protocol = 6;
    const plain_frame = canonical.DecodedFrame{ .event = plain, .src_ipv6 = null, .dst_ipv6 = null };
    try std.testing.expect(pushDecodedFrame(&plain_frame, &[_]u8{}));
    try std.testing.expectEqual(@as(u8, 0), popEvent().?.tcp_flags);
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

test "QLOSS-CRITICAL-001 a protected system write survives quota and working-tail pressure" {
    while (popEvent()) |_| {}
    const fim_ord: usize = @intFromEnum(event.EventSource.capture_fim);

    // Churn ordinary paths until the working tail is full: FIM first (its own
    // share), then ETW for the remainder.
    var churn = event.IpcEvent.init(.fim_change);
    churn.source = .capture_fim;
    var filled: usize = 0;
    while (filled < WORKING_HOST_TAIL) : (filled += 1) {
        if (!pushEvent(churn, "c:\\users\\user\\appdata\\local\\temp\\churn.tmp")) break;
    }
    try std.testing.expectEqual(@as(u64, SOURCE_OCCUPANCY_CAP), queueDepth());
    var noise = event.IpcEvent.init(.fim_change);
    noise.source = .capture_etw;
    while (filled < WORKING_HOST_TAIL) : (filled += 1) {
        if (!pushEvent(noise, "c:\\users\\user\\appdata\\local\\temp\\noise.tmp")) break;
    }
    try std.testing.expectEqual(@as(u64, WORKING_HOST_TAIL), queueDepth());
    try std.testing.expect(!pushEvent(noise, "c:\\users\\user\\appdata\\local\\temp\\noise.tmp"));

    // A System32 write is still admitted, into the reserve nobody else can use,
    // even though this source is far past its share and the working tail is out.
    const before = state.g_critical_pushed.load(.acquire);
    var critical = event.IpcEvent.init(.fim_change);
    critical.source = .capture_fim;
    var admitted: usize = 0;
    while (admitted < CRITICAL_SLOTS + 8) : (admitted += 1) {
        if (!pushEvent(critical, "C:\\Windows\\System32\\drivers\\etc\\hosts")) break;
    }
    try std.testing.expectEqual(CRITICAL_SLOTS, admitted);
    try std.testing.expect(state.g_critical_pushed.load(.acquire) - before == CRITICAL_SLOTS);
    try std.testing.expectEqual(@as(u64, PIPELINE_QUEUE_SIZE - RESERVED_NETWORK_SLOTS), queueDepth());

    // The network reserve is untouched by the protected class.
    var network = event.IpcEvent.init(.packet_captured);
    network.source = .capture_npcap;
    try std.testing.expect(pushEvent(network, &[_]u8{}));
    try std.testing.expectEqual(@as(u64, PIPELINE_QUEUE_SIZE - RESERVED_NETWORK_SLOTS + 1), queueDepth());
    try std.testing.expectEqual(@as(u64, SOURCE_OCCUPANCY_CAP + CRITICAL_SLOTS), g_ingress_active[fim_ord].load(.acquire));

    while (popEvent()) |_| {}
}

test "isCriticalPath matches protected trees only, case-insensitively" {
    try std.testing.expect(isCriticalPath("C:\\Windows\\System32\\drivers\\etc\\hosts"));
    try std.testing.expect(isCriticalPath("c:\\windows\\system32\\winlogon.exe"));
    try std.testing.expect(isCriticalPath("C:\\Windows\\SysWOW64\\cmd.exe"));
    try std.testing.expect(!isCriticalPath("C:\\Windows\\Temp\\x.tmp"));
    try std.testing.expect(!isCriticalPath("D:\\Windows\\System32\\x.dll"));
    try std.testing.expect(!isCriticalPath(""));
    try std.testing.expect(!isCriticalPath("C:\\Windows\\System32"));
}

test "QLOSS-FAIRSHARE-001 a host storm cannot consume the whole host tail" {
    while (popEvent()) |_| {}
    try std.testing.expectEqual(@as(u64, 0), queueDepth());
    const fim_ord: usize = @intFromEnum(event.EventSource.capture_fim);
    const etw_ord: usize = @intFromEnum(event.EventSource.capture_etw);
    const shed0 = state.g_source_quota_shed.load(.acquire);
    const tail0 = state.g_reserved_tail_shed.load(.acquire);
    const host_tail = PIPELINE_QUEUE_SIZE - RESERVED_NETWORK_SLOTS;

    var ev = event.IpcEvent.init(.packet_captured);
    ev.source = .capture_fim;
    var fim_accepted: usize = 0;
    while (fim_accepted < PIPELINE_QUEUE_SIZE) : (fim_accepted += 1) {
        if (!pushEvent(ev, "x")) break;
    }
    try std.testing.expectEqual(SOURCE_OCCUPANCY_CAP, fim_accepted);
    try std.testing.expectEqual(@as(u64, SOURCE_OCCUPANCY_CAP), g_ingress_active[fim_ord].load(.acquire));
    // Refused by the per-source cap, not by the shared tail: the distinction is
    // what lets an operator tell starvation policy from a full queue.
    try std.testing.expect(state.g_source_quota_shed.load(.acquire) - shed0 >= 1);
    try std.testing.expectEqual(tail0, state.g_reserved_tail_shed.load(.acquire));

    // The rest of the host tail is still reachable by another host sensor.
    ev.source = .capture_etw;
    var etw_accepted: usize = 0;
    while (etw_accepted < host_tail) : (etw_accepted += 1) {
        if (!pushEvent(ev, "y")) break;
    }
    try std.testing.expectEqual(WORKING_HOST_TAIL - SOURCE_OCCUPANCY_CAP, etw_accepted);
    try std.testing.expectEqual(@as(u64, WORKING_HOST_TAIL - SOURCE_OCCUPANCY_CAP), g_ingress_active[etw_ord].load(.acquire));
    try std.testing.expectEqual(@as(u64, WORKING_HOST_TAIL), queueDepth());

    // Occupancy is released on pop, so a drained queue grants the cap again.
    while (popEvent()) |_| {}
    try std.testing.expectEqual(@as(u64, 0), queueDepth());
    try std.testing.expectEqual(@as(u64, 0), g_ingress_active[fim_ord].load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), g_ingress_active[etw_ord].load(.acquire));
}

test "queue peak depth records the high-water mark, not the sampled depth" {
    while (popEvent()) |_| {}
    try std.testing.expectEqual(@as(u64, 0), queueDepth());
    const before = queuePeakDepth();
    var ev = event.IpcEvent.init(.packet_captured);
    ev.source = @enumFromInt(78);
    var pushed: u64 = 0;
    while (pushed < 5) : (pushed += 1) try std.testing.expect(pushEvent(ev, "p"));
    try std.testing.expectEqual(@as(u64, 5), queueDepth());
    try std.testing.expect(queuePeakDepth() >= 5);
    // Draining lowers depth but never the high-water mark: that is the whole
    // point of the counter for burst sizing.
    while (popEvent()) |_| {}
    try std.testing.expectEqual(@as(u64, 0), queueDepth());
    try std.testing.expect(queuePeakDepth() >= 5);
    try std.testing.expect(queuePeakDepth() >= before);
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

test "IDS-QUEUE-001 reserves network tail from host telemetry flood" {
    while (popEvent()) |_| {}

    const reserved_before = state.g_reserved_tail_shed.load(.acquire);
    const drops_before = state.g_queue_drops.load(.acquire);

    var host = event.IpcEvent.init(.fim_change);
    host.source = .capture_fim;
    var filled: usize = 0;
    // QLOSS-FAIRSHARE-001: one host source owns at most its share, so FIM alone
    // stops at the per-source cap rather than at the shared host tail.
    while (filled < SOURCE_OCCUPANCY_CAP) : (filled += 1) {
        try std.testing.expect(pushEvent(host, &[_]u8{}));
    }
    try std.testing.expect(!pushEvent(host, &[_]u8{}));
    try std.testing.expectEqual(@as(u64, SOURCE_OCCUPANCY_CAP), queueDepth());
    try std.testing.expectEqual(reserved_before, state.g_reserved_tail_shed.load(.acquire));

    // The rest of the working tail stays reachable by another host sensor...
    var etw = event.IpcEvent.init(.fim_change);
    etw.source = .capture_etw;
    while (filled < WORKING_HOST_TAIL) : (filled += 1) {
        try std.testing.expect(pushEvent(etw, &[_]u8{}));
    }
    // ...and ordinary host telemetry stops before the critical reserve.
    try std.testing.expect(!pushEvent(etw, &[_]u8{}));
    try std.testing.expectEqual(@as(u64, WORKING_HOST_TAIL), queueDepth());
    try std.testing.expectEqual(reserved_before + 1, state.g_reserved_tail_shed.load(.acquire));
    try std.testing.expectEqual(drops_before + 2, state.g_queue_drops.load(.acquire));

    // A network observation still enters the reserved tail.
    var network = event.IpcEvent.init(.packet_captured);
    network.source = .capture_npcap;
    try std.testing.expect(pushEvent(network, &[_]u8{}));

    // Fill the rest of the queue with network observations (the reserve plus
    // the critical slice nobody else may use). A host refusal at true capacity
    // is counted as a reserved shed, never as quota starvation.
    while (queueDepth() < PIPELINE_QUEUE_SIZE) {
        try std.testing.expect(pushEvent(network, &[_]u8{}));
    }
    // At true capacity the full-queue refusal wins, so the reserve shed counter
    // does not move a second time.
    try std.testing.expect(!pushEvent(etw, &[_]u8{}));
    try std.testing.expectEqual(reserved_before + 1, state.g_reserved_tail_shed.load(.acquire));
    try std.testing.expectEqual(drops_before + 3, state.g_queue_drops.load(.acquire));

    while (popEvent()) |_| {}
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
    // QLOSS-FAIRSHARE-001: release the source's occupancy exactly once per
    // popped slot; the producer counted it before publishing the slot.
    const src_ord: usize = @intFromEnum(qe.ev.source);
    _ = g_ingress_active[src_ord].fetchSub(1, .monotonic);
    return qe;
}

test "pushEventWithAddrs rejects one-sided IPv6 metadata" {
    const ev = event.IpcEvent.init(.packet_captured);
    const src6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(!pushEventWithAddrs(ev, &[_]u8{}, src6, null));
    try std.testing.expect(popEvent() == null);
}
