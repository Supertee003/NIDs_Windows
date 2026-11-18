//! capture/wfp_telemetry.zig — EVT-202/EVT-211: kernel WFP flow telemetry,
//! submit-only.
//!
//! Reads flow records from the kernel ring through the Rust PEP adapter
//! (the SOLE device owner; aegis_pep_read_events on the adapter_cache
//! handle inside aegis_pep.dll, EVT-211) and submits them to the pipeline
//! queue. A missing provider read surface is LABELED, not silent: the loop
//! stamps runtime_state.g_wfp_provider_state, which control/queue renders
//! as the `wfp` block of queue.stats. Since EVT-231 the driver ring
//! copies a bounded transport payload per record (up to
//! AEGIS_MAX_PAYLOAD_SIZE = 4096 bytes; inbound data starts at payload,
//! outbound TCP/UDP headers are validated and stripped before copy, and no
//! stream reassembly is performed);
//! payload_length == 0 means empty, unavailable, or unsupported/malformed
//! outbound transport data. Since O1 (plan §26 ทาง A) a v6-flagged record
//! (header flags bit0) leads its payload with a 32-byte identity sidecar
//! (src16 ++ dst16, raw network order): the decoder strips it into full v6
//! sidecars (DecodedFrame.src_ipv6/dst_ipv6) and the payload view becomes
//! the L7 body only; the ring advance still follows the header claim. This
//! loop still performs no L7 matching itself
//! -- it transports the bytes; flow/5-tuple fields remain the primary
//! signal, and any content matching must name the bounded-copy limit
//! rather than imply reassembled streams.
//!
//! What this loop NEVER does (REBUILD-004): inspect_packet verdicts,
//! block/unblock calls, receipt handling, or policy decisions. The
//! quarantined windows_capture.capture_packets did all of those through
//! an unauthenticated Zig-to-WFP path and must stay retired; this loop
//! is telemetry transport only. Enforcement belongs to the Rust PEP
//! behind receipts; detection belongs to the pipeline.
//!
//! Canonical source is .wfp_sensor (already in the schema); the legacy
//! queue bucket mapping is the documented best-effort translation and
//! is unchanged by this file.

const std = @import("std");
const canonical = @import("../contract/canonical_event.zig");
const pipeline_queue = @import("../pipeline/event_queue.zig");
const runtime_state = @import("../pipeline/runtime_state.zig");
const rust_pep = @import("../core/rust_pep.zig");
const diag = @import("../core/diagnostics.zig");
const source_arbiter = @import("source_arbiter.zig");

const RING_BUF: usize = 65536;
const IDLE_SLEEP_MS: u64 = 1000;

/// One parsed ring record: header + payload view into the read buffer.
/// Driver u32 IPs are FWPM network-order integers: stored as-is, which
/// IS the BE canonical convention (Go nose identical). Do NOT byte-swap
/// here (EVT-201 class): the shared projector renders BE.
///
/// O1 (§26 ทาง A): for a v6-flagged record (header flags bit0) the payload
/// LEADS with a 32-byte identity sidecar (src16 ++ dst16, raw network
/// order); parseRecord strips it into the two full-address fields below
/// and .payload becomes the L7 body only. v4 rows keep null sidecars.
pub const ParsedRecord = struct {
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    direction: u8,
    layer_id: u8,
    rule_id: u32,
    severity: u8,
    payload: []const u8,
    src_ipv6: ?[16]u8 = null,
    dst_ipv6: ?[16]u8 = null,

    /// Ring advance for this record (EVT-213: the 48-byte header plus
    /// everything the header's payload_length claims, always). For v6 rows
    /// the claim includes the 32-byte sidecar the decoder already stripped
    /// from .payload, so the stride cannot be re-derived from the payload
    /// view; both sidecar halves are set together or not at all.
    pub fn advanceBytes(self: ParsedRecord) usize {
        const side: usize = if (self.src_ipv6 != null) V6_SIDECAR_SIZE else 0;
        return @sizeOf(rust_pep.WfpEventHeader) + self.payload.len + side;
    }
};

/// O1 §26 ทาง A: header flags bit0 marks a v6 identity sidecar leading the
/// payload (src16 ++ dst16 before the L7 body). The 48-byte header layout
/// is untouched; only this flag and the payload content change.
pub const FLAG_V6_SIDECAR: u8 = 1 << 0;
/// src16 (16 bytes) ++ dst16 (16 bytes), raw network order.
pub const V6_SIDECAR_SIZE: usize = 32;

/// Parse one header-prefixed record. Null on truncation (caller skips,
/// never partial-submits).
pub fn parseRecord(buf: []const u8) ?ParsedRecord {
    const H = rust_pep.WfpEventHeader;
    if (buf.len < @sizeOf(H)) return null;
    const hdr: *align(1) const H = @ptrCast(buf.ptr);
    const total = @sizeOf(H) +| hdr.payload_length;
    if (buf.len < total) return null;
    const sev: u8 = if (hdr.severity > 3) 3 else @intCast(hdr.severity);
    var rec = ParsedRecord{
        .source_ip = hdr.source_ip,
        .dest_ip = hdr.dest_ip,
        .source_port = hdr.source_port,
        .dest_port = hdr.dest_port,
        .protocol = hdr.protocol,
        .direction = hdr.direction,
        .layer_id = 1, // WFP provenance layer (canonical: 0=TCP,1=WFP,2=kernel,3=pipe)
        .rule_id = hdr.rule_id,
        .severity = sev,
        .payload = buf[@sizeOf(H)..total],
    };
    if ((hdr.flags & FLAG_V6_SIDECAR) != 0) {
        // Acceptance is fail-closed: BOTH sidecar halves must be present.
        // A record flagged v6 whose claimed payload is shorter than the
        // sidecar is malformed (producer/consumer ABI disagreement) and is
        // skipped whole — never partial-submitted, same as any truncation.
        if (rec.payload.len < V6_SIDECAR_SIZE) return null;
        var src: [16]u8 = undefined;
        var dst: [16]u8 = undefined;
        @memcpy(&src, rec.payload[0..16]);
        @memcpy(&dst, rec.payload[16..32]);
        rec.src_ipv6 = src;
        rec.dst_ipv6 = dst;
        rec.payload = rec.payload[V6_SIDECAR_SIZE..];
    }
    return rec;
}

/// Build the canonical decoded frame for one parsed ring record. v4 rows
/// stay v1 (null sidecars); v6 rows are promoted to wire v2 — both sidecar
/// halves + version 2 + the truncated-identity flag — exactly the shape the
/// Go nose path pushes (§12) and validateDecodedFrame gates. Pure function:
/// no queue, no global state.
pub fn decodedFrame(rec: ParsedRecord) canonical.DecodedFrame {
    var ce = canonical.create(.wfp_sensor);
    ce.source_ip = rec.source_ip;
    ce.dest_ip = rec.dest_ip;
    ce.source_port = rec.source_port;
    ce.dest_port = rec.dest_port;
    ce.protocol = rec.protocol;
    ce.direction = rec.direction;
    ce.layer_id = rec.layer_id;
    ce.rule_id = rec.rule_id;
    ce.severity = rec.severity;
    if (rec.src_ipv6 != null) {
        ce.version = canonical.EVENT_VERSION_V2;
        ce.context_flags |= canonical.CONTEXT_V6_TRUNCATED;
    }
    return .{ .event = ce, .src_ipv6 = rec.src_ipv6, .dst_ipv6 = rec.dst_ipv6 };
}

/// Submit one parsed record to the pipeline queue. Returns false when
/// the queue is full (dropped + counted, never blocking capture).
pub fn submitRecord(rec: ParsedRecord) bool {
    const frame = decodedFrame(rec);
    return pipeline_queue.pushDecodedFrame(&frame, rec.payload);
}

/// Lab/opt-in switch for simultaneous sources. Only valid where Npcap
/// and WFP are proven disjoint (separate pinned interfaces); the default
/// stays off so the arbiter keeps exactly one ingress authority.
fn captureSplitOptIn() bool {
    const v = std.process.getEnvVarOwned(std.heap.page_allocator, "AEGIS_CAPTURE_SPLIT") catch return false;
    defer std.heap.page_allocator.free(v);
    return v.len > 0 and !std.mem.eql(u8, v, "0") and !std.mem.eql(u8, v, "false");
}

fn logModeTransition(last: *source_arbiter.Mode, d: source_arbiter.Decision) void {
    if (d.mode == last.*) return;
    last.* = d.mode;
    diag.info("[CAPTURE] network acquisition mode={s} reason={s} packet={} kernel={}", .{
        source_arbiter.modeName(@intFromEnum(d.mode)),
        source_arbiter.reasonName(@intFromEnum(d.reason)),
        d.packet_may_submit,
        d.kernel_may_submit,
    });
}

/// Kernel telemetry loop: poll the ring, arbitrate ownership, sleep when
/// quiet, exit on supervisor stop. Driver-absent hosts sleep-retry and
/// stamp the labeled `unavailable` provider state (queue.stats renders
/// it). When the packet path owns ingress, kernel records are still
/// drained but counted as shadow rows and never submitted — one
/// authority at a time, no duplicated flow accounting.
pub fn telemetryLoop(stopSignal: *std.atomic.Value(bool)) void {
    var ring: [RING_BUF]u8 = undefined;
    diag.info("[WFP TELEMETRY] loop starting (submit-only, no inspect/block)", .{});
    var labeled_missing = false;
    var arbiter = source_arbiter.Arbiter{};
    var last_mode: source_arbiter.Mode = .undecided;
    const split_lab = captureSplitOptIn();
    while (!stopSignal.load(.acquire)) {
        switch (rust_pep.read_events_status(&ring)) {
            .no_provider => {
                runtime_state.g_wfp_provider_state.store(
                    @intFromEnum(runtime_state.WfpProviderState.unavailable),
                    .release,
                );
                if (!labeled_missing) {
                    diag.warn("[WFP TELEMETRY] kernel read provider unavailable; kernel flow rows will be absent until it returns (labeled, not silent)", .{});
                    labeled_missing = true;
                }
                const d = arbiter.evaluate(.{
                    .nose_ready = runtime_state.g_nose_ready.load(.acquire),
                    .nose_connected = runtime_state.g_nose_connected.load(.acquire),
                    .nose_frames_submitted = runtime_state.g_nose_frames_submitted.load(.acquire),
                    .kernel_available = false,
                    .kernel_row = false,
                    .split_lab = split_lab,
                    .now_ms = std.time.milliTimestamp(),
                });
                source_arbiter.publish(d);
                logModeTransition(&last_mode, d);
                std.time.sleep(IDLE_SLEEP_MS * std.time.ns_per_ms);
            },
            .bytes => |n| {
                runtime_state.g_wfp_provider_state.store(
                    @intFromEnum(runtime_state.WfpProviderState.ok),
                    .release,
                );
                if (labeled_missing) {
                    diag.info("[WFP TELEMETRY] kernel read provider restored", .{});
                    labeled_missing = false;
                }
                _ = runtime_state.g_wfp_reads.fetchAdd(1, .monotonic);
                runtime_state.g_wfp_last_bytes.store(n, .monotonic);
                if (n == 0) {
                    const d = arbiter.evaluate(.{
                        .nose_ready = runtime_state.g_nose_ready.load(.acquire),
                        .nose_connected = runtime_state.g_nose_connected.load(.acquire),
                        .nose_frames_submitted = runtime_state.g_nose_frames_submitted.load(.acquire),
                        .kernel_available = true,
                        .kernel_row = false,
                        .split_lab = split_lab,
                        .now_ms = std.time.milliTimestamp(),
                    });
                    source_arbiter.publish(d);
                    logModeTransition(&last_mode, d);
                    std.time.sleep(IDLE_SLEEP_MS * std.time.ns_per_ms);
                } else {
                    var off: usize = 0;
                    while (off < n) {
                        const rec = parseRecord(ring[off..n]) orelse break;
                        // EVT-213: advance by the header plus the claimed
                        // payload_length; for O1 v6 rows the claim includes
                        // the identity sidecar the decoder stripped from
                        // the payload view (see ParsedRecord.advanceBytes).
                        const adv = rec.advanceBytes();
                        const d = arbiter.evaluate(.{
                            .nose_ready = runtime_state.g_nose_ready.load(.acquire),
                            .nose_connected = runtime_state.g_nose_connected.load(.acquire),
                            .nose_frames_submitted = runtime_state.g_nose_frames_submitted.load(.acquire),
                            .kernel_available = true,
                            .kernel_row = true,
                            .split_lab = split_lab,
                            .now_ms = std.time.milliTimestamp(),
                        });
                        source_arbiter.publish(d);
                        logModeTransition(&last_mode, d);
                        if (!d.kernel_may_submit) {
                            // Drained so the kernel ring never overflows,
                            // counted so the shadowing is observable.
                            _ = runtime_state.g_wfp_shadow_rows.fetchAdd(1, .monotonic);
                        } else if (submitRecord(rec)) {
                            _ = runtime_state.g_wfp_rows.fetchAdd(1, .monotonic);
                        } else {
                            _ = runtime_state.g_queue_drops.fetchAdd(1, .monotonic);
                        }
                        off += adv;
                        if (adv == 0) break;
                    }
                }
            },
        }
    }
    diag.info("[WFP TELEMETRY] loop exiting", .{});
}

// ============================================================
// Tests (hermetic: synthetic ring bytes, no device)
// ============================================================

test "parseRecord keeps BE network integers and slices payload" {
    // The driver stores FWPM network-order INTEGERS (e.g. 0xC0A80127 for
    // 192.168.1.39), not wire bytes: write the value the way a
    // little-endian host holds it, then assert the BE integer survives
    // end to end (Go-identical). Header is 48 bytes.
    var buf: [64]u8 = [_]u8{0} ** 64;
    std.mem.writeInt(u32, buf[4..8], 0xC0A80127, .little);
    std.mem.writeInt(u32, buf[8..12], 0x08080808, .little);
    std.mem.writeInt(u16, buf[12..14], 0x1122, .little);
    buf[16] = 6; // proto TCP
    std.mem.writeInt(u32, buf[20..24], 3, .little); // payload_length
    buf[48] = 'S';
    buf[49] = 'Y';
    buf[50] = 'N';
    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 0xC0A80127), rec.source_ip);
    try std.testing.expectEqual(@as(u32, 0x08080808), rec.dest_ip);
    try std.testing.expectEqual(@as(u16, 0x1122), rec.source_port);
    try std.testing.expectEqual(@as(u8, 6), rec.protocol);
    try std.testing.expectEqual(@as(u8, 0), rec.direction);
    try std.testing.expectEqual(@as(u8, 1), rec.layer_id);
    try std.testing.expectEqual(@as(usize, 3), rec.payload.len);
    try std.testing.expectEqualSlices(u8, "SYN", rec.payload);
}

test "outbound kernel records carry direction=1 into the canonical event" {
    // O2: the driver marks outbound transport records with header.direction=1.
    // The reader must forward it unchanged; dropping it would relabel every
    // outbound row as inbound (a detection-attribution error, not cosmetic).
    var buf: [48]u8 = [_]u8{0} ** 48;
    std.mem.writeInt(u32, buf[4..8], 0xC0A80127, .little); // local source
    std.mem.writeInt(u32, buf[8..12], 0xCB00710A, .little); // remote destination
    std.mem.writeInt(u16, buf[12..14], 49152, .little);
    std.mem.writeInt(u16, buf[14..16], 443, .little);
    buf[16] = 6; // proto TCP
    buf[17] = 1; // direction: outbound
    buf[18] = 1; // FWPM_LAYER_OUTBOUND_TRANSPORT_V4

    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 1), rec.direction);
    try std.testing.expectEqual(@as(u32, 0xC0A80127), rec.source_ip);
    try std.testing.expectEqual(@as(u32, 0xCB00710A), rec.dest_ip);
}

test "parseRecord rejects truncation instead of partial-submit" {
    var tiny: [10]u8 = [_]u8{0} ** 10;
    try std.testing.expect(parseRecord(&tiny) == null);
    var hdr_only: [48]u8 = [_]u8{0} ** 48;
    hdr_only[20] = 8; // claims 8 payload bytes, none present
    try std.testing.expect(parseRecord(&hdr_only) == null);
}

test "EVT-213: records advance by the 48-byte wrapped header stride" {
    // Two back-to-back kernel records: rec0 carries a 4-byte payload,
    // rec1 none. The consumer advance must be 48 + payload_length for
    // each record (a 44-byte writer stride used to shift every record
    // after the first). Pins kernel/consumer stride agreement.
    var buf: [48 + 4 + 48]u8 = [_]u8{0} ** (48 + 4 + 48);
    std.mem.writeInt(u32, buf[4..8], 0x0A000001, .little); // rec0 src 10.0.0.1
    std.mem.writeInt(u16, buf[14..16], 80, .little); // rec0 dest port
    std.mem.writeInt(u32, buf[20..24], 4, .little); // rec0 payload_length
    buf[48] = 'P';
    buf[49] = 'I';
    buf[50] = 'N';
    buf[51] = 'G';
    const off1: usize = 48 + 4;
    std.mem.writeInt(u32, buf[off1 + 4 .. off1 + 8], 0x0A000002, .little); // rec1 src
    std.mem.writeInt(u16, buf[off1 + 14 .. off1 + 16], 443, .little); // rec1 dest port

    const r0 = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 0x0A000001), r0.source_ip);
    try std.testing.expectEqual(@as(u16, 80), r0.dest_port);
    try std.testing.expectEqualSlices(u8, "PING", r0.payload);

    const adv0 = @sizeOf(rust_pep.WfpEventHeader) + r0.payload.len;
    try std.testing.expectEqual(off1, adv0);

    const r1 = parseRecord(buf[adv0..]) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 0x0A000002), r1.source_ip);
    try std.testing.expectEqual(@as(u16, 443), r1.dest_port);
    try std.testing.expectEqual(@as(usize, 0), r1.payload.len);
}

// ============================================================
// O1 (§26 ทาง A): v6 identity sidecar-in-payload
// flags bit0 => the payload lead is src16 (16B) ++ dst16 (16B);
// payload_length claims sidecar + body; header stays 48 bytes.
// ============================================================

/// Fill a 48-byte record header the way the kernel writes it (LE integers,
/// FWPM network-order IP values, flags @19, payload_length @20).
fn writeRingHeader(buf: []u8, flags: u8, payload_len: u32, src_ip: u32, dst_ip: u32, direction: u8) void {
    @memset(buf, 0);
    std.mem.writeInt(u32, buf[4..8], src_ip, .little);
    std.mem.writeInt(u32, buf[8..12], dst_ip, .little);
    std.mem.writeInt(u16, buf[12..14], 49152, .little);
    std.mem.writeInt(u16, buf[14..16], 445, .little);
    buf[16] = 6; // TCP
    buf[17] = direction;
    buf[19] = flags;
    std.mem.writeInt(u32, buf[20..24], payload_len, .little);
}

test "O1: flags bit0 promotes the payload lead into full v6 sidecars" {
    const src6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    const dst6 = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 };
    var buf: [48 + 32 + 5]u8 = [_]u8{0} ** (48 + 32 + 5);
    // u32 identity = first 4 sidecar bytes as a BE integer value (the Go
    // nose convention: BE.Uint32(addr[:4]); FWPM stores the value as-is).
    writeRingHeader(
        &buf,
        0x01, // flags bit0: v6 sidecar leads the payload
        32 + 5, // claim includes the sidecar
        std.mem.readInt(u32, src6[0..4], .big),
        std.mem.readInt(u32, dst6[0..4], .big),
        0,
    );
    @memcpy(buf[48..][0..16], &src6);
    @memcpy(buf[48 + 16 ..][0..16], &dst6);
    @memcpy(buf[48 + 32 ..][0..5], "hello");

    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    const got_src = rec.src_ipv6 orelse return error.TestUnexpectedResult;
    const got_dst = rec.dst_ipv6 orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &src6, &got_src);
    try std.testing.expectEqualSlices(u8, &dst6, &got_dst);
    try std.testing.expectEqualSlices(u8, "hello", rec.payload);
    // BE pass-through: the u32 identity equals the sidecar's first 4 bytes
    // (the convention serializeV2's IpMismatch contract pins downstream).
    try std.testing.expectEqual(std.mem.readInt(u32, src6[0..4], .big), rec.source_ip);
    try std.testing.expectEqual(std.mem.readInt(u32, dst6[0..4], .big), rec.dest_ip);
    // Ring stride: 48 header + 32 sidecar + 5 body. The sidecar counts
    // toward the advance even though the decoder stripped it from .payload
    // (EVT-213: advance = header + the claimed payload_length, always).
    try std.testing.expectEqual(@as(usize, 48 + 32 + 5), rec.advanceBytes());
}

test "O1: a v6-flagged record shorter than its sidecar is rejected whole" {
    var buf: [48 + 16]u8 = [_]u8{0} ** (48 + 16);
    writeRingHeader(&buf, 0x01, 16, 0, 0, 0); // claim 16 < src16++dst16
    try std.testing.expect(parseRecord(&buf) == null);
    // Boundary: one byte short of the sidecar stays rejected.
    writeRingHeader(&buf, 0x01, 31, 0, 0, 0);
    try std.testing.expect(parseRecord(&buf) == null);
}

test "O1: clear flags keep v4 rows sidecar-free (regression)" {
    var buf: [48 + 3]u8 = [_]u8{0} ** (48 + 3);
    writeRingHeader(&buf, 0x00, 3, 0xC0A80127, 0x08080808, 0);
    @memcpy(buf[48..][0..3], "SYN");
    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expect(rec.src_ipv6 == null);
    try std.testing.expect(rec.dst_ipv6 == null);
    try std.testing.expectEqualSlices(u8, "SYN", rec.payload);
    try std.testing.expectEqual(@as(usize, 48 + 3), rec.advanceBytes());
}

test "O1: an exactly-32-byte sidecar record is accepted with an empty body" {
    var buf: [48 + 32]u8 = [_]u8{0} ** (48 + 32);
    writeRingHeader(&buf, 0x01, 32, 0x20010DB8, 0x20010DB8, 0);
    buf[48] = 0x20; // src6[0]
    buf[48 + 16] = 0x20; // dst6[0]
    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    const got_src = rec.src_ipv6 orelse return error.TestUnexpectedResult;
    const got_dst = rec.dst_ipv6 orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 0x20), got_src[0]);
    try std.testing.expectEqual(@as(u8, 0x20), got_dst[0]);
    try std.testing.expectEqual(@as(usize, 0), rec.payload.len);
    try std.testing.expectEqual(@as(usize, 48 + 32), rec.advanceBytes());
}

test "O1: v6 outbound rows keep direction=1 through the decode" {
    var buf: [48 + 32]u8 = [_]u8{0} ** (48 + 32);
    writeRingHeader(&buf, 0x01, 32, 0x20010DB8, 0x20010DB8, 1);
    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u8, 1), rec.direction);
    try std.testing.expect(rec.src_ipv6 != null);
    try std.testing.expect(rec.dst_ipv6 != null);
}

test "O1: decodedFrame promotes v6 rows to wire v2 and keeps v4 rows v1" {
    var buf6: [48 + 32 + 3]u8 = [_]u8{0} ** (48 + 32 + 3);
    writeRingHeader(&buf6, 0x01, 32 + 3, 0x20010DB8, 0x20010DB9, 0);
    @memcpy(buf6[48 + 32 ..][0..3], "abc");
    const rec6 = parseRecord(&buf6) orelse return error.TestUnexpectedResult;
    const f6 = decodedFrame(rec6);
    // The queue's own gate (V6-QUEUE-DROP shape contract) accepts it:
    try std.testing.expect(canonical.validateDecodedFrame(&f6));
    try std.testing.expectEqual(canonical.EVENT_VERSION_V2, f6.event.version);
    try std.testing.expect(f6.event.context_flags & canonical.CONTEXT_V6_TRUNCATED != 0);
    try std.testing.expect(f6.src_ipv6 != null);
    try std.testing.expect(f6.dst_ipv6 != null);

    var buf4: [48 + 2]u8 = [_]u8{0} ** (48 + 2);
    writeRingHeader(&buf4, 0x00, 2, 0x0A000001, 0x0A000002, 1);
    const rec4 = parseRecord(&buf4) orelse return error.TestUnexpectedResult;
    const f4 = decodedFrame(rec4);
    try std.testing.expect(canonical.validateDecodedFrame(&f4));
    try std.testing.expectEqual(canonical.EVENT_VERSION, f4.event.version);
    try std.testing.expect(f4.src_ipv6 == null);
    try std.testing.expect(f4.dst_ipv6 == null);
}
