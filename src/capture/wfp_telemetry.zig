//! capture/wfp_telemetry.zig — EVT-202/EVT-211: kernel WFP flow telemetry,
//! submit-only.
//!
//! Reads flow records from the kernel ring through the Rust PEP adapter
//! (the SOLE device owner; aegis_pep_read_events on the adapter_cache
//! handle inside aegis_pep.dll, EVT-211) and submits them to the pipeline
//! queue. A missing provider read surface is LABELED, not silent: the loop
//! stamps runtime_state.g_wfp_provider_state, which control/queue renders
//! as the `wfp` block of queue.stats. Since EVT-231 the driver ring
//! copies a bounded raw payload per record (up to AEGIS_MAX_PAYLOAD_SIZE
//! = 4096 bytes exactly as delivered at the transport layer: on the
//! verified loopback path the bytes begin at the transport payload, no
//! transport header, no stream reassembly);
//! payload_length == 0 is the degraded copy-unavailable case. This loop still performs no L7 matching itself
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

const RING_BUF: usize = 65536;
const IDLE_SLEEP_MS: u64 = 1000;

/// One parsed ring record: header + payload view into the read buffer.
/// Driver u32 IPs are FWPM network-order integers: stored as-is, which
/// IS the BE canonical convention (Go nose identical). Do NOT byte-swap
/// here (EVT-201 class): the shared projector renders BE.
pub const ParsedRecord = struct {
    source_ip: u32,
    dest_ip: u32,
    source_port: u16,
    dest_port: u16,
    protocol: u8,
    layer_id: u8,
    rule_id: u32,
    severity: u8,
    payload: []const u8,
};

/// Parse one header-prefixed record. Null on truncation (caller skips,
/// never partial-submits).
pub fn parseRecord(buf: []const u8) ?ParsedRecord {
    const H = rust_pep.WfpEventHeader;
    if (buf.len < @sizeOf(H)) return null;
    const hdr: *align(1) const H = @ptrCast(buf.ptr);
    const total = @sizeOf(H) +| hdr.payload_length;
    if (buf.len < total) return null;
    const sev: u8 = if (hdr.severity > 3) 3 else @intCast(hdr.severity);
    return .{
        .source_ip = hdr.source_ip,
        .dest_ip = hdr.dest_ip,
        .source_port = hdr.source_port,
        .dest_port = hdr.dest_port,
        .protocol = hdr.protocol,
        .layer_id = 1, // WFP provenance layer (canonical: 0=TCP,1=WFP,2=kernel,3=pipe)
        .rule_id = hdr.rule_id,
        .severity = sev,
        .payload = buf[@sizeOf(H)..total],
    };
}

/// Submit one parsed record to the pipeline queue. Returns false when
/// the queue is full (dropped + counted, never blocking capture).
pub fn submitRecord(rec: ParsedRecord) bool {
    var ce = canonical.create(.wfp_sensor);
    ce.source_ip = rec.source_ip;
    ce.dest_ip = rec.dest_ip;
    ce.source_port = rec.source_port;
    ce.dest_port = rec.dest_port;
    ce.protocol = rec.protocol;
    ce.layer_id = rec.layer_id;
    ce.rule_id = rec.rule_id;
    ce.severity = rec.severity;
    const frame = canonical.DecodedFrame{ .event = ce, .src_ipv6 = null, .dst_ipv6 = null };
    return pipeline_queue.pushDecodedFrame(&frame, rec.payload);
}

/// Kernel telemetry loop: poll the ring, submit, sleep when quiet, exit
/// on supervisor stop. Driver-absent hosts sleep-retry and stamp the
/// labeled `unavailable` provider state (queue.stats renders it).
pub fn telemetryLoop(stopSignal: *std.atomic.Value(bool)) void {
    var ring: [RING_BUF]u8 = undefined;
    diag.info("[WFP TELEMETRY] loop starting (submit-only, no inspect/block)", .{});
    var labeled_missing = false;
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
                    std.time.sleep(IDLE_SLEEP_MS * std.time.ns_per_ms);
                } else {
                    var off: usize = 0;
                    while (off < n) {
                        const rec = parseRecord(ring[off..n]) orelse break;
                        const adv = @sizeOf(rust_pep.WfpEventHeader) + rec.payload.len;
                        if (submitRecord(rec)) {
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
    buf[48] = 'S'; buf[49] = 'Y'; buf[50] = 'N';
    const rec = parseRecord(&buf) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 0xC0A80127), rec.source_ip);
    try std.testing.expectEqual(@as(u32, 0x08080808), rec.dest_ip);
    try std.testing.expectEqual(@as(u16, 0x1122), rec.source_port);
    try std.testing.expectEqual(@as(u8, 6), rec.protocol);
    try std.testing.expectEqual(@as(u8, 1), rec.layer_id);
    try std.testing.expectEqual(@as(usize, 3), rec.payload.len);
    try std.testing.expectEqualSlices(u8, "SYN", rec.payload);
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
    std.mem.writeInt(u32, buf[4..8], 0x0A000001, .little);   // rec0 src 10.0.0.1
    std.mem.writeInt(u16, buf[14..16], 80, .little);         // rec0 dest port
    std.mem.writeInt(u32, buf[20..24], 4, .little);          // rec0 payload_length
    buf[48] = 'P'; buf[49] = 'I'; buf[50] = 'N'; buf[51] = 'G';
    const off1: usize = 48 + 4;
    std.mem.writeInt(u32, buf[off1 + 4 .. off1 + 8], 0x0A000002, .little); // rec1 src
    std.mem.writeInt(u16, buf[off1 + 14 .. off1 + 16], 443, .little);      // rec1 dest port

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
