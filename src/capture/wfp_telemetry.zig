//! capture/wfp_telemetry.zig — EVT-202: kernel WFP flow telemetry, submit-only.
//!
//! Reads flow records from the kernel ring through the Rust PEP adapter
//! (the SOLE device owner) and submits them to the pipeline queue. The
//! driver ring carries 5-tuples only (payload_length = 0 by driver
//! construction): this is FLOW visibility for correlator/flow/threat
//! stages, never L7 payload matching -- L7 stays with npcap/host paths
//! that actually carry bytes. Claiming otherwise would be dishonest.
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
/// on supervisor stop. Driver-absent hosts sleep-retry (quiet).
pub fn telemetryLoop(stopSignal: *std.atomic.Value(bool)) void {
    var ring: [RING_BUF]u8 = undefined;
    diag.info("[WFP TELEMETRY] loop starting (submit-only, no inspect/block)", .{});
    while (!stopSignal.load(.acquire)) {
        const n = rust_pep.read_events(&ring);
        if (n == 0) {
            std.time.sleep(IDLE_SLEEP_MS * std.time.ns_per_ms);
            continue;
        }
        var off: usize = 0;
        while (off < n) {
            const rec = parseRecord(ring[off..n]) orelse break;
            const adv = @sizeOf(rust_pep.WfpEventHeader) + rec.payload.len;
            if (!submitRecord(rec)) {
                _ = runtime_state.g_queue_drops.fetchAdd(1, .monotonic);
            }
            off += adv;
            if (adv == 0) break;
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
