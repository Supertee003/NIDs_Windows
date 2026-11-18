//! Npcap packet capture: raw packet → IpcEvent conversion and capture thread.
//!
//! Extracted from main.zig. packetCallback() converts raw Ethernet/IP frames
//! into IpcEvents (with full payload bytes) and pushes them into the pipeline
//! queue; captureThread() drives NpcapAdapter until shutdown.

const std = @import("std");
const event = @import("../contract/event.zig");
const diag = @import("../core/diagnostics.zig");
const npcap = @import("../capture/npcap_adapter.zig");
const state = @import("runtime_state.zig");
const queue = @import("event_queue.zig");

pub const pushEvent = queue.pushEvent;

/// Npcap packet callback — converts raw Ethernet/IP packets into IpcEvent
/// and pushes them into the pipeline queue with full payload bytes.
pub fn packetCallback(ctx: *anyopaque, hdr: *const npcap.pcap_pkthdr, data: []const u8) void {
    _ = ctx;
    if (data.len < 14) return; // Too short for Ethernet header

    // Parse Ethernet header (14 bytes)
    const eth_proto: u16 = @as(u16, data[12]) << 8 | data[13];
    const is_ipv4 = eth_proto == 0x0800;
    const is_ipv6 = eth_proto == 0x86DD;
    if (!is_ipv4 and !is_ipv6) return; // Only IP packets

    var ev = event.IpcEvent.init(.packet_captured);
    ev.source = .capture_npcap;
    // pcap_pkthdr uses 32-bit signed timeval fields on Windows. Keep the
    // conversion checked so a malformed native header cannot panic the
    // capture thread and silently kill the data plane.
    const ts_sec: i128 = @as(i128, hdr.ts_sec);
    const ts_usec: i128 = @as(i128, hdr.ts_usec);
    const timestamp_ns: i128 = ts_sec * std.time.ns_per_s + ts_usec * 1000;
    ev.timestamp_ns = if (timestamp_ns >= 0 and timestamp_ns <= std.math.maxInt(u64))
        @intCast(timestamp_ns)
    else
        @as(u64, @intCast(@max(@as(i128, 0), std.time.nanoTimestamp())));

    var tcp_flags: u8 = 0;
    if (is_ipv4 and data.len >= 34) {
        // Parse IPv4 header (starts at offset 14)
        const ip_offset: usize = 14;
        const ihl: u8 = (data[ip_offset] & 0x0F) * 4;
        ev.protocol = data[ip_offset + 9];
        const src_bytes: [4]u8 = data[ip_offset + 12 .. ip_offset + 16][0..4].*;
        const dst_bytes: [4]u8 = data[ip_offset + 16 .. ip_offset + 20][0..4].*;
        // EVT-201: network-integer (big-endian) convention, identical to Go
        // nose (binary.BigEndian.Uint32). The old @bitCast stored LE memory
        // layout, which the shared projector rendered byte-reversed
        // (192.168.126.10 displayed as 10.126.168.192) and which split
        // flows/joins against Go-sourced events for the same host
        // (JOIN-TRACE-119). Ingress canonicalization: every producer emits
        // BE, so identity is single-convention end to end.
        ev.src_ip = std.mem.readInt(u32, &src_bytes, .big);
        ev.dst_ip = std.mem.readInt(u32, &dst_bytes, .big);

        // Parse TCP/UDP ports if applicable
        const transport_offset = ip_offset + ihl;
        if ((ev.protocol == 6 or ev.protocol == 17) and data.len >= transport_offset + 4) {
            ev.src_port = @as(u16, data[transport_offset]) << 8 | data[transport_offset + 1];
            ev.dst_port = @as(u16, data[transport_offset + 2]) << 8 | data[transport_offset + 3];
        }
        tcp_flags = tcpFlagsAt(data, transport_offset, ev.protocol);
    } else if (is_ipv6 and data.len >= 54) {
        // Parse IPv6 header (starts at offset 14, fixed 40 bytes)
        const ip6_offset: usize = 14;
        ev.protocol = data[ip6_offset + 6];
        const src_bytes: [16]u8 = data[ip6_offset + 8 .. ip6_offset + 24][0..16].*;
        const dst_bytes: [16]u8 = data[ip6_offset + 24 .. ip6_offset + 40][0..16].*;
        // For IPv6, store first 4 bytes of 128-bit address into u32 --
        // same BE convention as IPv4 above (EVT-201).
        ev.src_ip = std.mem.readInt(u32, src_bytes[0..4], .big);
        ev.dst_ip = std.mem.readInt(u32, dst_bytes[0..4], .big);

        // Parse TCP/UDP ports if applicable
        const transport_offset = ip6_offset + 40;
        if ((ev.protocol == 6 or ev.protocol == 17) and data.len >= transport_offset + 4) {
            ev.src_port = @as(u16, data[transport_offset]) << 8 | data[transport_offset + 1];
            ev.dst_port = @as(u16, data[transport_offset + 2]) << 8 | data[transport_offset + 3];
        }
        tcp_flags = tcpFlagsAt(data, transport_offset, ev.protocol);
    } else {
        return; // Not parseable
    }

    ev.payload_len = @intCast(@min(data.len, 65535));
    ev.event_id = diag.metrics.packets_captured.get();

    // Push event + full payload into pipeline queue. tcp_flags is an
    // in-memory sidecar; it never enters the canonical wire event.
    if (!queue.pushEventWithTcpFlags(ev, data, tcp_flags)) {
        diag.metrics.events_dropped.inc();
    }
}

/// Read the TCP flags byte at the start of the transport header. Any
/// non-TCP protocol or truncated header yields 0 ("no flag evidence").
fn tcpFlagsAt(data: []const u8, transport_offset: usize, protocol: u8) u8 {
    if (protocol != 6) return 0;
    if (transport_offset + 14 > data.len) return 0;
    return data[transport_offset + 13];
}

test "tcpFlagsAt reads SYN and refuses non-TCP or truncated frames" {
    var frame = [_]u8{0} ** 54; // Ethernet + IPv4 + 20-byte TCP header
    frame[34 + 13] = 0x02; // SYN
    try std.testing.expectEqual(@as(u8, 0x02), tcpFlagsAt(&frame, 34, 6));
    try std.testing.expectEqual(@as(u8, 0), tcpFlagsAt(&frame, 34, 17));
    try std.testing.expectEqual(@as(u8, 0), tcpFlagsAt(frame[0..40], 34, 6));
}

/// Npcap capture thread — runs NpcapAdapter and pushes packets into pipeline.
pub fn captureThread() void {
    diag.info("capture thread starting", .{});
    const cfg = npcap.CaptureConfig{
        .device = .{0} ** 256, // default device
        .snaplen = 65535,
        .promiscuous = true,
        .read_timeout_ms = 100,
    };
    var adapter = npcap.NpcapAdapter.open(cfg) catch |err| {
        diag.warn("Npcap open failed: {} — capture disabled", .{err});
        return;
    };
    defer adapter.close();

    adapter.running.store(true, .release);
    diag.info("Npcap capture loop starting", .{});
    while (adapter.running.load(.acquire) and !state.g_stop_requested.load(.acquire)) {
        // EVT-216: pcap_next_ex publishes pointers; read through them.
        // The old one-indirection-short declaration left caplen/len
        // unwritten (0xAA safety fill >= 1500) and padded every window.
        var hdr_ptr: ?*const npcap.pcap_pkthdr = null;
        var data_ptr: ?[*]const u8 = null;
        const rc = npcap.pcap_next_ex(adapter.handle.?, &hdr_ptr, &data_ptr);
        if (rc == 0) continue;
        if (rc < 0) {
            diag.err("pcap_next_ex error: {}", .{rc});
            break;
        }
        const hdr = hdr_ptr orelse {
            adapter.packets_dropped += 1;
            continue;
        };
        const data = data_ptr orelse {
            adapter.packets_dropped += 1;
            continue;
        };
        const slice = data[0..hdr.caplen];
        adapter.packets_captured += 1;
        diag.metrics.packets_captured.inc();
        packetCallback(undefined, hdr, slice);
    }
    diag.info("capture thread stopped: captured={}, dropped={}", .{
        adapter.packets_captured, adapter.packets_dropped,
    });
}

test "packetCallback parses IPv4/TCP frame (BYTE-ORDER-096)" {
    // Ethernet(14) + IPv4(20, ihl=5, proto=TCP) + ports. Addresses are
    // non-palindromic so a byte-order regression cannot hide: 10.0.0.5
    // must decode to BE-network-integer 0x0A000005 -- the Go nose
    // convention (binary.BigEndian.Uint32) and the shared projector's
    // assumption. EVT-201 fixed the old LE memory-layout values here
    // (0x0500000A), which rendered dotted IPs byte-reversed downstream.
    var frame = [_]u8{0} ** 40;
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[14 + 9] = 6;
    frame[14 + 12] = 10;
    frame[14 + 15] = 5;
    frame[14 + 16] = 192;
    frame[14 + 17] = 168;
    frame[14 + 18] = 1;
    frame[14 + 19] = 1;
    frame[34] = 0x04;
    frame[35] = 0xD2;
    frame[36] = 0x00;
    frame[37] = 0x50;
    var hdr = npcap.pcap_pkthdr{ .ts_sec = 1700000000, .ts_usec = 123456, .caplen = 40, .len = 40 };
    packetCallback(undefined, &hdr, &frame);
    const qe = queue.popEvent() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(event.EventKind.packet_captured, qe.ev.kind);
    try std.testing.expectEqual(event.EventSource.capture_npcap, qe.ev.source);
    try std.testing.expectEqual(@as(u8, 6), qe.ev.protocol);
    try std.testing.expectEqual(@as(u32, 0x0A000005), qe.ev.src_ip);
    try std.testing.expectEqual(@as(u32, 0xC0A80101), qe.ev.dst_ip);
    try std.testing.expectEqual(@as(u16, 1234), qe.ev.src_port);
    try std.testing.expectEqual(@as(u16, 80), qe.ev.dst_port);
    try std.testing.expectEqual(@as(u64, 1700000000123456000), qe.ev.timestamp_ns);
    try std.testing.expectEqual(@as(u16, 40), qe.payload_len);
    try std.testing.expectEqualSlices(u8, &frame, qe.payload[0..40]);
}

test "packetCallback parses IPv6 frame first-32-bits (BYTE-ORDER-096)" {
    // Ethernet(14, ethertype IPv6) + fixed 40-byte header + ports.
    // Only the first 4 bytes of each 128-bit address are retained.
    var frame = [_]u8{0} ** 58;
    frame[12] = 0x86;
    frame[13] = 0xDD;
    frame[14] = 0x60;
    frame[14 + 6] = 6;
    // src 2001:0db8::/32 prefix in first 4 bytes
    frame[22] = 0x20;
    frame[23] = 0x01;
    frame[24] = 0x0D;
    frame[25] = 0xB8;
    // dst fe80:: prefix in first 4 bytes
    frame[38] = 0xFE;
    frame[39] = 0x80;
    // ports 8080/80 at offset 54
    frame[54] = 0x1F;
    frame[55] = 0x90;
    frame[56] = 0x00;
    frame[57] = 0x50;
    var hdr = npcap.pcap_pkthdr{ .ts_sec = 1700000000, .ts_usec = 0, .caplen = 58, .len = 58 };
    packetCallback(undefined, &hdr, &frame);
    const qe = queue.popEvent() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u32, 0x20010DB8), qe.ev.src_ip);
    try std.testing.expectEqual(@as(u32, 0xFE800000), qe.ev.dst_ip);
    try std.testing.expectEqual(@as(u16, 8080), qe.ev.src_port);
    try std.testing.expectEqual(@as(u16, 80), qe.ev.dst_port);
}

test "packetCallback drops non-IP and runt frames without enqueue" {
    // Relies on suite convention: every test pops exactly what it pushes,
    // so the global queue is empty here; a null pop proves nothing was
    // enqueued (not merely consumed).
    var arp = [_]u8{0} ** 14;
    arp[12] = 0x08;
    arp[13] = 0x06;
    var hdr = npcap.pcap_pkthdr{ .ts_sec = 1, .ts_usec = 0, .caplen = 14, .len = 14 };
    packetCallback(undefined, &hdr, &arp);
    try std.testing.expect(queue.popEvent() == null);
    var runt = [_]u8{0} ** 5;
    hdr.caplen = 5;
    hdr.len = 5;
    packetCallback(undefined, &hdr, &runt);
    try std.testing.expect(queue.popEvent() == null);
}
