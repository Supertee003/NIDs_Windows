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
    ev.timestamp_ns = @intCast(@as(i128, hdr.ts_sec) * std.time.ns_per_s + @as(i128, hdr.ts_usec) * 1000);

    if (is_ipv4 and data.len >= 34) {
        // Parse IPv4 header (starts at offset 14)
        const ip_offset: usize = 14;
        const ihl: u8 = (data[ip_offset] & 0x0F) * 4;
        ev.protocol = data[ip_offset + 9];
        const src_bytes: [4]u8 = data[ip_offset + 12 .. ip_offset + 16][0..4].*;
        const dst_bytes: [4]u8 = data[ip_offset + 16 .. ip_offset + 20][0..4].*;
        ev.src_ip = @bitCast(src_bytes);
        ev.dst_ip = @bitCast(dst_bytes);

        // Parse TCP/UDP ports if applicable
        const transport_offset = ip_offset + ihl;
        if ((ev.protocol == 6 or ev.protocol == 17) and data.len >= transport_offset + 4) {
            ev.src_port = @as(u16, data[transport_offset]) << 8 | data[transport_offset + 1];
            ev.dst_port = @as(u16, data[transport_offset + 2]) << 8 | data[transport_offset + 3];
        }
    } else if (is_ipv6 and data.len >= 54) {
        // Parse IPv6 header (starts at offset 14, fixed 40 bytes)
        const ip6_offset: usize = 14;
        ev.protocol = data[ip6_offset + 6];
        const src_bytes: [16]u8 = data[ip6_offset + 8 .. ip6_offset + 24][0..16].*;
        const dst_bytes: [16]u8 = data[ip6_offset + 24 .. ip6_offset + 40][0..16].*;
        // For IPv6, store first 4 bytes of 128-bit address into u32
        ev.src_ip = @bitCast(src_bytes[0..4].*);
        ev.dst_ip = @bitCast(dst_bytes[0..4].*);

        // Parse TCP/UDP ports if applicable
        const transport_offset = ip6_offset + 40;
        if ((ev.protocol == 6 or ev.protocol == 17) and data.len >= transport_offset + 4) {
            ev.src_port = @as(u16, data[transport_offset]) << 8 | data[transport_offset + 1];
            ev.dst_port = @as(u16, data[transport_offset + 2]) << 8 | data[transport_offset + 3];
        }
    } else {
        return; // Not parseable
    }

    ev.payload_len = @intCast(@min(data.len, 65535));
    ev.event_id = diag.metrics.packets_captured.get();

    // Push event + full payload into pipeline queue
    if (!queue.pushEvent(ev, data)) {
        diag.metrics.events_dropped.inc();
    }
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
        var hdr: npcap.pcap_pkthdr = undefined;
        var data_ptr: [*]const u8 = undefined;
        const rc = npcap.pcap_next_ex(adapter.handle.?, &hdr, &data_ptr);
        if (rc == 0) continue;
        if (rc < 0) {
            diag.err("pcap_next_ex error: {}", .{rc});
            break;
        }
        const slice = data_ptr[0..hdr.caplen];
        adapter.packets_captured += 1;
        diag.metrics.packets_captured.inc();
        packetCallback(undefined, &hdr, slice);
    }
    diag.info("capture thread stopped: captured={}, dropped={}", .{
        adapter.packets_captured, adapter.packets_dropped,
    });
}
