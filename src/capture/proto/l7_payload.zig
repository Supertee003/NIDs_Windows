//! Defensive L7 payload extraction for direct Npcap frames.
//!
//! The direct Npcap queue stores the captured Ethernet frame. Protocol
//! detectors must receive only the transport payload, never a guessed slice.
//! Unsupported link/network/transport forms return null rather than exposing
//! headers or reading beyond a truncated frame.

const std = @import("std");

pub fn extractEthernet(frame: []const u8) ?[]const u8 {
    if (frame.len < 14) return null;
    const ether_type = std.mem.readInt(u16, frame[12..14], .big);
    return switch (ether_type) {
        0x0800 => extractIpv4(frame),
        0x86DD => extractIpv6(frame),
        else => null,
    };
}

fn extractIpv4(frame: []const u8) ?[]const u8 {
    const ip = frame[14..];
    if (ip.len < 20) return null;
    const version = ip[0] >> 4;
    const ihl_words = ip[0] & 0x0f;
    if (version != 4 or ihl_words < 5) return null;
    const ihl = @as(usize, ihl_words) * 4;
    if (ip.len < ihl) return null;
    const total_len = std.mem.readInt(u16, ip[2..4], .big);
    if (total_len < ihl or total_len > ip.len) return null;
    const protocol = ip[9];
    const transport = ip[ihl..total_len];
    return extractTransport(transport, protocol);
}

fn extractIpv6(frame: []const u8) ?[]const u8 {
    const ip = frame[14..];
    if (ip.len < 40 or (ip[0] >> 4) != 6) return null;
    const payload_len = std.mem.readInt(u16, ip[4..6], .big);
    if (@as(usize, payload_len) > ip.len - 40) return null;
    // The first slice intentionally supports only the fixed-header TCP/UDP
    // cases. Extension-header traversal belongs to a separate parser contract.
    const next_header = ip[6];
    return extractTransport(ip[40 .. 40 + payload_len], next_header);
}

fn extractTransport(transport: []const u8, protocol: u8) ?[]const u8 {
    return switch (protocol) {
        6 => blk: {
            if (transport.len < 20) break :blk null;
            const data_offset_words = transport[12] >> 4;
            if (data_offset_words < 5) break :blk null;
            const data_offset = @as(usize, data_offset_words) * 4;
            if (data_offset > transport.len) break :blk null;
            break :blk transport[data_offset..];
        },
        17 => if (transport.len >= 8) transport[8..] else null,
        else => null,
    };
}

test "extractEthernet returns only TCP payload" {
    const http = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    var frame: [14 + 20 + 20 + http.len]u8 = undefined;
    @memset(&frame, 0);
    @memcpy(frame[54..], http);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    const ip_total_len = frame.len - 14;
    frame[14 + 2] = @intCast(ip_total_len >> 8);
    frame[14 + 3] = @intCast(ip_total_len & 0xff);
    frame[14 + 9] = 6;
    frame[14 + 20 + 12] = 0x50;
    const payload = extractEthernet(&frame).?;
    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: x\r\n\r\n", payload);
}

test "extractEthernet rejects truncated and unsupported frames" {
    try std.testing.expect(extractEthernet("short") == null);
    var arp = [_]u8{0} ** 14;
    arp[12] = 0x08;
    arp[13] = 0x06;
    try std.testing.expect(extractEthernet(&arp) == null);
}
