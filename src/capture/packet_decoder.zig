// I07 - Packet Decoder (Layer 2 â†’ Layer 4)
// AEGIS NIDS v5.0+ â€” Stateless packet decoder for Ethernet/ARP/IPv4/IPv6/UDP/TCP/ICMP
//
// Returns a DecodedPacket with const pointers into the original buffer.
// Zero-copy: no allocation in hot path.

const std = @import("std");

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    vlan = 0x8100,
    vlan_ad = 0x88a8, // 802.1ad provider bridge tag (QinQ)
    mpls = 0x8847,
    _,
};

pub const IpProto = enum(u8) {
    none = 0,
    icmp = 1,
    igmp = 2,
    tcp = 6,
    udp = 17,
    ipv6_route = 43,
    ipv6_frag = 44,
    ipv6_icmp = 58,
    sctp = 132,
    _,
};

pub const EthHdr = extern struct {
    dst: [6]u8,
    src: [6]u8,
    ether_type: u16, // network order
};

pub const ArpHdr = extern struct {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    op: u16, // 1=req, 2=reply
    sha: [6]u8,
    spa: [4]u8,
    tha: [6]u8,
    tpa: [4]u8,
};

pub const Ipv4Hdr = extern struct {
    ver_ihl: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    flags_frag: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: [4]u8,
    dst: [4]u8,
};

pub const Ipv6Hdr = extern struct {
    ver_tc_flow: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src: [16]u8,
    dst: [16]u8,
};

pub const TcpHdr = extern struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_off_flags: u16,
    window: u16,
    checksum: u16,
    urg_ptr: u16,
};

pub const UdpHdr = extern struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

pub const IcmpHdr = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    rest: u32,
};

pub const DecodedPacket = struct {
    raw: []const u8,
    eth: ?*align(1) const EthHdr = null,
    ether_type: EtherType = .ipv4,
    vlan_id: ?u16 = null,
    arp: ?*align(1) const ArpHdr = null,
    ipv4: ?*align(1) const Ipv4Hdr = null,
    ipv6: ?*align(1) const Ipv6Hdr = null,
    ip_proto: IpProto = .none,
    src_ip: [16]u8 = [_]u8{0} ** 16,
    dst_ip: [16]u8 = [_]u8{0} ** 16,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    tcp: ?*align(1) const TcpHdr = null,
    udp: ?*align(1) const UdpHdr = null,
    icmp: ?*align(1) const IcmpHdr = null,
    payload: []const u8 = &[_]u8{},
    is_ipv6: bool = false,
    decode_error: ?[]const u8 = null,
};

// Bounded traversal limits. A decoder must fail closed rather than loop on a
// hostile header chain; these limits are local parsing state, not wire fields.
const max_vlan_tags: u8 = 2; // 802.1Q + 802.1ad (QinQ)
const max_ipv6_ext_headers: u8 = 8;

const Ipv6Walk = struct {
    off: usize,
    proto: u8,
};

/// Walk the common IPv6 extension headers without allocating. Option-style
/// headers (0, 43, 60), Fragment (44) and AH (51) have a next-header byte and a
/// bounded length. ESP (50) and No Next Header (59) stop the walk because their
/// payload cannot be safely interpreted as a following transport header.
/// An unsupported value stops with that protocol value; decodeL4 then decides
/// whether it can consume it. A truncated or over-long chain returns null.
fn walkIpv6ExtensionHeaders(raw: []const u8, off_in: usize, next_in: u8) ?Ipv6Walk {
    var off = off_in;
    var next = next_in;
    var hops: u8 = 0;
    while (hops < max_ipv6_ext_headers) {
        switch (next) {
            0, 43, 60 => { // Hop-by-Hop, Routing, Destination Options
                if (raw.len < off + 2) return null;
                const hdr_len = (@as(usize, raw[off + 1]) + 1) * 8;
                if (hdr_len < 8 or raw.len < off + hdr_len) return null;
                next = raw[off];
                off += hdr_len;
            },
            44 => { // Fragment: fixed 8 bytes
                if (raw.len < off + 8) return null;
                next = raw[off];
                off += 8;
            },
            51 => { // Authentication Header: (length + 2) * 4 bytes
                if (raw.len < off + 2) return null;
                const hdr_len = (@as(usize, raw[off + 1]) + 2) * 4;
                if (hdr_len < 8 or raw.len < off + hdr_len) return null;
                next = raw[off];
                off += hdr_len;
            },
            50, 59 => return .{ .off = off, .proto = next }, // ESP / No Next Header
            else => return .{ .off = off, .proto = next },
        }
        hops += 1;
    }
    return null; // bound exceeded: fail closed, never loop forever
}

// ============================================================================
// Decoding functions
// ============================================================================
pub fn decode(raw: []const u8) DecodedPacket {
    var dp = DecodedPacket{ .raw = raw };
    if (raw.len < @sizeOf(EthHdr)) {
        dp.decode_error = "truncated-eth";
        return dp;
    }
    dp.eth = @as(*align(1) const EthHdr, @ptrCast(raw.ptr));
    const et = std.mem.readInt(u16, raw[12..14], .big);
    dp.ether_type = @enumFromInt(et);

    var off: usize = @sizeOf(EthHdr);

    // VLAN / QinQ: unwrap up to max_vlan_tags tags. vlan_id records the outer
    // tag for compatibility. A third tag is left as ether_type and falls
    // through to the non-IP branch rather than being decoded as IP.
    var vlan_tags: u8 = 0;
    while ((dp.ether_type == .vlan or dp.ether_type == .vlan_ad) and vlan_tags < max_vlan_tags) {
        if (raw.len < off + 4) {
            dp.decode_error = "truncated-vlan";
            return dp;
        }
        const tci = std.mem.readInt(u16, raw[off..][0..2], .big);
        if (vlan_tags == 0) dp.vlan_id = tci & 0x0FFF;
        const inner_et = std.mem.readInt(u16, raw[off + 2 ..][0..2], .big);
        dp.ether_type = @enumFromInt(inner_et);
        off += 4;
        vlan_tags += 1;
    }

    switch (dp.ether_type) {
        .arp => {
            if (raw.len < off + @sizeOf(ArpHdr)) {
                dp.decode_error = "truncated-arp";
                return dp;
            }
            dp.arp = @as(*align(1) const ArpHdr, @ptrCast(raw.ptr + off));
        },
        .ipv4 => decodeIpv4(&dp, raw, off),
        .ipv6 => decodeIpv6(&dp, raw, off),
        else => {
            // Non-IP â€” leave decoded fields zero, no error
        },
    }
    return dp;
}

fn decodeIpv4(dp: *DecodedPacket, raw: []const u8, off: usize) void {
    if (raw.len < off + @sizeOf(Ipv4Hdr)) {
        dp.decode_error = "truncated-ipv4";
        return;
    }
    const ip: *align(1) const Ipv4Hdr = @ptrCast(raw.ptr + off);
    dp.ipv4 = ip;
    dp.ip_proto = @enumFromInt(ip.protocol);
    @memcpy(dp.src_ip[0..4], &ip.src);
    @memcpy(dp.dst_ip[0..4], &ip.dst);

    const ihl = (ip.ver_ihl & 0x0F) * 4;
    if (ihl < @sizeOf(Ipv4Hdr)) {
        dp.decode_error = "bad-ihl";
        return;
    }
    const l4_off = off + ihl;
    decodeL4(dp, raw, l4_off, ip.protocol);
}

fn decodeIpv6(dp: *DecodedPacket, raw: []const u8, off: usize) void {
    if (raw.len < off + @sizeOf(Ipv6Hdr)) {
        dp.decode_error = "truncated-ipv6";
        return;
    }
    const ip: *align(1) const Ipv6Hdr = @ptrCast(raw.ptr + off);
    dp.ipv6 = ip;
    dp.is_ipv6 = true;
    dp.ip_proto = @enumFromInt(ip.next_header);
    @memcpy(&dp.src_ip, &ip.src);
    @memcpy(&dp.dst_ip, &ip.dst);
    // Walk any extension headers so L4 sees the real transport protocol and
    // offset. With no extension headers this returns the fixed-header defaults
    // and keeps the previous behavior. A truncated/over-long chain fails
    // closed with a decode_error instead of silently decoding garbage.
    const ext = walkIpv6ExtensionHeaders(raw, off + @sizeOf(Ipv6Hdr), ip.next_header) orelse {
        dp.decode_error = "truncated-ipv6-ext";
        return;
    };
    dp.ip_proto = @enumFromInt(ext.proto);
    decodeL4(dp, raw, ext.off, ext.proto);
}

fn decodeL4(dp: *DecodedPacket, raw: []const u8, off: usize, proto: u8) void {
    switch (proto) {
        @intFromEnum(IpProto.tcp) => decodeTcp(dp, raw, off),
        @intFromEnum(IpProto.udp) => decodeUdp(dp, raw, off),
        @intFromEnum(IpProto.icmp), @intFromEnum(IpProto.ipv6_icmp) => decodeIcmp(dp, raw, off),
        else => {},
    }
}

fn decodeTcp(dp: *DecodedPacket, raw: []const u8, off: usize) void {
    if (raw.len < off + @sizeOf(TcpHdr)) {
        dp.decode_error = "truncated-tcp";
        return;
    }
    const tcp: *align(1) const TcpHdr = @ptrCast(raw.ptr + off);
    dp.tcp = tcp;
    dp.src_port = std.mem.readInt(u16, raw[off..][0..2], .big);
    dp.dst_port = std.mem.readInt(u16, raw[off + 2 ..][0..2], .big);
    const data_off = ((tcp.data_off_flags >> 12) & 0xF) * 4;
    const payload_off = off + data_off;
    if (raw.len > payload_off) {
        dp.payload = raw[payload_off..];
    }
}

fn decodeUdp(dp: *DecodedPacket, raw: []const u8, off: usize) void {
    if (raw.len < off + @sizeOf(UdpHdr)) {
        dp.decode_error = "truncated-udp";
        return;
    }
    const udp: *align(1) const UdpHdr = @ptrCast(raw.ptr + off);
    dp.udp = udp;
    dp.src_port = std.mem.readInt(u16, raw[off..][0..2], .big);
    dp.dst_port = std.mem.readInt(u16, raw[off + 2 ..][0..2], .big);
    const payload_off = off + @sizeOf(UdpHdr);
    if (raw.len > payload_off) {
        dp.payload = raw[payload_off..];
    }
}

fn decodeIcmp(dp: *DecodedPacket, raw: []const u8, off: usize) void {
    if (raw.len < off + @sizeOf(IcmpHdr)) {
        dp.decode_error = "truncated-icmp";
        return;
    }
    dp.icmp = @as(*align(1) const IcmpHdr, @ptrCast(raw.ptr + off));
    if (raw.len > off + @sizeOf(IcmpHdr)) {
        dp.payload = raw[off + @sizeOf(IcmpHdr) ..];
    }
}

// ============================================================================
// Tests
// ============================================================================
test "decode trivial ethernet+ipv4+tcp" {
    // Build a minimal packet
    var pkt: [54]u8 = undefined;
    @memset(&pkt, 0);
    // Eth: dst[6] src[6] type=0x0800
    pkt[12] = 0x08;
    pkt[13] = 0x00;
    // IPv4: ver=4, ihl=5, len=40, proto=6 (TCP)
    pkt[14] = 0x45; // ver+ihl
    pkt[16] = 0x00;
    pkt[17] = 40; // total_len
    pkt[23] = 6; // proto=TCP
    // src/dst IP at offset 26/30
    pkt[26] = 192;
    pkt[27] = 168;
    pkt[28] = 1;
    pkt[29] = 10;
    pkt[30] = 8;
    pkt[31] = 8;
    pkt[32] = 8;
    pkt[33] = 8;
    // TCP at offset 34, header len 5 (20 bytes)
    pkt[34] = 0x12;
    pkt[35] = 0x34; // src_port = 0x1234
    pkt[36] = 0x00;
    pkt[37] = 0x50; // dst_port = 80
    pkt[46] = 0x50; // data_off = 5 (20 bytes), no flags

    const dp = decode(&pkt);
    try std.testing.expect(dp.eth != null);
    try std.testing.expectEqual(EtherType.ipv4, dp.ether_type);
    try std.testing.expect(dp.ipv4 != null);
    try std.testing.expectEqual(IpProto.tcp, dp.ip_proto);
    try std.testing.expect(dp.tcp != null);
    try std.testing.expectEqual(@as(u16, 0x1234), dp.src_port);
    try std.testing.expectEqual(@as(u16, 80), dp.dst_port);
}

test "decode truncated ethernet" {
    var pkt: [10]u8 = undefined;
    @memset(&pkt, 0);
    const dp = decode(&pkt);
    try std.testing.expect(dp.decode_error != null);
    try std.testing.expect(dp.eth == null);
}

test "decode VLAN-tagged packet" {
    var pkt: [58]u8 = undefined;
    @memset(&pkt, 0);
    pkt[12] = 0x81;
    pkt[13] = 0x00; // outer = VLAN
    pkt[14] = 0x12;
    pkt[15] = 0x34; // TCI
    pkt[16] = 0x08;
    pkt[17] = 0x00; // inner = IPv4
    pkt[18] = 0x45; // IPv4
    pkt[27] = 6; // proto=TCP
    const dp = decode(&pkt);
    try std.testing.expectEqual(@as(u16, 0x0234), dp.vlan_id.?);
    try std.testing.expectEqual(EtherType.ipv4, dp.ether_type);
}

test "decode QinQ double-tagged packet" {
    var pkt: [70]u8 = undefined;
    @memset(&pkt, 0);
    pkt[12] = 0x81;
    pkt[13] = 0x00; // outer TPID 802.1Q
    pkt[14] = 0x12;
    pkt[15] = 0x34; // outer TCI
    pkt[16] = 0x88;
    pkt[17] = 0xa8; // inner TPID 802.1ad
    pkt[18] = 0x56;
    pkt[19] = 0x78; // inner TCI
    pkt[20] = 0x08;
    pkt[21] = 0x00; // IPv4
    pkt[22] = 0x45; // ver+ihl
    pkt[31] = 6; // proto=TCP at 22+9
    pkt[42] = 0x12;
    pkt[43] = 0x34; // TCP src port at 22+20
    pkt[44] = 0x00;
    pkt[45] = 0x50; // TCP dst port 80
    pkt[54] = 0x50; // data offset at 42+12
    const dp = decode(&pkt);
    try std.testing.expectEqual(@as(u16, 0x0234), dp.vlan_id.?); // outer tag recorded
    try std.testing.expectEqual(EtherType.ipv4, dp.ether_type);
    try std.testing.expect(dp.ipv4 != null);
    try std.testing.expectEqual(IpProto.tcp, dp.ip_proto);
    try std.testing.expectEqual(@as(u16, 80), dp.dst_port);
}

test "decode IPv6 with hop-by-hop extension header" {
    var pkt: [90]u8 = undefined;
    @memset(&pkt, 0);
    pkt[12] = 0x86;
    pkt[13] = 0xdd; // IPv6
    pkt[20] = 0; // IPv6 next_header = Hop-by-Hop
    // Hop-by-Hop at 54: next = TCP, hdr ext len = 0 -> 8 bytes
    pkt[54] = 6;
    pkt[55] = 0;
    // TCP at 62
    pkt[62] = 0x12;
    pkt[63] = 0x34; // src port
    pkt[64] = 0x00;
    pkt[65] = 0x50; // dst port 80
    pkt[74] = 0x50; // data offset
    const dp = decode(&pkt);
    try std.testing.expect(dp.is_ipv6);
    try std.testing.expectEqual(IpProto.tcp, dp.ip_proto); // transport, not ext header
    try std.testing.expect(dp.tcp != null);
    try std.testing.expectEqual(@as(u16, 80), dp.dst_port);
}

test "decode IPv6 with hop-by-hop and routing extension headers" {
    var pkt: [100]u8 = undefined;
    @memset(&pkt, 0);
    pkt[12] = 0x86;
    pkt[13] = 0xdd;
    pkt[20] = 0; // Hop-by-Hop
    pkt[54] = 43; // Hop-by-Hop next = Routing
    pkt[55] = 0; // 8 bytes
    pkt[62] = 6; // Routing next = TCP
    pkt[63] = 0; // 8 bytes
    pkt[70] = 0x12;
    pkt[71] = 0x34; // TCP src port
    pkt[72] = 0x00;
    pkt[73] = 0x50; // dst port 80
    pkt[82] = 0x50; // data offset
    const dp = decode(&pkt);
    try std.testing.expect(dp.is_ipv6);
    try std.testing.expectEqual(IpProto.tcp, dp.ip_proto);
    try std.testing.expect(dp.tcp != null);
    try std.testing.expectEqual(@as(u16, 80), dp.dst_port);
}

test "decode IPv6 extension header chain fails closed at bound" {
    var pkt: [130]u8 = undefined;
    @memset(&pkt, 0);
    pkt[12] = 0x86;
    pkt[13] = 0xdd;
    pkt[20] = 43; // Routing
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const at = 54 + i * 8;
        pkt[at] = 43; // next = another Routing header
        pkt[at + 1] = 0; // 8 bytes
    }
    const dp = decode(&pkt);
    try std.testing.expect(dp.decode_error != null);
    try std.testing.expectEqualStrings("truncated-ipv6-ext", dp.decode_error.?);
    try std.testing.expect(dp.tcp == null);
}

test "decode IPv6 without extension headers is unchanged" {
    var pkt: [90]u8 = undefined;
    @memset(&pkt, 0);
    pkt[12] = 0x86;
    pkt[13] = 0xdd;
    pkt[20] = 6; // next_header = TCP directly
    pkt[54] = 0x12;
    pkt[55] = 0x34; // src port
    pkt[56] = 0x00;
    pkt[57] = 0x50; // dst port 80
    pkt[66] = 0x50; // data offset
    const dp = decode(&pkt);
    try std.testing.expect(dp.is_ipv6);
    try std.testing.expectEqual(IpProto.tcp, dp.ip_proto);
    try std.testing.expectEqual(@as(u16, 80), dp.dst_port);
    try std.testing.expect(dp.decode_error == null);
}
