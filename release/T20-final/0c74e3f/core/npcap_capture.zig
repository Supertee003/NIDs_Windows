// npcap_capture.zig - AEGIS Npcap Real Traffic Capture (Phase 32)
//
// Real packet capture using Npcap / libpcap loaded DYNAMICALLY at runtime
// via std.DynLib - no import libs, no build.zig changes, graceful fallback
// when the capture library is not installed.
//
// Architecture:
//   - NpcapLoader      loads wpcap.dll / libpcap.so, resolves symbols
//   - enumerateDevices lists capture adapters (pcap_findalldevs)
//   - NpcapSensor      capture session (open, BPF filter, read packets)
//   - PacketParser     Ethernet / VLAN / IPv4 / TCP / UDP / ICMP (pure fns)
//   - CanonicalEvent   normalized event for the AEGIS detection pipeline
//
// Design decisions (DevSecOps):
//   - PASSIVE CAPTURE ONLY - no packet injection in this module
//     (enforcement stays in the WFP kernel driver)
//   - Graceful degradation: if Npcap is absent the module still compiles,
//     all tests pass, parsing helpers remain usable (offline .pcap analysis)
//   - One BPF filter per sensor lifetime (filter program intentionally kept)
//
// Risk: MEDIUM (new sensor integration; passive capture only in v1)
// Mitigation: dynamic load + graceful fallback + capture-only

const std = @import("std");
const builtin = @import("builtin");

// ============================================================
// Constants
// ============================================================

pub const SNAPLEN: c_int = 65535;
pub const DEFAULT_READ_TIMEOUT_MS: c_int = 1000;
pub const MAX_DEVICES = 32;
pub const MAX_FRAME_SIZE = 65535;
pub const PCAP_ERRBUF_SIZE = 256;
pub const PCAP_NETMASK_UNKNOWN: u32 = 0xFFFFFFFF;

// Data link types
pub const DLT_NULL: c_int = 0;
pub const DLT_EN10MB: c_int = 1;
pub const DLT_RAW: c_int = 12;

// Address families
pub const AF_INET = 2;

// Ethernet types
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_EAPOL: u16 = 0x888E; // 802.1X auth (also arrives inside LLC/SNAP on Wi-Fi)
pub const ETHERTYPE_LLDP: u16 = 0x88CC;

// IP protocols
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

// ARP operations
pub const ARP_OPER_REQUEST: u16 = 1;
pub const ARP_OPER_REPLY: u16 = 2;

// TCP flags
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

// pcap_if_t flags
pub const PCAP_IF_LOOPBACK: c_uint = 0x00000001;
pub const PCAP_IF_UP: c_uint = 0x00000002;
pub const PCAP_IF_RUNNING: c_uint = 0x00000004;

pub const ZERO_MAC: EthAddr = .{ 0, 0, 0, 0, 0, 0 };
pub const ZERO_IP4: [4]u8 = .{ 0, 0, 0, 0 };
pub const ZERO_IP6: [16]u8 = [_]u8{0} ** 16;

// Capture library candidates (first one that opens wins).
// Windows: Npcap (WinPcap-compatible). Non-Windows: libpcap.
pub const CAPTURE_LIB_CANDIDATES = if (builtin.os.tag == .windows)
    [_][]const u8{
        "C:\\Windows\\System32\\Npcap\\wpcap.dll", // Npcap default install
        "C:\\Windows\\System32\\wpcap.dll", // WinPcap legacy / Npcap compat mode
        "wpcap.dll", // loader search path
    }
else
    [_][]const u8{
        "libpcap.so.1",
        "libpcap.so",
    };

// ============================================================
// Common types
// ============================================================

pub const EthAddr = [6]u8;

/// timeval layout differs: Windows long = 32-bit, Linux x86_64 time_t = 64-bit
pub const Timeval = if (builtin.os.tag == .windows)
    extern struct { sec: c_long, usec: c_long }
else
    extern struct { sec: isize, usec: isize };

pub const Sockaddr = extern struct {
    family: u16,
    data: [14]u8,
};

pub const PcapAddr = extern struct {
    next: ?*PcapAddr,
    addr: ?*Sockaddr,
    netmask: ?*Sockaddr,
    broadaddr: ?*Sockaddr,
    dstaddr: ?*Sockaddr,
};

pub const PcapIf = extern struct {
    next: ?*PcapIf,
    name: [*:0]u8,
    description: ?[*:0]u8,
    addresses: ?*PcapAddr,
    flags: c_uint,
};

pub const PcapPkthdr = extern struct {
    ts: Timeval,
    caplen: u32,
    len: u32,
};

pub const BpfProgram = extern struct {
    bf_len: c_uint,
    bf_insns: ?*anyopaque,
};

// ============================================================
// pcap function pointer types (WinPcap / libpcap C ABI)
// ============================================================

pub const PcapFindAllDevsFn = *const fn (alldevs: ?*?*PcapIf, errbuf: [*]u8) callconv(.C) c_int;
pub const PcapFreeAllDevsFn = *const fn (alldevs: *PcapIf) callconv(.C) void;
pub const PcapOpenLiveFn = *const fn (device: [*:0]const u8, snaplen: c_int, promisc: c_int, to_ms: c_int, ebuf: [*]u8) callconv(.C) ?*anyopaque;
pub const PcapCloseFn = *const fn (p: ?*anyopaque) callconv(.C) void;
pub const PcapNextExFn = *const fn (p: ?*anyopaque, hdr: *?*const PcapPkthdr, data: *?[*]const u8) callconv(.C) c_int;
pub const PcapGetErrFn = *const fn (p: ?*anyopaque) callconv(.C) [*:0]const u8;
pub const PcapCompileFn = *const fn (p: ?*anyopaque, fp: *BpfProgram, str: [*:0]const u8, optimize: c_int, netmask: u32) callconv(.C) c_int;
pub const PcapSetFilterFn = *const fn (p: ?*anyopaque, fp: *BpfProgram) callconv(.C) c_int;
pub const PcapDataLinkFn = *const fn (p: ?*anyopaque) callconv(.C) c_int;

// ============================================================
// NpcapLoader - dynamic library loader
// ============================================================

pub const NpcapLoader = struct {
    pub const LoadError = enum { none, dll_not_found, symbol_lookup_failed };

    lib: ?std.DynLib = null,
    loaded_path: [256]u8 = undefined,
    loaded_path_len: usize = 0,
    available: bool = false,
    load_error: LoadError = .none,

    // Resolved function pointers
    findalldevs: ?PcapFindAllDevsFn = null,
    freealldevs: ?PcapFreeAllDevsFn = null,
    open_live: ?PcapOpenLiveFn = null,
    close: ?PcapCloseFn = null,
    next_ex: ?PcapNextExFn = null,
    geterr: ?PcapGetErrFn = null,
    compile: ?PcapCompileFn = null,
    setfilter: ?PcapSetFilterFn = null,
    datalink: ?PcapDataLinkFn = null,

    /// Try every candidate path until one loads with all required symbols.
    pub fn load() NpcapLoader {
        var self = NpcapLoader{};
        var opened_any = false;

        for (CAPTURE_LIB_CANDIDATES) |candidate| {
            // Note: use open() (slice-based) - openZ is inconsistent across
            // std implementations in 0.13 for the dlopen variant.
            var lib = std.DynLib.open(candidate) catch continue;
            opened_any = true;

            // Required symbols - mandatory for a working capture session
            const fa = lib.lookup(PcapFindAllDevsFn, "pcap_findalldevs") orelse {
                lib.close();
                continue;
            };
            const fr = lib.lookup(PcapFreeAllDevsFn, "pcap_freealldevs") orelse {
                lib.close();
                continue;
            };
            const ol = lib.lookup(PcapOpenLiveFn, "pcap_open_live") orelse {
                lib.close();
                continue;
            };
            const cl = lib.lookup(PcapCloseFn, "pcap_close") orelse {
                lib.close();
                continue;
            };
            const ne = lib.lookup(PcapNextExFn, "pcap_next_ex") orelse {
                lib.close();
                continue;
            };
            const ge = lib.lookup(PcapGetErrFn, "pcap_geterr") orelse {
                lib.close();
                continue;
            };
            const dl = lib.lookup(PcapDataLinkFn, "pcap_datalink") orelse {
                lib.close();
                continue;
            };

            // Optional symbols - BPF filtering (nice to have)
            const comp = lib.lookup(PcapCompileFn, "pcap_compile");
            const sf = lib.lookup(PcapSetFilterFn, "pcap_setfilter");

            // Keep this library
            const cand_len = @min(candidate.len, self.loaded_path.len);
            @memcpy(self.loaded_path[0..cand_len], candidate[0..cand_len]);
            self.loaded_path_len = cand_len;
            self.lib = lib;
            self.findalldevs = fa;
            self.freealldevs = fr;
            self.open_live = ol;
            self.close = cl;
            self.next_ex = ne;
            self.geterr = ge;
            self.datalink = dl;
            self.compile = comp;
            self.setfilter = sf;
            self.available = true;
            self.load_error = .none;

            std.log.info("[NPCAP] Capture library loaded: {s}", .{candidate});
            return self;
        }

        self.load_error = if (opened_any) .symbol_lookup_failed else .dll_not_found;
        std.log.warn("[NPCAP] No capture library available (error={s}) - capture disabled", .{
            self.loadErrorName(),
        });
        return self;
    }

    pub fn deinit(self: *NpcapLoader) void {
        if (self.lib) |*lib| lib.close();
        self.lib = null;
        self.available = false;
    }

    pub fn loadedPath(self: *const NpcapLoader) []const u8 {
        return self.loaded_path[0..self.loaded_path_len];
    }

    pub fn loadErrorName(self: NpcapLoader) []const u8 {
        return switch (self.load_error) {
            .none => "none",
            .dll_not_found => "dll_not_found",
            .symbol_lookup_failed => "symbol_lookup_failed",
        };
    }
};

// ============================================================
// Device enumeration
// ============================================================

pub const DeviceInfo = struct {
    name_buf: [256]u8 = undefined,
    name_len: usize = 0,
    desc_buf: [128]u8 = undefined,
    desc_len: usize = 0,
    is_loopback: bool = false,
    is_up: bool = false,
    has_ipv4: bool = false,
    ipv4: [4]u8 = ZERO_IP4,

    pub fn name(self: *const DeviceInfo) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn description(self: *const DeviceInfo) []const u8 {
        return self.desc_buf[0..self.desc_len];
    }
};

/// Enumerate capture devices into caller-provided buffer.
/// Returns the number of devices written.
pub fn enumerateDevices(loader: *NpcapLoader, out: []DeviceInfo) !usize {
    if (!loader.available) return error.NpcapUnavailable;
    const fa = loader.findalldevs orelse return error.NpcapUnavailable;

    var dev_list: ?*PcapIf = null;
    var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;
    @memset(&errbuf, 0);

    if (fa(&dev_list, &errbuf) != 0) {
        std.log.err("[NPCAP] findalldevs failed: {s}", .{std.mem.sliceTo(&errbuf, 0)});
        return error.EnumerationFailed;
    }
    defer if (dev_list) |dl| {
        if (loader.freealldevs) |fr| fr(dl);
    };

    var count: usize = 0;
    var cur = dev_list;
    while (cur) |dev| {
        if (count >= out.len) break;

        var info = DeviceInfo{};

        const name_slice = std.mem.sliceTo(dev.name, 0);
        const n = @min(name_slice.len, info.name_buf.len);
        @memcpy(info.name_buf[0..n], name_slice[0..n]);
        info.name_len = n;

        if (dev.description) |desc| {
            const desc_slice = std.mem.sliceTo(desc, 0);
            const d = @min(desc_slice.len, info.desc_buf.len);
            @memcpy(info.desc_buf[0..d], desc_slice[0..d]);
            info.desc_len = d;
        }

        info.is_loopback = (dev.flags & PCAP_IF_LOOPBACK) != 0;
        info.is_up = (dev.flags & PCAP_IF_UP) != 0;

        // Find first IPv4 address (sin_addr at sockaddr offset 4)
        var addr_cur = dev.addresses;
        while (addr_cur) |a| : (addr_cur = a.next) {
            if (a.addr) |sa| {
                if (sa.family == AF_INET) {
                    info.ipv4 = .{ sa.data[2], sa.data[3], sa.data[4], sa.data[5] };
                    info.has_ipv4 = true;
                    break;
                }
            }
        }

        out[count] = info;
        count += 1;
        cur = dev.next;
    }

    return count;
}

// ============================================================
// Packet parsing (pure functions - testable without Npcap)
// ============================================================

pub const EthernetHeader = struct {
    dst_mac: EthAddr,
    src_mac: EthAddr,
    ethertype: u16,
};

pub fn parseEthernet(frame: []const u8) ?EthernetHeader {
    if (frame.len < 14) return null;
    var h: EthernetHeader = undefined;
    @memcpy(&h.dst_mac, frame[0..6]);
    @memcpy(&h.src_mac, frame[6..12]);
    h.ethertype = (@as(u16, frame[12]) << 8) | @as(u16, frame[13]);
    return h;
}

pub const IPv4Header = struct {
    version: u8,
    ihl_words: u8,
    tos: u8,
    total_len: u16,
    id: u16,
    flags: u8, // 3-bit: reserved | DF | MF
    frag_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    checksum_ok: bool,
    src_ip: [4]u8,
    dst_ip: [4]u8,
    header_len: u16,

    pub fn isFragment(self: IPv4Header) bool {
        return (self.frag_offset != 0) or (self.flags & 0x01 != 0); // MF or offset
    }
};

pub fn parseIPv4(data: []const u8) ?IPv4Header {
    if (data.len < 20) return null;
    const version = data[0] >> 4;
    if (version != 4) return null;
    const ihl = data[0] & 0x0F;
    if (ihl < 5) return null;
    const header_len: u16 = @as(u16, ihl) * 4;
    if (data.len < header_len) return null;

    return IPv4Header{
        .version = version,
        .ihl_words = ihl,
        .tos = data[1],
        .total_len = bigU16(data[2], data[3]),
        .id = bigU16(data[4], data[5]),
        .flags = data[6] >> 5,
        .frag_offset = bigU16(data[6] & 0x1F, data[7]),
        .ttl = data[8],
        .protocol = data[9],
        .checksum = bigU16(data[10], data[11]),
        .checksum_ok = verifyIPv4Checksum(data[0..header_len]),
        .src_ip = .{ data[12], data[13], data[14], data[15] },
        .dst_ip = .{ data[16], data[17], data[18], data[19] },
        .header_len = header_len,
    };
}

pub const TCPHeader = struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    data_offset_words: u8,
    flags: u8,
    window: u16,
    checksum: u16,
    urgent: u16,
    header_len: u16,

    pub fn hasFin(self: TCPHeader) bool {
        return self.flags & TCP_FLAG_FIN != 0;
    }
    pub fn hasSyn(self: TCPHeader) bool {
        return self.flags & TCP_FLAG_SYN != 0;
    }
    pub fn hasRst(self: TCPHeader) bool {
        return self.flags & TCP_FLAG_RST != 0;
    }
    pub fn hasAck(self: TCPHeader) bool {
        return self.flags & TCP_FLAG_ACK != 0;
    }
};

pub fn parseTCP(data: []const u8) ?TCPHeader {
    if (data.len < 20) return null;
    const data_offset = data[12] >> 4;
    if (data_offset < 5) return null;
    const header_len: u16 = @as(u16, data_offset) * 4;
    if (data.len < header_len) return null;

    return TCPHeader{
        .src_port = bigU16(data[0], data[1]),
        .dst_port = bigU16(data[2], data[3]),
        .seq = bigU32(data[4], data[5], data[6], data[7]),
        .ack = bigU32(data[8], data[9], data[10], data[11]),
        .data_offset_words = data_offset,
        .flags = data[13],
        .window = bigU16(data[14], data[15]),
        .checksum = bigU16(data[16], data[17]),
        .urgent = bigU16(data[18], data[19]),
        .header_len = header_len,
    };
}

pub const UDPHeader = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

pub fn parseUDP(data: []const u8) ?UDPHeader {
    if (data.len < 8) return null;
    return UDPHeader{
        .src_port = bigU16(data[0], data[1]),
        .dst_port = bigU16(data[2], data[3]),
        .length = bigU16(data[4], data[5]),
        .checksum = bigU16(data[6], data[7]),
    };
}

/// Compute the one's complement IPv4 header checksum.
/// Header must have the checksum field zeroed before calling.
pub fn computeIPv4Checksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) {
        sum += (@as(u32, header[i]) << 8) | @as(u32, header[i + 1]);
    }
    if (i < header.len) sum += @as(u32, header[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return @intCast(~sum & 0xFFFF);
}

/// Verify a full IPv4 header (checksum field included).
pub fn verifyIPv4Checksum(header: []const u8) bool {
    if (header.len < 20) return false;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < header.len) : (i += 2) {
        sum += (@as(u32, header[i]) << 8) | @as(u32, header[i + 1]);
    }
    if (i < header.len) sum += @as(u32, header[i]) << 8;
    while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
    return (~sum & 0xFFFF) == 0;
}

inline fn bigU16(hi: u8, lo: u8) u16 {
    return (@as(u16, hi) << 8) | @as(u16, lo);
}

inline fn bigU32(b0: u8, b1: u8, b2: u8, b3: u8) u32 {
    return (@as(u32, b0) << 24) | (@as(u32, b1) << 16) | (@as(u32, b2) << 8) | @as(u32, b3);
}

// ============================================================
// L2 classification (what did this Ethernet frame actually carry?)
// ============================================================

/// Link-layer classification of a captured frame.
/// Drives stats accounting and the "emit to pipeline" policy:
/// only .ipv4 / .ipv6 / .arp frames become CanonicalEvents.
pub const L2Class = enum {
    ipv4,
    ipv6,
    arp,
    vlan,
    eapol,
    llc_stp,
    llc_snap_other,
    llc_other,
    /// 802.11 null-data / keepalive frames that Npcap surfaces as
    /// Ethernet headers with type=0 and no payload (Wi-Fi L2 chatter).
    dot11_null,
    /// Any other non-IP ethertype (0x88xx vendor frames etc.)
    l2_unknown,
    too_short,
};

/// Classify a raw Ethernet frame without full parsing (pure function).
pub fn classifyEthernetFrame(frame: []const u8) L2Class {
    if (frame.len < 14) return .too_short;
    const et = (@as(u16, frame[12]) << 8) | @as(u16, frame[13]);
    if (et == ETHERTYPE_VLAN) return .vlan;
    if (et == ETHERTYPE_IPV4) return .ipv4;
    if (et == ETHERTYPE_IPV6) return .ipv6;
    if (et == ETHERTYPE_ARP) return .arp;
    if (et == ETHERTYPE_EAPOL) return .eapol;
    if (et > 1500) return .l2_unknown;

    // Ethertype slot holds an 802.3 length field (or 0).
    if (et == 0) {
        // Npcap converts 802.11 null-data (power-save keepalive) frames to
        // Ethernet headers with type=0 and no payload.
        if (frame.len <= 18) return .dot11_null;
        return .l2_unknown;
    }

    // 802.3 + 802.2 LLC
    if (frame.len >= 17) {
        const dsap = frame[14];
        const ssap = frame[15];
        const ctrl = frame[16];
        if (dsap == 0xAA and ssap == 0xAA and ctrl == 0x03) {
            if (frame.len >= 22) {
                const snap_et = (@as(u16, frame[20]) << 8) | @as(u16, frame[21]);
                return switch (snap_et) {
                    ETHERTYPE_IPV4 => .ipv4,
                    ETHERTYPE_IPV6 => .ipv6,
                    ETHERTYPE_ARP => .arp,
                    ETHERTYPE_EAPOL => .eapol,
                    else => .llc_snap_other,
                };
            }
            return .llc_snap_other;
        }
        if (dsap == 0x42 and ssap == 0x42) return .llc_stp; // 802.1D spanning tree
        return .llc_other;
    }
    return .llc_other;
}

// ============================================================
// PacketInfo - full stack parse result
// ============================================================

pub const PacketInfo = struct {
    // Link layer
    dst_mac: EthAddr,
    src_mac: EthAddr,
    ethertype: u16,
    vlan_tagged: bool = false,
    l3_offset: u16 = 0, // frame offset where the IP header starts

    // Network layer (IPv4)
    src_ip: [4]u8,
    dst_ip: [4]u8,
    is_ipv4: bool = false,
    ttl: u8 = 0,
    protocol: u8 = 0,
    ip_header_len: u16 = 0,
    ip_total_len: u16 = 0,

    // Transport layer
    src_port: u16 = 0,
    dst_port: u16 = 0,
    tcp_flags: u8 = 0,

    // Payload (offset relative to start of IP header, i.e. l3_offset)
    payload_offset: u16 = 0,
    payload_len: u16 = 0,

    // v2: L2 classification + IPv6 + ARP
    l2_class: L2Class = .l2_unknown,
    is_ipv6: bool = false,
    src_ip6: [16]u8 = ZERO_IP6,
    dst_ip6: [16]u8 = ZERO_IP6,
    is_arp: bool = false,
    arp_oper: u16 = 0,

    /// Return the payload slice out of the full frame buffer.
    pub fn payloadSlice(self: PacketInfo, frame: []const u8) []const u8 {
        const start = @as(usize, self.l3_offset) + self.payload_offset;
        if (start > frame.len) return &.{};
        const end = @min(frame.len, start + self.payload_len);
        return frame[start..end];
    }

    /// Pipeline policy: only frames that resolved to a network layer
    /// become CanonicalEvents. Wi-Fi keepalives, STP, unknown L2 chatter
    /// are counted in stats but NOT forwarded as events.
    pub fn isEventWorthy(self: PacketInfo) bool {
        return self.is_ipv4 or self.is_ipv6 or self.is_arp;
    }

    pub fn toCanonicalEvent(self: PacketInfo, ts_sec: i64, ts_usec: i64, adapter_ip: ?[4]u8) CanonicalEvent {
        var ev = CanonicalEvent{};
        ev.timestamp_ns = ts_sec * std.time.ns_per_s + ts_usec * std.time.ns_per_us;
        ev.src_mac = self.src_mac;
        ev.dst_mac = self.dst_mac;
        ev.src_ip = self.src_ip;
        ev.dst_ip = self.dst_ip;
        ev.src_port = self.src_port;
        ev.dst_port = self.dst_port;
        ev.protocol = if (self.is_ipv4 or self.is_ipv6) self.protocol else 0;
        ev.tcp_flags = self.tcp_flags;
        ev.payload_len = self.payload_len;
        ev.event_type = switch (self.protocol) {
            PROTO_TCP => CanonicalEvent.EventType.packet_tcp,
            PROTO_UDP => CanonicalEvent.EventType.packet_udp,
            PROTO_ICMP, PROTO_ICMPV6 => CanonicalEvent.EventType.packet_icmp,
            else => CanonicalEvent.EventType.packet_other,
        };
        if (adapter_ip) |aip| {
            if (self.is_ipv4 or self.is_arp) {
                if (std.mem.eql(u8, &self.src_ip, &aip)) {
                    ev.direction = .outbound;
                } else if (std.mem.eql(u8, &self.dst_ip, &aip)) {
                    ev.direction = .inbound;
                }
            }
        }
        return ev;
    }
};

fn zeroPacketInfo() PacketInfo {
    return PacketInfo{
        .dst_mac = ZERO_MAC,
        .src_mac = ZERO_MAC,
        .ethertype = 0,
        .src_ip = ZERO_IP4,
        .dst_ip = ZERO_IP4,
    };
}

/// Parse an Ethernet II frame (optionally VLAN-tagged, LLC/SNAP, or ARP/IPv6)
/// into PacketInfo. Non-IP frames still return a PacketInfo carrying the
/// L2Class (dot11_null keepalives, STP, EAPOL, ...).
pub fn parsePacket(frame: []const u8) ?PacketInfo {
    const eth = parseEthernet(frame) orelse return null;

    var info = zeroPacketInfo();
    info.dst_mac = eth.dst_mac;
    info.src_mac = eth.src_mac;
    info.ethertype = eth.ethertype;
    info.l3_offset = 14;

    const cls = classifyEthernetFrame(frame);
    info.l2_class = cls;

    switch (cls) {
        .vlan => {
            if (frame.len < 18) return info;
            info.vlan_tagged = true;
            info.ethertype = (@as(u16, frame[16]) << 8) | @as(u16, frame[17]);
            info.l3_offset = 18;
            return parseL3(&info, frame[18..]);
        },
        .ipv4, .ipv6, .arp => {
            // L3 headers normally start at 14 - unless the classification
            // resolved through an LLC/SNAP wrapper (payload at 22).
            var l3: usize = 14;
            if (frame.len >= 22 and
                frame[14] == 0xAA and frame[15] == 0xAA and frame[16] == 0x03)
            {
                info.ethertype = (@as(u16, frame[20]) << 8) | @as(u16, frame[21]);
                l3 = 22;
            }
            info.l3_offset = @intCast(l3);
            return switch (info.ethertype) {
                ETHERTYPE_IPV4 => parseInternet(&info, frame[l3..]),
                ETHERTYPE_IPV6 => parseInternet6(&info, frame[l3..]),
                ETHERTYPE_ARP => parseArpInto(&info, frame[l3..]),
                else => info,
            };
        },
        .eapol => {
            // Payload starts after the (optional) LLC/SNAP wrapper.
            const off: usize = if (frame.len >= 17 and
                frame[14] == 0xAA and frame[15] == 0xAA and frame[16] == 0x03) 22 else 14;
            info.l3_offset = @intCast(off);
            info.payload_offset = 0;
            info.payload_len = @intCast(frame.len - off);
            return info;
        },
        // dot11_null, llc_stp, llc_snap_other, llc_other, l2_unknown, too_short:
        // keep the classified header info; no L3 to parse.
        else => return info,
    }
}

/// Dispatch on the inner ethertype for VLAN-encapsulated frames.
fn parseL3(info: *PacketInfo, pkt: []const u8) PacketInfo {
    switch (info.ethertype) {
        ETHERTYPE_IPV4 => return parseInternet(info, pkt),
        ETHERTYPE_IPV6 => return parseInternet6(info, pkt),
        ETHERTYPE_ARP => return parseArpInto(info, pkt),
        else => return info.*,
    }
}

/// Parse a frame captured with any supported DLT.
pub fn parsePacketDLT(dlt: c_int, frame: []const u8) ?PacketInfo {
    switch (dlt) {
        DLT_EN10MB => return parsePacket(frame),
        DLT_RAW => {
            if (frame.len < 20) return null;
            var info = zeroPacketInfo();
            info.l3_offset = 0;
            if (frame[0] >> 4 == 4) {
                info.ethertype = ETHERTYPE_IPV4;
                info.l2_class = .ipv4;
                return parseInternet(&info, frame);
            }
            if (frame[0] >> 4 == 6) {
                info.ethertype = ETHERTYPE_IPV6;
                info.l2_class = .ipv6;
                return parseInternet6(&info, frame);
            }
            return info;
        },
        DLT_NULL => {
            if (frame.len < 24) return null;
            var info = zeroPacketInfo();
            info.l3_offset = 4;
            // 4-byte AF header in host byte order (little-endian on x86)
            const af = @as(u32, frame[0]) | (@as(u32, frame[1]) << 8) |
                (@as(u32, frame[2]) << 16) | (@as(u32, frame[3]) << 24);
            if (af == AF_INET) {
                info.ethertype = ETHERTYPE_IPV4;
                info.l2_class = .ipv4;
                return parseInternet(&info, frame[4..]);
            }
            return info;
        },
        else => return null,
    }
}

fn parseInternet(info: *PacketInfo, pkt: []const u8) PacketInfo {
    if (info.ethertype != ETHERTYPE_IPV4) return info.*;

    const ip = parseIPv4(pkt) orelse return info.*;
    info.is_ipv4 = true;
    info.src_ip = ip.src_ip;
    info.dst_ip = ip.dst_ip;
    info.ttl = ip.ttl;
    info.protocol = ip.protocol;
    info.ip_header_len = ip.header_len;
    info.ip_total_len = ip.total_len;

    // Skip L4 for non-first fragments (no ports available)
    if (ip.isFragment()) return info.*;

    const ip_hdr: usize = ip.header_len;
    const ip_total: usize = ip.total_len;
    const l4_available = if (ip_total > ip_hdr)
        @min(pkt.len - ip_hdr, ip_total - ip_hdr)
    else
        0;
    const l4 = pkt[ip_hdr .. ip_hdr + l4_available];

    switch (ip.protocol) {
        PROTO_TCP => {
            if (parseTCP(l4)) |tcp| {
                info.src_port = tcp.src_port;
                info.dst_port = tcp.dst_port;
                info.tcp_flags = tcp.flags;
                info.payload_offset = @intCast(ip_hdr + tcp.header_len);
                info.payload_len = @intCast(l4.len - tcp.header_len);
            }
        },
        PROTO_UDP => {
            if (parseUDP(l4)) |udp| {
                info.src_port = udp.src_port;
                info.dst_port = udp.dst_port;
                info.payload_offset = @intCast(ip_hdr + 8);
                info.payload_len = if (l4.len > 8) @intCast(l4.len - 8) else 0;
            }
        },
        PROTO_ICMP => {
            info.payload_offset = @intCast(ip_hdr + 8);
            info.payload_len = if (l4.len > 8) @intCast(l4.len - 8) else 0;
        },
        else => {
            info.payload_offset = @intCast(ip_hdr);
            info.payload_len = @intCast(l4.len);
        },
    }

    return info.*;
}

// ============================================================
// ARP parsing (L2.5 - enables future ARP-spoofing detection)
// ============================================================

pub const ARPHeader = struct {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [6]u8,
    spa: [4]u8,
    tha: [6]u8,
    tpa: [4]u8,

    pub fn isRequest(self: ARPHeader) bool {
        return self.oper == ARP_OPER_REQUEST;
    }
    pub fn isReply(self: ARPHeader) bool {
        return self.oper == ARP_OPER_REPLY;
    }
};

pub fn parseARP(data: []const u8) ?ARPHeader {
    if (data.len < 28) return null;
    return ARPHeader{
        .htype = bigU16(data[0], data[1]),
        .ptype = bigU16(data[2], data[3]),
        .hlen = data[4],
        .plen = data[5],
        .oper = bigU16(data[6], data[7]),
        .sha = .{ data[8], data[9], data[10], data[11], data[12], data[13] },
        .spa = .{ data[14], data[15], data[16], data[17] },
        .tha = .{ data[18], data[19], data[20], data[21], data[22], data[23] },
        .tpa = .{ data[24], data[25], data[26], data[27] },
    };
}

fn parseArpInto(info: *PacketInfo, pkt: []const u8) PacketInfo {
    if (parseARP(pkt)) |arp| {
        info.is_arp = true;
        info.arp_oper = arp.oper;
        // Sender/target protocol addresses feed the IPv4-format event fields,
        // so CanonicalEvent stays byte-compatible (contract frozen).
        info.src_ip = arp.spa;
        info.dst_ip = arp.tpa;
        info.payload_len = 0; // ARP padding is not application payload
    }
    return info.*;
}

// ============================================================
// IPv6 parsing (40-byte fixed header + extension header walk)
// ============================================================

pub const IPv6Header = struct {
    traffic_class: u8,
    flow_label: u32,
    payload_len: u16,
    next_header: u8,
    hop_limit: u8,
    src_ip: [16]u8,
    dst_ip: [16]u8,
};

pub fn parseIPv6(data: []const u8) ?IPv6Header {
    if (data.len < 40) return null;
    if (data[0] >> 4 != 6) return null;
    return IPv6Header{
        .traffic_class = (data[0] & 0x0F) << 4 | data[1] >> 4,
        .flow_label = (@as(u32, data[1] & 0x0F) << 16) |
            (@as(u32, data[2]) << 8) | @as(u32, data[3]),
        .payload_len = bigU16(data[4], data[5]),
        .next_header = data[6],
        .hop_limit = data[7],
        .src_ip = .{ data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23] },
        .dst_ip = .{ data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39] },
    };
}

/// Walk IPv6 extension headers (hop-by-hop 0, routing 43, fragment 44,
/// destination options 60). Returns the final protocol and the offset of
/// the L4 header relative to the start of the L4 region (after the fixed
/// 40-byte header).
pub fn ipv6SkipExtHeaders(next_header: u8, data: []const u8) struct { proto: u8, offset: usize } {
    var proto = next_header;
    var off: usize = 0;
    var hops: usize = 0;
    while (hops < 8) : (hops += 1) {
        const is_ext = switch (proto) {
            0, 43, 44, 60 => true,
            else => false,
        };
        if (!is_ext) break;
        if (off + 2 > data.len) break;
        const ext_len: usize = (@as(usize, data[off + 1]) + 1) * 8;
        if (off + ext_len > data.len) break;
        proto = data[off];
        off += ext_len;
    }
    return .{ .proto = proto, .offset = off };
}

fn parseInternet6(info: *PacketInfo, pkt: []const u8) PacketInfo {
    const v6 = parseIPv6(pkt) orelse return info.*;
    info.is_ipv6 = true;
    info.src_ip6 = v6.src_ip;
    info.dst_ip6 = v6.dst_ip;
    info.ttl = v6.hop_limit; // hop limit reuses the ttl field
    info.ip_header_len = 40;
    info.ip_total_len = 40 + v6.payload_len;

    const w = ipv6SkipExtHeaders(v6.next_header, pkt[40..]);
    info.protocol = w.proto;

    const in_payload: usize = @min(pkt.len - 40, @as(usize, v6.payload_len));
    const l4_off = @min(w.offset, in_payload);
    const l4 = pkt[40 + l4_off .. 40 + in_payload];

    switch (info.protocol) {
        PROTO_TCP => {
            if (parseTCP(l4)) |tcp| {
                info.src_port = tcp.src_port;
                info.dst_port = tcp.dst_port;
                info.tcp_flags = tcp.flags;
                info.payload_offset = @intCast(40 + l4_off + tcp.header_len);
                info.payload_len = @intCast(l4.len - tcp.header_len);
            }
        },
        PROTO_UDP => {
            if (parseUDP(l4)) |udp| {
                info.src_port = udp.src_port;
                info.dst_port = udp.dst_port;
                info.payload_offset = @intCast(40 + l4_off + 8);
                info.payload_len = if (l4.len > 8) @intCast(l4.len - 8) else 0;
            }
        },
        PROTO_ICMPV6 => {
            info.payload_offset = @intCast(40 + l4_off + 8);
            info.payload_len = if (l4.len > 8) @intCast(l4.len - 8) else 0;
        },
        else => {
            info.payload_offset = @intCast(40 + l4_off);
            info.payload_len = @intCast(l4.len);
        },
    }

    return info.*;
}

// ============================================================
// CanonicalEvent - normalized event for the AEGIS pipeline
// ============================================================

pub const CanonicalEvent = struct {
    timestamp_ns: i64 = 0,
    src_mac: EthAddr = ZERO_MAC,
    dst_mac: EthAddr = ZERO_MAC,
    src_ip: [4]u8 = ZERO_IP4,
    dst_ip: [4]u8 = ZERO_IP4,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: u8 = 0, // 6=TCP, 17=UDP, 1=ICMP, 0=non-IP
    tcp_flags: u8 = 0,
    payload_len: u16 = 0,
    event_type: EventType = .packet_other,
    direction: Direction = .unknown,

    pub const EventType = enum(u8) {
        packet_tcp = 1,
        packet_udp = 2,
        packet_icmp = 3,
        packet_other = 4,
    };

    pub const Direction = enum(u8) {
        unknown = 0,
        inbound = 1,
        outbound = 2,
    };
};

// ============================================================
// Capture stats
// ============================================================

pub const CaptureStats = struct {
    packets_seen: u64 = 0,
    packets_captured: u64 = 0,
    packets_parsed: u64 = 0,
    packets_malformed: u64 = 0,
    packets_truncated: u64 = 0,
    tcp_packets: u64 = 0,
    udp_packets: u64 = 0,
    icmp_packets: u64 = 0,
    other_packets: u64 = 0,
    ipv6_packets: u64 = 0,
    arp_packets: u64 = 0,
    eapol_packets: u64 = 0,
    /// 802.11 null-data/keepalive frames (Wi-Fi L2 chatter, no IP)
    l2_keepalives: u64 = 0,
    /// STP / LLC / unknown ethertypes - understood but not IP
    l2_other_packets: u64 = 0,
    /// L3 frames only (IPv4/IPv6/ARP) - what the pipeline receives
    events_emitted: u64 = 0,
    timeouts: u64 = 0,
    errors: u64 = 0,
    last_event_ts: i64 = 0,

    pub fn parseRate(self: CaptureStats) f64 {
        if (self.packets_captured == 0) return 0.0;
        return @as(f64, @floatFromInt(self.packets_parsed)) /
            @as(f64, @floatFromInt(self.packets_captured)) * 100.0;
    }
};

// ============================================================
// NpcapSensor - capture session
// ============================================================

pub const PacketFrame = struct {
    data: []const u8, // borrowed from caller's frame buffer
    caplen: u32,
    wirelen: u32,
    ts_sec: i64,
    ts_usec: i64,
};

/// One captured frame with its full parse result (richer than CanonicalEvent:
/// keeps L2Class, IPv6 addresses, ARP ops - used by diagnostics/UI consumers).
pub const FrameInfo = struct {
    info: PacketInfo,
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    wirelen: u32,
};

pub const NpcapSensor = struct {
    allocator: std.mem.Allocator,
    loader: *NpcapLoader,
    handle: ?*anyopaque = null,
    device_name: []u8 = &.{},
    link_type: c_int = -1,
    bpf: BpfProgram = .{ .bf_len = 0, .bf_insns = null },
    filter_active: bool = false,
    adapter_ipv4: ?[4]u8 = null,
    stats: CaptureStats = .{},
    opened: bool = false,

    /// Create a sensor for a device (not yet capturing - call open()).
    /// Deinit exactly once on the owning instance.
    pub fn init(allocator: std.mem.Allocator, loader: *NpcapLoader, device_name: []const u8) !NpcapSensor {
        return .{
            .allocator = allocator,
            .loader = loader,
            .device_name = try allocator.dupe(u8, device_name),
        };
    }

    pub fn deinit(self: *NpcapSensor) void {
        self.closeHandle();
        if (self.device_name.len > 0) self.allocator.free(self.device_name);
        self.device_name = &.{};
    }

    fn closeHandle(self: *NpcapSensor) void {
        if (self.handle) |h| {
            if (self.loader.close) |cl| cl(h);
            self.handle = null;
        }
        self.opened = false;
    }

    /// Open a live capture session on the device.
    pub fn open(self: *NpcapSensor, snapshot_len: c_int, promiscuous: bool, timeout_ms: c_int) !void {
        if (!self.loader.available) return error.NpcapUnavailable;
        const ol = self.loader.open_live orelse return error.NpcapUnavailable;

        const name_z = try std.fmt.allocPrintZ(self.allocator, "{s}", .{self.device_name});
        defer self.allocator.free(name_z);

        var errbuf: [PCAP_ERRBUF_SIZE]u8 = undefined;
        @memset(&errbuf, 0);

        const h = ol(name_z.ptr, snapshot_len, if (promiscuous) 1 else 0, timeout_ms, &errbuf);
        if (h == null) {
            std.log.err("[NPCAP] open_live({s}) failed: {s}", .{
                self.device_name, std.mem.sliceTo(&errbuf, 0),
            });
            return error.OpenFailed;
        }

        self.handle = h;
        if (self.loader.datalink) |dl| self.link_type = dl(h);
        self.opened = true;
        std.log.info("[NPCAP] Capturing on {s} (dlt={d}, promisc={s}, timeout={d}ms)", .{
            self.device_name, self.link_type, if (promiscuous) "on" else "off", timeout_ms,
        });
    }

    /// Set the adapter's own IPv4 - enables inbound/outbound classification.
    pub fn setAdapterIp(self: *NpcapSensor, ip: ?[4]u8) void {
        self.adapter_ipv4 = ip;
    }

    /// Compile and apply a BPF filter (e.g. "tcp port 443").
    /// Note: one filter per sensor lifetime (program kept for sensor's life).
    pub fn setBpfFilter(self: *NpcapSensor, expr: []const u8) !void {
        if (!self.opened) return error.NotOpen;
        const comp = self.loader.compile orelse return error.BpfUnsupported;
        const sf = self.loader.setfilter orelse return error.BpfUnsupported;
        const h = self.handle orelse return error.NotOpen;

        const expr_z = try std.fmt.allocPrintZ(self.allocator, "{s}", .{expr});
        defer self.allocator.free(expr_z);

        var prog = BpfProgram{ .bf_len = 0, .bf_insns = null };
        if (comp(h, &prog, expr_z.ptr, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            if (self.loader.geterr) |ge| {
                const e = ge(h);
                std.log.err("[NPCAP] BPF compile failed: {s}", .{std.mem.sliceTo(e, 0)});
            }
            return error.BpfCompileFailed;
        }
        if (sf(h, &prog) != 0) {
            return error.BpfSetFilterFailed;
        }

        self.bpf = prog;
        self.filter_active = true;
        std.log.info("[NPCAP] BPF filter active: {s}", .{expr});
    }

    /// Read ONE packet. Returns null on timeout (no packet available).
    pub fn readPacket(self: *NpcapSensor, frame_buf: []u8) !?PacketFrame {
        if (!self.opened) return error.NotOpen;
        const ne = self.loader.next_ex orelse return error.NpcapUnavailable;
        const h = self.handle orelse return error.NotOpen;

        var hdr: ?*const PcapPkthdr = null;
        var data: ?[*]const u8 = null;
        const ret = ne(h, &hdr, &data);

        switch (ret) {
            1 => {
                const pkthdr = hdr orelse return error.MalformedHeader;
                const pktdata = data orelse return error.MalformedHeader;
                const caplen: usize = @intCast(pkthdr.caplen);
                self.stats.packets_seen += 1;
                if (caplen > frame_buf.len) {
                    self.stats.packets_truncated += 1;
                    return error.FrameTooLarge;
                }
                @memcpy(frame_buf[0..caplen], pktdata[0..caplen]);
                self.stats.packets_captured += 1;
                return PacketFrame{
                    .data = frame_buf[0..caplen],
                    .caplen = pkthdr.caplen,
                    .wirelen = pkthdr.len,
                    .ts_sec = @intCast(pkthdr.ts.sec),
                    .ts_usec = @intCast(pkthdr.ts.usec),
                };
            },
            0 => {
                self.stats.timeouts += 1;
                return null; // timeout - no packet
            },
            else => {
                self.stats.errors += 1;
                return error.CaptureError;
            },
        }
    }

    /// Shared stats accounting for one parsed frame.
    fn accountInfo(self: *NpcapSensor, info: PacketInfo) void {
        self.stats.packets_parsed += 1;
        if (info.is_ipv4) {
            switch (info.protocol) {
                PROTO_TCP => self.stats.tcp_packets += 1,
                PROTO_UDP => self.stats.udp_packets += 1,
                PROTO_ICMP => self.stats.icmp_packets += 1,
                else => self.stats.other_packets += 1,
            }
            return;
        }
        if (info.is_ipv6) {
            self.stats.ipv6_packets += 1;
            switch (info.protocol) {
                PROTO_TCP => self.stats.tcp_packets += 1,
                PROTO_UDP => self.stats.udp_packets += 1,
                PROTO_ICMPV6 => self.stats.icmp_packets += 1,
                else => self.stats.other_packets += 1,
            }
            return;
        }
        if (info.is_arp) {
            self.stats.arp_packets += 1;
            return;
        }
        switch (info.l2_class) {
            .dot11_null => self.stats.l2_keepalives += 1,
            .eapol => self.stats.eapol_packets += 1,
            else => self.stats.l2_other_packets += 1,
        }
    }

    /// Read and parse up to out.len frames, returning rich FrameInfo
    /// (L2 classification, IPv6, ARP included). Diagnostics/UI consumers
    /// use this to see EVERYTHING on the wire, L2 chatter included.
    pub fn pollFrames(self: *NpcapSensor, out: []FrameInfo, frame_buf: []u8) !usize {
        var count: usize = 0;
        while (count < out.len) {
            const frame = (try self.readPacket(frame_buf)) orelse break;

            const info = parsePacketDLT(self.link_type, frame.data) orelse {
                self.stats.packets_malformed += 1;
                continue;
            };

            self.accountInfo(info);
            out[count] = .{
                .info = info,
                .ts_sec = frame.ts_sec,
                .ts_usec = frame.ts_usec,
                .caplen = frame.caplen,
                .wirelen = frame.wirelen,
            };
            count += 1;
        }
        return count;
    }

    /// Parse up to events.len packets into canonical events (PIPELINE API).
    /// Only L3 frames (IPv4 / IPv6 / ARP) become events; Wi-Fi keepalives,
    /// STP, EAPOL and unknown L2 chatter are counted in stats but skipped.
    /// Returns the number of events written (0 on timeout).
    pub fn pollEvents(self: *NpcapSensor, events: []CanonicalEvent, frame_buf: []u8) !usize {
        var count: usize = 0;
        while (count < events.len) {
            const frame = (try self.readPacket(frame_buf)) orelse break;

            const info = parsePacketDLT(self.link_type, frame.data) orelse {
                self.stats.packets_malformed += 1;
                continue;
            };

            self.accountInfo(info);
            if (!info.isEventWorthy()) continue;

            events[count] = info.toCanonicalEvent(frame.ts_sec, frame.ts_usec, self.adapter_ipv4);
            self.stats.events_emitted += 1;
            self.stats.last_event_ts = std.time.timestamp();
            count += 1;
        }
        return count;
    }

    pub fn getStats(self: *const NpcapSensor) CaptureStats {
        return self.stats;
    }

    pub fn resetStats(self: *NpcapSensor) void {
        self.stats = .{};
    }
};

// ============================================================
// Formatting helpers
// ============================================================

pub fn formatMac(buf: []u8, mac: EthAddr) []const u8 {
    return std.fmt.bufPrint(buf, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch "";
}

pub fn formatIp(buf: []u8, ip: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "";
}

/// Format an IPv6 address in full uncompressed form (8 groups).
/// Buffer must be at least 40 bytes.
pub fn formatIp6(buf: []u8, ip: [16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        ip[0],  ip[1],  ip[2],  ip[3],
        ip[4],  ip[5],  ip[6],  ip[7],
        ip[8],  ip[9],  ip[10], ip[11],
        ip[12], ip[13], ip[14], ip[15],
    }) catch "";
}

// ============================================================
// Singleton facade
// ============================================================

var g_loader: ?NpcapLoader = null;
var g_initialized: bool = false;

pub fn init(allocator: std.mem.Allocator) void {
    _ = allocator;
    if (g_initialized) return;
    g_loader = NpcapLoader.load();
    g_initialized = true;
}

pub fn isInitialized() bool {
    return g_initialized;
}

pub fn shutdown() void {
    if (!g_initialized) return;
    if (g_loader) |*l| l.deinit();
    g_loader = null;
    g_initialized = false;
    std.log.info("[NPCAP] Shutdown", .{});
}

pub fn isAvailable() bool {
    if (!g_initialized) return false;
    if (g_loader) |*l| return l.available;
    return false;
}

pub fn getLoader() ?*NpcapLoader {
    if (!g_initialized) return null;
    if (g_loader) |*l| return l;
    return null;
}

// ============================================================
// Tests (all pass WITHOUT Npcap - parsing is pure, loader degrades)
// ============================================================

test "parseEthernet extracts MACs and ethertype" {
    const frame = [_]u8{
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // dst
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // src
        0x08, 0x00, // IPv4
        0x00, 0x01, 0x02, 0x03, // payload
    };
    const eth = parseEthernet(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E }, &eth.dst_mac);
    try std.testing.expectEqualSlices(u8, &.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, &eth.src_mac);
    try std.testing.expectEqual(@as(u16, 0x0800), eth.ethertype);
}

test "parseEthernet rejects short frame" {
    const frame = [_]u8{ 0x00, 0x01, 0x02, 0x03 };
    try std.testing.expect(parseEthernet(&frame) == null);
}

test "parseIPv4 extracts header fields with valid checksum" {
    var hdr = [_]u8{
        0x45, 0x00, 0x00, 0x28, // version/ihl, tos, total_len=40
        0x12, 0x34, 0x40, 0x00, // id, DF flag
        0x40, 0x06, 0x00, 0x00, // ttl=64, proto=TCP, checksum=0
        192, 168, 1, 5, // src
        192, 168, 1, 10, // dst
    };
    const cksum = computeIPv4Checksum(&hdr);
    hdr[10] = @intCast(cksum >> 8);
    hdr[11] = @intCast(cksum & 0xFF);

    const ip = parseIPv4(&hdr) orelse return error.TestUnexpectedResult;
    try std.testing.expect(ip.checksum_ok);
    try std.testing.expectEqual(@as(u8, 6), ip.protocol);
    try std.testing.expectEqual(@as(u16, 40), ip.total_len);
    try std.testing.expectEqual(@as(u16, 20), ip.header_len);
    try std.testing.expectEqual(@as(u8, 64), ip.ttl);
    try std.testing.expect(!ip.isFragment());
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 5 }, &ip.src_ip);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &ip.dst_ip);
}

test "parseIPv4 rejects non-IPv4 and short data" {
    const not_ip = [_]u8{ 0x60, 0x00 } ++ [_]u8{0} ** 18; // IPv6 version nibble
    try std.testing.expect(parseIPv4(&not_ip) == null);

    const too_short = [_]u8{ 0x45, 0x00, 0x00 };
    try std.testing.expect(parseIPv4(&too_short) == null);

    // valid first byte but truncated
    const truncated = [_]u8{ 0x45, 0x00 } ++ [_]u8{0} ** 10;
    try std.testing.expect(parseIPv4(&truncated) == null);
}

test "parseTCP extracts ports, flags and header length" {
    const hdr = [_]u8{
        0xC8, 0x62, 0x01, 0xBB, // src=51298, dst=443
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x02, // ack
        0x50, 0x12, 0xFA, 0xF0, // offset=5, flags=SYN|ACK, window
        0x00, 0x00, 0x00, 0x00, // checksum, urgent
    };
    const tcp = parseTCP(&hdr) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 51298), tcp.src_port);
    try std.testing.expectEqual(@as(u16, 443), tcp.dst_port);
    try std.testing.expectEqual(@as(u8, TCP_FLAG_SYN | TCP_FLAG_ACK), tcp.flags);
    try std.testing.expectEqual(@as(u16, 20), tcp.header_len);
    try std.testing.expect(tcp.hasSyn());
    try std.testing.expect(tcp.hasAck());
    try std.testing.expect(!tcp.hasRst());
}

test "parseUDP extracts ports and length" {
    const hdr = [_]u8{
        0x14, 0xE9, 0x00, 0x35, // src=5353, dst=53
        0x00, 0x0C, 0x00, 0x00, // length=12, checksum
        0xDE, 0xAD, 0xBE, 0xEF, // payload
    };
    const udp = parseUDP(&hdr) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u16, 5353), udp.src_port);
    try std.testing.expectEqual(@as(u16, 53), udp.dst_port);
    try std.testing.expectEqual(@as(u16, 12), udp.length);
}

test "computeIPv4Checksum matches verifyIPv4Checksum" {
    const hdr = [_]u8{
        0x45, 0x00, 0x00, 0x28,
        0x12, 0x34, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2,
    };
    const cksum = computeIPv4Checksum(&hdr);
    // Checksum must be non-zero and self-consistent
    try std.testing.expect(cksum != 0);

    var with_cksum = hdr;
    with_cksum[10] = @intCast(cksum >> 8);
    with_cksum[11] = @intCast(cksum & 0xFF);
    try std.testing.expect(verifyIPv4Checksum(&with_cksum));

    // Corrupt one byte - must fail
    with_cksum[19] ^= 0xFF;
    try std.testing.expect(!verifyIPv4Checksum(&with_cksum));
}

test "parsePacket full TCP/IP/Ethernet stack with payloadSlice" {
    var frame: [54]u8 = [_]u8{0} ** 54;

    // Ethernet
    frame[0..6].* = .{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    frame[6..12].* = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    frame[12] = 0x08;
    frame[13] = 0x00;

    // IPv4 (total_len = 20 + 20 = 40)
    frame[14] = 0x45;
    frame[15] = 0x00;
    frame[16] = 0x00;
    frame[17] = 0x28;
    frame[18] = 0x12;
    frame[19] = 0x34;
    frame[20] = 0x40; // DF
    frame[22] = 0x40; // TTL
    frame[23] = 0x06; // TCP
    frame[26] = 192;
    frame[27] = 168;
    frame[28] = 1;
    frame[29] = 5;
    frame[30] = 192;
    frame[31] = 168;
    frame[32] = 1;
    frame[33] = 10;

    // TCP SYN from 51298 to 443
    frame[34] = 0xC8;
    frame[35] = 0x62;
    frame[36] = 0x01;
    frame[37] = 0xBB;
    frame[46] = 0x50; // data offset 5
    frame[47] = 0x02; // SYN
    frame[48] = 0xFA;
    frame[49] = 0xF0; // window

    const cksum = computeIPv4Checksum(frame[14..34]);
    frame[24] = @intCast(cksum >> 8);
    frame[25] = @intCast(cksum & 0xFF);

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(info.is_ipv4);
    try std.testing.expectEqual(@as(u8, 6), info.protocol);
    try std.testing.expectEqual(@as(u16, 51298), info.src_port);
    try std.testing.expectEqual(@as(u16, 443), info.dst_port);
    try std.testing.expectEqual(@as(u8, TCP_FLAG_SYN), info.tcp_flags);
    try std.testing.expectEqual(@as(u16, 14), info.l3_offset);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 5 }, &info.src_ip);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 10 }, &info.dst_ip);

    // No payload: header-only SYN
    const payload = info.payloadSlice(&frame);
    try std.testing.expectEqual(@as(usize, 0), payload.len);
}

test "parsePacket keeps ARP as L2-only event" {
    var frame: [42]u8 = [_]u8{0} ** 42;
    frame[12] = 0x08;
    frame[13] = 0x06; // ARP
    frame[14] = 0x00;
    frame[15] = 0x01; // hw type ethernet

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(!info.is_ipv4);
    try std.testing.expectEqual(@as(u16, ETHERTYPE_ARP), info.ethertype);
    try std.testing.expectEqual(@as(u8, 0), info.protocol);
}

test "parsePacket handles VLAN-tagged IPv4" {
    var frame: [18 + 20]u8 = [_]u8{0} ** 38;

    // Ethernet with 802.1Q tag
    frame[12] = 0x81;
    frame[13] = 0x00; // VLAN
    frame[14] = 0x00;
    frame[15] = 0x0A; // VLAN id 10
    frame[16] = 0x08;
    frame[17] = 0x00; // inner ethertype IPv4

    // IPv4 header (proto UDP, total 28)
    frame[18] = 0x45; // version/ihl
    frame[20] = 0x00;
    frame[21] = 0x1C; // total_len 28
    frame[26] = 0x40; // TTL
    frame[27] = 0x11; // proto 17 UDP
    frame[30] = 10;
    frame[31] = 0;
    frame[32] = 0;
    frame[33] = 1;

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(info.vlan_tagged);
    try std.testing.expect(info.is_ipv4);
    try std.testing.expectEqual(@as(u16, 18), info.l3_offset);
    try std.testing.expectEqual(@as(u8, 17), info.protocol);
}

test "parsePacketDLT handles RAW and NULL link types" {
    const ip_pkt = [_]u8{
        0x45, 0x00, 0x00, 0x1C,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        10, 1, 2, 3,
        10, 1, 2, 4,
        0x00, 0x35, 0x00, 0x35,
        0x00, 0x08, 0x00, 0x00,
    };

    // RAW: IP packet starts at offset 0
    const raw_info = parsePacketDLT(DLT_RAW, &ip_pkt) orelse return error.TestUnexpectedResult;
    try std.testing.expect(raw_info.is_ipv4);
    try std.testing.expectEqual(@as(u16, 0), raw_info.l3_offset);
    try std.testing.expectEqual(@as(u16, 53), raw_info.dst_port);

    // NULL (BSD loopback): 4-byte AF header then IP
    var null_frame: [4 + 28]u8 = undefined;
    null_frame[0] = 2; // AF_INET little-endian
    null_frame[1] = 0;
    null_frame[2] = 0;
    null_frame[3] = 0;
    @memcpy(null_frame[4..], &ip_pkt);
    const null_info = parsePacketDLT(DLT_NULL, &null_frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(null_info.is_ipv4);
    try std.testing.expectEqual(@as(u16, 4), null_info.l3_offset);

    // Unknown DLT rejected
    try std.testing.expect(parsePacketDLT(999, &ip_pkt) == null);
}

test "toCanonicalEvent maps fields and direction" {
    const info = PacketInfo{
        .dst_mac = .{ 1, 2, 3, 4, 5, 6 },
        .src_mac = .{ 6, 5, 4, 3, 2, 1 },
        .ethertype = ETHERTYPE_IPV4,
        .l3_offset = 14,
        .src_ip = .{ 192, 168, 1, 5 },
        .dst_ip = .{ 93, 184, 216, 34 },
        .is_ipv4 = true,
        .ttl = 64,
        .protocol = PROTO_TCP,
        .src_port = 51234,
        .dst_port = 443,
        .tcp_flags = TCP_FLAG_SYN,
        .payload_len = 100,
    };

    // Outbound: source is the adapter
    const ev_out = info.toCanonicalEvent(1700000000, 500000, .{ 192, 168, 1, 5 });
    try std.testing.expectEqual(CanonicalEvent.Direction.outbound, ev_out.direction);
    try std.testing.expectEqual(CanonicalEvent.EventType.packet_tcp, ev_out.event_type);
    try std.testing.expectEqual(@as(u16, 443), ev_out.dst_port);
    try std.testing.expectEqual(@as(u8, PROTO_TCP), ev_out.protocol);
    try std.testing.expectEqual(@as(i64, 1700000000500000000), ev_out.timestamp_ns);

    // Inbound: destination is the adapter
    const ev_in = info.toCanonicalEvent(1700000000, 0, .{ 93, 184, 216, 34 });
    try std.testing.expectEqual(CanonicalEvent.Direction.inbound, ev_in.direction);

    // Unknown: adapter not involved
    const ev_unk = info.toCanonicalEvent(1700000000, 0, .{ 10, 0, 0, 1 });
    try std.testing.expectEqual(CanonicalEvent.Direction.unknown, ev_unk.direction);

    // No adapter info at all
    const ev_none = info.toCanonicalEvent(1700000000, 0, null);
    try std.testing.expectEqual(CanonicalEvent.Direction.unknown, ev_none.direction);
}

test "formatMac and formatIp produce canonical strings" {
    var buf1: [18]u8 = undefined;
    const mac = formatMac(&buf1, .{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E });
    try std.testing.expectEqualStrings("00:1a:2b:3c:4d:5e", mac);

    var buf2: [16]u8 = undefined;
    const ip = formatIp(&buf2, .{ 192, 168, 1, 100 });
    try std.testing.expectEqualStrings("192.168.1.100", ip);
}

test "CaptureStats.parseRate computations" {
    const empty = CaptureStats{};
    try std.testing.expect(empty.parseRate() == 0.0);

    const partial = CaptureStats{
        .packets_captured = 10,
        .packets_parsed = 9,
    };
    try std.testing.expect(partial.parseRate() == 90.0);
}

test "NpcapLoader.load degrades gracefully without capture lib" {
    var loader = NpcapLoader.load();
    defer loader.deinit();

    if (loader.available) {
        // Capture library present (Npcap on Windows / libpcap on Linux)
        try std.testing.expect(loader.findalldevs != null);
        try std.testing.expect(loader.freealldevs != null);
        try std.testing.expect(loader.open_live != null);
        try std.testing.expect(loader.close != null);
        try std.testing.expect(loader.next_ex != null);
        try std.testing.expect(loader.geterr != null);
        try std.testing.expect(loader.datalink != null);
        try std.testing.expect(loader.loadedPath().len > 0);
    } else {
        // No capture library - module still usable for pure parsing
        try std.testing.expect(loader.findalldevs == null);
        try std.testing.expect(loader.load_error == .dll_not_found);
    }
}

test "enumerateDevices errors cleanly when unavailable" {
    var loader = NpcapLoader.load();
    defer loader.deinit();

    var devices: [MAX_DEVICES]DeviceInfo = undefined;
    if (!loader.available) {
        const result = enumerateDevices(&loader, &devices);
        try std.testing.expectError(error.NpcapUnavailable, result);
    } else {
        // Real enumeration must not crash; count is within bounds
        const count = try enumerateDevices(&loader, &devices);
        try std.testing.expect(count <= MAX_DEVICES);
    }
}

test "npcap_capture singleton lifecycle" {
    if (isInitialized()) shutdown();
    try std.testing.expect(!isInitialized());
    try std.testing.expect(!isAvailable());
    try std.testing.expect(getLoader() == null);

    init(std.testing.allocator);
    defer shutdown();
    try std.testing.expect(isInitialized());
    // Either state is valid - no crash is what matters
    _ = isAvailable();
    if (getLoader()) |ldr| {
        try std.testing.expect(ldr.available or ldr.load_error == .dll_not_found);
    }
}

// ============================================================
// v2 tests: L2 classification, ARP, IPv6, LLC/SNAP, event policy
// ============================================================

test "classifyEthernetFrame identifies wifi keepalive, STP and unknown types" {
    // 802.11 null-data/keepalive as Npcap surfaces it: Ethernet header
    // with type=0 and no payload (exactly what the field test showed).
    const keepalive = [_]u8{
        0x00, 0x93, 0x37, 0xE5, 0xE7, 0x55, // dst
        0x78, 0x53, 0x0D, 0x68, 0x7C, 0x18, // src
        0x00, 0x00, // type 0
    };
    try std.testing.expectEqual(L2Class.dot11_null, classifyEthernetFrame(&keepalive));

    // 802.1D STP: 802.3 length + LLC 42 42 03
    var stp = [_]u8{0} ** 20;
    stp[12] = 0;
    stp[13] = 4; // 802.3 length field
    stp[14] = 0x42;
    stp[15] = 0x42;
    stp[16] = 0x03;
    try std.testing.expectEqual(L2Class.llc_stp, classifyEthernetFrame(&stp));

    // Unknown ethertype 0x8899
    var unk = [_]u8{0} ** 20;
    unk[12] = 0x88;
    unk[13] = 0x99;
    try std.testing.expectEqual(L2Class.l2_unknown, classifyEthernetFrame(&unk));

    // Raw EAPOL ethertype
    var eapol = [_]u8{0} ** 30;
    eapol[12] = 0x88;
    eapol[13] = 0x8E;
    try std.testing.expectEqual(L2Class.eapol, classifyEthernetFrame(&eapol));

    // Too short
    const short = [_]u8{ 0, 1, 2, 3, 4, 5 };
    try std.testing.expectEqual(L2Class.too_short, classifyEthernetFrame(&short));
}

test "parsePacket handles LLC/SNAP encapsulated IPv4" {
    var frame: [14 + 8 + 28]u8 = [_]u8{0} ** (14 + 8 + 28);

    frame[0..6].* = .{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    frame[6..12].* = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    frame[12] = 0x00;
    frame[13] = 0x24; // 802.3 length = 36 (8 LLC/SNAP + 28 IP)
    // LLC/SNAP: AA AA 03 00 00 00 + ethertype
    frame[14] = 0xAA;
    frame[15] = 0xAA;
    frame[16] = 0x03;
    frame[17] = 0x00;
    frame[18] = 0x00;
    frame[19] = 0x00;
    frame[20] = 0x08;
    frame[21] = 0x00; // SNAP ethertype = IPv4

    // IPv4 + UDP DNS (5353 -> 53), total_len 28
    frame[22] = 0x45;
    frame[24] = 0x00;
    frame[25] = 0x1C; // total_len 28
    frame[30] = 0x40; // TTL
    frame[31] = 0x11; // UDP
    frame[34] = 10;
    frame[35] = 0;
    frame[36] = 0;
    frame[37] = 1;
    frame[38] = 10;
    frame[39] = 0;
    frame[40] = 0;
    frame[41] = 2;
    frame[42] = 0x14;
    frame[43] = 0xE9; // src 5353
    frame[44] = 0x00;
    frame[45] = 0x35; // dst 53
    frame[46] = 0x00;
    frame[47] = 0x08; // UDP len 8

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(info.is_ipv4);
    try std.testing.expectEqual(L2Class.ipv4, info.l2_class);
    try std.testing.expectEqual(@as(u16, 22), info.l3_offset);
    try std.testing.expectEqual(@as(u16, 53), info.dst_port);
    try std.testing.expect(info.isEventWorthy());
}

test "parsePacket extracts ARP request into PacketInfo" {
    var frame: [42]u8 = [_]u8{0} ** 42; // 14 eth + 28 arp (classic 60-byte frame is 42+18 pad)
    frame[12] = 0x08;
    frame[13] = 0x06;
    // ARP request
    frame[14] = 0x00;
    frame[15] = 0x01; // htype ethernet
    frame[16] = 0x08;
    frame[17] = 0x00; // ptype IPv4
    frame[18] = 6; // hlen
    frame[19] = 4; // plen
    frame[20] = 0x00;
    frame[21] = 0x01; // oper = request
    // sha zeroed
    frame[28] = 192;
    frame[29] = 168;
    frame[30] = 1;
    frame[31] = 41; // spa = 192.168.1.41
    frame[38] = 192;
    frame[39] = 168;
    frame[40] = 1;
    frame[41] = 1; // tpa = 192.168.1.1

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(info.is_arp);
    try std.testing.expect(!info.is_ipv4);
    try std.testing.expectEqual(@as(u16, ARP_OPER_REQUEST), info.arp_oper);
    try std.testing.expectEqual(L2Class.arp, info.l2_class);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 41 }, &info.src_ip);
    try std.testing.expectEqualSlices(u8, &.{ 192, 168, 1, 1 }, &info.dst_ip);
    try std.testing.expect(info.isEventWorthy());

    const arp = parseARP(frame[14..]) orelse return error.TestUnexpectedResult;
    try std.testing.expect(arp.isRequest());
    try std.testing.expect(!arp.isReply());
}

test "parsePacket parses IPv6 TCP with canonical event mapping" {
    var frame: [14 + 40 + 20]u8 = [_]u8{0} ** (14 + 40 + 20);

    frame[12] = 0x86;
    frame[13] = 0xDD; // IPv6

    // IPv6 header: version 6, payload_len 20, next_header TCP(6), hop 64
    frame[14] = 0x60;
    frame[18] = 0x00;
    frame[19] = 0x14; // payload_len 20
    frame[20] = 6; // TCP
    frame[21] = 64; // hop limit
    // src fe80::1, dst fe80::2
    frame[37] = 1; // last byte of src
    frame[53] = 2; // last byte of dst

    // TCP 52341 -> 443 SYN
    frame[54] = 0xCC;
    frame[55] = 0x75; // src port 52341
    frame[56] = 0x01;
    frame[57] = 0xBB; // dst port 443
    frame[66] = 0x50; // data offset 5
    frame[67] = 0x02; // SYN

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(info.is_ipv6);
    try std.testing.expect(!info.is_ipv4);
    try std.testing.expectEqual(L2Class.ipv6, info.l2_class);
    try std.testing.expectEqual(@as(u8, PROTO_TCP), info.protocol);
    try std.testing.expectEqual(@as(u16, 52341), info.src_port);
    try std.testing.expectEqual(@as(u16, 443), info.dst_port);
    try std.testing.expectEqual(@as(u8, TCP_FLAG_SYN), info.tcp_flags);
    try std.testing.expectEqual(@as(u8, 64), info.ttl); // hop limit

    // Pipeline mapping (contract frozen): IPv6 TCP still yields packet_tcp
    const ev = info.toCanonicalEvent(1700000000, 0, null);
    try std.testing.expectEqual(CanonicalEvent.EventType.packet_tcp, ev.event_type);
    try std.testing.expectEqual(@as(u8, PROTO_TCP), ev.protocol);
}

test "parsePacket walks IPv6 hop-by-hop extension header to TCP" {
    // 14 eth + 40 v6 + 8 hop-by-hop + 20 tcp
    var frame: [14 + 40 + 8 + 20]u8 = [_]u8{0} ** (14 + 40 + 8 + 20);

    frame[12] = 0x86;
    frame[13] = 0xDD;
    frame[14] = 0x60;
    frame[18] = 0x00;
    frame[19] = 0x1C; // payload_len 28 (8 ext + 20 tcp)
    frame[20] = 0; // next header = hop-by-hop options
    frame[21] = 64;

    // Hop-by-hop ext header at 54: next=6 (TCP), ext len = (0+1)*8 = 8
    frame[54] = 6;
    frame[55] = 0;

    // TCP at frame[62] (src 52341 -> dst 443 SYN)
    frame[62] = 0xCC;
    frame[63] = 0x75; // src port 52341
    frame[64] = 0x01;
    frame[65] = 0xBB; // dst port 443
    frame[74] = 0x50; // offset 5
    frame[75] = 0x02; // SYN

    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expect(info.is_ipv6);
    try std.testing.expectEqual(@as(u8, PROTO_TCP), info.protocol);
    try std.testing.expectEqual(@as(u16, 443), info.dst_port);
    try std.testing.expectEqual(@as(u8, TCP_FLAG_SYN), info.tcp_flags);
}

test "parsePacket classifies dot11 null frames as non-event L2 chatter" {
    // The exact pattern from the field test: type=0, no payload.
    const frame = [_]u8{
        0x00, 0x93, 0x37, 0xE5, 0xE7, 0x55,
        0x78, 0x53, 0x0D, 0x68, 0x7C, 0x18,
        0x00, 0x00,
    };
    const info = parsePacket(&frame) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(L2Class.dot11_null, info.l2_class);
    try std.testing.expect(!info.is_ipv4);
    try std.testing.expect(!info.is_ipv6);
    try std.testing.expect(!info.is_arp);
    try std.testing.expect(!info.isEventWorthy()); // pipeline skips it
}

test "formatIp6 produces full uncompressed form" {
    var buf: [40]u8 = undefined;
    const s = formatIp6(&buf, .{
        0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    });
    try std.testing.expectEqualStrings("fe80:0000:0000:0000:0000:0000:0000:0001", s);
}

test "parseIPv6 rejects short and non-IPv6 data" {
    const short = [_]u8{ 0x60, 0x00, 0x00, 0x00 };
    try std.testing.expect(parseIPv6(&short) == null);

    var not_v6 = [_]u8{0} ** 40;
    not_v6[0] = 0x45; // IPv4 version nibble
    try std.testing.expect(parseIPv6(&not_v6) == null);
}
