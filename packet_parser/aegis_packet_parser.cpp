/**
 * aegis_packet_parser.cpp — AEGIS NIDS Packet Parser (Layer 1: KERNEL)
 *
 * Zero-allocation, branch-prediction-friendly protocol parser that extracts
 * structured fields from raw network frames. Designed for hot-path use:
 * called for every packet before it enters the Zig Aho-Corasick matcher.
 *
 * Build: MSVC C++20 (userspace DLL, linked with aegis_ipc.dll)
 * Language: C++ (constexpr, std::bit_cast, zero-copy spans)
 *
 * Copyright (c) 2024 AEGIS NIDS Project
 */

#pragma once
#include <cstdint>
#include <span>
#include <optional>
#include <bit>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iphlpapi.h>

/* ─── Ethernet Header ─── */
struct EthHeader {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;   /* Network byte order */
};

/* ─── IPv4 Header (no options) ─── */
struct IPv4Header {
    uint8_t  ver_ihl;     /* Version (4) + IHL (5-15) */
    uint8_t  tos;
    uint16_t total_len;   /* Network byte order */
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

/* ─── IPv6 Header ─── */
struct IPv6Header {
    uint32_t ver_tc_flow; /* Version(4) + TC(8) + Flow Label(20) */
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
};

/* ─── TCP Header ─── */
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset; /* Only high 4 bits */
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

/* ─── UDP Header ─── */
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

/* ─── Parsed Result ─── */
enum class L4Proto : uint8_t {
    Unknown = 0,
    TCP     = 6,
    UDP     = 17,
    ICMP    = 1,
    ICMPv6  = 58,
    SCTP    = 132,
};

struct ParsedPacket {
    /* L2 */
    uint16_t ethertype;       /* 0x0800=IPv4, 0x86DD=IPv6 */
    const uint8_t* src_mac;
    const uint8_t* dst_mac;

    /* L3 */
    bool     is_ipv6;
    uint32_t src_ip4;         /* Network byte order (0 if IPv6) */
    uint32_t dst_ip4;
    const uint8_t* src_ip6;   /* nullptr if IPv4 */
    const uint8_t* dst_ip6;
    uint8_t  ip_proto;        /* IP protocol number */
    uint8_t  ttl;

    /* L4 */
    L4Proto  l4_proto;
    uint16_t src_port;        /* Host byte order (0 if N/A) */
    uint16_t dst_port;
    uint8_t  tcp_flags;       /* TCP flags byte (0 if not TCP) */

    /* Payload */
    std::span<const uint8_t> payload;  /* L7 data (after all headers) */

    /* Metadata */
    uint32_t total_len;       /* Total frame length */
    uint32_t header_len;      /* Total header length (L2+L3+L4) */
    bool     valid;           /* Parse succeeded */
};

/* ─── Utility: Network ↔ Host Byte Order ─── */
static constexpr uint16_t net_to_host16(uint16_t v) {
    return (v >> 8) | (v << 8);
}
static constexpr uint32_t net_to_host32(uint32_t v) {
    return ((v >> 24) & 0xFF) | ((v >> 8) & 0xFF00) |
           ((v << 8) & 0xFF0000) | ((v << 24) & 0xFF000000);
}

/* ─── Core Parser ─── */
class PacketParser {
public:
    /**
     * parse - Parse a raw Ethernet frame into structured fields.
     * Zero-copy: all pointers reference the original frame data.
     *
     * @frame   Raw frame bytes (starting from Ethernet header)
     * @return  ParsedPacket with extracted fields
     */
    static ParsedPacket parse(std::span<const uint8_t> frame) noexcept {
        ParsedPacket pkt{};
        pkt.total_len = static_cast<uint32_t>(frame.size());
        pkt.valid = false;

        if (frame.size() < sizeof(EthHeader))
            return pkt;

        /* ── L2: Ethernet ── */
        const auto* eth = reinterpret_cast<const EthHeader*>(frame.data());
        pkt.ethertype = net_to_host16(eth->ethertype);
        pkt.src_mac = eth->src_mac;
        pkt.dst_mac = eth->dst_mac;

        size_t offset = sizeof(EthHeader);

        /* Handle VLAN tags (802.1Q) */
        while (pkt.ethertype == 0x8100 || pkt.ethertype == 0x88A8) {
            if (offset + 4 > frame.size()) return pkt;
            pkt.ethertype = net_to_host16(*reinterpret_cast<const uint16_t*>(frame.data() + offset + 2));
            offset += 4;
        }

        /* ── L3: IPv4 or IPv6 ── */
        if (pkt.ethertype == 0x0800) {
            /* IPv4 */
            pkt.is_ipv6 = false;
            if (offset + sizeof(IPv4Header) > frame.size()) return pkt;

            const auto* ip4 = reinterpret_cast<const IPv4Header*>(frame.data() + offset);
            uint8_t ihl = ip4->ver_ihl & 0x0F;
            if (ihl < 5) return pkt;  /* Minimum IHL */

            size_t ip_hdr_len = static_cast<size_t>(ihl) * 4;
            if (offset + ip_hdr_len > frame.size()) return pkt;

            pkt.src_ip4  = ip4->src_ip;
            pkt.dst_ip4  = ip4->dst_ip;
            pkt.ip_proto = ip4->protocol;
            pkt.ttl      = ip4->ttl;
            offset += ip_hdr_len;

        } else if (pkt.ethertype == 0x86DD) {
            /* IPv6 */
            pkt.is_ipv6 = true;
            if (offset + sizeof(IPv6Header) > frame.size()) return pkt;

            const auto* ip6 = reinterpret_cast<const IPv6Header*>(frame.data() + offset);
            pkt.src_ip6 = ip6->src_ip;
            pkt.dst_ip6 = ip6->dst_ip;
            pkt.ip_proto = ip6->next_header;
            pkt.ttl = ip6->hop_limit;

            /* Handle IPv6 extension headers */
            size_t ip_hdr_len = sizeof(IPv6Header);
            uint8_t next_hdr = ip6->next_header;
            while (next_hdr != 6 && next_hdr != 17 && next_hdr != 58 && next_hdr != 132 &&
                   next_hdr != 59 /* No Next Header */) {
                if (offset + ip_hdr_len + 8 > frame.size()) break;
                const uint8_t* ext = frame.data() + offset + ip_hdr_len;
                next_hdr = ext[0];
                uint8_t ext_len = ext[1];
                ip_hdr_len += static_cast<size_t>(ext_len + 1) * 8;
            }
            pkt.ip_proto = next_hdr;
            offset += ip_hdr_len;

        } else {
            /* Not IP — ARP, LLDP, etc. — still valid at L2 */
            pkt.valid = true;
            pkt.header_len = static_cast<uint32_t>(offset);
            if (offset < frame.size())
                pkt.payload = frame.subspan(offset);
            return pkt;
        }

        /* ── L4: TCP / UDP / ICMP ── */
        switch (pkt.ip_proto) {
        case 6: { /* TCP */
            pkt.l4_proto = L4Proto::TCP;
            if (offset + sizeof(TCPHeader) > frame.size()) return pkt;

            const auto* tcp = reinterpret_cast<const TCPHeader*>(frame.data() + offset);
            pkt.src_port  = net_to_host16(tcp->src_port);
            pkt.dst_port  = net_to_host16(tcp->dst_port);
            pkt.tcp_flags = tcp->flags;

            size_t tcp_hdr_len = static_cast<size_t>((tcp->data_offset >> 4) & 0x0F) * 4;
            if (tcp_hdr_len < 20) return pkt;
            offset += tcp_hdr_len;
            break;
        }
        case 17: { /* UDP */
            pkt.l4_proto = L4Proto::UDP;
            if (offset + sizeof(UDPHeader) > frame.size()) return pkt;

            const auto* udp = reinterpret_cast<const UDPHeader*>(frame.data() + offset);
            pkt.src_port = net_to_host16(udp->src_port);
            pkt.dst_port = net_to_host16(udp->dst_port);
            offset += sizeof(UDPHeader);
            break;
        }
        case 1:   /* ICMP */
            pkt.l4_proto = L4Proto::ICMP;
            offset += 8; /* ICMP header = 8 bytes */
            break;
        case 58:  /* ICMPv6 */
            pkt.l4_proto = L4Proto::ICMPv6;
            offset += 8;
            break;
        case 132: /* SCTP */
            pkt.l4_proto = L4Proto::SCTP;
            offset += 12; /* SCTP common header = 12 bytes */
            break;
        default:
            pkt.l4_proto = L4Proto::Unknown;
            break;
        }

        /* ── Payload ── */
        pkt.header_len = static_cast<uint32_t>(offset);
        if (offset < frame.size()) {
            pkt.payload = frame.subspan(offset);
        }

        pkt.valid = true;
        return pkt;
    }

    /**
     * quick_classify - Fast packet classification without full parse.
     * Returns (ip_proto, src_port, dst_port) for 5-tuple matching.
     * Hot-path optimized: <50 cycles on modern x86.
     */
    static void quick_classify(
        std::span<const uint8_t> frame,
        uint8_t*  out_proto,
        uint16_t* out_src_port,
        uint16_t* out_dst_port
    ) noexcept {
        *out_proto = 0;
        *out_src_port = 0;
        *out_dst_port = 0;

        if (frame.size() < 14 + 20) return;

        uint16_t ethertype = net_to_host16(*reinterpret_cast<const uint16_t*>(frame.data() + 12));
        if (ethertype != 0x0800) return; /* Only IPv4 fast path */

        const uint8_t* ip = frame.data() + 14;
        *out_proto = ip[9];

        uint8_t ihl = (ip[0] & 0x0F) * 4;
        const uint8_t* l4 = ip + ihl;

        if (*out_proto == 6 || *out_proto == 17) { /* TCP or UDP */
            *out_src_port = net_to_host16(*reinterpret_cast<const uint16_t*>(l4));
            *out_dst_port = net_to_host16(*reinterpret_cast<const uint16_t*>(l4 + 2));
        }
    }
};

/* ─── C-ABI Exports (for Zig/Rust FFI) ─── */
extern "C" {

/**
 * aegis_parse_packet - C-ABI wrapper for PacketParser::parse.
 * @frame_data  Pointer to raw frame bytes
 * @frame_len   Frame length in bytes
 * @out_result  Pointer to ParsedPacket (caller-allocated)
 */
__declspec(dllexport) void aegis_parse_packet(
    const uint8_t* frame_data,
    uint32_t       frame_len,
    ParsedPacket*  out_result
) {
    auto frame = std::span<const uint8_t>(frame_data, frame_len);
    *out_result = PacketParser::parse(frame);
}

/**
 * aegis_quick_classify - C-ABI wrapper for PacketParser::quick_classify.
 */
__declspec(dllexport) void aegis_quick_classify(
    const uint8_t* frame_data,
    uint32_t       frame_len,
    uint8_t*       out_proto,
    uint16_t*      out_src_port,
    uint16_t*      out_dst_port
) {
    auto frame = std::span<const uint8_t>(frame_data, frame_len);
    PacketParser::quick_classify(frame, out_proto, out_src_port, out_dst_port);
}

} /* extern "C" */
