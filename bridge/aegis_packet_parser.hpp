@@ -0,0 +1,407 @@
/**
 * aegis_packet_parser.hpp — AEGIS NIDS Packet Parser Engine (C++ Header)
 *
 * Template-based, zero-copy packet parser for the NETWORK layer.
 * Parses raw packet data into structured protocol headers without copying
 * payload data — uses pointer/offset references instead.
 *
 * Architecture: C++ Packet Parser sits in the IPC Bridge, receiving raw
 * packet data from WFP callout (kernel) via shared memory. It parses
 * protocol headers and passes structured IpcEvent to the event queue
 * for downstream processing by Zig Core (Tier-1) and Python Brain (Tier-2).
 *
 * Supported protocols:
 *   - IPv4 header parsing (20-60 bytes)
 *   - TCP header parsing (20-60 bytes, with options)
 *   - UDP header parsing (8 bytes)
 *   - ICMP header parsing (8 bytes)
 *   - HTTP request/response detection (layer-7 heuristic)
 *   - DNS query parsing (layer-7 heuristic)
 *
 * Design principles:
 *   - Zero-copy: Never allocate or copy payload data
 *   - Template-based: Protocol parsers are type-parameterized
 *   - Safe: Bounds-checked header parsing, malformed packet detection
 *   - Extensible: New protocols added via template specialization
 */

#ifndef AEGIS_PACKET_PARSER_HPP
#define AEGIS_PACKET_PARSER_HPP

#include "aegis_ipc.hpp"  // For Aegis::Bridge::IpcEvent
#include <cstdint>
#include <cstring>

namespace Aegis {
namespace Parser {

// ====== Protocol Constants ======
constexpr uint8_t kProtoICMP = 1;
constexpr uint8_t kProtoTCP  = 6;
constexpr uint8_t kProtoUDP  = 17;

// ====== IPv4 Header (20 bytes minimum) ======
#pragma pack(push, 1)
struct IPv4Header {
    uint8_t   version_ihl;     // Version (4 bits) + IHL (4 bits)
    uint8_t   dscp_ecn;        // DSCP (6 bits) + ECN (2 bits)
    uint16_t  total_length;    // Total packet length
    uint16_t  identification;  // Identification
    uint16_t  flags_fragment;  // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t   ttl;             // Time to live
    uint8_t   protocol;        // Protocol (TCP/UDP/ICMP)
    uint16_t  header_checksum; // Header checksum
    uint32_t  source_ip;       // Source IPv4 address
    uint32_t  dest_ip;         // Destination IPv4 address
    // Options follow if IHL > 5 (up to 40 bytes)
};
#pragma pack(pop)

// ====== TCP Header (20 bytes minimum) ======
#pragma pack(push, 1)
struct TCPHeader {
    uint16_t  source_port;     // Source port
    uint16_t  dest_port;       // Destination port
    uint32_t  seq_number;      // Sequence number
    uint32_t  ack_number;      // Acknowledgment number
    uint8_t   data_offset;     // Data offset (4 bits) + reserved (4 bits)
    uint8_t   flags;           // TCP flags (CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)
    uint16_t  window_size;     // Window size
    uint16_t  checksum;        // TCP checksum
    uint16_t  urgent_pointer;  // Urgent pointer
    // Options follow if data_offset > 5
};
#pragma pack(pop)

// ====== UDP Header (8 bytes) ======
#pragma pack(push, 1)
struct UDPHeader {
    uint16_t  source_port;     // Source port
    uint16_t  dest_port;       // Destination port
    uint16_t  length;          // UDP length (header + data)
    uint16_t  checksum;        // UDP checksum
};
#pragma pack(pop)

// ====== ICMP Header (8 bytes) ======
#pragma pack(push, 1)
struct ICMPHeader {
    uint8_t   type;            // ICMP type (0=Echo Reply, 8=Echo Request, etc.)
    uint8_t   code;            // ICMP code
    uint16_t  checksum;        // ICMP checksum
    uint16_t  identifier;      // Identifier
    uint16_t  sequence;        // Sequence number
};
#pragma pack(pop)

// ====== Parse Result ======
enum ParseStatus : int32_t {
    kParseSuccess       = 0,
    kParseTruncated     = -1,   // Packet too short for this protocol
    kParseMalformed     = -2,   // Invalid header fields detected
    kParseUnknownProto  = -3,   // Protocol not recognized
    kParseBufferTooSmall = -4,  // Provided buffer smaller than minimum header
};

// ====== Generic Protocol Parser Template ======
// Template parameter T is the header struct type (IPv4Header, TCPHeader, etc.)
template<typename T>
class ProtocolParser {
public:
    // Minimum header size for this protocol
    static constexpr size_t kMinHeaderSize = sizeof(T);

    // Parse header from raw packet data (zero-copy — returns pointer into original buffer)
    static ParseStatus Parse(const uint8_t* data, size_t dataLen, const T** outHeader) {
        if (!data || !outHeader) return kParseMalformed;
        if (dataLen < kMinHeaderSize) return kParseTruncated;

        // Bounds check: ensure header fits within packet data
        *outHeader = reinterpret_cast<const T*>(data);
        return kParseSuccess;
    }

    // Validate header fields (protocol-specific, overridden by specialization)
    static ParseStatus Validate(const T* header, size_t dataLen) {
        if (!header) return kParseMalformed;
        return kParseSuccess;  // Base: always valid (specializations add checks)
    }
};

// ====== IPv4 Parser Specialization ======
template<>
class ProtocolParser<IPv4Header> {
public:
    static constexpr size_t kMinHeaderSize = sizeof(IPv4Header);

    static ParseStatus Parse(const uint8_t* data, size_t dataLen, const IPv4Header** outHeader) {
        if (!data || !outHeader) return kParseMalformed;
        if (dataLen < kMinHeaderSize) return kParseTruncated;

        const IPv4Header* hdr = reinterpret_cast<const IPv4Header*>(data);

        // Validate version must be 4 (IPv4)
        uint8_t version = (hdr->version_ihl >> 4) & 0x0F;
        if (version != 4) return kParseMalformed;

        // Validate IHL (Internet Header Length) — minimum 5 (20 bytes)
        uint8_t ihl = hdr->version_ihl & 0x0F;
        if (ihl < 5) return kParseMalformed;

        // Validate total_length matches buffer
        uint16_t totalLen = (hdr->total_length >> 8) | ((hdr->total_length & 0xFF) << 8);  // ntohs
        size_t headerLen = ihl * 4;
        if (totalLen < headerLen || dataLen < headerLen) return kParseMalformed;

        *outHeader = hdr;
        return kParseSuccess;
    }

    static ParseStatus Validate(const IPv4Header* header, size_t dataLen) {
        if (!header) return kParseMalformed;
        uint8_t version = (header->version_ihl >> 4) & 0x0F;
        if (version != 4) return kParseMalformed;
        return kParseSuccess;
    }

    // Utility: Get header length in bytes
    static size_t HeaderLength(const IPv4Header* hdr) {
        return (hdr->version_ihl & 0x0F) * 4;
    }

    // Utility: Get payload offset (after IPv4 header)
    static size_t PayloadOffset(const IPv4Header* hdr) {
        return HeaderLength(hdr);
    }
};

// ====== TCP Parser Specialization ======
template<>
class ProtocolParser<TCPHeader> {
public:
    static constexpr size_t kMinHeaderSize = sizeof(TCPHeader);

    static ParseStatus Parse(const uint8_t* data, size_t dataLen, const TCPHeader** outHeader) {
        if (!data || !outHeader) return kParseMalformed;
        if (dataLen < kMinHeaderSize) return kParseTruncated;

        const TCPHeader* hdr = reinterpret_cast<const TCPHeader*>(data);

        // Validate data offset (minimum 5 = 20 bytes)
        uint8_t dataOffset = (hdr->data_offset >> 4) & 0x0F;
        if (dataOffset < 5) return kParseMalformed;

        size_t tcpHeaderLen = dataOffset * 4;
        if (dataLen < tcpHeaderLen) return kParseTruncated;

        *outHeader = hdr;
        return kParseSuccess;
    }

    static ParseStatus Validate(const TCPHeader* header, size_t dataLen) {
        if (!header) return kParseMalformed;
        uint8_t dataOffset = (header->data_offset >> 4) & 0x0F;
        if (dataOffset < 5) return kParseMalformed;
        return kParseSuccess;
    }

    // Utility: Get TCP header length
    static size_t HeaderLength(const TCPHeader* hdr) {
        return ((hdr->data_offset >> 4) & 0x0F) * 4;
    }

    // Utility: Check specific TCP flags
    static bool HasFlag(const TCPHeader* hdr, uint8_t flag) {
        return (hdr->flags & flag) != 0;
    }

    // TCP flag constants
    static constexpr uint8_t kFlagFIN  = 0x01;
    static constexpr uint8_t kFlagSYN  = 0x02;
    static constexpr uint8_t kFlagRST  = 0x04;
    static constexpr uint8_t kFlagPSH  = 0x08;
    static constexpr uint8_t kFlagACK  = 0x10;
    static constexpr uint8_t kFlagURG  = 0x20;
};

// ====== UDP Parser (no specialization needed — simple struct) ======
// ProtocolParser<UDPHeader> uses the generic template (8 bytes, minimal validation)

// ====== ICMP Parser (no specialization needed — simple struct) ======
// ProtocolParser<ICMPHeader> uses the generic template

// ====== Full Packet Parser ======
// Parses a complete raw packet: IPv4 → TCP/UDP/ICMP → payload reference
struct PacketParseResult {
    ParseStatus          status;
    const IPv4Header*    ipHeader;
    const TCPHeader*     tcpHeader;     // nullptr if not TCP
    const UDPHeader*     udpHeader;     // nullptr if not UDP
    const ICMPHeader*    icmpHeader;    // nullptr if not ICMP
    const uint8_t*       payload;       // Pointer to payload (zero-copy, into original buffer)
    size_t               payloadLength; // Payload length
    uint8_t              protocol;      // Protocol number
};

class PacketParser {
public:
    // Parse a complete packet from raw data (zero-copy)
    static PacketParseResult ParsePacket(const uint8_t* data, size_t dataLen) {
        PacketParseResult result = {};
        result.status = kParseSuccess;

        // 1. Parse IPv4 header
        ParseStatus ipStatus = ProtocolParser<IPv4Header>::Parse(data, dataLen, &result.ipHeader);
        if (ipStatus != kParseSuccess) {
            result.status = ipStatus;
            return result;
        }

        size_t ipHeaderLen = ProtocolParser<IPv4Header>::HeaderLength(result.ipHeader);
        result.protocol = result.ipHeader->protocol;

        // 2. Parse transport layer header (based on protocol)
        const uint8_t* transportData = data + ipHeaderLen;
        size_t transportLen = dataLen - ipHeaderLen;

        switch (result.ipHeader->protocol) {
        case kProtoTCP:
            result.tcpHeader = nullptr;
            result.udpHeader = nullptr;
            result.icmpHeader = nullptr;

            if (ProtocolParser<TCPHeader>::Parse(transportData, transportLen, &result.tcpHeader) == kParseSuccess) {
                size_t tcpHeaderLen = ProtocolParser<TCPHeader>::HeaderLength(result.tcpHeader);
                result.payload = transportData + tcpHeaderLen;
                result.payloadLength = transportLen - tcpHeaderLen;
            } else {
                result.status = kParseMalformed;
                result.tcpHeader = nullptr;
            }
            break;

        case kProtoUDP:
            result.tcpHeader = nullptr;
            result.icmpHeader = nullptr;

            if (ProtocolParser<UDPHeader>::Parse(transportData, transportLen, &result.udpHeader) == kParseSuccess) {
                result.payload = transportData + sizeof(UDPHeader);
                result.payloadLength = transportLen - sizeof(UDPHeader);
            } else {
                result.status = kParseMalformed;
                result.udpHeader = nullptr;
            }
            break;

        case kProtoICMP:
            result.tcpHeader = nullptr;
            result.udpHeader = nullptr;

            if (ProtocolParser<ICMPHeader>::Parse(transportData, transportLen, &result.icmpHeader) == kParseSuccess) {
                result.payload = transportData + sizeof(ICMPHeader);
                result.payloadLength = transportLen - sizeof(ICMPHeader);
            } else {
                result.status = kParseMalformed;
                result.icmpHeader = nullptr;
            }
            break;

        default:
            result.status = kParseUnknownProto;
            break;
        }

        return result;
    }

    // ====== Layer-7 Heuristic: HTTP Detection ======
    // Checks if payload starts with HTTP method or response code
    static bool IsHTTPRequest(const uint8_t* payload, size_t len) {
        if (!payload || len < 4) return false;
        // GET, POST, PUT, HEAD, DELETE, PATCH, OPTIONS, CONNECT, TRACE
        return (memcmp(payload, "GET ", 4) == 0 ||
                memcmp(payload, "POST", 4) == 0 ||
                memcmp(payload, "PUT ", 4) == 0 ||
                memcmp(payload, "HEAD", 4) == 0 ||
                memcmp(payload, "DELE", 4) == 0 ||
                memcmp(payload, "OPTI", 4) == 0);
    }

    static bool IsHTTPResponse(const uint8_t* payload, size_t len) {
        if (!payload || len < 5) return false;
        return (memcmp(payload, "HTTP/", 5) == 0);
    }

    // ====== Layer-7 Heuristic: DNS Detection ======
    // UDP port 53 with valid DNS header
    static bool IsDNSQuery(const UDPHeader* udp, const uint8_t* payload, size_t len) {
        if (!udp || !payload || len < 12) return false;
        // DNS standard query: port 53, QDCOUNT >= 1
        uint16_t srcPort = udp->source_port;
        uint16_t dstPort = udp->dest_port;
        if (srcPort != 53 && dstPort != 53) return false;
        // DNS header: Transaction ID (2) + Flags (2) + Questions (2) + ...
        uint16_t flags = (payload[2] << 8) | payload[3];
        uint16_t questions = (payload[4] << 8) | payload[5];
        return (questions > 0);
    }

    // ====== NOP Sled Detection (Rust Mouth Tier-3 pattern) ======
    // Checks for sequences of NOP (0x90) instructions — buffer overflow indicator
    static bool HasNopSled(const uint8_t* payload, size_t len, size_t minSequence = 5) {
        if (!payload || len < minSequence) return false;
        size_t consecutive = 0;
        for (size_t i = 0; i < len; i++) {
            if (payload[i] == 0x90) {
                consecutive++;
                if (consecutive >= minSequence) return true;
            } else {
                consecutive = 0;
            }
        }
        return false;
    }

    // ====== Malformed Header Detection ======
    // Checks for suspicious header patterns that indicate crafted/attack packets
    static bool IsMalformedHeader(const IPv4Header* ip, const TCPHeader* tcp) {
        if (!ip) return false;

        // Check: IHL < 5 (invalid minimum)
        uint8_t ihl = ip->version_ihl & 0x0F;
        if (ihl < 5) return true;

        // Check: TTL = 0 (packet should have been dropped)
        if (ip->ttl == 0) return true;

        // Check: TCP with SYN+FIN (invalid flag combination)
        if (tcp) {
            uint8_t tcpFlags = tcp->flags;
            if ((tcpFlags & 0x02) && (tcpFlags & 0x01)) {  // SYN (0x02) + FIN (0x01)
                return true;
            }
        }

        return false;
    }
};

} // namespace Parser
} // namespace Aegis

// ====== extern "C" ABI for Packet Parser ======
extern "C" {

// Parse a raw packet and return structured result
int32_t aegis_parse_packet(const uint8_t* data, uint32_t dataLen,
                           Aegis::Bridge::IpcEvent* outEvent);

// Check if payload contains NOP sled
int32_t aegis_check_nop_sled(const uint8_t* payload, uint32_t len, uint32_t minSeq);

// Check if packet has malformed headers
int32_t aegis_check_malformed(const uint8_t* data, uint32_t dataLen);

} // extern "C"

#endif // AEGIS_PACKET_PARSER_HPP
