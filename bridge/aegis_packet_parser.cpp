@@ -0,0 +1,100 @@
/**
 * aegis_packet_parser.cpp — AEGIS NIDS Packet Parser Implementation
 *
 * Implements extern "C" ABI functions for the template-based packet parser.
 * These functions are callable from Zig (@cImport), Rust (FFI), and Python (ctypes).
 *
 * Architecture: C++ Packet Parser → IPC Bridge → Event Queue → Dashboard
 */

#include "aegis_packet_parser.hpp"
#include "aegis_ipc.hpp"
#include <cstdio>

extern "C" {

int32_t aegis_parse_packet(const uint8_t* data, uint32_t dataLen,
                           Aegis::Bridge::IpcEvent* outEvent)
{
    if (!data || !outEvent) return -1;

    using namespace Aegis::Parser;
    using namespace Aegis::Bridge;

    // Parse the complete packet using PacketParser (zero-copy)
    PacketParseResult result = PacketParser::ParsePacket(data, dataLen);

    if (result.status != kParseSuccess) {
        fprintf(stderr, "[AEGIS Parser] Parse failed: status=%d\n", result.status);
        return result.status;
    }

    // Fill IpcEvent from parsed packet data (zero-copy references)
    outEvent->event_type     = kNetworkEvent;
    outEvent->source_ip      = result.ipHeader->source_ip;
    outEvent->dest_ip        = result.ipHeader->dest_ip;
    outEvent->protocol       = result.protocol;
    outEvent->direction      = 0;  // inbound (from WFP classify)
    outEvent->layer_id       = 0;  // NETWORK layer
    outEvent->payload_length = static_cast<uint32_t>(result.payloadLength);
    outEvent->rule_id        = 0;  // Not yet matched
    outEvent->severity       = kSeverityLow;  // Default, will be updated by tiers
    outEvent->timestamp      = 0;  // TODO: GetTickCount64()

    // Extract port numbers based on protocol
    if (result.protocol == kProtoTCP && result.tcpHeader) {
        outEvent->source_port = result.tcpHeader->source_port;
        outEvent->dest_port   = result.tcpHeader->dest_port;

        // Check for SYN+FIN malformed header
        if (PacketParser::IsMalformedHeader(result.ipHeader, result.tcpHeader)) {
            outEvent->severity = kSeverityHigh;
            fprintf(stdout, "[AEGIS Parser] Malformed TCP header detected — SYN+FIN or TTL=0\n");
        }
    } else if (result.protocol == kProtoUDP && result.udpHeader) {
        outEvent->source_port = result.udpHeader->source_port;
        outEvent->dest_port   = result.udpHeader->dest_port;
    } else if (result.protocol == kProtoICMP && result.icmpHeader) {
        outEvent->source_port = 0;
        outEvent->dest_port   = 0;
    }

    // Layer-7 heuristic checks (zero-copy — only reads payload, no allocation)
    if (result.payload && result.payloadLength > 0) {
        // Check for NOP sled (buffer overflow indicator — Rust Mouth Tier-3)
        if (PacketParser::HasNopSled(result.payload, result.payloadLength)) {
            outEvent->severity   = kSeverityCritical;
            outEvent->tier_result = kTier3Behavioral;
            fprintf(stdout, "[AEGIS Parser] NOP sled detected in payload — severity: CRITICAL\n");
        }

        // Check for HTTP attack patterns (SQLi, XSS, etc. — Python Brain Tier-2)
        if (PacketParser::IsHTTPRequest(result.payload, result.payloadLength)) {
            outEvent->tier_result = kTier2RegexMatch;  // HTTP needs regex inspection
        }
    }

    return 0;
}

int32_t aegis_check_nop_sled(const uint8_t* payload, uint32_t len, uint32_t minSeq)
{
    using namespace Aegis::Parser;
    return PacketParser::HasNopSled(payload, len, minSeq) ? 1 : 0;
}

int32_t aegis_check_malformed(const uint8_t* data, uint32_t dataLen)
{
    using namespace Aegis::Parser;

    PacketParseResult result = PacketParser::ParsePacket(data, dataLen);
    if (result.status != kParseSuccess) return 1;  // Failed parse = malformed

    if (PacketParser::IsMalformedHeader(result.ipHeader, result.tcpHeader)) {
        return 1;
    }

    return 0;
}

} // extern "C"
