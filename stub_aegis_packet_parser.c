/*
 * AEGIS NIDS - Stub DLL: aegis_packet_parser
 * Auto-generated stub. Replace with real implementations.
 */

#include <stdint.h>

/* parse_packet */
__declspec(dllexport) int32_t parse_packet(void* data, uint32_t len, void* out_meta) {
    return -1;
}

/* get_protocol_name */
__declspec(dllexport) const char* get_protocol_name(uint8_t ip_proto) {
    return "unknown";
}

/* decode_ethernet */
__declspec(dllexport) int32_t decode_ethernet(void* frame, uint32_t len, void* out_header) {
    return -1;
}

/* decode_ip */
__declspec(dllexport) int32_t decode_ip(void* packet, uint32_t len, void* out_header) {
    return -1;
}

/* decode_tcp */
__declspec(dllexport) int32_t decode_tcp(void* segment, uint32_t len, void* out_header) {
    return -1;
}

/* decode_udp */
__declspec(dllexport) int32_t decode_udp(void* datagram, uint32_t len, void* out_header) {
    return -1;
}

