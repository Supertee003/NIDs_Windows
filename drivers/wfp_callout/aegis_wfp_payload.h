/* Pure helpers for converting WFP transport-layer buffers to L4 payloads.
 * This header is shared by the kernel callout and the host C regression test.
 */
#ifndef AEGIS_WFP_PAYLOAD_H
#define AEGIS_WFP_PAYLOAD_H

#include <stddef.h>

#if defined(_MSC_VER)
#define AEGIS_WFP_INLINE static __inline
#else
#define AEGIS_WFP_INLINE static inline
#endif

/* WFP documents inbound transport data as beginning at the payload, while
 * outbound transport data begins at the TCP/UDP header. Return the byte slice
 * that is application/transport payload for the unchanged ring contract.
 * On malformed or unsupported outbound headers, return false and zero the
 * outputs; the caller still emits the event header and permits the packet.
 */
AEGIS_WFP_INLINE int aegis_wfp_get_payload_slice(
    const unsigned char *data,
    size_t data_length,
    unsigned char protocol,
    unsigned char direction,
    size_t *payload_offset,
    size_t *payload_length)
{
    size_t offset = 0;
    size_t length = 0;

    if (payload_offset == NULL || payload_length == NULL) {
        return 0;
    }
    *payload_offset = 0;
    *payload_length = 0;

    if (direction == 0) {
        *payload_length = data_length;
        return 1;
    }
    if (direction != 1) {
        return 0;
    }

    if (protocol == 6) { /* TCP */
        size_t tcp_header_length;
        if (data_length < 20 || data == NULL) {
            return 0;
        }
        tcp_header_length = (size_t)((data[12] >> 4) & 0x0f) * 4;
        if (tcp_header_length < 20 || tcp_header_length > data_length) {
            return 0;
        }
        offset = tcp_header_length;
        length = data_length - tcp_header_length;
    } else if (protocol == 17) { /* UDP */
        size_t udp_length;
        if (data_length < 8 || data == NULL) {
            return 0;
        }
        udp_length = ((size_t)data[4] << 8) | (size_t)data[5];
        if (udp_length < 8 || udp_length > data_length) {
            return 0;
        }
        offset = 8;
        length = udp_length - 8;
    } else {
        return 0;
    }

    *payload_offset = offset;
    *payload_length = length;
    return 1;
}

#undef AEGIS_WFP_INLINE

#endif /* AEGIS_WFP_PAYLOAD_H */
