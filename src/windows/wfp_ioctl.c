/* II05 - WFP Callout Driver IOCTL Bridge (User-mode)
 * AEGIS NIDS v5.0+
 *
 * Opens \\.\AegisWfpDevice (exported by drivers/wfp_callout/aegis_wfp.sys)
 * and issues buffered IOCTLs for event readback, IPS block/unblock and
 * ring statistics. Gracefully degrades when the driver is not installed.
 *
 * This file is compiled by CMakeLists.txt into aegis_wfp_user.dll.
 */

#include <windows.h>
#include <winioctl.h>
#include <stdint.h>
#include <stdio.h>

#ifndef FILE_DEVICE_NETWORK
#define FILE_DEVICE_NETWORK 0x00000012
#endif

#define AEGIS_WFP_USER_DEVICE L"\\\\.\\AegisWfpDevice"

/* Kernel IOCTL codes (must match drivers/wfp_callout/aegis_wfp.h) */
#define IOCTL_AEGIS_READ_EVENTS  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_BLOCK_FLOW   CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_GET_STATS    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_UNBLOCK_FLOW CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_QUERY_FILTER CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)
typedef struct _AEGIS_WFP_FLOW_REQUEST {
    uint32_t remote_ipv4;
    uint16_t remote_port;
    uint8_t  protocol;
    uint8_t  reserved;
} AEGIS_WFP_FLOW_REQUEST;

typedef struct _AEGIS_WFP_FLOW_RESPONSE {
    uint64_t filter_id;
    uint32_t provider_status;
} AEGIS_WFP_FLOW_RESPONSE;

typedef struct _AEGIS_WFP_FILTER_QUERY {
    uint64_t filter_id;
} AEGIS_WFP_FILTER_QUERY;

typedef struct _AEGIS_WFP_FILTER_STATE {
    uint64_t filter_id;
    uint32_t remote_ipv4;
    uint16_t remote_port;
    uint8_t  protocol;
    uint8_t  present;
    uint32_t provider_status;
} AEGIS_WFP_FILTER_STATE;
#pragma pack(pop)

/* Keep the user/kernel buffered-IOCTL contract explicit. */
typedef char aegis_flow_request_must_be_8_bytes[
    sizeof(AEGIS_WFP_FLOW_REQUEST) == 8 ? 1 : -1];
typedef char aegis_flow_response_must_be_12_bytes[
    sizeof(AEGIS_WFP_FLOW_RESPONSE) == 12 ? 1 : -1];
typedef char aegis_filter_query_must_be_8_bytes[
    sizeof(AEGIS_WFP_FILTER_QUERY) == 8 ? 1 : -1];
typedef char aegis_filter_state_must_be_20_bytes[
    sizeof(AEGIS_WFP_FILTER_STATE) == 20 ? 1 : -1];

/* 40-byte AEGIS event header (packed, mirrors drivers/wfp_callout/aegis_wfp.h) */
#pragma pack(push, 1)
typedef struct _AEGIS_WFP_EVENT_HEADER {
    uint32_t event_type;     /* 0=NETWORK, 1=FILE, 2=PROCESS, 3=PIPE */
    uint32_t source_ip;      /* IPv4 source (network byte order) */
    uint32_t dest_ip;        /* IPv4 destination */
    uint16_t source_port;
    uint16_t dest_port;
    uint8_t  protocol;       /* 6=TCP, 17=UDP, 1=ICMP */
    uint8_t  direction;      /* 0=inbound, 1=outbound */
    uint8_t  layer_id;
    uint8_t  flags;
    uint32_t payload_length;
    uint32_t rule_id;
    uint32_t severity;
    uint32_t reserved;
    uint64_t timestamp;
} AEGIS_WFP_EVENT_HEADER;

/* 24-byte ring statistics (packed, mirrors drivers/wfp_callout/aegis_wfp.h) */
typedef struct _AEGIS_WFP_RING_STATS {
    uint32_t total_events_written;
    uint32_t total_drops;
    uint32_t total_bytes_written;
    uint32_t total_bytes_read;
    uint32_t current_used_bytes;
    uint32_t padding;
} AEGIS_WFP_RING_STATS;
#pragma pack(pop)

static HANDLE g_wfp_device = INVALID_HANDLE_VALUE;

static int wfp_ioctl_send(DWORD code, void *in_buf, DWORD in_len,
                          void *out_buf, DWORD out_len, DWORD *ret_len) {
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(g_wfp_device, code, in_buf, in_len,
                              out_buf, out_len, &bytes_returned, NULL);
    if (ret_len) *ret_len = bytes_returned;
    return ok ? 0 : -1;
}

int aegis_wfp_ioctl_open(void) {
    if (g_wfp_device != INVALID_HANDLE_VALUE) return 0;
    g_wfp_device = CreateFileW(AEGIS_WFP_USER_DEVICE,
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_wfp_device == INVALID_HANDLE_VALUE) {
        return -1;
    }
    return 0;
}

int aegis_wfp_ioctl_close(void) {
    if (g_wfp_device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_wfp_device);
        g_wfp_device = INVALID_HANDLE_VALUE;
    }
    return 0;
}

int aegis_wfp_ioctl_is_connected(void) {
    return (g_wfp_device != INVALID_HANDLE_VALUE) ? 1 : 0;
}

int aegis_wfp_ioctl_block_ip(uint32_t ipv4) {
    (void)ipv4;
    /* Deprecated IP-only mutation is not part of the receipt-aware ABI. */
    return -2;
}

int aegis_wfp_ioctl_unblock_ip(uint32_t ipv4) {
    (void)ipv4;
    /* Exact cleanup must use aegis_wfp_ioctl_unblock_filter(filter_id). */
    return -2;
}

/* Port-specific PEP-owned mutation. The driver returns the exact filter ID;
 * callers must retain it and use unblock_filter for cleanup. */
int aegis_wfp_ioctl_block_flow(const AEGIS_WFP_FLOW_REQUEST *request,
                               AEGIS_WFP_FLOW_RESPONSE *response) {
    DWORD out_len = 0;
    if (request == NULL || response == NULL) return -1;
    ZeroMemory(response, sizeof(*response));
    if (wfp_ioctl_send(IOCTL_AEGIS_BLOCK_FLOW, (void *)request,
                       (DWORD)sizeof(*request), response,
                       (DWORD)sizeof(*response), &out_len) != 0) {
        return -1;
    }
    return out_len == sizeof(*response) && response->filter_id != 0 &&
           response->provider_status == 0 ? 0 : -1;
}

int aegis_wfp_ioctl_unblock_filter(uint64_t filter_id) {
    DWORD out_len = 0;
    if (filter_id == 0) return -1;
    return wfp_ioctl_send(IOCTL_AEGIS_UNBLOCK_FLOW, &filter_id,
                          (DWORD)sizeof(filter_id), NULL, 0, &out_len);
}

/* Read-only exact-filter postcondition query. The filter_id is mandatory;
 * IP-only lookup is intentionally unsupported. */
int aegis_wfp_ioctl_query_filter(uint64_t filter_id,
                                 AEGIS_WFP_FILTER_STATE *state) {
    DWORD out_len = 0;
    AEGIS_WFP_FILTER_QUERY query;
    if (filter_id == 0 || state == NULL) return -1;
    query.filter_id = filter_id;
    ZeroMemory(state, sizeof(*state));
    if (wfp_ioctl_send(IOCTL_AEGIS_QUERY_FILTER, &query, sizeof(query),
                       state, sizeof(*state), &out_len) != 0) return -1;
    return out_len == sizeof(*state) ? 0 : -1;
}

int aegis_wfp_ioctl_read_events(void *out_buf, uint32_t buf_size,
                                uint32_t *bytes_read) {
    DWORD out_len = 0;
    if (out_buf == NULL || buf_size == 0) return -1;
    if (wfp_ioctl_send(IOCTL_AEGIS_READ_EVENTS, NULL, 0,
                       out_buf, buf_size, &out_len) != 0) {
        return -1;
    }
    if (bytes_read) *bytes_read = (uint32_t)out_len;
    return 0;
}

int aegis_wfp_ioctl_get_stats(AEGIS_WFP_RING_STATS *out_stats) {
    DWORD out_len = 0;
    if (out_stats == NULL) return -1;
    if (wfp_ioctl_send(IOCTL_AEGIS_GET_STATS, NULL, 0,
                       out_stats, (DWORD)sizeof(*out_stats), &out_len) != 0) {
        return -1;
    }
    return 0;
}
