/**
 * aegis_wfp.h — AEGIS NIDS WFP Callout Driver Shared Header
 *
 * Defines the AEGIS_EVENT_HEADER structure (40 bytes) that is shared
 * between kernel-mode WFP callout and user-mode Zig reader via IOCTL.
 *
 * Architecture: C++ Kernel Driver (WFP Callout) → Ring Buffer → Zig Reader
 * This is part of the NETWORK layer (3-Layer Architecture).
 */

#ifndef AEGIS_WFP_H
#define AEGIS_WFP_H

#include <initguid.h>

// ====== IOCTL Codes ======
#define IOCTL_AEGIS_READ_EVENTS CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_BLOCK_FLOW  CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_GET_STATS   CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

// ====== AEGIS Event Header (40 bytes — matches Zig extern struct) ======
#pragma pack(push, 1)
typedef struct _AEGIS_EVENT_HEADER {
    UINT32  event_type;     // 0=NETWORK, 1=KERNEL_FILE, 2=KERNEL_PROCESS, 3=L2_PIPE
    UINT32  source_ip;      // IPv4 address of the packet source
    UINT32  dest_ip;        // IPv4 address of the packet destination
    UINT16  source_port;    // Source port number
    UINT16  dest_port;      // Destination port number
    UINT8   protocol;       // 6=TCP, 17=UDP, 1=ICMP
    UINT8   direction;      // 0=inbound, 1=outbound
    UINT8   layer_id;       // WFP layer ID (FWPM_LAYER_INBOUND_TRANSPORT_V4 etc.)
    UINT8   flags;          // Additional flags
    UINT32  payload_length; // Length of captured payload following this header
    UINT32  rule_id;        // Matched rule ID (if fast_pattern matched)
    UINT32  severity;       // 0=Low, 1=Medium, 2=High, 3=Critical
    UINT32  reserved;       // Reserved for future use
    UINT64  timestamp;      // Event timestamp (KeQueryPerformanceCounter)
} AEGIS_EVENT_HEADER;
#pragma pack(pop)

// ====== Device Name ======
#define AEGIS_WFP_DEVICE_NAME  L"\\Device\\AegisWfpDevice"
#define AEGIS_WFP_SYMLINK_NAME L"\\DosDevices\\AegisWfpDevice"

// ====== WFP Callout GUID ======
DEFINE_GUID(AEGIS_CALLOUT_KEY,
    0x8e6c3d2a, 0x4f5b, 0x1a7e, 0x9c, 0x3d, 0x5b, 0x8f, 0x2a, 0x4e, 0x6c, 0xd7);

// ====== Ring Buffer Configuration ======
#define AEGIS_RING_BUFFER_SIZE     (2 * 1024 * 1024)  // 2MB
#define AEGIS_MAX_EVENTS_PER_READ  100
#define AEGIS_MAX_PAYLOAD_SIZE     4096

#endif // AEGIS_WFP_H
