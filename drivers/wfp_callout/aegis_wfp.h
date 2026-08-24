/**
 * aegis_wfp.h - AEGIS WFP Callout Driver Shared Header
 *
 * 40-byte AEGIS_EVENT_HEADER (packed, Zig FFI compatible),
 * IOCTL codes, device names, GUID decl, extern globals,
 * cross-file function declarations.
 */

#ifndef AEGIS_WFP_H
#define AEGIS_WFP_H

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

/* ====== IOCTL Codes ====== */
#define IOCTL_AEGIS_READ_EVENTS  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_BLOCK_FLOW   CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_GET_STATS    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

/* ====== Device Names ====== */
#define AEGIS_WFP_DEVICE_NAME  L"\\Device\\AegisWfpDevice"
#define AEGIS_WFP_SYMLINK_NAME L"\\DosDevices\\AegisWfpDevice"

/* ====== Ring Buffer ====== */
#define AEGIS_RING_BUFFER_SIZE     (2 * 1024 * 1024)   /* 2 MB */
#define AEGIS_MAX_PAYLOAD_SIZE     4096

/* Ring used-space helper (call under spinlock) */
#define AEGIS_RING_USED() \
    ((g_RingWriteOffset >= g_RingReadOffset) ? \
     (g_RingWriteOffset - g_RingReadOffset) : \
     (g_RingBufferSize - g_RingReadOffset + g_RingWriteOffset))

/* ====== AEGIS Event Header (40 bytes, packed for Zig FFI) ====== */
#pragma pack(push, 1)
typedef struct _AEGIS_EVENT_HEADER {
    UINT32  event_type;     /* 0=NETWORK, 1=FILE, 2=PROCESS, 3=PIPE */
    UINT32  source_ip;      /* IPv4 source (network byte order) */
    UINT32  dest_ip;        /* IPv4 destination */
    UINT16  source_port;    /* Source port */
    UINT16  dest_port;      /* Destination port */
    UINT8   protocol;       /* 6=TCP, 17=UDP, 1=ICMP */
    UINT8   direction;      /* 0=inbound, 1=outbound */
    UINT8   layer_id;       /* WFP layer ID (low byte) */
    UINT8   flags;          /* Reserved */
    UINT32  payload_length; /* Captured payload length (0=none) */
    UINT32  rule_id;        /* Matched rule ID (0=none) */
    UINT32  severity;       /* 0=Low 1=Med 2=High 3=Critical */
    UINT32  reserved;       /* Reserved */
    UINT64  timestamp;      /* KeQueryPerformanceCounter */
} AEGIS_EVENT_HEADER;
#pragma pack(pop)

/* ====== Ring Buffer Statistics (24 bytes, packed) ====== */
#pragma pack(push, 1)
typedef struct _AEGIS_RING_STATS {
    ULONG totalEventsWritten;
    ULONG totalDrops;
    ULONG totalBytesWritten;
    ULONG totalBytesRead;
    ULONG currentUsedBytes;
    ULONG padding;
} AEGIS_RING_STATS;
#pragma pack(pop)

/* ====== GUID (defined via DEFINE_GUID in aegis_wfp.c) ====== */
extern const GUID AEGIS_CALLOUT_KEY;

/* ====== Globals (defined in aegis_wfp.c) ====== */
extern PVOID          g_RingBuffer;
extern SIZE_T         g_RingBufferSize;
extern KSPIN_LOCK     g_RingLock;
extern SIZE_T         g_RingWriteOffset;
extern SIZE_T         g_RingReadOffset;
extern HANDLE         g_WfpEngineHandle;
extern UINT32         g_CalloutId;
extern UINT64         g_FilterId;     /* FIX 5: UINT32 -> UINT64 */
extern PDEVICE_OBJECT g_AegisDeviceObject;

/* ====== Cross-file declarations ====== */

/* aegis_wfp_callout.c */
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject);
VOID     AegisWfpUnregisterCallout(void);

/* aegis_wfp_comm.c */
NTSTATUS AegisWfpCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif /* AEGIS_WFP_H */