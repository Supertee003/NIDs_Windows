// =====================================================================
// aegis_wfp.h — Shared header ระหว่าง kernel WFP driver และ user-mode Zig
// ---------------------------------------------------------------------
//   ใช้ #pragma pack(push, 1) เพื่อให้ struct layout ตรงกับ extern struct
//   ใน Zig (nids_analyze.zig → EventHeader)
//
//   Build: ต้องการ WDK + Visual Studio (kernel-mode development)
// =====================================================================

#pragma once

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

// =====================================================================
// EVENT TYPES — ตรงกับ Zig EventSource enum
// =====================================================================
typedef enum _AEGIS_EVENT_TYPE {
    AEGIS_EVENT_TCP_SOCKET      = 0,
    AEGIS_EVENT_WFP_PACKET      = 1,
    AEGIS_EVENT_KERNEL_FILE     = 2,
    AEGIS_EVENT_KERNEL_PROCESS  = 3,
    AEGIS_EVENT_KERNEL_REGISTRY = 4,
    AEGIS_EVENT_PIPE_MONITOR    = 5,
    AEGIS_EVENT_PIPE_IPC        = 6,
} AEGIS_EVENT_TYPE;

// =====================================================================
// EVENT HEADER — ตรงกับ Zig EventHeader (extern struct, 40 bytes)
//   ใช้ #pragma pack(push, 1) เพื่อให้ไม่มี padding
// =====================================================================
#pragma pack(push, 1)
typedef struct _AEGIS_EVENT_HEADER {
    UINT32 event_type;        // AEGIS_EVENT_TYPE
    UINT32 event_size;        // total size including payload
    UINT64 timestamp;         // nanoseconds since epoch (KeQuerySystemTime)
    UINT32 process_id;        // PID
    // Network fields (zero if N/A)
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8  protocol;          // TCP=6, UDP=17
    UINT8  direction;         // 0=inbound, 1=outbound
    UINT16 payload_length;
    // Extended fields for file/process events
    UINT16 path_offset;       // offset within payload where path string starts
    UINT16 path_length;       // length of path string
    UINT16 operation;         // IRP_MJ_CREATE=0, IRP_MJ_WRITE=1, etc.
    UINT16 _reserved;
} AEGIS_EVENT_HEADER, *PAEGIS_EVENT_HEADER;
#pragma pack(pop)

// Compile-time assert: ตรวจสอบขนาด struct ตรงกับฝั่ง Zig (40 bytes)
C_ASSERT(sizeof(AEGIS_EVENT_HEADER) == 40);

// =====================================================================
// CONFIG
// =====================================================================
#define AEGIS_RING_SIZE         (2 * 1024 * 1024)  // 2MB ring buffer
#define AEGIS_DEVICE_NAME       L"\\Device\\AegisWfpDevice"
#define AEGIS_SYMLINK_NAME      L"\\??\\AegisWfpDevice"  // user-mode: \\.\AegisWfpDevice
#define AEGIS_CALLOUT_NAME      L"AegisWfpCallout"

// =====================================================================
// IOCTL CODES — ตรงกับฝั่ง Zig (nids_analyze.zig)
//   CTL_CODE(DeviceType, Function, Method, Access)
//   FILE_DEVICE_UNKNOWN = 0x00000022
//   METHOD_BUFFERED = 0
//   FILE_READ_DATA  = 0x0001, FILE_WRITE_DATA = 0x0002
// =====================================================================
#define IOCTL_AEGIS_READ_EVENTS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_AEGIS_BLOCK_FLOW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_AEGIS_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

// =====================================================================
// STATS STRUCT (สำหรับ IOCTL_AEGIS_GET_STATS)
// =====================================================================
typedef struct _AEGIS_DRIVER_STATS {
    UINT64 total_events;
    UINT64 events_dropped;     // ring buffer overflow
    UINT64 bytes_processed;
    UINT32 ring_buffer_usage;  // 0..AEGIS_RING_SIZE
    UINT32 block_table_count;  // จำนวน flows ที่ block อยู่
} AEGIS_DRIVER_STATS, *PAEGIS_DRIVER_STATS;

// =====================================================================
// GLOBAL STATE (defined in aegis_wfp.c)
// =====================================================================
extern KSPIN_LOCK g_ring_lock;
extern PVOID g_ring_buffer;       // NonPagedPool, AEGIS_RING_SIZE bytes
extern ULONG g_ring_write_offset; // head
extern ULONG g_ring_read_offset;  // tail
extern LONGLONG g_event_count;
extern LONGLONG g_dropped_count;

// =====================================================================
// FUNCTION PROTOTYPES
// =====================================================================
// aegis_wfp.c
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AegisUnload;

// aegis_wfp_callout.c
NTSTATUS AegisRegisterCallout(PDEVICE_OBJECT deviceObj);
void AegisUnregisterCallout(void);
void NTAPI AegisClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
);

// aegis_wfp_comm.c
NTSTATUS AegisRingInit(void);
void AegisRingCleanup(void);
ULONG AegisRingWrite(const void* data, ULONG size);     // returns bytes written
ULONG AegisRingRead(PVOID out_buf, ULONG out_size);      // returns bytes read
NTSTATUS AegisIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
