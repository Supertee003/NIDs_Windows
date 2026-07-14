// =====================================================================
// aegis_minifilter.h — Shared header สำหรับ Minifilter driver
// ---------------------------------------------------------------------
//   Minifilter ดัก file I/O + process creation แล้วส่ง events ไป
//   user-mode Zig ผ่าน FilterCommunicationPort
//
//   Build: ต้องการ WDK + Visual Studio (kernel-mode)
// =====================================================================

#pragma once

#include <fltKernel.h>
#include <fltUserStructures.h>

// =====================================================================
// CONSTANTS
// =====================================================================
#define AEGIS_MINIFILTER_NAME         L"AegisMinifilter"
#define AEGIS_MINIFILTER_PORT_NAME    L"\\AegisMinifilterPort"
#define AEGIS_MINIFILTER_ALTITUDE     L"370000"  // Anti-virus range (Microsoft-assigned)

// Reuse AEGIS_EVENT_HEADER จาก WFP driver
// (ต้อง copy struct หรือ include aegis_wfp.h ถ้าอยู่ใน project เดียวกัน)
#pragma pack(push, 1)
typedef struct _AEGIS_EVENT_HEADER {
    UINT32 event_type;        // AEGIS_EVENT_TYPE
    UINT32 event_size;
    UINT64 timestamp;
    UINT32 process_id;
    UINT32 src_ip;
    UINT32 dst_ip;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8  protocol;
    UINT8  direction;
    UINT16 payload_length;
    UINT16 path_offset;
    UINT16 path_length;
    UINT16 operation;
    UINT16 _reserved;
} AEGIS_EVENT_HEADER, *PAEGIS_EVENT_HEADER;
#pragma pack(pop)

C_ASSERT(sizeof(AEGIS_EVENT_HEADER) == 40);

// Event types ตรงกับฝั่ง Zig EventSource
#define AEGIS_EVENT_KERNEL_FILE     2
#define AEGIS_EVENT_KERNEL_PROCESS  3
#define AEGIS_EVENT_KERNEL_REGISTRY 4

// IRP major function codes (สำหรับ operation field)
#define AEGIS_OP_CREATE  0   // IRP_MJ_CREATE
#define AEGIS_OP_WRITE   1   // IRP_MJ_WRITE
#define AEGIS_OP_RENAME  2   // IRP_MJ_SET_INFORMATION (FileRenameInfo)
#define AEGIS_OP_DELETE  3   // IRP_MJ_SET_INFORMATION (FileDispositionInfo)

// =====================================================================
// GLOBAL STATE (defined in aegis_minifilter.c)
// =====================================================================
extern PFLT_FILTER g_filter_handle;
extern PFLT_PORT g_server_port;
extern PFLT_PORT g_client_port;
extern FAST_MUTEX g_port_lock;
extern LONG g_event_count;

// =====================================================================
// FUNCTION PROTOTYPES
// =====================================================================
// aegis_minifilter.c
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AegisMiniUnload;
NTSTATUS AegisMiniInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType
);
NTSTATUS AegisMiniInstanceQueryTeardown(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

// aegis_minifilter_file.c
FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);
FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);
FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext
);

// aegis_minifilter_proc.c
VOID AegisProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
);

// aegis_minifilter_comm.c
NTSTATUS AegisCommInit(PFLT_FILTER Filter);
void AegisCommCleanup(void);
NTSTATUS AegisConnectNotify(
    PFLT_PORT ClientPort,
    PVOID ConnectionContext,
    ULONG SizeOfContext
);
VOID AegisDisconnectNotify(PFLT_PORT ClientPort);
NTSTATUS AegisSendEvent(PAEGIS_EVENT_HEADER Header, PVOID Payload, ULONG PayloadSize);
