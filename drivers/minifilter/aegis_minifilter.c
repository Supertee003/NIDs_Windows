// =====================================================================
// aegis_minifilter.c — Minifilter lifecycle (DriverEntry / Unload)
// ---------------------------------------------------------------------
//   ลงทะเบียน minifilter กับ FilterManager พร้อม callbacks สำหรับ:
//     - IRP_MJ_CREATE      (file open)
//     - IRP_MJ_WRITE       (file write)
//     - IRP_MJ_SET_INFORMATION (rename / delete)
//     - PsSetCreateProcessNotifyRoutineEx (process create/exit)
//
//   ส่ง events ไป user-mode ผ่าน FilterCommunicationPort
// =====================================================================

#include "aegis_minifilter.h"

// =====================================================================
// GLOBAL STATE
// =====================================================================
PFLT_FILTER g_filter_handle = NULL;
PFLT_PORT g_server_port = NULL;
PFLT_PORT g_client_port = NULL;
FAST_MUTEX g_port_lock;
LONG g_event_count = 0;

// =====================================================================
// OPERATION REGISTRATION TABLE
//   บอก FilterManager ว่าเราสนใจ IRP_MJ_* อะไรบ้าง
// =====================================================================
const FLT_OPERATION_REGISTRATION g_callback_table[] = {
    { IRP_MJ_CREATE,
      0,
      AegisPreCreate,
      NULL },

    { IRP_MJ_WRITE,
      0,
      AegisPreWrite,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      AegisPreSetInfo,
      NULL },

    { IRP_MJ_OPERATION_END }
};

// =====================================================================
// CONTEXT REGISTRATION (none — we use no contexts)
// =====================================================================
const FLT_CONTEXT_REGISTRATION g_context_table[] = {
    { FLT_CONTEXT_END }
};

// =====================================================================
// FILTER REGISTRATION STRUCT
// =====================================================================
const FLT_REGISTRATION g_filter_registration = {
    sizeof(FLT_REGISTRATION),         // Size
    FLT_REGISTRATION_VERSION,         // Version
    0,                                // Flags
    g_context_table,                  // Context
    g_callback_table,                 // OperationRegistration
    AegisMiniUnload,                  // FilterUnloadCallback
    AegisMiniInstanceSetup,           // InstanceSetupCallback
    AegisMiniInstanceQueryTeardown,   // InstanceQueryTeardownCallback
    NULL,                             // InstanceTeardownStartCallback
    NULL,                             // InstanceTeardownCompleteCallback
    NULL,                             // GenerateFileNameCallback
    NULL,                             // NormalizeNameComponentCallback
    NULL,                             // NormalizeContextCleanupCallback
    NULL,                             // TransactionNotificationCallback
    NULL,                             // NormalizeNameComponentExCallback
    NULL                              // SectionNotificationCallback
};

// =====================================================================
// DRIVER ENTRY
// =====================================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING port_name;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AEGIS-MINI] DriverEntry: loading...\n");

    ExInitializeFastMutex(&g_port_lock);

    // 1. Register with FilterManager
    status = FltRegisterFilter(DriverObject, RegistryPath, &g_filter_registration, &g_filter_handle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-MINI] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    // 2. Init communication port
    status = AegisCommInit(g_filter_handle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-MINI] AegisCommInit failed: 0x%08X\n", status);
        FltUnregisterFilter(g_filter_handle);
        g_filter_handle = NULL;
        return status;
    }

    // 3. Register process notification
    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-MINI] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        AegisCommCleanup();
        FltUnregisterFilter(g_filter_handle);
        g_filter_handle = NULL;
        return status;
    }

    // 4. Start filtering
    status = FltStartFiltering(g_filter_handle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-MINI] FltStartFiltering failed: 0x%08X\n", status);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessNotify, TRUE);
        AegisCommCleanup();
        FltUnregisterFilter(g_filter_handle);
        g_filter_handle = NULL;
        return status;
    }

    DbgPrint("[AEGIS-MINI] Driver loaded successfully.\n");
    return STATUS_SUCCESS;
}

// =====================================================================
// DRIVER UNLOAD
// =====================================================================
VOID AegisMiniUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    DbgPrint("[AEGIS-MINI] Unloading...\n");

    PsSetCreateProcessNotifyRoutineEx(AegisProcessNotify, TRUE);
    AegisCommCleanup();
    FltUnregisterFilter(g_filter_handle);
    g_filter_handle = NULL;

    DbgPrint("[AEGIS-MINI] Unloaded.\n");
}

// =====================================================================
// INSTANCE SETUP — allow attaching to all volumes
// =====================================================================
NTSTATUS AegisMiniInstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    return STATUS_SUCCESS;
}

// =====================================================================
// INSTANCE QUERY TEARDOWN — allow detaching
// =====================================================================
NTSTATUS AegisMiniInstanceQueryTeardown(
    PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}
