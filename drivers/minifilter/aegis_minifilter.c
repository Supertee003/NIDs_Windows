/**
 * aegis_minifilter.c - AEGIS NIDS Minifilter Driver Entry (C5)
 *
 * C5: Ring buffer initialized in DriverEntry step 1,
 *     destroyed in FilterUnload step 4.
 * C4: Communication port created in DriverEntry step 5.
 *
 * WDK 10.0.28000:
 *   - FLT_REGISTRATION has no Altitude/Name (use INF)
 *   - No FltStopFiltering
 *   - FltCreateCommunicationPort: 8 params
 */

#include "aegis_minifilter.h"

/* ====== Global State ====== */
PFLT_FILTER g_FilterHandle = NULL;
PAEGIS_RING_BUFFER g_EventRing = NULL;

extern PFLT_PORT g_ServerPort;

/* ====== Forward declarations ====== */
NTSTATUS AegisFilterUnload(FLT_FILTER_UNLOAD_FLAGS flags);

/* File operation callbacks (aegis_minifilter_file.c) */
FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx);
FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx);
FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx);
FLT_POSTOP_CALLBACK_STATUS AegisPostOperation(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects,
    PVOID ctx, FLT_POST_OPERATION_FLAGS flags);

/* Process notification (aegis_minifilter_proc.c) */
VOID AegisProcessCallback(
    PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo);

/* Communication port (aegis_minifilter_comm.c) */
NTSTATUS AegisFilterConnect(PFLT_PORT* serverPort, PFLT_PORT* clientPort);
VOID AegisFilterDisconnect(void);

/* Ring buffer (aegis_minifilter_comm.c) */
NTSTATUS AegisRingInitialize(ULONG size);
VOID AegisRingDestroy(void);

/* ====== Filter Registration (C4 pattern: no Altitude/Name) ====== */
const FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_CREATE,            0, AegisPreCreate,  AegisPostOperation },
    { IRP_MJ_WRITE,             0, AegisPreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION,  0, AegisPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION contextRegistration[] = {
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION filterRegistration = {
    .Size                        = sizeof(FLT_REGISTRATION),
    .Version                     = FLT_REGISTRATION_VERSION,
    .Flags                       = 0,
    .ContextRegistration         = contextRegistration,
    .OperationRegistration       = callbacks,
    .FilterUnloadCallback        = AegisFilterUnload,
    .InstanceSetupCallback       = NULL,
    .InstanceQueryTeardownCallback = NULL,
    .InstanceTeardownStartCallback  = NULL,
    .InstanceTeardownCompleteCallback = NULL
};

/* ====== DriverEntry (5 steps) ====== */
extern NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;

    DbgPrint("[AEGIS MF] DriverEntry (C5)\n");

    /* Step 1: Initialize ring buffer (C5) */
    status = AegisRingInitialize(AEGIS_RING_SIZE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] Ring init failed: 0x%08X\n", status);
        return status;
    }

    /* Step 2: Register minifilter */
    status = FltRegisterFilter(DriverObject, &filterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] FltRegisterFilter failed: 0x%08X\n", status);
        AegisRingDestroy();
        return status;
    }

    /* Step 3: Process notification */
    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        AegisRingDestroy();
        return status;
    }

    /* Step 4: Start filtering */
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] FltStartFiltering failed: 0x%08X\n", status);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, TRUE);
        FltUnregisterFilter(g_FilterHandle);
        AegisRingDestroy();
        return status;
    }

    /* Step 5: Create communication port (C4) */
    status = AegisFilterConnect(&g_ServerPort, &clientPort);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] Comm port warning: 0x%08X\n", status);
        /* Non-fatal: filter works without user-mode comm */
    }

    DbgPrint("[AEGIS MF] Loaded (C5 ring %d KB)\n", AEGIS_RING_SIZE / 1024);
    return STATUS_SUCCESS;
}

/* ====== Unload (reverse order) ====== */
NTSTATUS AegisFilterUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    DbgPrint("[AEGIS MF] Unloading...\n");

    AegisFilterDisconnect();
    PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, TRUE);

    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    AegisRingDestroy();
    DbgPrint("[AEGIS MF] Unloaded\n");
    return STATUS_SUCCESS;
}