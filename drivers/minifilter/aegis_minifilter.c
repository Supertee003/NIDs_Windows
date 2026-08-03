/**
 * aegis_minifilter.c — AEGIS NIDS Minifilter Driver Entry & Registration
 *
 * Registers the minifilter at altitude 370000 (Anti-Virus layer),
 * sets up process notification callback, and creates communication port
 * for user-mode Zig reader.
 *
 * Build: WDK + Visual Studio 2022
 * Runtime: Test Signing required
 */

#include "aegis_minifilter.h"

// ====== Global State ======
PFLT_FILTER g_FilterHandle = NULL;
HANDLE g_CommPort = NULL;

// Pre-operation callbacks (defined in aegis_minifilter_file.c)
FLT_PREOP_CALLBACK_STATUS AegisPreCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS AegisPreWrite(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);

// Post-operation callback
FLT_POSTOP_CALLBACK_STATUS AegisPostOperation(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS,
    PVOID, FLT_POST_OPERATION_FLAGS);

// Process notification (defined in aegis_minifilter_proc.c)
VOID AegisProcessCallback(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);

// Communication port (defined in aegis_minifilter_comm.c)
NTSTATUS AegisFilterConnect(PFLT_PORT*, PFLT_PORT*);
VOID AegisFilterDisconnect();

// ====== Filter Registration Structure ======
const FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_CREATE,       0, AegisPreCreate,  AegisPostOperation },
    { IRP_MJ_WRITE,        0, AegisPreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, AegisPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION contextRegistration[] = {
    { FLT_CONTEXT_END }
};

const FLT_REGISTRATION filterRegistration = {
    .Size = sizeof(FLT_REGISTRATION),
    .Version = FLT_REGISTRATION_VERSION,
    .Flags = 0,
    .ContextRegistration = contextRegistration,
    .OperationRegistration = callbacks,
    .FilterUnloadCallback = AegisFilterUnload,
    .InstanceSetupCallback = NULL,
    .InstanceQueryTeardownCallback = NULL,
    .InstanceTeardownStartCallback = NULL,
    .InstanceTeardownCompleteCallback = NULL,
    .Altitude = AEGIS_MINIFILTER_ALTITUDE,
    .Name = L"AegisMinifilter",
};

// ====== DriverEntry ======
extern NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    DbgPrint("[AEGIS Minifilter] DriverEntry\n");

    // 1. Register minifilter with Filter Manager
    status = FltRegisterFilter(DriverObject, &filterRegistration, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    // 2. Set up process notification callback
    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    // 3. Start filtering
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltStartFiltering failed: 0x%08X\n", status);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, TRUE);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }

    DbgPrint("[AEGIS Minifilter] Started — Altitude 370000 (Anti-Virus layer)\n");
    return STATUS_SUCCESS;
}

// ====== Unload ======
NTSTATUS AegisFilterUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);

    DbgPrint("[AEGIS Minifilter] Unloading...\n");

    // Remove process notification callback
    PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, TRUE);

    // Close communication port
    AegisFilterDisconnect();

    // Unregister filter
    if (g_FilterHandle) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
    }

    DbgPrint("[AEGIS Minifilter] Unloaded\n");
    return STATUS_SUCCESS;
}
