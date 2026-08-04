@@ -0,0 +1,128 @@
/**
 * aegis_minifilter.cpp — AEGIS NIDS Minifilter Driver Entry & Registration (C++ Edition)
 *
 * Registers the minifilter at altitude 370000 (Anti-Virus layer),
 * sets up process notification callback, and creates communication port
 * for user-mode Zig reader — all using RAII guards.
 *
 * C++ enhancements:
 *   - FilterGuard: RAII for FltRegisterFilter / FltUnregisterFilter
 *   - CommPortGuard: RAII for FltCreateCommunicationPort / FltCloseCommunicationPort
 *   - Namespace Aegis::Minifilter: Clean separation from WFP driver
 *
 * Architecture: C++ Kernel Driver (KERNEL_FILE/KERNEL_PROCESS layer)
 * Build: WDK + Visual Studio 2022 (compile with /KernelDisableExceptions)
 * Runtime: Test Signing required
 */

#include "aegis_minifilter.hpp"

// ====== Global State (RAII-managed) ======
namespace Aegis {
namespace Minifilter {

static FilterGuard    g_filterGuard;
static CommPortGuard  g_commPortGuard;

} // namespace Minifilter
} // namespace Aegis

// ====== extern "C" forward declarations (WDK requires C linkage) ======
extern "C" {
    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

    // Pre-operation callbacks (defined in aegis_minifilter_file.cpp)
    FLT_PREOP_CALLBACK_STATUS AegisPreCreate(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
    FLT_PREOP_CALLBACK_STATUS AegisPreWrite(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);
    FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS, PVOID*);

    // Post-operation callback
    FLT_POSTOP_CALLBACK_STATUS AegisPostOperation(PFLT_CALLBACK_DATA, PCFLT_RELATED_OBJECTS,
        PVOID, FLT_POST_OPERATION_FLAGS);

    // Process notification (defined in aegis_minifilter_proc.cpp)
    VOID AegisProcessCallback(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);

    // Unload
    NTSTATUS AegisFilterUnload(FLT_FILTER_UNLOAD_FLAGS flags);
}

// ====== Filter Registration Structure ======
static const FLT_OPERATION_REGISTRATION callbacks[] = {
    { IRP_MJ_CREATE,            0, AegisPreCreate,  AegisPostOperation },
    { IRP_MJ_WRITE,             0, AegisPreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION,   0, AegisPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION contextRegistration[] = {
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION filterRegistration = {
    .Size                       = sizeof(FLT_REGISTRATION),
    .Version                    = FLT_REGISTRATION_VERSION,
    .Flags                      = 0,
    .ContextRegistration        = contextRegistration,
    .OperationRegistration      = callbacks,
    .FilterUnloadCallback       = AegisFilterUnload,
    .InstanceSetupCallback      = NULL,
    .InstanceQueryTeardownCallback = NULL,
    .InstanceTeardownStartCallback = NULL,
    .InstanceTeardownCompleteCallback = NULL,
    .Altitude                   = AEGIS_MINIFILTER_ALTITUDE,
    .Name                       = L"AegisMinifilter",
};

// ====== DriverEntry (extern "C") ======
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DbgPrint("[AEGIS Minifilter] DriverEntry (C++)\n");
    using namespace Aegis::Minifilter;

    // 1. Register minifilter with Filter Manager (RAII FilterGuard)
    NTSTATUS status = g_filterGuard.Register(DriverObject, &filterRegistration);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FilterGuard::Register failed: 0x%08X\n", status);
        return status;  // RAII auto-cleans
    }

    // 2. Set up process notification callback
    status = PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        g_filterGuard.Unregister();  // RAII cleanup
        return status;
    }

    // 3. Start filtering
    status = FltStartFiltering(g_filterGuard.Get());
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltStartFiltering failed: 0x%08X\n", status);
        PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, TRUE);
        g_filterGuard.Unregister();
        return status;
    }

    DbgPrint("[AEGIS Minifilter] Started (C++) — Altitude 370000\n");
    return STATUS_SUCCESS;
}

// ====== Unload ======
extern "C" NTSTATUS AegisFilterUnload(FLT_FILTER_UNLOAD_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flags);
    DbgPrint("[AEGIS Minifilter] Unloading (C++)...\n");

    using namespace Aegis::Minifilter;

    // Remove process notification callback
    PsSetCreateProcessNotifyRoutineEx(AegisProcessCallback, TRUE);

    // RAII auto-cleans:
    g_commPortGuard.Close();
    g_filterGuard.Unregister();

    DbgPrint("[AEGIS Minifilter] Unloaded (C++)\n");
    return STATUS_SUCCESS;
}
