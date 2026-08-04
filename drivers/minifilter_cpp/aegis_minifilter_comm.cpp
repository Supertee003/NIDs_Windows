/**
 * aegis_minifilter_comm.cpp — AEGIS NIDS Communication Port (C++ Edition)
 *
 * Creates FilterCommunicationPort for kernel→user mode messaging.
 * Uses CommPortGuard for RAII port management.
 *
 * C++ enhancements:
 *   - CommPortGuard: RAII for port create/close — no manual FltCloseCommunicationPort
 *   - Namespace Aegis::Minifilter: Clean separation from WFP driver globals
 *   - Structured error handling with early-return pattern
 */

#include "aegis_minifilter.hpp"

extern "C" {

// ====== Message Notify Callback ======
NTSTATUS AegisFilterMessageNotify(
    PVOID portCookie,
    PVOID inputBuffer,
    ULONG inputBufferLength,
    PVOID outputBuffer,
    ULONG outputBufferLength,
    PULONG returnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(portCookie);
    UNREFERENCED_PARAMETER(inputBuffer);
    UNREFERENCED_PARAMETER(inputBufferLength);

    using namespace Aegis::Minifilter;

    // User-mode Zig reader sends requests here
    if (outputBuffer && outputBufferLength >= sizeof(ULONG)) {
        *static_cast<PULONG>(outputBuffer) = 0;  // Number of pending events
        *returnOutputBufferLength = sizeof(ULONG);
    }

    return STATUS_SUCCESS;
}

// ====== Connect Notify ======
NTSTATUS AegisFilterConnectNotify(
    PFLT_PORT clientPort,
    PVOID portCookie,
    PVOID connectionContext,
    ULONG contextSize,
    PVOID* connectionCookie)
{
    UNREFERENCED_PARAMETER(portCookie);
    UNREFERENCED_PARAMETER(connectionContext);
    UNREFERENCED_PARAMETER(contextSize);
    UNREFERENCED_PARAMETER(connectionCookie);

    DbgPrint("[AEGIS Minifilter] Client connected to communication port (C++)\n");

    using namespace Aegis::Minifilter;
    g_commPortGuard.SetClientPort(clientPort);
    *connectionCookie = nullptr;
    return STATUS_SUCCESS;
}

// ====== Disconnect Notify ======
VOID AegisFilterDisconnectNotify(PVOID connectionCookie)
{
    UNREFERENCED_PARAMETER(connectionCookie);

    DbgPrint("[AEGIS Minifilter] Client disconnected (C++)\n");

    using namespace Aegis::Minifilter;
    // CommPortGuard handles client port cleanup
    if (g_commPortGuard.ClientPort()) {
        FltCloseCommunicationPort(g_commPortGuard.ClientPort());
        g_commPortGuard.SetClientPort(nullptr);
    }
}

} // extern "C"

// ====== C++ internal: Create Communication Port ======
namespace Aegis {
namespace Minifilter {

NTSTATUS AegisFilterConnectImpl()
{
    DbgPrint("[AEGIS Minifilter] Creating communication port (C++): %ws\n", AEGIS_FILTER_PORT_NAME);

    // RAII security descriptor
    PSECURITY_DESCRIPTOR sd = nullptr;
    NTSTATUS status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltBuildDefaultSecurityDescriptor failed: 0x%08X\n", status);
        return status;
    }

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, AEGIS_FILTER_PORT_NAME);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, sd);

    status = FltCreateCommunicationPort(g_filterGuard.Get(),
        g_commPortGuard.ServerPortPtr(),
        &oa,
        AegisFilterConnectNotify,
        AegisFilterDisconnectNotify,
        AegisFilterMessageNotify,
        1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltCreateCommunicationPort failed: 0x%08X\n", status);
        return status;
    }

    DbgPrint("[AEGIS Minifilter] Communication port created (C++)\n");
    return STATUS_SUCCESS;
}

} // namespace Minifilter
} // namespace Aegis
