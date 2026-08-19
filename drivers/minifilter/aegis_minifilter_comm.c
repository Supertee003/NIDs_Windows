/**
 * aegis_minifilter_comm.c — AEGIS NIDS Minifilter Communication Port
 *
 * Creates FilterCommunicationPort for kernel→user mode messaging.
 * The Zig minifilter_reader.zig connects to this port and receives
 * AEGIS_FILE_EVENT structures for each suspicious file/process event.
 */

#include "aegis_minifilter.h"

// ====== Communication Port Globals ======
PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;

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

    // User-mode Zig reader sends requests here
    // For now, return statistics or pending events
    if (outputBuffer && outputBufferLength >= sizeof(ULONG)) {
        *(PULONG)outputBuffer = 0;  // Number of pending events
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

    DbgPrint("[AEGIS Minifilter] Client connected to communication port\n");
    g_ClientPort = clientPort;
    *connectionCookie = NULL;
    return STATUS_SUCCESS;
}

// ====== Disconnect Notify ======
VOID AegisFilterDisconnectNotify(PVOID connectionCookie)
{
    UNREFERENCED_PARAMETER(connectionCookie);

    DbgPrint("[AEGIS Minifilter] Client disconnected from communication port\n");
    if (g_ClientPort) {
        FltCloseCommunicationPort(g_ClientPort);
        g_ClientPort = NULL;
    }
}

// ====== Create Communication Port ======
NTSTATUS AegisFilterConnect(PFLT_PORT* serverPort, PFLT_PORT* clientPort)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;

    DbgPrint("[AEGIS Minifilter] Creating communication port: %ws\n", AEGIS_FILTER_PORT_NAME);

    // Create security descriptor allowing user-mode access
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltBuildDefaultSecurityDescriptor failed: 0x%08X\n", status);
        return status;
    }

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, AEGIS_FILTER_PORT_NAME);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(g_FilterHandle, serverPort, &oa,
        AegisFilterConnectNotify, AegisFilterDisconnectNotify, AegisFilterMessageNotify, 1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS Minifilter] FltCreateCommunicationPort failed: 0x%08X\n", status);
        return status;
    }

    DbgPrint("[AEGIS Minifilter] Communication port created\n");
    return STATUS_SUCCESS;
}

// ====== Close Communication Port ======
VOID AegisFilterDisconnect()
{
    if (g_ClientPort) {
        FltCloseCommunicationPort(g_ClientPort);
        g_ClientPort = NULL;
    }
    if (g_ServerPort) {
        FltCloseCommunicationPort(g_ServerPort);
        g_ServerPort = NULL;
    }
}
