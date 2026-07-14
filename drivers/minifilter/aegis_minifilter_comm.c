// =====================================================================
// aegis_minifilter_comm.c — FilterCommunicationPort (kernel side)
// ---------------------------------------------------------------------
//   Flow:
//     DriverEntry → AegisCommInit:
//       FltCreateCommunicationPort  →  \\AegisMinifilterPort
//
//     User-mode → FilterConnectCommunicationPort:
//       kernel calls AegisConnectNotify → keep client_port for sending
//
//     Driver callback → AegisSendEvent:
//       FltSendMessage(client_port, msg, msg_size, timeout)
//
//     User-mode → FilterClose:
//       kernel calls AegisDisconnectNotify → cleanup
// =====================================================================

#include "aegis_minifilter.h"

// =====================================================================
// INIT COMMUNICATION PORT
// =====================================================================
NTSTATUS AegisCommInit(PFLT_FILTER Filter)
{
    NTSTATUS status;
    UNICODE_STRING port_name;
    OBJECT_ATTRIBUTES oa;
    SECURITY_DESCRIPTOR sd;

    RtlInitUnicodeString(&port_name, AEGIS_MINIFILTER_PORT_NAME);

    // Build a security descriptor that allows user-mode to connect
    if (!NT_SUCCESS(RtlCreateSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    InitializeObjectAttributes(&oa,
        &port_name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        &sd);

    status = FltCreateCommunicationPort(
        Filter,
        &g_server_port,
        &oa,
        NULL,                          // ServerPortCookie
        AegisConnectNotify,
        AegisDisconnectNotify,
        NULL,                          // MessageNotifyCallback (none)
        1);                            // MaxConnections

    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-MINI] FltCreateCommunicationPort failed: 0x%08X\n", status);
        return status;
    }

    DbgPrint("[AEGIS-MINI] Communication port created: %ws\n", AEGIS_MINIFILTER_PORT_NAME);
    return STATUS_SUCCESS;
}

// =====================================================================
// CLEANUP COMMUNICATION PORT
// =====================================================================
void AegisCommCleanup(void)
{
    if (g_server_port) {
        FltCloseCommunicationPort(g_server_port);
        g_server_port = NULL;
    }
}

// =====================================================================
// CONNECT NOTIFY — called when user-mode connects to port
// =====================================================================
NTSTATUS AegisConnectNotify(
    PFLT_PORT ClientPort,
    PVOID ConnectionContext,
    ULONG SizeOfContext)
{
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    ExAcquireFastMutex(&g_port_lock);
    g_client_port = ClientPort;
    ExReleaseFastMutex(&g_port_lock);

    DbgPrint("[AEGIS-MINI] User-mode client connected\n");
    return STATUS_SUCCESS;
}

// =====================================================================
// DISCONNECT NOTIFY — called when user-mode closes port
// =====================================================================
VOID AegisDisconnectNotify(PFLT_PORT ClientPort)
{
    ExAcquireFastMutex(&g_port_lock);
    if (g_client_port == ClientPort) {
        g_client_port = NULL;
    }
    ExReleaseFastMutex(&g_port_lock);

    FltCloseClientPort(g_filter_handle, &ClientPort);
    DbgPrint("[AEGIS-MINI] User-mode client disconnected\n");
}

// =====================================================================
// SEND EVENT — push event ไป user-mode
//   Returns STATUS_SUCCESS ถ้าส่งสำเร็จ, STATUS_FLT_DELETING_OBJECT ถ้าไม่มี client
// =====================================================================
NTSTATUS AegisSendEvent(PAEGIS_EVENT_HEADER Header, PVOID Payload, ULONG PayloadSize)
{
    NTSTATUS status;
    ULONG total_size;
    PVOID msg_buf;
    LARGE_INTEGER timeout;

    if (!Header) return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_port_lock);
    PFLT_PORT client = g_client_port;
    ExReleaseFastMutex(&g_port_lock);

    if (!client) {
        // No user-mode client connected — silently drop
        return STATUS_FLT_DELETING_OBJECT;
    }

    total_size = sizeof(AEGIS_EVENT_HEADER) + PayloadSize;
    msg_buf = ExAllocatePoolWithTag(PagedPool, total_size, 'AEGS');
    if (!msg_buf) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(msg_buf, Header, sizeof(AEGIS_EVENT_HEADER));
    if (Payload && PayloadSize > 0) {
        RtlCopyMemory((PUCHAR)msg_buf + sizeof(AEGIS_EVENT_HEADER), Payload, PayloadSize);
    }

    // Timeout: 100ms (don't block kernel too long)
    timeout.QuadPart = -1000000; // 100ms in 100ns units (negative = relative)

    status = FltSendMessage(
        g_filter_handle,
        &client,
        msg_buf,
        total_size,
        &timeout);

    ExFreePoolWithTag(msg_buf, 'AEGS');

    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&g_event_count);
    }

    return status;
}
