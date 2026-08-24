/**
 * aegis_minifilter_comm.c - Communication Port + Ring Buffer (C5)
 *
 * C4: FilterConnectCommunicationPort for user-mode Zig reader
 * C5: Ring buffer implementation + MessageNotify event delivery
 */

#include "aegis_minifilter.h"

extern PFLT_FILTER g_FilterHandle;

/* ====== Communication Port Globals ====== */
PFLT_PORT g_ServerPort = NULL;
PFLT_PORT g_ClientPort = NULL;

/* ================================================================
   Ring Buffer Implementation (C5)
   ================================================================ */

/* Write bytes to ring with wrap-around */
static VOID RingWriteBytes(PAEGIS_RING_BUFFER r, PUCHAR data, ULONG size)
{
    ULONG first;
    first = (size < r->Size - r->Head) ? size : (r->Size - r->Head);
    RtlCopyMemory(r->Data + r->Head, data, first);
    if (first < size)
        RtlCopyMemory(r->Data, data + first, size - first);
    r->Head = (r->Head + size) % r->Size;
}

/* Read bytes from ring with wrap-around */
static VOID RingReadBytes(PAEGIS_RING_BUFFER r, PUCHAR data, ULONG size)
{
    ULONG first;
    first = (size < r->Size - r->Tail) ? size : (r->Size - r->Tail);
    RtlCopyMemory(data, r->Data + r->Tail, first);
    if (first < size)
        RtlCopyMemory(data + first, r->Data, size - first);
    r->Tail = (r->Tail + size) % r->Size;
}

NTSTATUS AegisRingInitialize(ULONG size)
{
    g_EventRing = (PAEGIS_RING_BUFFER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AEGIS_RING_BUFFER), 'giEA');
    if (!g_EventRing)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_EventRing, sizeof(AEGIS_RING_BUFFER));

    g_EventRing->Data = (PUCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, size, 'gdEA');
    if (!g_EventRing->Data) {
        ExFreePoolWithTag(g_EventRing, 'giEA');
        g_EventRing = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_EventRing->Size = size;
    KeInitializeSpinLock(&g_EventRing->Lock);
    DbgPrint("[AEGIS MF] Ring buffer %u bytes\n", size);
    return STATUS_SUCCESS;
}

VOID AegisRingDestroy(void)
{
    if (g_EventRing) {
        if (g_EventRing->Data)
            ExFreePoolWithTag(g_EventRing->Data, 'gdEA');
        ExFreePoolWithTag(g_EventRing, 'giEA');
        g_EventRing = NULL;
    }
}

NTSTATUS AegisRingWriteEvent(ULONG type, ULONG pid, ULONG parentPid,
    NTSTATUS status, PWSTR path)
{
    KIRQL oldIrql;
    AEGIS_EVENT_RECORD evt;
    ULONG evtSize = sizeof(AEGIS_EVENT_RECORD);
    ULONG used, freeSpace;

    if (!g_EventRing)
        return STATUS_NOT_FOUND;

    RtlZeroMemory(&evt, sizeof(evt));
    evt.EventType  = type;
    evt.Size      = evtSize;
    evt.ProcessId = pid;
    evt.ParentPid = parentPid;
    KeQuerySystemTime(&evt.Timestamp);
    evt.Status    = status;

    if (path) {
        ULONG len = 0;
        while (path[len] && len < 219) len++;
        RtlCopyMemory(evt.Path, path, len * sizeof(WCHAR));
        evt.NameLen = (USHORT)len;
    }

    KeAcquireSpinLock(&g_EventRing->Lock, &oldIrql);

    used = AEGIS_RING_USED(g_EventRing);
    freeSpace = g_EventRing->Size - used - 1;

    if (freeSpace < evtSize) {
        g_EventRing->DroppedEvents++;
        KeReleaseSpinLock(&g_EventRing->Lock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RingWriteBytes(g_EventRing, (PUCHAR)&evt, evtSize);
    g_EventRing->TotalEvents++;

    KeReleaseSpinLock(&g_EventRing->Lock, oldIrql);
    return STATUS_SUCCESS;
}

ULONG AegisRingReadEvents(PUCHAR outBuf, ULONG outSize)
{
    KIRQL oldIrql;
    ULONG copied = 0;
    ULONG evtSize = sizeof(AEGIS_EVENT_RECORD);

    if (!g_EventRing || !outBuf || outSize == 0)
        return 0;

    KeAcquireSpinLock(&g_EventRing->Lock, &oldIrql);

    while (AEGIS_RING_USED(g_EventRing) >= evtSize &&
           (outSize - copied) >= evtSize) {
        RingReadBytes(g_EventRing, outBuf + copied, evtSize);
        copied += evtSize;
    }

    KeReleaseSpinLock(&g_EventRing->Lock, oldIrql);
    return copied;
}

VOID AegisRingGetStats(PULONG totalEvents, PULONG droppedEvents,
    PULONG usedBytes, PULONG capacity)
{
    KIRQL oldIrql;
    if (!g_EventRing) return;

    KeAcquireSpinLock(&g_EventRing->Lock, &oldIrql);
    if (totalEvents)   *totalEvents   = g_EventRing->TotalEvents;
    if (droppedEvents) *droppedEvents = g_EventRing->DroppedEvents;
    if (usedBytes)     *usedBytes     = AEGIS_RING_USED(g_EventRing);
    if (capacity)      *capacity      = g_EventRing->Size;
    KeReleaseSpinLock(&g_EventRing->Lock, oldIrql);
}

/* ================================================================
   Communication Port Callbacks (C4)
   ================================================================ */

NTSTATUS AegisFilterMessageNotify(
    PVOID portCookie,
    PVOID inputBuffer,
    ULONG inputBufferLength,
    PVOID outputBuffer,
    ULONG outputBufferLength,
    PULONG returnOutputBufferLength)
{
    ULONG cmd = 0;

    UNREFERENCED_PARAMETER(portCookie);

    if (!inputBuffer || inputBufferLength < sizeof(ULONG))
        return STATUS_INVALID_PARAMETER;

    cmd = *(PULONG)inputBuffer;

    switch (cmd) {
    case AEGIS_MSG_READ_EVENTS:
        if (!outputBuffer || outputBufferLength == 0)
            return STATUS_BUFFER_TOO_SMALL;
        *returnOutputBufferLength = AegisRingReadEvents(
            (PUCHAR)outputBuffer, outputBufferLength);
        return STATUS_SUCCESS;

    case AEGIS_MSG_GET_STATS: {
        ULONG total = 0, dropped = 0, used = 0, cap = 0;
        AegisRingGetStats(&total, &dropped, &used, &cap);
        if (!outputBuffer || outputBufferLength < 4 * sizeof(ULONG))
            return STATUS_BUFFER_TOO_SMALL;
        ((PULONG)outputBuffer)[0] = total;
        ((PULONG)outputBuffer)[1] = dropped;
        ((PULONG)outputBuffer)[2] = used;
        ((PULONG)outputBuffer)[3] = cap;
        *returnOutputBufferLength = 4 * sizeof(ULONG);
        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

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

    DbgPrint("[AEGIS MF] Client connected\n");
    g_ClientPort = clientPort;
    *connectionCookie = NULL;
    return STATUS_SUCCESS;
}

VOID AegisFilterDisconnectNotify(PVOID connectionCookie)
{
    UNREFERENCED_PARAMETER(connectionCookie);
    DbgPrint("[AEGIS MF] Client disconnected\n");
    g_ClientPort = NULL;
}

/* ================================================================
   Communication Port Setup / Teardown (C4)
   ================================================================ */

NTSTATUS AegisFilterConnect(PFLT_PORT* serverPort, PFLT_PORT* clientPort)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;

    DbgPrint("[AEGIS MF] Creating port: %ws\n", AEGIS_FILTER_PORT_NAME);

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] BuildSecurityDescriptor failed: 0x%08X\n", status);
        return status;
    }

    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, AEGIS_FILTER_PORT_NAME);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    /* WDK 10.0.28000: 8 params (4th = ServerPortCookie) */
    status = FltCreateCommunicationPort(g_FilterHandle, serverPort, &oa,
        NULL,
        AegisFilterConnectNotify, AegisFilterDisconnectNotify,
        AegisFilterMessageNotify, 1);

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS MF] FltCreateCommunicationPort failed: 0x%08X\n", status);
        return status;
    }

    DbgPrint("[AEGIS MF] Communication port created\n");
    return STATUS_SUCCESS;
}

VOID AegisFilterDisconnect(void)
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