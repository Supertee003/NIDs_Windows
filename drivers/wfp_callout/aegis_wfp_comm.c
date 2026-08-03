/**
 * aegis_wfp_comm.c — AEGIS NIDS WFP Ring Buffer Communication Layer
 *
 * Manages the 2MB ring buffer (spinlock-protected) that stores captured
 * network events. The user-mode Zig reader (windows_capture.zig) reads
 * from this buffer via IOCTL_AEGIS_READ_EVENTS.
 *
 * Also provides IOCTL_AEGIS_BLOCK_FLOW for IPS enforcement —
 * the Python Brain can request blocking of specific flows.
 */

#include "aegis_wfp.h"
#include <ntddk.h>

// ====== Ring Buffer Statistics ======
typedef struct _AEGIS_RING_STATS {
    ULONG totalEventsWritten;
    ULONG totalEventsRead;
    ULONG totalBytesWritten;
    ULONG totalBytesRead;
    ULONG overflowCount;        // Events lost due to buffer full
} AEGIS_RING_STATS;

AEGIS_RING_STATS g_RingStats = {0};

// ====== Write event to ring buffer (called from classify function) ======
NTSTATUS AegisWfpWriteEvent(PVOID eventData, SIZE_T eventSize)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    SIZE_T availableSpace = g_RingBufferSize - ((g_RingWriteOffset - g_RingReadOffset) % g_RingBufferSize);

    if (eventSize > availableSpace) {
        g_RingStats.overflowCount++;
        KeReleaseSpinLock(&g_RingLock, oldIrql);
        return STATUS_BUFFER_OVERFLOW;
    }

    PUCHAR writePos = (PUCHAR)g_RingBuffer + g_RingWriteOffset;
    SIZE_T firstPart = g_RingBufferSize - g_RingWriteOffset;

    if (firstPart >= eventSize) {
        RtlCopyMemory(writePos, eventData, eventSize);
        g_RingWriteOffset = (g_RingWriteOffset + eventSize) % g_RingBufferSize;
    } else {
        RtlCopyMemory(writePos, eventData, firstPart);
        RtlCopyMemory(g_RingBuffer, (PUCHAR)eventData + firstPart, eventSize - firstPart);
        g_RingWriteOffset = eventSize - firstPart;
    }

    g_RingStats.totalEventsWritten++;
    g_RingStats.totalBytesWritten += eventSize;

    KeReleaseSpinLock(&g_RingLock, oldIrql);
    return STATUS_SUCCESS;
}

// ====== Read events from ring buffer (IOCTL handler) ======
// Implemented in aegis_wfp.c::AegisWfpReadEvents()

// ====== Block a specific flow (IOCTL_AEGIS_BLOCK_FLOW) ======
// This allows the Python Brain (Tier-2 IPS) to request blocking
// of a specific source IP at the kernel level via WFP filter.
NTSTATUS AegisWfpBlockFlow(PIRP Irp)
{
    // TODO: Implement WFP filter addition for blocking specific IPs
    // Input: source IP address (UINT32) from Python Brain
    // Action: Add WFP filter with FWP_ACTION_BLOCK for that IP

    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.InputBufferLength;

    if (!inputBuffer || inputLength < sizeof(UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }

    UINT32 blockIp = *(PUINT32)inputBuffer;
    DbgPrint("[AEGIS WFP] IPS: Block request for IP %d.%d.%d.%d\n",
        (blockIp >> 0) & 0xFF, (blockIp >> 8) & 0xFF,
        (blockIp >> 16) & 0xFF, (blockIp >> 24) & 0xFF);

    // TODO: Add WFP filter here (FWPM_FILTER_CONDITION0 for source IP)

    return STATUS_NOT_IMPLEMENTED;
}

// ====== Get ring buffer statistics (IOCTL_AEGIS_GET_STATS) ======
NTSTATUS AegisWfpGetStats(PIRP Irp)
{
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputLength = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.OutputBufferLength;

    if (!outputBuffer || outputLength < sizeof(AEGIS_RING_STATS)) {
        return STATUS_INVALID_PARAMETER;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    RtlCopyMemory(outputBuffer, &g_RingStats, sizeof(AEGIS_RING_STATS));
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    Irp->IoStatus.Information = sizeof(AEGIS_RING_STATS);
    return STATUS_SUCCESS;
}
