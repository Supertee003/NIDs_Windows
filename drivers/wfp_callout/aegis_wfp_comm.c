/**
 * aegis_wfp_comm.c - AEGIS NIDS WFP IRP Dispatch & IPS Block
 *
 * C3: CreateClose/ReadEvents/DeviceControl/BlockFlow/GetStats
 *     all live here (aegis_wfp.c delegates to this file).
 * M1: AegisWfpBlockFlow adds real WFP block filter.
 *
 * Uses AEGIS_RING_STATS and AEGIS_RING_USED() from aegis_wfp.h.
 */

#include "aegis_wfp.h"
#include <ntddk.h>
#include <fwpmk.h>

/* Extern global defined in aegis_wfp.c */
extern HANDLE g_WfpEngineHandle;

/* ====== IRP_MJ_CREATE / IRP_MJ_CLOSE ====== */
NTSTATUS AegisWfpCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* ====== Ring Buffer Read (IOCTL_AEGIS_READ_EVENTS) ====== */
static NTSTATUS AegisWfpReadEvents(PIRP Irp, ULONG_PTR *pInfo)
{
    PVOID  userBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG  userLen = IoGetCurrentIrpStackLocation(Irp)
                          ->Parameters.DeviceIoControl.OutputBufferLength;
    KIRQL   oldIrql;
    SIZE_T available, toCopy, firstPart;

    if (!userBuf || userLen == 0) {
        *pInfo = 0;
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    available = AEGIS_RING_USED();
    toCopy    = (available < (SIZE_T)userLen) ? available : (SIZE_T)userLen;

    if (toCopy > 0) {
        if (g_RingReadOffset + toCopy <= g_RingBufferSize) {
            RtlCopyMemory(userBuf,
                (PUCHAR)g_RingBuffer + g_RingReadOffset, toCopy);
        } else {
            firstPart = g_RingBufferSize - g_RingReadOffset;
            RtlCopyMemory(userBuf,
                (PUCHAR)g_RingBuffer + g_RingReadOffset, firstPart);
            RtlCopyMemory((PUCHAR)userBuf + firstPart,
                g_RingBuffer, toCopy - firstPart);
        }
        g_RingReadOffset = (g_RingReadOffset + toCopy) % g_RingBufferSize;
    }

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    *pInfo = (ULONG_PTR)toCopy;
    return (toCopy > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

/* ====== Block Flow (IOCTL_AEGIS_BLOCK_FLOW) - M1 ======
 *
 * Input:  UINT32 IPv4 address (network byte order)
 * Action: WFP filter FWP_ACTION_BLOCK at INBOUND_TRANSPORT_V4
 *         with IP_REMOTE_ADDRESS condition. Weight=15 > capture(0).
 */
static NTSTATUS AegisWfpBlockFlow(PIRP Irp, ULONG_PTR *pInfo)
{
    PVOID inputBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG  inputLen = IoGetCurrentIrpStackLocation(Irp)
                          ->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status;
    FWPM_FILTER0         filter;
    FWPM_ACTION0         action;
    FWPM_FILTER_CONDITION0 cond;
    UINT64 filterId = 0;

    if (!inputBuf || inputLen < sizeof(UINT32)) {
        *pInfo = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (!g_WfpEngineHandle) {
        DbgPrint("[AEGIS WFP] BlockFlow: engine not open\n");
        *pInfo = 0;
        return STATUS_DEVICE_NOT_READY;
    }

    {
        UINT32 blockIp = *(PUINT32)inputBuf;

        DbgPrint("[AEGIS WFP] IPS: Block %d.%d.%d.%d\n",
            (blockIp >>  0) & 0xFF,
            (blockIp >>  8) & 0xFF,
            (blockIp >> 16) & 0xFF,
            (blockIp >> 24) & 0xFF);

        RtlZeroMemory(&cond, sizeof(cond));
        cond.fieldKey  = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type   = FWP_UINT32;
        cond.conditionValue.uint32 = blockIp;

        RtlZeroMemory(&action, sizeof(action));
        action.type = FWP_ACTION_BLOCK;

        RtlZeroMemory(&filter, sizeof(filter));
        filter.layerKey              = FWPM_LAYER_INBOUND_TRANSPORT_V4;
        filter.displayData.name        = L"AEGIS IPS Block";
        filter.displayData.description = L"Dynamic IPS block";
        filter.action                 = action;
        filter.weight.type            = FWP_UINT8;
        filter.weight.uint8           = 15;
        filter.numFilterConditions    = 1;
        filter.filterCondition        = &cond;

        status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
                                NULL, &filterId);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[AEGIS WFP] Block add failed: 0x%08X\n",
                status);
            *pInfo = 0;
            return status;
        }

        DbgPrint("[AEGIS WFP] BLOCKED %d.%d.%d.%d fid=%llu\n",
            (blockIp >>  0) & 0xFF,
            (blockIp >>  8) & 0xFF,
            (blockIp >> 16) & 0xFF,
            (blockIp >> 24) & 0xFF,
            filterId);
    }

    *pInfo = sizeof(UINT32);
    return STATUS_SUCCESS;
}

/* ====== Get Stats (IOCTL_AEGIS_GET_STATS) ====== */
static NTSTATUS AegisWfpGetStats(PIRP Irp, ULONG_PTR *pInfo)
{
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG  outLen = IoGetCurrentIrpStackLocation(Irp)
                          ->Parameters.DeviceIoControl.OutputBufferLength;
    KIRQL   oldIrql;
    AEGIS_RING_STATS stats;

    if (!outBuf || outLen < sizeof(AEGIS_RING_STATS)) {
        *pInfo = 0;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&stats, sizeof(stats));

    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    stats.currentUsedBytes =
        (ULONG)AEGIS_RING_USED();
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    RtlCopyMemory(outBuf, &stats, sizeof(stats));
    *pInfo = sizeof(stats);
    return STATUS_SUCCESS;
}

/* ====== IOCTL Dispatch (IRP_MJ_DEVICE_CONTROL) ====== */
NTSTATUS AegisWfpDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS          status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR         info   = 0;

    UNREFERENCED_PARAMETER(DeviceObject);
    irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_AEGIS_READ_EVENTS:
        status = AegisWfpReadEvents(Irp, &info);
        break;

    case IOCTL_AEGIS_BLOCK_FLOW:
        status = AegisWfpBlockFlow(Irp, &info);
        break;

    case IOCTL_AEGIS_GET_STATS:
        status = AegisWfpGetStats(Irp, &info);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}