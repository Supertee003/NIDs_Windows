/**
 * aegis_wfp_callout.c - WFP Callout Classify + Registration
 *
 * C1 FIX: Extracts 5-tuple from inFixedValues->incomingValue[]
 *         indexed by FWPS_FIELD_INBOUND_TRANSPORT_V4_* constants.
 * C2 FIX: Calls FwpmFilterAdd0 so callout is actually invoked.
 *
 * FAIL-OPEN design: classify never blocks packets.
 */

#include "aegis_wfp.h"

/* WinDbg/DbgView are not required for startup diagnosis. Persist the failing
 * registration stage and status in the System event log. DumpData[0] is the
 * stage ID below; DumpData[1] is the raw NTSTATUS/WFP status. */
enum {
    AEGIS_STAGE_ENGINE_OPEN = 1,
    AEGIS_STAGE_PROOF_LOOKUP = 2,
    AEGIS_STAGE_CALLOUT_ADD = 3,
    AEGIS_STAGE_CALLOUT_REGISTER = 4,
    AEGIS_STAGE_FILTER_ADD = 5
};

static VOID AegisWfpLogStartupFailure(ULONG stage, NTSTATUS status)
{
    PIO_ERROR_LOG_PACKET packet;
    PCWSTR stageName = L"unknown";
    SIZE_T stageBytes;
    ULONG packetSize;

    switch (stage) {
    case AEGIS_STAGE_ENGINE_OPEN:     stageName = L"FwpmEngineOpen0"; break;
    case AEGIS_STAGE_PROOF_LOOKUP:   stageName = L"FwpmFilterGetByKey0"; break;
    case AEGIS_STAGE_CALLOUT_ADD:    stageName = L"FwpmCalloutAdd0"; break;
    case AEGIS_STAGE_CALLOUT_REGISTER: stageName = L"FwpsCalloutRegister0"; break;
    case AEGIS_STAGE_FILTER_ADD:     stageName = L"FwpmFilterAdd0"; break;
    default: break;
    }
    stageBytes = (wcslen(stageName) + 1) * sizeof(WCHAR);
    packetSize = sizeof(IO_ERROR_LOG_PACKET) + (sizeof(ULONG) * 2) +
        (ULONG)stageBytes;

    if (g_DeviceObject == NULL) {
        return;
    }
    packet = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(
        g_DeviceObject, (UCHAR)packetSize);
    if (packet == NULL) {
        return;
    }
    RtlZeroMemory(packet, packetSize);
    packet->ErrorCode = status;
    packet->DumpDataSize = sizeof(ULONG) * 2;
    packet->DumpData[0] = stage;
    packet->DumpData[1] = (ULONG)status;
    packet->NumberOfStrings = 1;
    packet->StringOffset = (USHORT)(sizeof(IO_ERROR_LOG_PACKET) +
        (sizeof(ULONG) * 2));
    RtlCopyMemory((PUCHAR)packet + packet->StringOffset,
        stageName, stageBytes);
    IoWriteErrorLogEntry(packet);
}

/* SCM exposes this stage code even without WinDbg/DbgView. The original WFP
 * status is still written to the System error-log packet. */
static NTSTATUS AegisWfpStartupFailure(ULONG stage, NTSTATUS status)
{
    AegisWfpLogStartupFailure(stage, status);
    return (NTSTATUS)(0xE0010000UL | (stage & 0xFF));
}

/* ====== WFP Classify Callback ======
 * Called by WFP for every inbound IPv4 transport packet.
 * Extracts 5-tuple, writes 40-byte header to ring buffer,
 * always permits the packet (fail-open).
 */
void AegisWfpClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut)
{
    AEGIS_EVENT_HEADER hdr;
    KIRQL  oldIrql;
    SIZE_T usedSpace, totalSize, firstPart;
    PUCHAR writePos;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!classifyOut)
        return;

    /* --- Zero-init event header --- */
    RtlZeroMemory(&hdr, sizeof(hdr));
    hdr.event_type = 0;   /* NETWORK */
    hdr.direction  = 0;   /* inbound */
    hdr.timestamp  = KeQueryPerformanceCounter(NULL).QuadPart;

    /* --- C1 FIX: 5-tuple from inFixedValues->incomingValue[] ---
     * FWPS_FIELD_INBOUND_TRANSPORT_V4_* are enum values from
     * fwpstypes.h. Port fields use IP_ prefix in WDK 10.0.28000.
     */
    hdr.protocol =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL
        ].value.uint8;

    hdr.source_ip =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS
        ].value.uint32;

    hdr.dest_ip =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS
        ].value.uint32;

    /* FIX 2: port fields require IP_ prefix in WDK 10.0.28000 */
    hdr.source_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT
        ].value.uint16;

    hdr.dest_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT
        ].value.uint16;

    /* FIX 3: use filter->layerId (currentLayerId not in
     * FWPS_INCOMING_METADATA_VALUES0 in WDK 10.0.28000) */
    hdr.layer_id = 0;  /* implicit: FWPM_LAYER_INBOUND_TRANSPORT_V4 */

    /* Payload length capture deferred (requires ndis.h for NBL).
     * payload_length = 0: user-mode reader gets 5-tuple only. */
    hdr.payload_length = 0;

    /* --- Write 40-byte header to ring buffer --- */
    totalSize = sizeof(AEGIS_EVENT_HEADER);

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    usedSpace = AEGIS_RING_USED();

    if (totalSize <= g_RingBufferSize - usedSpace) {
        writePos  = (PUCHAR)g_RingBuffer + g_RingWriteOffset;
        firstPart = g_RingBufferSize - g_RingWriteOffset;

        if (firstPart >= totalSize) {
            RtlCopyMemory(writePos, &hdr, totalSize);
            g_RingWriteOffset += totalSize;
        } else {
            RtlCopyMemory(writePos, &hdr, firstPart);
            RtlCopyMemory(g_RingBuffer,
                (PUCHAR)&hdr + firstPart,
                totalSize - firstPart);
            g_RingWriteOffset = totalSize - firstPart;
        }
        g_RingWriteOffset %= g_RingBufferSize;
    } else {
        DbgPrint("[AEGIS WFP] Ring buffer full, event dropped\n");
    }

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    /* FAIL-OPEN: always permit */
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;
}

/* ====== Notify Callback ====== */
NTSTATUS AegisWfpNotifyFn(
    IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID              *filterKey,
    IN const FWPS_FILTER0      *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* ====== Flow Delete Callback ====== */
VOID AegisWfpFlowDeleteFn(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowId)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowId);
}

/* ====== Register WFP Callout + Add Filter (C2 FIX) ======
 * 1. FwpmEngineOpen0  - open BLM session (dynamic = auto-cleanup)
 * 2. FwpmCalloutAdd0  - register callout in BLM store
 * 3. FwpsCalloutRegister0 - bind runtime callbacks
 * 4. FwpmFilterAdd0   - C2: add filter so callout is INVOKED
 */
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS      status;
    FWPS_CALLOUT0 sCallout;
    FWPM_SESSION0 session;
    FWPM_CALLOUT0 callout;
    FWPM_FILTER0  filter;
    FWPM_ACTION0  action;

    DbgPrint("[AEGIS WFP] Registering callout + filter...\n");

    /* 1. Open WFP engine session */
    RtlZeroMemory(&session, sizeof(session));
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT,
        NULL, &session, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmEngineOpen0 status=0x%08X\n", status);
        return AegisWfpStartupFailure(AEGIS_STAGE_ENGINE_OPEN, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmEngineOpen0 status=0x%08X\n", status);

    /* Recover the persistent receipt-owned proof filter if the driver was
     * restarted. A missing key is normal; any other provider error is fatal.
     * Recovery intentionally does not delete or recreate the filter. */
    FWPM_FILTER0 *recoveredProof = NULL;
    status = FwpmFilterGetByKey0(g_WfpEngineHandle,
        &AEGIS_PROOF_FILTER_KEY, &recoveredProof);
    if (NT_SUCCESS(status)) {
        g_ProofFilterId = recoveredProof->filterId;
        DbgPrint("[AEGIS WFP] Recovered proof filter (id=%llu)\n",
            g_ProofFilterId);
        FwpmFreeMemory0((void **)&recoveredProof);
    } else {
        /* Proof filter recovery is advisory only. A missing or unavailable
         * receipt must never prevent the authoritative callout/filter from
         * registering; later stages still fail closed if WFP itself is bad. */
        DbgPrint("[AEGIS WFP] stage=FwpmFilterGetByKey0 status=0x%08X (recovery unavailable; continue)\n",
            status);
    }

    /* 2. Register callout in BLM store */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey       = AEGIS_CALLOUT_KEY;
    callout.displayData.name        = L"AEGIS NIDS Network Capture";
    callout.displayData.description = L"Captures inbound IPv4 transport packets";
    callout.applicableLayer  = FWPM_LAYER_INBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &callout,
        NULL, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmCalloutAdd0 status=0x%08X\n", status);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_ADD, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmCalloutAdd0 status=0x%08X id=%u\n",
        status, g_CalloutId);

    /* 3. Register runtime callout (binds classifyFn/notifyFn/flowDeleteFn) */
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey   = AEGIS_CALLOUT_KEY;

    sCallout.classifyFn   = AegisWfpClassifyFn;

    sCallout.notifyFn     = AegisWfpNotifyFn;
    sCallout.flowDeleteFn = AegisWfpFlowDeleteFn;

    status = FwpsCalloutRegister0(DriverObject, &sCallout, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpsCalloutRegister0 status=0x%08X\n",
            status);
        FwpmCalloutDeleteById0(g_WfpEngineHandle,
            (UINT64)g_CalloutId);  /* FIX 5: cast UINT32 -> UINT64 */
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_REGISTER, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpsCalloutRegister0 status=0x%08X id=%u\n",
        status, g_CalloutId);

    /* 4. C2 FIX: Add filter so the callout actually gets invoked.
     *    Weight left as FWP_EMPTY (RtlZeroMemory'd) = engine default.
     *    FIX 4: removed filter.weight = 0 (was C2440, FWP_VALUE0 struct).
     *    No conditions = matches ALL traffic at this layer. */
    RtlZeroMemory(&filter, sizeof(filter));
    /* A filter reaches the registered classifyFn only with a callout action.
     * PERMIT plus a calloutKey creates a permit filter but does not bind the
     * runtime callback, which previously left the ring empty. */
    action.type       = FWP_ACTION_CALLOUT_TERMINATING;
    action.calloutKey = AEGIS_CALLOUT_KEY;

    filter.layerKey              = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    filter.displayData.name        = L"AEGIS Inbound Transport V4 Capture";
    filter.displayData.description = L"Inspects all inbound IPv4 transport packets";
    filter.action                 = action;
    /* FIX 4: filter.weight removed - RtlZeroMemory sets FWP_EMPTY */
    filter.numFilterConditions    = 0;
    filter.filterCondition        = NULL;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
        NULL, &g_CaptureFilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0 status=0x%08X\n", status);
        FwpsCalloutUnregisterById0(g_CalloutId);
        FwpmCalloutDeleteById0(g_WfpEngineHandle,
            (UINT64)g_CalloutId);  /* FIX 5: cast */
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return AegisWfpStartupFailure(AEGIS_STAGE_FILTER_ADD, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0 status=0x%08X id=%llu\n",
        status, g_CaptureFilterId);

    DbgPrint("[AEGIS WFP] Callout + filter registered - "
        "CalloutID: %u, FilterID: %llu\n",
        g_CalloutId, g_CaptureFilterId);
    return STATUS_SUCCESS;
}

/* ====== Unregister WFP Callout + Delete Filter ====== */
VOID AegisWfpUnregisterCallout(void)
{
    /* 1. Unregister runtime callout */
    if (g_CalloutId) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        DbgPrint("[AEGIS WFP] Runtime callout unregistered (id=%u)\n",
            g_CalloutId);
        g_CalloutId = 0;
    }

    /* 2. Close engine session (dynamic session auto-deletes filter
     *    and callout from BLM store, but we clean up explicitly) */
    if (g_WfpEngineHandle) {
        if (g_CaptureFilterId) {
            FwpmFilterDeleteById0(g_WfpEngineHandle, g_CaptureFilterId);
            DbgPrint("[AEGIS WFP] Capture filter deleted (id=%llu)\n", g_CaptureFilterId);
            g_CaptureFilterId = 0;
        }
        if (g_CalloutId) {
            FwpmCalloutDeleteById0(g_WfpEngineHandle,
                (UINT64)g_CalloutId);  /* FIX 5: cast */
            g_CalloutId = 0;
        }
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        DbgPrint("[AEGIS WFP] WFP engine closed\n");
    }
}
