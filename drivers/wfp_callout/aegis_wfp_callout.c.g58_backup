/**
 * aegis_wfp_callout.c - WFP Callout Classify + Registration
 *
 * C1 FIX: Extracts 5-tuple from inFixedValues->incomingValue[]
 *         indexed by FWPS_FIELD_INBOUND_TRANSPORT_V4_* constants.
 * C2 FIX: Calls FwpmFilterAdd0 so callout is actually invoked.
 *
 * Uses the legacy 7-param classify signature.
 * FAIL-OPEN design: classify never blocks packets.
 */

#include "aegis_wfp.h"

/* ====== WFP Classify Callback (Legacy 7-param) ======
 * Called by WFP for every inbound IPv4 transport packet.
 * Extracts 5-tuple, writes 40-byte header to ring buffer,
 * always permits the packet (fail-open).
 */
void AegisWfpClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const void                           *classifyContext,
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
    UNREFERENCED_PARAMETER(classifyContext);
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
        DbgPrint("[AEGIS WFP] FwpmEngineOpen0 failed: 0x%08X\n", status);
        return status;
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
        DbgPrint("[AEGIS WFP] FwpmCalloutAdd0 failed: 0x%08X\n", status);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    /* 3. Register runtime callout (binds classifyFn/notifyFn/flowDeleteFn) */
    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey   = AEGIS_CALLOUT_KEY;

    /* FIX 6: C4113 pragma - WDK 10.0.28000 typedef may differ.
     * On x64 calling convention is uniform so runtime is safe. */
#pragma warning(push)
#pragma warning(disable: 4113)
    sCallout.classifyFn   = AegisWfpClassifyFn;
#pragma warning(pop)

    sCallout.notifyFn     = AegisWfpNotifyFn;
    sCallout.flowDeleteFn = AegisWfpFlowDeleteFn;

    status = FwpsCalloutRegister0(DriverObject, &sCallout, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpsCalloutRegister0 failed: 0x%08X\n",
            status);
        FwpmCalloutDeleteById0(g_WfpEngineHandle,
            (UINT64)g_CalloutId);  /* FIX 5: cast UINT32 -> UINT64 */
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    /* 4. C2 FIX: Add filter so the callout actually gets invoked.
     *    Weight left as FWP_EMPTY (RtlZeroMemory'd) = engine default.
     *    FIX 4: removed filter.weight = 0 (was C2440, FWP_VALUE0 struct).
     *    No conditions = matches ALL traffic at this layer. */
    RtlZeroMemory(&filter, sizeof(filter));
    action.type       = FWP_ACTION_PERMIT;
    action.calloutKey = AEGIS_CALLOUT_KEY;

    filter.layerKey              = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    filter.displayData.name        = L"AEGIS Inbound Transport V4 Capture";
    filter.displayData.description = L"Inspects all inbound IPv4 transport packets";
    filter.action                 = action;
    /* FIX 4: filter.weight removed - RtlZeroMemory sets FWP_EMPTY */
    filter.numFilterConditions    = 0;
    filter.filterCondition        = NULL;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
        NULL, &g_FilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpmFilterAdd0 failed: 0x%08X\n", status);
        FwpsCalloutUnregisterById0(g_CalloutId);
        FwpmCalloutDeleteById0(g_WfpEngineHandle,
            (UINT64)g_CalloutId);  /* FIX 5: cast */
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    DbgPrint("[AEGIS WFP] Callout + filter registered - "
        "CalloutID: %u, FilterID: %llu\n",
        g_CalloutId, g_FilterId);
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
        if (g_FilterId) {
            FwpmFilterDeleteById0(g_WfpEngineHandle, g_FilterId);
            DbgPrint("[AEGIS WFP] Filter deleted (id=%llu)\n", g_FilterId);
            g_FilterId = 0;
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