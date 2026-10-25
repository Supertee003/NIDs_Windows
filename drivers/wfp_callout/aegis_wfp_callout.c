/**
 * aegis_wfp_callout.c - WFP Callout Classify + Registration
 *
 * C1 FIX: Extracts 5-tuple from inFixedValues->incomingValue[]
 *         indexed by FWPS_FIELD_INBOUND_TRANSPORT_V4_* constants.
 * C2 FIX: Calls FwpmFilterAdd0 so callout is actually invoked.
 * EVT-231: classify copies a bounded raw payload (<= AEGIS_MAX_PAYLOAD_SIZE
 *         bytes as delivered at the transport layer) into the ring after
 *         the 48-byte header.
 *
 * FAIL-OPEN design: classify never blocks packets.
 */

#include "aegis_wfp.h"

/* WinDbg/DbgView are not required for startup diagnosis. Persist the failing
 * registration stage and status in the System event log. DumpData[0] is the
 * stage ID; DumpData[1] is the raw NTSTATUS/WFP status. */
static VOID AegisWfpLogStartupFailure(ULONG stage, NTSTATUS status)
{
    PIO_ERROR_LOG_PACKET packet;
    PCWSTR stageName = L"unknown";
    SIZE_T stageBytes;
    ULONG packetSize;

    switch (stage) {
    case AEGIS_STAGE_ENGINE_OPEN:     stageName = L"FwpmEngineOpen0"; break;
    case AEGIS_STAGE_CALLOUT_ADD:    stageName = L"FwpmCalloutAdd0"; break;
    case AEGIS_STAGE_CALLOUT_REGISTER: stageName = L"FwpsCalloutRegister0"; break;
    case AEGIS_STAGE_FILTER_ADD:     stageName = L"FwpmFilterAdd0"; break;
    case AEGIS_STAGE_PROOF_PROVIDER: stageName = L"AegisWfpPrepareProofProvider"; break;
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
NTSTATUS AegisWfpStartupFailure(ULONG stage, NTSTATUS status)
{
    AegisWfpLogStartupFailure(stage, status);
    return (NTSTATUS)(0xE0010000UL | (stage & 0xFF));
}

/* ====== Ring write helper (EVT-231) ======
 * Copies bytes into the event ring, wrapping at the end of the buffer.
 * Call under g_RingLock; the caller has already checked the bytes fit. */
static VOID AegisWfpRingWrite(const VOID *source, SIZE_T length)
{
    PUCHAR writePos  = (PUCHAR)g_RingBuffer + g_RingWriteOffset;
    SIZE_T firstPart = g_RingBufferSize - g_RingWriteOffset;

    if (firstPart >= length) {
        RtlCopyMemory(writePos, source, length);
        g_RingWriteOffset += length;
    } else {
        RtlCopyMemory(writePos, source, firstPart);
        RtlCopyMemory(g_RingBuffer, (PUCHAR)source + firstPart,
            length - firstPart);
        g_RingWriteOffset = length - firstPart;
    }
    g_RingWriteOffset %= g_RingBufferSize;
}

/* ====== WFP Classify Callback ======
 * Called by WFP for every inbound IPv4 transport packet. Extracts the
 * 5-tuple, copies a bounded raw payload (EVT-231), and writes one
 * variable-length record (48-byte header + payload) to the ring buffer.
 * Always permits the packet (fail-open).
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
    SIZE_T usedSpace, totalSize;
    PNET_BUFFER_LIST nbl;
    PNET_BUFFER nb = NULL;
    ULONG  availableBytes = 0;
    ULONG  copyLen = 0;
    PVOID  payload = NULL;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!classifyOut)
        return;

    /* Unload owns a rundown gate: while it waits, no classify may touch the
     * ring or engine. A callout that arrives after the gate closes must still
     * return a fail-open action. */
    if (!ExAcquireRundownProtection(&g_CalloutRundown)) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

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

    /* --- EVT-231: bounded kernel payload copy ---
     * layerData is the WFP NET_BUFFER_LIST for the inbound transport
     * layer. Copy at most AEGIS_MAX_PAYLOAD_SIZE raw bytes exactly as
     * delivered at the layer: no L7 parse, no stream reassembly, and no
     * assumption about which header the bytes start with. Verified on the
     * loopback test path (EVT-231 probe dump): the delivered data begins
     * at the transport payload -- a 180-byte UDP payload was copied
     * byte-exact with no UDP header. Fail-open: when the bytes cannot be
     * gathered the record degrades to the 48-byte header
     * (payload_length = 0) and the packet is still permitted. */
    nbl = (PNET_BUFFER_LIST)layerData;
    if (nbl != NULL) {
        nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    }
    if (nb != NULL) {
        availableBytes = NET_BUFFER_DATA_LENGTH(nb);
        copyLen = (availableBytes > AEGIS_MAX_PAYLOAD_SIZE)
            ? AEGIS_MAX_PAYLOAD_SIZE : availableBytes;
    }
    hdr.payload_length = copyLen;

    totalSize = sizeof(AEGIS_EVENT_HEADER) + (SIZE_T)copyLen;

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    /* Gather the payload under the ring lock: NdisGetDataBuffer returns a
     * pointer into the packet when the data is contiguous, else copies
     * into the pre-allocated non-paged scratch buffer (never the kernel
     * stack). */
    if (copyLen > 0) {
        payload = NdisGetDataBuffer(nb, copyLen, g_PayloadScratch, 1, 0);
        if (payload == NULL) {
            copyLen = 0;
            hdr.payload_length = 0;
            totalSize = sizeof(AEGIS_EVENT_HEADER);
        }
    }

    usedSpace = AEGIS_RING_USED();

    /* Strict less-than keeps empty/full unambiguous: AEGIS_RING_USED
     * reads used == size as empty, so a write must never fill the ring
     * exactly. Honest accounting: drops are counted, not just logged. */
    if (totalSize < g_RingBufferSize - usedSpace) {
        AegisWfpRingWrite(&hdr, sizeof(AEGIS_EVENT_HEADER));
        if (copyLen > 0) {
            AegisWfpRingWrite(payload, copyLen);
        }
        g_WfpTotalEventsWritten++;
        g_WfpTotalBytesWritten += (ULONG)totalSize;
    } else {
        g_WfpTotalDrops++;
        DbgPrint("[AEGIS WFP] Ring buffer full, event dropped (drops=%lu)\n",
            g_WfpTotalDrops);
    }

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    /* FAIL-OPEN: always permit */
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;

    ExReleaseRundownProtection(&g_CalloutRundown);
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
 * 1. FwpmEngineOpen0  - open a non-dynamic BLM session
 * 2. FwpmCalloutAdd0  - register callout in BLM store
 * 3. FwpsCalloutRegister0 - bind runtime callbacks
 * 4. FwpmFilterAdd0   - C2: add filter so callout is INVOKED
 *
 * The session must stay non-dynamic: the proof provider and its filters are
 * persistent objects, and WFP rejects persistent objects added through a
 * dynamic session. The capture callout/filter are explicitly removed during
 * unload; closing the static session is the final backstop.
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

    /* 1. Open WFP engine session. Keep this static (flags = 0): the proof
     * provider and proof filters are FWPM_*_FLAG_PERSISTENT and WFP does not
     * permit persistent objects in a dynamic session. This is also the single
     * engine handle used by the callout registration and proof lifecycle. */
    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = L"AEGIS NIDS WFP Session";
    session.flags = 0;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT,
        NULL, &session, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmEngineOpen0 status=0x%08X\n", status);
        return AegisWfpStartupFailure(AEGIS_STAGE_ENGINE_OPEN, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmEngineOpen0 status=0x%08X\n", status);

    /* 2. Register callout in BLM store. The proof provider is established by
     * AegisWfpPrepareProofProvider() after this registration succeeds; the
     * retired fixed-key recovery path must not run here. */
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
        /* g_CalloutId is the BLM id here; delete by the stable callout key
         * rather than relying on the id that the runtime registration would
         * have replaced. */
        FwpmCalloutDeleteByKey0(g_WfpEngineHandle, &AEGIS_CALLOUT_KEY);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        g_CalloutId = 0;
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
    /* Fail-open teardown: if this callout is unregistered while the filter is
     * still present (or deletion fails), WFP must permit the traffic rather
     * than treat the terminating callout action as BLOCK. */
    filter.flags                  = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    /* FIX 4: filter.weight removed - RtlZeroMemory sets FWP_EMPTY */
    filter.numFilterConditions    = 0;
    filter.filterCondition        = NULL;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
        NULL, &g_CaptureFilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0 status=0x%08X\n", status);
        FwpsCalloutUnregisterById0(g_CalloutId);
        FwpmCalloutDeleteByKey0(g_WfpEngineHandle, &AEGIS_CALLOUT_KEY);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        g_CalloutId = 0;
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
    /* 0. Drain classify calls first. New classify calls fail open at the
     * rundown gate; this wait returns only after every in-flight callout has
     * released the ring. The filter is still present during the wait, but the
     * callout action remains fail-open. */
    ExWaitForRundownProtectionRelease(&g_CalloutRundown);

    /* 1. Remove the terminating capture filter before unregistering the
     * runtime callout. Unregistering first would make WFP treat that filter's
     * callout action as BLOCK until the filter is deleted. The filter also
     * carries PERMIT_IF_CALLOUT_UNREGISTERED as a second fail-open guard in
     * case this delete fails. */
    if (g_WfpEngineHandle && g_CaptureFilterId) {
        NTSTATUS status = FwpmFilterDeleteById0(g_WfpEngineHandle,
                                                g_CaptureFilterId);
        if (!NT_SUCCESS(status) &&
            status != FWP_E_FILTER_NOT_FOUND &&
            status != STATUS_NOT_FOUND) {
            DbgPrint("[AEGIS WFP] Capture filter delete failed (id=%llu): 0x%08X\n",
                g_CaptureFilterId, status);
            /* Keep the id: a later engine-close backstop still owns the
             * nonpersistent object, and the permit-if-unregistered flag keeps
             * traffic fail-open if the callout is torn down first. */
        } else {
            DbgPrint("[AEGIS WFP] Capture filter deleted (id=%llu)\n",
                g_CaptureFilterId);
            g_CaptureFilterId = 0;
        }
    }

    /* 2. Unregister runtime callout. The unload contract requires success
     * before returning; a callout whose code is still registered must never
     * outlive this driver image. Flow contexts are not used, so the only
     * expected transient failure is a concurrent in-flight classify, which
     * the rundown wait above has already drained. Retry rather than returning
     * an unloaded callback pointer. */
    if (g_CalloutId) {
        LARGE_INTEGER delay;
        delay.QuadPart = -100000; /* 10 ms, relative */
        for (;;) {
            NTSTATUS status = FwpsCalloutUnregisterById0(g_CalloutId);
            if (NT_SUCCESS(status) ||
                status == FWP_E_CALLOUT_NOT_FOUND ||
                status == STATUS_NOT_FOUND) {
                DbgPrint("[AEGIS WFP] Runtime callout unregistered (id=%u)\n",
                    g_CalloutId);
                g_CalloutId = 0;
                break;
            }
            DbgPrint("[AEGIS WFP] Runtime callout unregister pending (id=%u): 0x%08X; retrying\n",
                g_CalloutId, status);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    /* 3. Remove the BLM callout and close the static engine session. The
     * session is static because the proof provider is persistent; closing it
     * is the final backstop, not the only cleanup. */
    if (g_WfpEngineHandle) {
        NTSTATUS status = FwpmCalloutDeleteByKey0(g_WfpEngineHandle,
                                                  &AEGIS_CALLOUT_KEY);
        if (!NT_SUCCESS(status) &&
            status != FWP_E_CALLOUT_NOT_FOUND &&
            status != STATUS_NOT_FOUND) {
            DbgPrint("[AEGIS WFP] BLM callout delete failed: 0x%08X\n",
                status);
        }
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        DbgPrint("[AEGIS WFP] WFP engine closed\n");
    }
}
