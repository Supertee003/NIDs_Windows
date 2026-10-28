/**
 * aegis_wfp_callout.c - WFP Callout Classify + Registration
 *
 * C1 FIX: Extracts 5-tuple from inFixedValues->incomingValue[]
 *         indexed by FWPS_FIELD_INBOUND_TRANSPORT_V4_* constants.
 * C2 FIX: Calls FwpmFilterAdd0 so callout is actually invoked.
 * EVT-231 / O2: classify copies a bounded L4 payload (<= AEGIS_MAX_PAYLOAD_SIZE)
 *         into the ring after the 48-byte header. Outbound callbacks strip
 *         the TCP/UDP header required by the WFP layer's data offset.
 * O1 (plan §26 ทาง A): IPv6 transport pairs emit a 32-byte identity sidecar
 *         (src16 ++ dst16) behind header flags bit0, leading the payload;
 *         the body budget shrinks so payload_length stays within contract.
 *
 * FAIL-OPEN design: classify never blocks packets.
 */

#include "aegis_wfp.h"
#include "aegis_wfp_payload.h"

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

/* ====== Shared ring record emit (EVT-231 / O2 / O1) ======
 * Called with the rundown gate held and a fully populated 48-byte header.
 * Copies a bounded raw payload and writes one variable-length record
 * (header [+ v6 sidecar] + payload) under the ring lock. Fail-open: a
 * gather failure degrades the record to the header plus any captured v6
 * identity sidecar (payload_length = sidecar only).
 *
 * O1 (plan §26 ทาง A): when src6/dst6 are both non-NULL the record is
 * IPv6 — a 32-byte identity sidecar (src16 ++ dst16, raw network order)
 * leads the payload behind AEGIS_EVENT_FLAG_V6_SIDECAR, and the L7 body
 * budget shrinks to AEGIS_MAX_PAYLOAD_SIZE - 32 so payload_length never
 * exceeds the reader's write contract. NULL/NULL is the v4 path: no flag,
 * no sidecar, unchanged record shape. The flag is only ever set alongside
 * a written sidecar, so the consumer's fail-closed guard
 * (payload_length >= 32 when bit0 set) can never trip on our records. */
static VOID AegisWfpEmitRecord(AEGIS_EVENT_HEADER *hdr, void *layerData,
                               const UINT8 *src6, const UINT8 *dst6)
{
    KIRQL  oldIrql;
    SIZE_T usedSpace, totalSize;
    SIZE_T payloadOffset = 0;
    SIZE_T availablePayload = 0;
    SIZE_T readLength = 0;
    PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
    PNET_BUFFER nb = NULL;
    ULONG  availableBytes = 0;
    ULONG  copyLen = 0;
    PVOID  payload = NULL;
    PVOID  layerHeader = NULL;
    ULONG  headerBytes = 0;
    BOOLEAN payloadRangeValid = FALSE;
    UINT8  sidecarBuf[AEGIS_V6_SIDECAR_SIZE];
    SIZE_T sidecarLen = 0;

    /* Snapshot the identity before the ring lock: the fixed-value pointers
     * stay valid for the whole classify call, but a single contiguous
     * sidecar write keeps the record one atomic tail under the lock. */
    if (src6 != NULL && dst6 != NULL) {
        RtlCopyMemory(sidecarBuf, src6, 16);
        RtlCopyMemory(sidecarBuf + 16, dst6, 16);
        sidecarLen = AEGIS_V6_SIDECAR_SIZE;
        hdr->flags |= AEGIS_EVENT_FLAG_V6_SIDECAR;
    }

    if (nbl != NULL) {
        nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    }
    if (nb != NULL) {
        availableBytes = NET_BUFFER_DATA_LENGTH(nb);
    }
    /* The sidecar is part of the record tail even when no packet payload
     * can be gathered: a flagged record always carries its 32 bytes. */
    hdr->payload_length = 0;
    totalSize = sizeof(AEGIS_EVENT_HEADER);
    if (sidecarLen > 0) {
        hdr->payload_length = (UINT32)sidecarLen;
        totalSize += sidecarLen;
    }

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    if (nb != NULL) {
        if (hdr->direction == 1) {
            if (hdr->protocol == 6) {
                headerBytes = 20; /* Minimum TCP header; data offset gives full size. */
            } else if (hdr->protocol == 17) {
                headerBytes = 8; /* UDP header. */
            }
            if (headerBytes > 0 && availableBytes >= headerBytes) {
                layerHeader = NdisGetDataBuffer(nb, headerBytes,
                    g_PayloadScratch, 1, 0);
            }
        }
        payloadRangeValid = (BOOLEAN)(aegis_wfp_get_payload_slice(
            (const unsigned char *)layerHeader,
            availableBytes,
            (unsigned char)hdr->protocol,
            (unsigned char)hdr->direction,
            &payloadOffset,
            &availablePayload) != 0);
        if (payloadRangeValid) {
            /* O1: the sidecar shares the payload budget, so a v6 record's
             * body can never push payload_length past AEGIS_MAX_PAYLOAD_SIZE
             * (the reader resets the ring on any larger claim). */
            copyLen = (availablePayload > AEGIS_MAX_PAYLOAD_SIZE - sidecarLen)
                ? (ULONG)(AEGIS_MAX_PAYLOAD_SIZE - sidecarLen)
                : (ULONG)availablePayload;
        }
        hdr->payload_length = (UINT32)(sidecarLen + copyLen);
        totalSize = sizeof(AEGIS_EVENT_HEADER) + sidecarLen + (SIZE_T)copyLen;
    }

    /* Gather the payload under the ring lock: NdisGetDataBuffer returns a
     * pointer into the packet when the data is contiguous, else copies
     * into the pre-allocated non-paged scratch buffer (never the kernel
     * stack). Outbound transport buffers begin with TCP/UDP headers, so read
     * through the validated header offset before writing only payload bytes. */
    if (copyLen > 0) {
        readLength = payloadOffset + (SIZE_T)copyLen;
        if (readLength > AEGIS_MAX_CAPTURE_WINDOW) {
            payload = NULL;
        } else {
            payload = NdisGetDataBuffer(nb, (ULONG)readLength,
                g_PayloadScratch, 1, 0);
        }
        if (payload == NULL) {
            /* Degrade to header + sidecar: the v6 identity stays valid and
             * the flagged record keeps carrying its 32 bytes. */
            copyLen = 0;
            hdr->payload_length = (UINT32)sidecarLen;
            totalSize = sizeof(AEGIS_EVENT_HEADER) + sidecarLen;
        } else {
            payload = (PUCHAR)payload + payloadOffset;
        }
    }
    usedSpace = AEGIS_RING_USED();

    /* Strict less-than keeps empty/full unambiguous: AEGIS_RING_USED
     * reads used == size as empty, so a write must never fill the ring
     * exactly. Honest accounting: drops are counted, not just logged. */
    if (totalSize < g_RingBufferSize - usedSpace) {
        AegisWfpRingWrite(hdr, sizeof(AEGIS_EVENT_HEADER));
        if (sidecarLen > 0) {
            AegisWfpRingWrite(sidecarBuf, sidecarLen);
        }
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
}

/* ====== WFP Inbound Classify Callback ======
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

    /* EVT-231: bounded kernel payload copy. Verified on the loopback test
     * path: the delivered data begins at the transport payload -- a
     * 180-byte UDP payload was copied byte-exact with no UDP header.
     * Fail-open: a gather failure degrades the record to the header. */
    AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);

    /* FAIL-OPEN: always permit */
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;

    ExReleaseRundownProtection(&g_CalloutRundown);
}

/* ====== WFP Outbound Classify Callback (O2) ======
 * Mirrors the inbound path at FWPM_LAYER_OUTBOUND_TRANSPORT_V4. The only
 * record discriminator is the header direction byte (1=outbound); the
 * 48-byte header and ring contract are unchanged. Always permits. */
void AegisWfpOutboundClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut)
{
    AEGIS_EVENT_HEADER hdr;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!classifyOut)
        return;

    if (!ExAcquireRundownProtection(&g_CalloutRundown)) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    RtlZeroMemory(&hdr, sizeof(hdr));
    hdr.event_type = 0;   /* NETWORK */
    hdr.direction  = 1;   /* outbound */
    hdr.timestamp  = KeQueryPerformanceCounter(NULL).QuadPart;

    hdr.protocol =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL
        ].value.uint8;

    hdr.source_ip =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS
        ].value.uint32;

    hdr.dest_ip =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS
        ].value.uint32;

    hdr.source_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT
        ].value.uint16;

    hdr.dest_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT
        ].value.uint16;

    /* Distinguish the layer for diagnostics. Consumers key on direction;
     * the record layout and ring contract are unchanged. */
    hdr.layer_id = 1;  /* FWPM_LAYER_OUTBOUND_TRANSPORT_V4 */

    AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);

    /* FAIL-OPEN: always permit */
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;

    ExReleaseRundownProtection(&g_CalloutRundown);
}

/* ====== O1 (plan §26 ทาง A): IPv6 transport capture pair ======
 * Mirrors the v4 pair at the IPv6 transport layers. Same 48-byte header,
 * same ring contract, plus a 32-byte identity sidecar (src16 ++ dst16)
 * that leads the payload behind AEGIS_EVENT_FLAG_V6_SIDECAR. The u32
 * identity fields keep the BE-canonical convention: the first four
 * address bytes composed as a big-endian integer value — the same
 * derivation the Go nose path uses (BE.Uint32(addr[:4])). WFP hands v6
 * addresses in network order, so the composition is a plain byte shift.
 * Always permits (fail-open); capture only, never enforcement. */

/* First four address bytes as the BE integer value the consumer expects. */
static UINT32 AegisWfpV6Prefix32(const UINT8 addr[16])
{
    return ((UINT32)addr[0] << 24) | ((UINT32)addr[1] << 16) |
           ((UINT32)addr[2] << 8)  |  (UINT32)addr[3];
}

/* ====== WFP Inbound V6 Classify Callback (O1) ====== */
void AegisWfpInboundV6ClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut)
{
    AEGIS_EVENT_HEADER hdr;
    const FWP_BYTE_ARRAY16 *remote6 = NULL;
    const FWP_BYTE_ARRAY16 *local6 = NULL;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!classifyOut)
        return;

    if (!ExAcquireRundownProtection(&g_CalloutRundown)) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    RtlZeroMemory(&hdr, sizeof(hdr));
    hdr.event_type = 0;   /* NETWORK */
    hdr.direction  = 0;   /* inbound */
    hdr.timestamp  = KeQueryPerformanceCounter(NULL).QuadPart;

    hdr.protocol =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL
        ].value.uint8;

    /* Remote = sender (source), local = receiver (destination). */
    remote6 = inFixedValues->incomingValue[
        FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
    local6 = inFixedValues->incomingValue[
        FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16;

    hdr.source_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT
        ].value.uint16;

    hdr.dest_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT
        ].value.uint16;

    hdr.layer_id = 2;  /* FWPM_LAYER_INBOUND_TRANSPORT_V6 (diagnostic) */

    if (remote6 != NULL && local6 != NULL) {
        /* O1: u32 identity = first 4 sidecar bytes as a BE integer value
         * (Go convention); the full 16-byte addresses ride the sidecar. */
        hdr.source_ip = AegisWfpV6Prefix32(remote6->byteArray16);
        hdr.dest_ip   = AegisWfpV6Prefix32(local6->byteArray16);
        AegisWfpEmitRecord(&hdr, layerData,
                           remote6->byteArray16, local6->byteArray16);
    } else {
        /* Unreachable for WFP-populated v6 transport fixed values; degrade
         * to a v4-shaped header-only record (no flag, no sidecar) rather
         * than emit a flagged tail the decoder would fail-closed on. */
        AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);
    }

    /* FAIL-OPEN: always permit */
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;

    ExReleaseRundownProtection(&g_CalloutRundown);
}

/* ====== WFP Outbound V6 Classify Callback (O1) ====== */
void AegisWfpOutboundV6ClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut)
{
    AEGIS_EVENT_HEADER hdr;
    const FWP_BYTE_ARRAY16 *local6 = NULL;
    const FWP_BYTE_ARRAY16 *remote6 = NULL;

    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!classifyOut)
        return;

    if (!ExAcquireRundownProtection(&g_CalloutRundown)) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights    &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    RtlZeroMemory(&hdr, sizeof(hdr));
    hdr.event_type = 0;   /* NETWORK */
    hdr.direction  = 1;   /* outbound */
    hdr.timestamp  = KeQueryPerformanceCounter(NULL).QuadPart;

    hdr.protocol =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL
        ].value.uint8;

    /* Local = sender (source), remote = receiver (destination). */
    local6 = inFixedValues->incomingValue[
        FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
    remote6 = inFixedValues->incomingValue[
        FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16;

    hdr.source_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT
        ].value.uint16;

    hdr.dest_port =
        inFixedValues->incomingValue[
            FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT
        ].value.uint16;

    hdr.layer_id = 3;  /* FWPM_LAYER_OUTBOUND_TRANSPORT_V6 (diagnostic) */

    if (local6 != NULL && remote6 != NULL) {
        hdr.source_ip = AegisWfpV6Prefix32(local6->byteArray16);
        hdr.dest_ip   = AegisWfpV6Prefix32(remote6->byteArray16);
        AegisWfpEmitRecord(&hdr, layerData,
                           local6->byteArray16, remote6->byteArray16);
    } else {
        AegisWfpEmitRecord(&hdr, layerData, NULL, NULL);
    }

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

    /* 5. O2: outbound IPv4 transport capture. Same 48-byte record and ring
     * contract; header.direction=1 marks the origin. Any failure here tears
     * the whole pair down via AegisWfpUnregisterCallout, so a half-registered
     * capture can never survive. */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey       = AEGIS_OUTBOUND_CALLOUT_KEY;
    callout.displayData.name        = L"AEGIS NIDS Outbound Capture";
    callout.displayData.description = L"Captures outbound IPv4 transport packets";
    callout.applicableLayer  = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &callout,
        NULL, &g_OutboundCalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmCalloutAdd0(outbound) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_ADD, status);
    }

    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey   = AEGIS_OUTBOUND_CALLOUT_KEY;
    sCallout.classifyFn   = AegisWfpOutboundClassifyFn;
    sCallout.notifyFn     = AegisWfpNotifyFn;
    sCallout.flowDeleteFn = AegisWfpFlowDeleteFn;

    status = FwpsCalloutRegister0(DriverObject, &sCallout,
        &g_OutboundCalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpsCalloutRegister0(outbound) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_REGISTER, status);
    }

    RtlZeroMemory(&filter, sizeof(filter));
    action.type       = FWP_ACTION_CALLOUT_TERMINATING;
    action.calloutKey = AEGIS_OUTBOUND_CALLOUT_KEY;

    filter.layerKey              = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.displayData.name        = L"AEGIS Outbound Transport V4 Capture";
    filter.displayData.description = L"Inspects all outbound IPv4 transport packets";
    filter.action                 = action;
    filter.flags                  = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    filter.numFilterConditions    = 0;
    filter.filterCondition        = NULL;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
        NULL, &g_OutboundCaptureFilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0(outbound) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_FILTER_ADD, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0(outbound) status=0x%08X id=%llu\n",
        status, g_OutboundCaptureFilterId);

    /* 6. O1 (plan §26 ทาง A): inbound IPv6 transport capture pair. Same
     * 48-byte record and ring contract; header flags bit0 marks the 32-byte
     * identity sidecar leading the payload, direction=0 / layer_id=2 mark
     * the origin. Any failure tears the whole registration down via
     * AegisWfpUnregisterCallout — never a half pair. */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey       = AEGIS_INBOUND_V6_CALLOUT_KEY;
    callout.displayData.name        = L"AEGIS NIDS Inbound V6 Capture";
    callout.displayData.description = L"Captures inbound IPv6 transport packets";
    callout.applicableLayer  = FWPM_LAYER_INBOUND_TRANSPORT_V6;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &callout,
        NULL, &g_InboundV6CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmCalloutAdd0(inbound-v6) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_ADD, status);
    }

    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey   = AEGIS_INBOUND_V6_CALLOUT_KEY;
    sCallout.classifyFn   = AegisWfpInboundV6ClassifyFn;
    sCallout.notifyFn     = AegisWfpNotifyFn;
    sCallout.flowDeleteFn = AegisWfpFlowDeleteFn;

    status = FwpsCalloutRegister0(DriverObject, &sCallout,
        &g_InboundV6CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpsCalloutRegister0(inbound-v6) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_REGISTER, status);
    }

    RtlZeroMemory(&filter, sizeof(filter));
    action.type       = FWP_ACTION_CALLOUT_TERMINATING;
    action.calloutKey = AEGIS_INBOUND_V6_CALLOUT_KEY;

    filter.layerKey              = FWPM_LAYER_INBOUND_TRANSPORT_V6;
    filter.displayData.name        = L"AEGIS Inbound Transport V6 Capture";
    filter.displayData.description = L"Inspects all inbound IPv6 transport packets";
    filter.action                 = action;
    filter.flags                  = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    filter.numFilterConditions    = 0;
    filter.filterCondition        = NULL;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
        NULL, &g_InboundV6FilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0(inbound-v6) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_FILTER_ADD, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0(inbound-v6) status=0x%08X id=%llu\n",
        status, g_InboundV6FilterId);

    /* 7. O1: outbound IPv6 transport capture pair. Same contract as step 6
     * with direction=1 and layer_id=3. */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey       = AEGIS_OUTBOUND_V6_CALLOUT_KEY;
    callout.displayData.name        = L"AEGIS NIDS Outbound V6 Capture";
    callout.displayData.description = L"Captures outbound IPv6 transport packets";
    callout.applicableLayer  = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;

    status = FwpmCalloutAdd0(g_WfpEngineHandle, &callout,
        NULL, &g_OutboundV6CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmCalloutAdd0(outbound-v6) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_ADD, status);
    }

    RtlZeroMemory(&sCallout, sizeof(sCallout));
    sCallout.calloutKey   = AEGIS_OUTBOUND_V6_CALLOUT_KEY;
    sCallout.classifyFn   = AegisWfpOutboundV6ClassifyFn;
    sCallout.notifyFn     = AegisWfpNotifyFn;
    sCallout.flowDeleteFn = AegisWfpFlowDeleteFn;

    status = FwpsCalloutRegister0(DriverObject, &sCallout,
        &g_OutboundV6CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpsCalloutRegister0(outbound-v6) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_CALLOUT_REGISTER, status);
    }

    RtlZeroMemory(&filter, sizeof(filter));
    action.type       = FWP_ACTION_CALLOUT_TERMINATING;
    action.calloutKey = AEGIS_OUTBOUND_V6_CALLOUT_KEY;

    filter.layerKey              = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
    filter.displayData.name        = L"AEGIS Outbound Transport V6 Capture";
    filter.displayData.description = L"Inspects all outbound IPv6 transport packets";
    filter.action                 = action;
    filter.flags                  = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    filter.numFilterConditions    = 0;
    filter.filterCondition        = NULL;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter,
        NULL, &g_OutboundV6FilterId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0(outbound-v6) status=0x%08X\n",
            status);
        AegisWfpUnregisterCallout();
        return AegisWfpStartupFailure(AEGIS_STAGE_FILTER_ADD, status);
    }
    DbgPrint("[AEGIS WFP] stage=FwpmFilterAdd0(outbound-v6) status=0x%08X id=%llu\n",
        status, g_OutboundV6FilterId);

    DbgPrint("[AEGIS WFP] Callout + filter registered - "
        "CalloutID: %u, FilterID: %llu, OutboundCalloutID: %u, "
        "OutboundFilterID: %llu, InboundV6CalloutID: %u, "
        "InboundV6FilterID: %llu, OutboundV6CalloutID: %u, "
        "OutboundV6FilterID: %llu\n",
        g_CalloutId, g_CaptureFilterId,
        g_OutboundCalloutId, g_OutboundCaptureFilterId,
        g_InboundV6CalloutId, g_InboundV6FilterId,
        g_OutboundV6CalloutId, g_OutboundV6FilterId);
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

    /* 0a. O1 (plan §26 ทาง A): remove the IPv6 capture pairs before the v4
     * pairs. The same filter-before-callout order keeps WFP fail-open if a
     * delete fails; every id guard tolerates a pair that never registered
     * (a step-6/7 failure path lands here with the later pairs still 0). */
    if (g_WfpEngineHandle && g_OutboundV6FilterId) {
        NTSTATUS status = FwpmFilterDeleteById0(g_WfpEngineHandle,
                                                g_OutboundV6FilterId);
        if (!NT_SUCCESS(status) &&
            !AegisWfpFilterNotFound(status)) {
            DbgPrint("[AEGIS WFP] Outbound V6 capture filter delete failed (id=%llu): 0x%08X\n",
                g_OutboundV6FilterId, status);
        } else {
            DbgPrint("[AEGIS WFP] Outbound V6 capture filter deleted (id=%llu)\n",
                g_OutboundV6FilterId);
            g_OutboundV6FilterId = 0;
        }
    }

    if (g_OutboundV6CalloutId) {
        LARGE_INTEGER delay;
        delay.QuadPart = -100000; /* 10 ms, relative */
        for (;;) {
            NTSTATUS status = FwpsCalloutUnregisterById0(g_OutboundV6CalloutId);
            if (NT_SUCCESS(status) ||
                AegisWfpCalloutNotFound(status)) {
                DbgPrint("[AEGIS WFP] Outbound V6 runtime callout unregistered (id=%u)\n",
                    g_OutboundV6CalloutId);
                g_OutboundV6CalloutId = 0;
                break;
            }
            DbgPrint("[AEGIS WFP] Outbound V6 unregister pending (id=%u): 0x%08X; retrying\n",
                g_OutboundV6CalloutId, status);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    if (g_WfpEngineHandle && g_InboundV6FilterId) {
        NTSTATUS status = FwpmFilterDeleteById0(g_WfpEngineHandle,
                                                g_InboundV6FilterId);
        if (!NT_SUCCESS(status) &&
            !AegisWfpFilterNotFound(status)) {
            DbgPrint("[AEGIS WFP] Inbound V6 capture filter delete failed (id=%llu): 0x%08X\n",
                g_InboundV6FilterId, status);
        } else {
            DbgPrint("[AEGIS WFP] Inbound V6 capture filter deleted (id=%llu)\n",
                g_InboundV6FilterId);
            g_InboundV6FilterId = 0;
        }
    }

    if (g_InboundV6CalloutId) {
        LARGE_INTEGER delay;
        delay.QuadPart = -100000; /* 10 ms, relative */
        for (;;) {
            NTSTATUS status = FwpsCalloutUnregisterById0(g_InboundV6CalloutId);
            if (NT_SUCCESS(status) ||
                AegisWfpCalloutNotFound(status)) {
                DbgPrint("[AEGIS WFP] Inbound V6 runtime callout unregistered (id=%u)\n",
                    g_InboundV6CalloutId);
                g_InboundV6CalloutId = 0;
                break;
            }
            DbgPrint("[AEGIS WFP] Inbound V6 unregister pending (id=%u): 0x%08X; retrying\n",
                g_InboundV6CalloutId, status);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    /* 1a. O2: remove the outbound capture pair before the inbound pair. The
     * same filter-before-callout order keeps WFP fail-open if a delete fails. */
    if (g_WfpEngineHandle && g_OutboundCaptureFilterId) {
        NTSTATUS status = FwpmFilterDeleteById0(g_WfpEngineHandle,
                                                g_OutboundCaptureFilterId);
        if (!NT_SUCCESS(status) &&
            !AegisWfpFilterNotFound(status)) {
            DbgPrint("[AEGIS WFP] Outbound capture filter delete failed (id=%llu): 0x%08X\n",
                g_OutboundCaptureFilterId, status);
        } else {
            DbgPrint("[AEGIS WFP] Outbound capture filter deleted (id=%llu)\n",
                g_OutboundCaptureFilterId);
            g_OutboundCaptureFilterId = 0;
        }
    }

    if (g_OutboundCalloutId) {
        LARGE_INTEGER delay;
        delay.QuadPart = -100000; /* 10 ms, relative */
        for (;;) {
            NTSTATUS status = FwpsCalloutUnregisterById0(g_OutboundCalloutId);
            if (NT_SUCCESS(status) ||
                AegisWfpCalloutNotFound(status)) {
                DbgPrint("[AEGIS WFP] Outbound runtime callout unregistered (id=%u)\n",
                    g_OutboundCalloutId);
                g_OutboundCalloutId = 0;
                break;
            }
            DbgPrint("[AEGIS WFP] Outbound unregister pending (id=%u): 0x%08X; retrying\n",
                g_OutboundCalloutId, status);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    /* 1. Remove the terminating capture filter before unregistering the
     * runtime callout. Unregistering first would make WFP treat that filter's
     * callout action as BLOCK until the filter is deleted. The filter also
     * carries PERMIT_IF_CALLOUT_UNREGISTERED as a second fail-open guard in
     * case this delete fails. */
    if (g_WfpEngineHandle && g_CaptureFilterId) {
        NTSTATUS status = FwpmFilterDeleteById0(g_WfpEngineHandle,
                                                g_CaptureFilterId);
        if (!NT_SUCCESS(status) &&
            !AegisWfpFilterNotFound(status)) {
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
                AegisWfpCalloutNotFound(status)) {
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
                                                  &AEGIS_OUTBOUND_V6_CALLOUT_KEY);
        if (!NT_SUCCESS(status) &&
            !AegisWfpCalloutNotFound(status)) {
            DbgPrint("[AEGIS WFP] Outbound V6 BLM callout delete failed: 0x%08X\n",
                status);
        }
        status = FwpmCalloutDeleteByKey0(g_WfpEngineHandle,
                                         &AEGIS_INBOUND_V6_CALLOUT_KEY);
        if (!NT_SUCCESS(status) &&
            !AegisWfpCalloutNotFound(status)) {
            DbgPrint("[AEGIS WFP] Inbound V6 BLM callout delete failed: 0x%08X\n",
                status);
        }
        status = FwpmCalloutDeleteByKey0(g_WfpEngineHandle,
                                                  &AEGIS_OUTBOUND_CALLOUT_KEY);
        if (!NT_SUCCESS(status) &&
            !AegisWfpCalloutNotFound(status)) {
            DbgPrint("[AEGIS WFP] Outbound BLM callout delete failed: 0x%08X\n",
                status);
        }
        status = FwpmCalloutDeleteByKey0(g_WfpEngineHandle,
                                         &AEGIS_CALLOUT_KEY);
        if (!NT_SUCCESS(status) &&
            !AegisWfpCalloutNotFound(status)) {
            DbgPrint("[AEGIS WFP] BLM callout delete failed: 0x%08X\n",
                status);
        }
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        DbgPrint("[AEGIS WFP] WFP engine closed\n");
    }
}
