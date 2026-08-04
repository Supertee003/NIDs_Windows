@@ -0,0 +1,207 @@
/**
 * aegis_wfp_callout.c — AEGIS NIDS WFP Callout Classify Function
 *
 * This file implements the WFP callout classify function that captures
 * network packets at the inbound transport layer (FWPM_LAYER_INBOUND_TRANSPORT_V4).
 * Extracts 5-tuple (src/dst IP, src/dst port, protocol) and optional payload
 * from NBL (Network Buffer List), then stores the event in the ring buffer.
 *
 * Architecture: Kernel-mode C++ (NETWORK layer of 3-Layer Architecture)
 */

#include "aegis_wfp.h"
#include <ntddk.h>
#include <wfp.h>
#include <ip2string.h>

// ====== WFP Classify Callback ======
// This is invoked by the WFP engine for every inbound packet at the transport layer.
VOID NTAPI AegisWfpClassify(
    IN const FWPS_CLASSIFY_ENTRY0* classifyEntry,
    IN const FWPS_FILTER3* filter,
    IN UINT64 layerId,
    IN PVOID classifyContext,
    IN const FWPS_CLASSIFY_RESULT0* classifyResult)
{
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(classifyResult);
    UNREFERENCED_PARAMETER(layerId);

    FWPS_CLASSIFY_OUT0* classifyOut = classifyEntry->classifyOut;
    if (!classifyOut || classifyOut->actionType != FWP_ACTION_PERMIT) {
        return;
    }

    // Extract 5-tuple from the classify entry metadata
    AEGIS_EVENT_HEADER eventHeader = {0};
    eventHeader.event_type = 0;  // NETWORK layer event
    eventHeader.direction = 0;   // inbound
    eventHeader.layer_id = (UINT8)(layerId & 0xFF);
    eventHeader.timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

    // Get IP addresses from WFP metadata
    if (classifyEntry->layerData) {
        // Extract source/dest IP and ports from incoming packet metadata
        // FWPS_INBOUND_TRANSPORT_LAYER0 contains the 5-tuple
        eventHeader.source_ip = classifyEntry->layerData->sourceIp;
        eventHeader.dest_ip = classifyEntry->layerData->destIp;
        eventHeader.source_port = classifyEntry->layerData->sourcePort;
        eventHeader.dest_port = classifyEntry->layerData->destPort;
        eventHeader.protocol = classifyEntry->layerData->protocol;
    }

    // Try to extract payload from NBL (Network Buffer List)
    // This is for deep packet inspection — the payload is copied to ring buffer
    // after the event header
    eventHeader.payload_length = 0;
    if (classifyEntry->netBufferList) {
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(classifyEntry->netBufferList);
        if (nb) {
            ULONG payloadLen = NET_BUFFER_DATA_LENGTH(nb);
            if (payloadLen > 0 && payloadLen <= AEGIS_MAX_PAYLOAD_SIZE) {
                eventHeader.payload_length = payloadLen;
            }
        }
    }

    // Write event header + payload to ring buffer
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    SIZE_T totalSize = sizeof(AEGIS_EVENT_HEADER) + eventHeader.payload_length;
    if (totalSize <= g_RingBufferSize - ((g_RingWriteOffset - g_RingReadOffset) % g_RingBufferSize)) {
        // Write header
        PUCHAR writePos = (PUCHAR)g_RingBuffer + g_RingWriteOffset;
        SIZE_T firstPart = g_RingBufferSize - g_RingWriteOffset;

        if (firstPart >= sizeof(AEGIS_EVENT_HEADER)) {
            RtlCopyMemory(writePos, &eventHeader, sizeof(AEGIS_EVENT_HEADER));
            g_RingWriteOffset += sizeof(AEGIS_EVENT_HEADER);
        } else {
            RtlCopyMemory(writePos, &eventHeader, firstPart);
            RtlCopyMemory(g_RingBuffer, (PUCHAR)&eventHeader + firstPart,
                sizeof(AEGIS_EVENT_HEADER) - firstPart);
            g_RingWriteOffset = sizeof(AEGIS_EVENT_HEADER) - firstPart;
        }

        // Write payload (if available and small enough)
        if (eventHeader.payload_length > 0 && classifyEntry->netBufferList) {
            PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(classifyEntry->netBufferList);
            PVOID payloadBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, eventHeader.payload_length, 'PLD');
            if (payloadBuffer) {
                ULONG bytesCopied = 0;
                NdisCopyFromNetBufferToBuffer(nb, 0, eventHeader.payload_length,
                    payloadBuffer, &bytesCopied);
                if (bytesCopied > 0) {
                    writePos = (PUCHAR)g_RingBuffer + g_RingWriteOffset;
                    if (g_RingWriteOffset + bytesCopied <= g_RingBufferSize) {
                        RtlCopyMemory(writePos, payloadBuffer, bytesCopied);
                        g_RingWriteOffset += bytesCopied;
                    } else {
                        firstPart = g_RingBufferSize - g_RingWriteOffset;
                        RtlCopyMemory(writePos, payloadBuffer, firstPart);
                        RtlCopyMemory(g_RingBuffer, (PUCHAR)payloadBuffer + firstPart,
                            bytesCopied - firstPart);
                        g_RingWriteOffset = bytesCopied - firstPart;
                    }
                }
                ExFreePool(payloadBuffer);
            }
        }

        g_RingWriteOffset %= g_RingBufferSize;
    }

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    // Permit the packet to continue (we only capture, not block at kernel level)
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

// ====== WFP Callout Notify Callback ======
NTSTATUS NTAPI AegisWfpNotify(
    IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID* filterKey,
    IN const FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// ====== WFP Callout Flow Delete Callback ======
VOID NTAPI AegisWfpFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowId)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowId);
}

// ====== Register WFP Callout ======
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    FWPM_CALLOUT0 callout = {0};
    FWPS_CALLOUT0 sCallout = {0};

    DbgPrint("[AEGIS WFP] Registering callout...\n");

    // 1. Open WFP engine session
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // Auto-cleanup on unload
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpmEngineOpen0 failed: 0x%08X\n", status);
        return status;
    }

    // 2. Register callout with filter engine
    callout.calloutKey = AEGIS_CALLOUT_KEY;
    callout.displayData.name = L"AEGIS NIDS Network Capture";
    callout.displayData.description = L"Captures inbound transport packets for NIDS analysis";
    callout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    status = FwpmCalloutAdd0(g_WfpEngineHandle, &callout, NULL, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpmCalloutAdd0 failed: 0x%08X\n", status);
        FwpmEngineClose0(g_WfpEngineHandle);
        return status;
    }

    // 3. Register callout with filtering engine (runtime)
    sCallout.calloutKey = AEGIS_CALLOUT_KEY;
    sCallout.classifyFn = AegisWfpClassify;
    sCallout.notifyFn = AegisWfpNotify;
    sCallout.flowDeleteFn = AegisWfpFlowDelete;
    status = FwpsCalloutRegister0(&sCallout, &g_CalloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpsCalloutRegister0 failed: 0x%08X\n", status);
        FwpmCalloutDeleteById0(g_WfpEngineHandle, g_CalloutId);
        FwpmEngineClose0(g_WfpEngineHandle);
        return status;
    }

    DbgPrint("[AEGIS WFP] Callout registered — ID: %d\n", g_CalloutId);
    return STATUS_SUCCESS;
}

// ====== Unregister WFP Callout ======
VOID AegisWfpUnregisterCallout()
{
    if (g_CalloutId) {
        FwpsCalloutUnregisterById0(g_CalloutId);
        DbgPrint("[AEGIS WFP] Runtime callout unregistered\n");
    }
    if (g_WfpEngineHandle) {
        if (g_FilterId) {
            FwpmFilterDeleteById0(g_WfpEngineHandle, g_FilterId);
        }
        if (g_CalloutId) {
            FwpmCalloutDeleteById0(g_WfpEngineHandle, g_CalloutId);
        }
        FwpmEngineClose0(g_WfpEngineHandle);
        DbgPrint("[AEGIS WFP] WFP engine session closed\n");
    }
}
