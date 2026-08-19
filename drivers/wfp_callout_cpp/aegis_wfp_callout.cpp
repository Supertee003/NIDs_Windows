/**
 * aegis_wfp_callout.cpp — AEGIS NIDS WFP Callout Classify Function (C++ Edition)
 *
 * Implements the WFP callout classify function using Aegis::WFP namespace
 * and RAII patterns. Captures inbound transport packets, extracts 5-tuple,
 * and stores events in RingBuffer<EventHeader>.
 *
 * C++ enhancements:
 *   - SpinLockGuard for ring buffer writes (no manual KeReleaseSpinLock)
 *   - PoolAllocator<void> for temporary payload buffer (auto-free)
 *   - EventHeader struct (C++ struct instead of C typedef)
 *   - Scoped resource management — no leak paths
 *
 * Architecture: Kernel-mode C++ (NETWORK layer of 3-Layer Architecture)
 */

#include "aegis_wfp.hpp"
#include <ntddk.h>
#include <wfp.h>
#include <ip2string.h>

// ====== extern "C" callbacks (Windows kernel requires C linkage) ======
extern "C" {

// ====== WFP Classify Callback ======
// Invoked by WFP engine for every inbound packet at the transport layer.
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

    using namespace Aegis::WFP;

    FWPS_CLASSIFY_OUT0* classifyOut = classifyEntry->classifyOut;
    if (!classifyOut || classifyOut->actionType != FWP_ACTION_PERMIT) {
        return;
    }

    // ====== Build EventHeader (C++ struct — cleaner initialization) ======
    EventHeader eventHeader = {};  // Zero-initialize (C++ style)
    eventHeader.event_type = 0;    // NETWORK layer event
    eventHeader.direction   = 0;    // inbound
    eventHeader.layer_id    = static_cast<UINT8>(layerId & 0xFF);
    eventHeader.timestamp   = KeQueryPerformanceCounter(NULL).QuadPart;

    // Extract 5-tuple from WFP metadata
    if (classifyEntry->layerData) {
        eventHeader.source_ip    = classifyEntry->layerData->sourceIp;
        eventHeader.dest_ip      = classifyEntry->layerData->destIp;
        eventHeader.source_port  = classifyEntry->layerData->sourcePort;
        eventHeader.dest_port    = classifyEntry->layerData->destPort;
        eventHeader.protocol     = classifyEntry->layerData->protocol;
    }

    // ====== Extract payload from NBL (using RAII PoolAllocator) ======
    eventHeader.payload_length = 0;
    if (classifyEntry->netBufferList) {
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(classifyEntry->netBufferList);
        if (nb) {
            ULONG payloadLen = NET_BUFFER_DATA_LENGTH(nb);
            if (payloadLen > 0 && payloadLen <= kMaxPayloadSize) {
                eventHeader.payload_length = payloadLen;
            }
        }
    }

    // ====== Write to RingBuffer (using template Write method) ======
    // RingBuffer::Write handles spinlock internally via SpinLockGuard RAII
    SIZE_T headerSize = sizeof(EventHeader);

    // Write header
    NTSTATUS writeStatus = g_ringBuffer.Write(&eventHeader, headerSize);
    if (!NT_SUCCESS(writeStatus)) {
        // Buffer overflow — event dropped, but classify still permits packet
        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        return;
    }

    // Write payload (if available, using RAII PoolAllocator for temp buffer)
    if (eventHeader.payload_length > 0 && classifyEntry->netBufferList) {
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(classifyEntry->netBufferList);

        // RAII PoolAllocator — auto-frees on scope exit, no manual ExFreePool
        PoolAllocator<void> payloadBuf(POOL_FLAG_NON_PAGED,
            eventHeader.payload_length, 'PLD');

        if (payloadBuf.IsValid()) {
            ULONG bytesCopied = 0;
            NdisCopyFromNetBufferToBuffer(nb, 0, eventHeader.payload_length,
                payloadBuf.Get(), &bytesCopied);

            if (bytesCopied > 0) {
                g_ringBuffer.Write(payloadBuf.Get(), bytesCopied);
            }
            // payloadBuf auto-frees via RAII destructor — no ExFreePool needed!
        }
    }

    // Permit the packet (we capture, not block at kernel level)
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

// ====== WFP Notify Callback ======
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

// ====== WFP Flow Delete Callback ======
VOID NTAPI AegisWfpFlowDelete(UINT16 layerId, UINT32 calloutId, UINT64 flowId)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowId);
}

} // extern "C"

// ====== Register WFP Callout (C++ namespace) ======
namespace Aegis {
namespace WFP {

NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("[AEGIS WFP] Registering callout (C++)...\n");

    // ====== Step 1: Open WFP engine session (RAII WfpEngineGuard) ======
    NTSTATUS status = g_wfpEngine.Open();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] WfpEngineGuard::Open failed: 0x%08X\n", status);
        return status;
    }

    // ====== Step 2: Register callout with filter engine ======
    FWPM_CALLOUT0 callout = {};
    callout.calloutKey = AEGIS_CALLOUT_KEY;
    callout.displayData.name = L"AEGIS NIDS Network Capture (C++)";
    callout.displayData.description = L"Captures inbound transport packets for NIDS analysis";
    callout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(g_wfpEngine.Get(), &callout, NULL, &g_calloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpmCalloutAdd0 failed: 0x%08X\n", status);
        g_wfpEngine.Close();  // RAII auto-closes, but call explicitly for error path
        return status;
    }

    // ====== Step 3: Register runtime callout (classify/notify/flowDelete) ======
    FWPS_CALLOUT0 sCallout = {};
    sCallout.calloutKey    = AEGIS_CALLOUT_KEY;
    sCallout.classifyFn    = AegisWfpClassify;
    sCallout.notifyFn      = AegisWfpNotify;
    sCallout.flowDeleteFn  = AegisWfpFlowDelete;

    status = FwpsCalloutRegister0(&sCallout, &g_calloutId);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] FwpsCalloutRegister0 failed: 0x%08X\n", status);
        FwpmCalloutDeleteById0(g_wfpEngine.Get(), g_calloutId);
        g_wfpEngine.Close();
        return status;
    }

    DbgPrint("[AEGIS WFP] Callout registered (C++) — ID: %d\n", g_calloutId);
    return STATUS_SUCCESS;
}

VOID AegisWfpUnregisterCallout()
{
    if (g_calloutId) {
        FwpsCalloutUnregisterById0(g_calloutId);
        DbgPrint("[AEGIS WFP] Runtime callout unregistered\n");
    }

    if (g_wfpEngine.IsActive()) {
        if (g_filterId) {
            FwpmFilterDeleteById0(g_wfpEngine.Get(), g_filterId);
        }
        if (g_calloutId) {
            FwpmCalloutDeleteById0(g_wfpEngine.Get(), g_calloutId);
        }
        g_wfpEngine.Close();  // RAII auto-closes
    }
}

} // namespace WFP
} // namespace Aegis
