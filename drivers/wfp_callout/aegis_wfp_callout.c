// =====================================================================
// aegis_wfp_callout.c — WFP callout registration + classify function
// ---------------------------------------------------------------------
//   1. AegisRegisterCallout: open WFP engine, register callout,
//      add filters at inbound/outbound transport V4 layers
//   2. AegisClassifyFn: ดึง 5-tuple + payload จาก NBL, สร้าง
//      AEGIS_EVENT_HEADER, เขียนลง ring buffer, return FWP_ACTION_PERMIT
// =====================================================================

#include "aegis_wfp.h"

#define AEGIS_CALLOUT_LAYER_COUNT 2

static const GUID* g_layer_guids[AEGIS_CALLOUT_LAYER_COUNT] = {
    &FWPM_LAYER_INBOUND_TRANSPORT_V4,
    &FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
};

// =====================================================================
// REGISTER CALLOUT
// =====================================================================
NTSTATUS AegisRegisterCallout(PDEVICE_OBJECT deviceObj)
{
    NTSTATUS status;
    FWPM_SESSION0 session = {0};
    FWPS_CALLOUT0 callout = {0};
    FWPM_CALLOUT0 fwpm_callout = {0};
    UINT32 i;

    // 1. Open WFP engine
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_engine_handle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] FwpmEngineOpen0 failed: 0x%08X\n", status);
        return status;
    }

    // 2. Register callout with filter engine (FWPS)
    callout.calloutKey = AEGIS_CALLOUT_KEY; // define in header if needed
    callout.classifyFn = AegisClassifyFn;
    callout.notifyFn   = NULL;

    status = FwpsCalloutRegister0(deviceObj, &callout, &g_callout_id);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] FwpsCalloutRegister0 failed: 0x%08X\n", status);
        FwpmEngineClose0(g_engine_handle);
        g_engine_handle = NULL;
        return status;
    }

    // 3. Add callout to FWPM (so it can be referenced by filters)
    fwpm_callout.calloutKey = AEGIS_CALLOUT_KEY;
    fwpm_callout.displayData.name = L"Aegis NIDS WFP Callout";
    fwpm_callout.displayData.description = L"Intercepts packets for inspection by AEGIS NIDS user-mode";
    fwpm_callout.applicableLayer = *g_layer_guids[0]; // inbound V4
    fwpm_callout.flags = 0;

    status = FwpmCalloutAdd0(g_engine_handle, NULL, 0, &fwpm_callout, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] FwpmCalloutAdd0 failed: 0x%08X\n", status);
        FwpsCalloutUnregisterById0(g_callout_id);
        FwpmEngineClose0(g_engine_handle);
        return status;
    }

    // 4. Add filters at each layer (inbound + outbound V4)
    for (i = 0; i < AEGIS_CALLOUT_LAYER_COUNT; i++) {
        FWPM_FILTER0 filter = {0};
        FWPM_FILTER_CONDITION0 cond = {0}; // empty condition = match all

        filter.layerKey = *g_layer_guids[i];
        filter.displayData.name = L"Aegis NIDS Filter";
        filter.displayData.description = L"Filter that pends all packets to AEGIS callout";
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey = AEGIS_CALLOUT_KEY;
        filter.filterCondition = &cond;
        filter.numFilterConditions = 0;
        filter.weight.type = FWP_EMPTY; // auto weight

        status = FwpmFilterAdd0(g_engine_handle, &filter, NULL, 0,
            (i == 0) ? &g_filter_id_inbound : &g_filter_id_outbound);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[AEGIS-WFP] FwpmFilterAdd0 [%d] failed: 0x%08X\n", i, status);
            // Continue unregistering
            AegisUnregisterCallout();
            return status;
        }
    }

    DbgPrint("[AEGIS-WFP] Callout registered. Filters inbound=%I64x outbound=%I64x\n",
        g_filter_id_inbound, g_filter_id_outbound);
    return STATUS_SUCCESS;
}

// =====================================================================
// UNREGISTER CALLOUT
// =====================================================================
void AegisUnregisterCallout(void)
{
    if (g_engine_handle) {
        if (g_filter_id_inbound) {
            FwpmFilterDeleteById0(g_engine_handle, g_filter_id_inbound);
            g_filter_id_inbound = 0;
        }
        if (g_filter_id_outbound) {
            FwpmFilterDeleteById0(g_engine_handle, g_filter_id_outbound);
            g_filter_id_outbound = 0;
        }
        if (g_callout_id) {
            FwpsCalloutUnregisterById0(g_callout_id);
            g_callout_id = 0;
        }
        FwpmEngineClose0(g_engine_handle);
        g_engine_handle = NULL;
    }
}

// =====================================================================
// CLASSIFY FUNCTION — เรียกโดย WFP engine ทุกครั้งที่มี packet ผ่าน layer
// =====================================================================
void NTAPI AegisClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // 1. Determine direction (inbound vs outbound) from layer
    BOOLEAN is_inbound = (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4);

    // 2. Extract 5-tuple from inFixedValues
    //    Indices depend on layer — see fwpsk.h FWPS_FIELD_TRANSPORT_V4_*
    UINT32 src_ip = 0, dst_ip = 0;
    UINT16 src_port = 0, dst_port = 0;
    UINT8  protocol = 0;

    // FWPS_FIELD_TRANSPORT_V4_IP_LOCAL_ADDRESS  = 0
    // FWPS_FIELD_TRANSPORT_V4_IP_REMOTE_ADDRESS = 1
    // FWPS_FIELD_TRANSPORT_V4_IP_LOCAL_PORT     = 2
    // FWPS_FIELD_TRANSPORT_V4_IP_REMOTE_PORT    = 3
    // FWPS_FIELD_TRANSPORT_V4_IP_PROTOCOL       = 4
    if (inFixedValues->incomingValue[0].value.uint32 != 0) {
        src_ip = inFixedValues->incomingValue[0].value.uint32;
    }
    if (inFixedValues->incomingValue[1].value.uint32 != 0) {
        dst_ip = inFixedValues->incomingValue[1].value.uint32;
    }
    src_port = inFixedValues->incomingValue[2].value.uint16;
    dst_port = inFixedValues->incomingValue[3].value.uint16;
    protocol = inFixedValues->incomingValue[4].value.uint8;

    // 3. Extract payload from NBL (NET_BUFFER_LIST)
    UCHAR payload_buf[16384] = {0};
    ULONG payload_len = 0;
    if (layerData) {
        PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        if (nb) {
            ULONG available = min(nb->DataLength, sizeof(payload_buf));
            PVOID p = NdisGetDataBuffer(nb, available, payload_buf, 1, 0);
            if (p && p != payload_buf) {
                RtlCopyMemory(payload_buf, p, available);
            }
            payload_len = available;
        }
    }

    // 4. Build AEGIS_EVENT_HEADER + payload
    AEGIS_EVENT_HEADER header = {0};
    header.event_type = AEGIS_EVENT_WFP_PACKET;
    header.event_size = sizeof(AEGIS_EVENT_HEADER) + payload_len;
    header.timestamp = KeQueryInterruptTime() * 100; // approximate ns since epoch
    header.process_id = (inMetaValues && inMetaValues->processId)
        ? (UINT32)(ULONG_PTR)inMetaValues->processId : 0;
    header.src_ip = src_ip;
    header.dst_ip = dst_ip;
    header.src_port = src_port;
    header.dst_port = dst_port;
    header.protocol = protocol;
    header.direction = is_inbound ? 0 : 1;
    header.payload_length = (UINT16)payload_len;

    // 5. Write to ring buffer (header + payload)
    KIRQL old_irql;
    KeAcquireSpinLock(&g_ring_lock, &old_irql);
    AegisRingWrite(&header, sizeof(header));
    if (payload_len > 0) {
        AegisRingWrite(payload_buf, payload_len);
    }
    g_event_count++;
    KeReleaseSpinLock(&g_ring_lock, old_irql);

    // 6. Default action: PERMIT (IDS mode — let user-mode decide whether to block)
    //    For IPS mode: ตรวจ block table แล้ว return FWP_ACTION_BLOCK ถ้า flow_id อยู่ใน table
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags = 0;
}
