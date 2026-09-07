/* II05 - WFP Block Action (User-mode Callout Driver Helper)
 * AEGIS NIDS v5.0+
 *
 * Adds/removes WFP filters at the FWPM_LAYER_ALE_AUTH_CONNECT_V4 layer.
 * For kernel-mode callout (aegis_wfp.sys), see kernel/wfp_callout/.
 *
 * NOTE: This file is compiled by CMakeLists.txt as aegis_wfp_user.dll.
 */

#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

#define AEGIS_WFP_SUBLAYER_NAME L"AEGIS-NIDS-Sublayer"
#define AEGIS_WFP_PROVIDER_NAME L"AEGIS-NIDS-Provider"

// {D1E5A2B0-1234-5678-9ABC-DEF012345678}
static const GUID AEGIS_WFP_PROVIDER_KEY =
    { 0xd1e5a2b0, 0x1234, 0x5678, { 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78 } };
static const GUID AEGIS_WFP_SUBLAYER_KEY =
    { 0xe2f6b3c1, 0x2345, 0x6789, { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 } };
static const GUID AEGIS_WFP_FILTER_KEY_BASE =
    { 0xf3a7c4d2, 0x3456, 0x789a, { 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a } };

static HANDLE g_engine_handle = NULL;
static UINT64 g_next_filter_id = 1;

int aegis_wfp_open(void) {
    if (g_engine_handle) return 0;
    DWORD rc = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_engine_handle);
    if (rc != ERROR_SUCCESS) return (int)rc;

    // Register provider
    FWPM_PROVIDER0 provider = {0};
    provider.providerKey = AEGIS_WFP_PROVIDER_KEY;
    provider.displayData.name = AEGIS_WFP_PROVIDER_NAME;
    provider.displayData.description = L"AEGIS NIDS WFP Provider";
    FwpmProviderAdd0(g_engine_handle, &provider, NULL);

    // Add sublayer
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = AEGIS_WFP_SUBLAYER_KEY;
    sublayer.displayData.name = AEGIS_WFP_SUBLAYER_NAME;
    sublayer.providerKey = (GUID*)&AEGIS_WFP_PROVIDER_KEY;
    sublayer.weight = 0xEE;
    FwpmSubLayerAdd0(g_engine_handle, &sublayer, NULL);
    return 0;
}

int aegis_wfp_close(void) {
    if (!g_engine_handle) return 0;
    FwpmEngineClose0(g_engine_handle);
    g_engine_handle = NULL;
    return 0;
}

/* Add a block filter on a 5-tuple. Returns positive filter_id on success. */
int64_t aegis_wfp_add_block(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint8_t protocol, uint8_t weight) {
    if (!g_engine_handle) {
        if (aegis_wfp_open() != 0) return -1;
    }

    FWPM_FILTER0 filter = {0};
    filter.filterKey = AEGIS_WFP_FILTER_KEY_BASE;
    // Make unique by combining with a counter
    filter.filterKey.Data1 ^= (ULONG)g_next_filter_id;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = AEGIS_WFP_SUBLAYER_KEY;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.action.type = FWP_ACTION_BLOCK;
    wchar_t desc[128];
    swprintf_s(desc, 128, L"AEGIS NIDS block filter #%llu", (unsigned long long)g_next_filter_id);
    filter.displayData.name = desc;
    filter.displayData.description = desc;

    // Build filter conditions: src_ip, dst_ip, src_port, dst_port, protocol
    FWPM_FILTER_CONDITION0 conds[5];
    int n = 0;

    if (src_ip != 0) {
        conds[n].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
        conds[n].matchType = FWP_MATCH_EQUAL;
        conds[n].conditionValue.type = FWP_UINT32;
        conds[n].conditionValue.uint32 = src_ip;
        n++;
    }
    if (dst_ip != 0) {
        conds[n].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        conds[n].matchType = FWP_MATCH_EQUAL;
        conds[n].conditionValue.type = FWP_UINT32;
        conds[n].conditionValue.uint32 = dst_ip;
        n++;
    }
    if (src_port != 0) {
        conds[n].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
        conds[n].matchType = FWP_MATCH_EQUAL;
        conds[n].conditionValue.type = FWP_UINT16;
        conds[n].conditionValue.uint16 = src_port;
        n++;
    }
    if (dst_port != 0) {
        conds[n].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[n].matchType = FWP_MATCH_EQUAL;
        conds[n].conditionValue.type = FWP_UINT16;
        conds[n].conditionValue.uint16 = dst_port;
        n++;
    }
    if (protocol != 0) {
        conds[n].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        conds[n].matchType = FWP_MATCH_EQUAL;
        conds[n].conditionValue.type = FWP_UINT8;
        conds[n].conditionValue.uint8 = protocol;
        n++;
    }
    filter.filterCondition = conds;
    filter.numFilterConditions = n;

    UINT64 filter_id = 0;
    DWORD rc = FwpmFilterAdd0(g_engine_handle, &filter, NULL, &filter_id);
    if (rc != ERROR_SUCCESS) {
        return -(int)rc;
    }
    g_next_filter_id++;
    return (int64_t)filter_id;
}

int aegis_wfp_remove_filter(uint64_t filter_id) {
    if (!g_engine_handle) return -1;
    // We need the filterKey to remove; for simplicity, we enumerate and remove.
    // (In production, you'd keep a map of filter_id â†’ filterKey.)
    HANDLE enum_handle = NULL;
    DWORD rc = FwpmFilterCreateEnumHandle0(g_engine_handle, NULL, &enum_handle);
    if (rc != ERROR_SUCCESS) return (int)rc;

    FWPM_FILTER0** filters = NULL;
    UINT32 count = 0;
    rc = FwpmFilterEnum0(g_engine_handle, enum_handle, 256, &filters, &count);
    if (rc == ERROR_SUCCESS) {
        for (UINT32 i = 0; i < count; i++) {
            if (filters[i]->filterId == filter_id) {
                FwpmFilterDeleteById0(g_engine_handle, filter_id);
                break;
            }
        }
        FwpmFreeMemory0((void**)&filters);
    }
    FwpmFilterDestroyEnumHandle0(g_engine_handle, enum_handle);
    return 0;
}

/* FFI surface exposed to Zig (aegis_wfp_user.dll) */
int aegis_wfp_install(void) {
    return aegis_wfp_open();
}

int aegis_wfp_uninstall(void) {
    return aegis_wfp_close();
}
