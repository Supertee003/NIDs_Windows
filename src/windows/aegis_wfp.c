/* II05 - WFP lifecycle helper (mutation quarantined)
 * AEGIS NIDS v5.0+
 *
 * Opens/closes the WFP engine only; filter mutation is quarantined.
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

/*
 * Direct filter mutation was intentionally removed from this helper.
 *
 * The production authority must own authorization, provider identity,
 * filter ownership, cleanup, and a validated EnforcementReceipt. An
 * exported add/remove Boolean surface cannot satisfy that contract and
 * would create a second WFP authority. Keep this DLL lifecycle-only until
 * the receipt-producing Rust PEP adapter is wired to the selected provider.
 */

/* FFI surface exposed to Zig (aegis_wfp_user.dll) */
int aegis_wfp_install(void) {
    return aegis_wfp_open();
}

int aegis_wfp_uninstall(void) {
    return aegis_wfp_close();
}
