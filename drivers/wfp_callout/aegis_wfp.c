/**
 * aegis_wfp.c — AEGIS NIDS WFP Callout Driver Entry Point
 *
 * This is the main driver file for the AEGIS WFP (Windows Filtering Platform)
 * callout driver. It creates the device object for user-mode communication,
 * registers the WFP callout, and manages the ring buffer for event storage.
 *
 * Architecture: Kernel-mode C++ driver (NETWORK layer of 3-Layer Architecture)
 * Build Requirements: WDK (Windows Driver Kit), Visual Studio 2022
 * Runtime: Requires Test Signing enabled (bcdedit /set testsigning on)
 */

#define INITGUID
#include "aegis_wfp.h"

/* fwpmk.h on some WDK builds omits the user-mode WFP symbolic name even
 * though FwpmFilterGetById0 returns the same documented HRESULT. */
#ifndef FWP_E_FILTER_NOT_FOUND
#define FWP_E_FILTER_NOT_FOUND ((NTSTATUS)0x80320003L)
#endif
#include <ntddk.h>
#include <wdmsec.h>

// ====== GUID Definition ======
// {A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D}
DEFINE_GUID(AEGIS_CALLOUT_KEY,
    0xa1b2c3d4, 0xe5f6, 0x4a7b,
    0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d);

// O2: outbound IPv4 transport capture is a distinct callout identity so the
// two layers can be registered, torn down, and audited independently.
// {E5F60718-293A-4DBF-8C3D-4E5F60718293}
DEFINE_GUID(AEGIS_OUTBOUND_CALLOUT_KEY,
    0xe5f60718, 0x293a, 0x4dbf,
    0x8c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93);

// O1 (plan §26 ทาง A): IPv6 transport capture pairs are distinct callout
// identities so all four layers register, tear down, and audit
// independently. Fresh keys; a v4 identity is never reused.
// {F6A71829-3A4B-4DBF-8C3D-5E6F708192A4}
DEFINE_GUID(AEGIS_INBOUND_V6_CALLOUT_KEY,
    0xf6a71829, 0x3a4b, 0x4dbf,
    0x8c, 0x3d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa4);

// {A7B82930-4B5C-4DAE-9F2B-6F708192B315}
DEFINE_GUID(AEGIS_OUTBOUND_V6_CALLOUT_KEY,
    0xa7b82930, 0x4b5c, 0x4dae,
    0x9f, 0x2b, 0x6f, 0x70, 0x81, 0x92, 0xb3, 0x15);

// Retired single-key identity for the receipt-owned proof filter. It is no
// longer used to create filters; a driver start deletes the stale filter an
// older build left under this key.
DEFINE_GUID(AEGIS_PROOF_FILTER_KEY,
    0xb2c3d4e5, 0xf607, 0x4b8c,
    0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e);

// Ownership marker for every proof filter this driver mints. Filters carry
// this providerKey, so exact-filter attestation never relies on a shared
// filter key and restart/unload can enumerate everything the driver owns.
// {D4E5F607-1829-4DAE-9F2B-3C4D5E6F7081}
DEFINE_GUID(AEGIS_PROOF_PROVIDER_KEY,
    0xd4e5f607, 0x1829, 0x4dae,
    0x9f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81);

// Stable device-class identity used by IoCreateDeviceSecure.
DEFINE_GUID(AEGIS_DEVICE_CLASS_KEY,
    0xc3d4e5f6, 0x0718, 0x4c9d,
    0xae, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f);

// ====== Global State ======
PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING g_DeviceName;
UNICODE_STRING g_SymlinkName;

// Ring buffer for storing captured events
PVOID g_RingBuffer = NULL;
SIZE_T g_RingBufferSize = AEGIS_RING_BUFFER_SIZE;
KSPIN_LOCK g_RingLock;
SIZE_T g_RingWriteOffset = 0;
SIZE_T g_RingReadOffset = 0;

// EVT-231: non-paged scratch for NdisGetDataBuffer storage (payloads that
// span non-contiguous MDLs are copied here; never the kernel stack).
PVOID g_PayloadScratch = NULL;

// EVT-231: honest ring accounting. Every update happens under g_RingLock.
ULONG g_WfpTotalEventsWritten = 0;
ULONG g_WfpTotalDrops = 0;
ULONG g_WfpTotalBytesWritten = 0;
ULONG g_WfpTotalBytesRead = 0;

// WFP engine handle
HANDLE g_WfpEngineHandle = NULL;
UINT32 g_CalloutId = 0;
UINT64 g_CaptureFilterId = 0;
UINT32 g_OutboundCalloutId = 0;
UINT64 g_OutboundCaptureFilterId = 0;
/* O1 (plan §26 ทาง A): IPv6 transport capture pairs. */
UINT32 g_InboundV6CalloutId = 0;
UINT64 g_InboundV6FilterId = 0;
UINT32 g_OutboundV6CalloutId = 0;
UINT64 g_OutboundV6FilterId = 0;
EX_RUNDOWN_REF g_CalloutRundown;
UINT64 g_ProofFilterId = 0;
UINT32 g_BlockedIp = 0;
UINT16 g_BlockedPort = 0;
UINT8 g_BlockedProtocol = 0;

/* Receipt-owned proof filters this driver currently has installed. The key
 * is derived from (direction, tuple), so a repeated block finds its entry
 * without a provider lookup and returns the same filter id. The table is
 * rebuilt from the provider on driver start (persistent filters survive). */
typedef struct _AEGIS_PROOF_ENTRY {
    GUID   key;
    UINT64 filterId;
} AEGIS_PROOF_ENTRY;

static AEGIS_PROOF_ENTRY g_ProofEntries[AEGIS_PROOF_TABLE_CAPACITY];
static ULONG g_ProofEntryCount = 0;
/* WFP management APIs (FwpmFilterAdd0/GetById0/Enum0/DeleteById0) require
 * IRQL <= PASSIVE_LEVEL. A FAST_MUTEX raises IRQL to APC_LEVEL, so it cannot
 * guard those calls. A KMUTEX keeps the proof path at PASSIVE_LEVEL. */
static KMUTEX g_ProofLock;
static BOOLEAN g_ProofLockReady = FALSE;
static BOOLEAN g_ProofProviderReady = FALSE;

/* IRP drain gate. Every create/close/device-control dispatch acquires this
 * lock. Unload calls IoReleaseRemoveLockAndWait() before closing the shared
 * WFP engine handle or freeing the ring, so a block/query IRP can never race
 * teardown. */
static IO_REMOVE_LOCK g_RemoveLock;

// ====== Forward declarations ======
NTSTATUS AegisWfpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS AegisWfpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID     AegisWfpUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS AegisWfpReadEvents(PIRP Irp);
NTSTATUS AegisWfpBlockFlow(PIRP Irp);
NTSTATUS AegisWfpGetStats(PIRP Irp);
NTSTATUS AegisWfpUnblockFlow(PIRP Irp);
NTSTATUS AegisWfpQueryFilter(PIRP Irp);
NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static BOOLEAN AegisWfpFilterMatchesRequest(const FWPM_FILTER0 *filter,
                                            const AEGIS_WFP_FLOW_REQUEST *request,
                                            UINT64 *filterId);

// ====== Proof-filter identity and ownership ======
static UINT64 AegisWfpFnv1a64(const UINT8 *data, SIZE_T length, UINT64 basis)
{
    UINT64 hash = basis;
    SIZE_T i;
    for (i = 0; i < length; ++i) {
        hash ^= (UINT64)data[i];
        hash *= 0x00000100000001B3ULL;
    }
    return hash;
}

/* One stable key per layer direction + exact tuple. A collision would alias
 * two different blocks, so a full 128-bit FNV pair is used rather than a
 * 32-bit id. The key is only an index; the provider GUID is the ownership
 * marker that attestation trusts. */
static GUID AegisWfpProofKey(const AEGIS_WFP_FLOW_REQUEST *request)
{
    UINT8 tuple[8];
    UINT64 low;
    UINT64 high;
    GUID key;

    tuple[0] = request->direction;
    tuple[1] = (UINT8)(request->remote_ipv4 >> 24);
    tuple[2] = (UINT8)(request->remote_ipv4 >> 16);
    tuple[3] = (UINT8)(request->remote_ipv4 >> 8);
    tuple[4] = (UINT8)(request->remote_ipv4);
    tuple[5] = (UINT8)(request->remote_port >> 8);
    tuple[6] = (UINT8)(request->remote_port);
    tuple[7] = request->protocol;

    low = AegisWfpFnv1a64(tuple, sizeof(tuple), 0xCBF29CE484222325ULL);
    high = AegisWfpFnv1a64(tuple, sizeof(tuple), 0x9E3779B97F4A7C15ULL);
    RtlZeroMemory(&key, sizeof(key));
    RtlCopyMemory(&key, &low, sizeof(low));
    RtlCopyMemory((PUCHAR)&key + sizeof(low), &high, sizeof(high));
    if (key.Data1 == 0 && key.Data2 == 0 && key.Data3 == 0 &&
        key.Data4[0] == 0 && key.Data4[1] == 0 && key.Data4[2] == 0 &&
        key.Data4[3] == 0 && key.Data4[4] == 0 && key.Data4[5] == 0 &&
        key.Data4[6] == 0 && key.Data4[7] == 0) {
        key.Data4[7] = 1;
    }
    return key;
}

static BOOLEAN AegisWfpGuidEqual(const GUID *left, const GUID *right)
{
    return RtlCompareMemory(left, right, sizeof(GUID)) == sizeof(GUID);
}

static BOOLEAN AegisWfpFilterOwnedByProvider(const FWPM_FILTER0 *filter)
{
    return filter != NULL && filter->providerKey != NULL &&
        AegisWfpGuidEqual(filter->providerKey, &AEGIS_PROOF_PROVIDER_KEY);
}

static AEGIS_PROOF_ENTRY *AegisWfpFindProofByKey(const GUID *key)
{
    ULONG i;
    for (i = 0; i < g_ProofEntryCount; ++i) {
        if (AegisWfpGuidEqual(&g_ProofEntries[i].key, key)) {
            return &g_ProofEntries[i];
        }
    }
    return NULL;
}

static VOID AegisWfpRemoveProofById(UINT64 filterId)
{
    ULONG i;
    for (i = 0; i < g_ProofEntryCount; ++i) {
        if (g_ProofEntries[i].filterId == filterId) {
            g_ProofEntries[i] = g_ProofEntries[g_ProofEntryCount - 1];
            g_ProofEntryCount--;
            RtlZeroMemory(&g_ProofEntries[g_ProofEntryCount],
                          sizeof(AEGIS_PROOF_ENTRY));
            return;
        }
    }
}

static BOOLEAN AegisWfpRecordProof(const GUID *key, UINT64 filterId)
{
    AEGIS_PROOF_ENTRY *existing = AegisWfpFindProofByKey(key);
    if (existing != NULL) {
        existing->filterId = filterId;
        return TRUE;
    }
    if (g_ProofEntryCount >= AEGIS_PROOF_TABLE_CAPACITY) {
        return FALSE;
    }
    g_ProofEntries[g_ProofEntryCount].key = *key;
    g_ProofEntries[g_ProofEntryCount].filterId = filterId;
    g_ProofEntryCount++;
    return TRUE;
}

static VOID AegisWfpClearProofGlobals(void)
{
    g_ProofFilterId = 0;
    g_BlockedIp = 0;
    g_BlockedPort = 0;
    g_BlockedProtocol = 0;
}

/* Serialize proof-table mutation and WFP management calls. The KMUTEX is
 * initialized before the device is exposed; every caller is a PASSIVE_LEVEL
 * dispatch/unload path. */
static NTSTATUS AegisWfpAcquireProofLock(void)
{
    NTSTATUS status;

    if (!g_ProofLockReady) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("[AEGIS WFP] proof lock requested at IRQL %u\n",
                 KeGetCurrentIrql());
        return STATUS_INVALID_LEVEL;
    }
    status = KeWaitForSingleObject(&g_ProofLock, Executive, KernelMode,
                                   FALSE, NULL);
    /* Only STATUS_SUCCESS means this thread owns the mutex. A positive
     * non-success wait status must never turn into an unowned release. */
    return status == STATUS_SUCCESS ? STATUS_SUCCESS : status;
}

static VOID AegisWfpReleaseProofLock(void)
{
    (VOID)KeReleaseMutex(&g_ProofLock, FALSE);
}

static VOID AegisWfpRecordFirstFailure(NTSTATUS *result, NTSTATUS status)
{
    if (NT_SUCCESS(*result) && !NT_SUCCESS(status)) {
        *result = status;
    }
}

static NTSTATUS AegisWfpEnsureProofProvider(void)
{
    FWPM_PROVIDER0 provider;
    NTSTATUS status;

    if (g_ProofProviderReady) {
        return STATUS_SUCCESS;
    }
    if (g_WfpEngineHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey = AEGIS_PROOF_PROVIDER_KEY;
    provider.displayData.name = L"AEGIS NIDS Proof Filter Provider";
    provider.displayData.description =
        L"Owns receipt-backed AEGIS WFP proof filters";
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    status = FwpmProviderAdd0(g_WfpEngineHandle, &provider, NULL);
    if (AegisWfpAlreadyExists(status)) {
        status = STATUS_SUCCESS;
    }
    if (NT_SUCCESS(status)) {
        g_ProofProviderReady = TRUE;
    } else {
        DbgPrint("[AEGIS WFP] proof provider add failed: 0x%08X\n", status);
    }
    return status;
}

/* Enumerate only filters carrying the proof provider identity, on the two
 * layers the block path can mint. A foreign filter can never enter the table
 * merely because it shares a tuple. A callback failure (for example a recovery
 * table overflow) aborts that layer and is returned to the caller. */
typedef NTSTATUS (*AEGIS_PROOF_ENUM_CB)(const FWPM_FILTER0 *filter,
                                        PVOID context);

static NTSTATUS AegisWfpEnumProofFilters(AEGIS_PROOF_ENUM_CB callback,
                                         PVOID context)
{
    const GUID *layers[2] = {
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
    };
    ULONG layerIndex;
    NTSTATUS result = STATUS_SUCCESS;

    if (callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_WfpEngineHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    for (layerIndex = 0; layerIndex < 2; ++layerIndex) {
        FWPM_FILTER_ENUM_TEMPLATE0 template;
        HANDLE enumHandle = NULL;
        NTSTATUS status;

        RtlZeroMemory(&template, sizeof(template));
        template.providerKey = (GUID *)&AEGIS_PROOF_PROVIDER_KEY;
        template.layerKey = *layers[layerIndex];
        template.enumType = FWP_FILTER_ENUM_OVERLAPPING;
        template.actionMask = 0xFFFFFFFF;
        status = FwpmFilterCreateEnumHandle0(g_WfpEngineHandle, &template,
                                             &enumHandle);
        if (!NT_SUCCESS(status)) {
            /* WFP may report an empty provider-owned set as not-found when
             * the enum handle is created. That is an empty enumeration, not
             * a startup failure: a fresh provider has no proof filters yet. */
            if (AegisWfpFilterNotFound(status)) {
                DbgPrint("[AEGIS WFP] proof enum create: no matching filters\n");
                continue;
            }
            DbgPrint("[AEGIS WFP] proof enum create failed: 0x%08X\n", status);
            AegisWfpRecordFirstFailure(&result, status);
            continue;
        }
        for (;;) {
            FWPM_FILTER0 **entries = NULL;
            UINT32 count = 0;
            UINT32 i;
            BOOLEAN stopLayer = FALSE;

            status = FwpmFilterEnum0(g_WfpEngineHandle, enumHandle,
                                     AEGIS_PROOF_TABLE_CAPACITY,
                                     &entries, &count);
            if (!NT_SUCCESS(status)) {
                /* FwpmFilterEnum0 returns FWP_E_FILTER_NOT_FOUND when the
                 * provider-owned set is empty (the normal fresh-start case).
                 * Do not turn that into a DriverEntry failure. */
                if (AegisWfpFilterNotFound(status)) {
                    DbgPrint("[AEGIS WFP] proof enum: no matching filters\n");
                    if (entries != NULL) {
                        FwpmFreeMemory0((void **)&entries);
                    }
                    break;
                }
                DbgPrint("[AEGIS WFP] proof enum failed: 0x%08X\n", status);
                AegisWfpRecordFirstFailure(&result, status);
                if (entries != NULL) {
                    FwpmFreeMemory0((void **)&entries);
                }
                break;
            }
            if (count == 0) {
                break;
            }
            if (entries == NULL) {
                AegisWfpRecordFirstFailure(&result,
                                           STATUS_INVALID_BUFFER_SIZE);
                break;
            }
            for (i = 0; i < count; ++i) {
                if (!AegisWfpFilterOwnedByProvider(entries[i])) {
                    continue;
                }
                status = callback(entries[i], context);
                if (!NT_SUCCESS(status)) {
                    AegisWfpRecordFirstFailure(&result, status);
                    stopLayer = TRUE;
                    break;
                }
            }
            FwpmFreeMemory0((void **)&entries);
            if (stopLayer || count < AEGIS_PROOF_TABLE_CAPACITY) {
                break;
            }
        }
        status = FwpmFilterDestroyEnumHandle0(g_WfpEngineHandle, enumHandle);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[AEGIS WFP] proof enum handle destroy failed: 0x%08X\n",
                     status);
            AegisWfpRecordFirstFailure(&result, status);
        }
    }
    return result;
}

static NTSTATUS AegisWfpRecoverProofFilter(const FWPM_FILTER0 *filter,
                                           PVOID context)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(context);
    if (filter->filterId == 0) {
        return STATUS_SUCCESS;
    }
    /* A persistent provider without an auto-start service can have all of its
     * filters disabled by BFE at boot. A disabled filter must never be
     * recovered as an active block: delete it while the provider is ours, so
     * the next block request mints a fresh enabled filter. */
    if ((filter->flags & FWPM_FILTER_FLAG_DISABLED) != 0) {
        status = FwpmFilterDeleteById0(g_WfpEngineHandle, filter->filterId);
        if (NT_SUCCESS(status) || AegisWfpFilterNotFound(status)) {
            DbgPrint("[AEGIS WFP] removed disabled proof filter id=%llu\n",
                     filter->filterId);
            return STATUS_SUCCESS;
        }
        DbgPrint("[AEGIS WFP] disabled proof filter id=%llu delete failed: 0x%08X\n",
                 filter->filterId, status);
        return status;
    }
    if (filter->action.type != FWP_ACTION_BLOCK) {
        return STATUS_SUCCESS;
    }
    if (!AegisWfpRecordProof(&filter->filterKey, filter->filterId)) {
        DbgPrint("[AEGIS WFP] proof recovery table full; id=%llu untracked\n",
                 filter->filterId);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return STATUS_SUCCESS;
}

/* Older builds installed one filter under a fixed key and no provider. That
 * filter can outlive the driver and permanently block its tuple; delete it on
 * start before any new proof filter exists. A query/delete failure other than
 * "not found" is returned so the caller fails closed instead of assuming the
 * stale filter is gone. */
static NTSTATUS AegisWfpDeleteLegacyProofFilter(void)
{
    FWPM_FILTER0 *legacy = NULL;
    NTSTATUS status;
    NTSTATUS result = STATUS_SUCCESS;

    status = FwpmFilterGetByKey0(g_WfpEngineHandle, &AEGIS_PROOF_FILTER_KEY,
                                 &legacy);
    if (!NT_SUCCESS(status)) {
        if (AegisWfpFilterNotFound(status)) {
            return STATUS_SUCCESS;
        }
        DbgPrint("[AEGIS WFP] legacy proof lookup failed: 0x%08X\n", status);
        return status;
    }
    if (legacy == NULL) {
        return STATUS_SUCCESS;
    }
    /* Delete a block filter under the retired key when it is either unowned
     * (the old build) or explicitly ours. The key is no longer minted, so a
     * provider-owned copy is also duplicate preservation, not a live proof
     * filter. A foreign provider keeps its object. */
    if (legacy->action.type == FWP_ACTION_BLOCK &&
        (legacy->providerKey == NULL ||
         AegisWfpFilterOwnedByProvider(legacy))) {
        status = FwpmFilterDeleteById0(g_WfpEngineHandle, legacy->filterId);
        if (!NT_SUCCESS(status) &&
            !AegisWfpFilterNotFound(status)) {
            DbgPrint("[AEGIS WFP] legacy fixed-key proof filter %llu delete failed: 0x%08X\n",
                     legacy->filterId, status);
            result = status;
        } else {
            DbgPrint("[AEGIS WFP] legacy fixed-key proof filter %llu removed\n",
                     legacy->filterId);
        }
    }
    FwpmFreeMemory0((void **)&legacy);
    return result;
}

typedef struct _AEGIS_PROOF_SNAPSHOT {
    AEGIS_PROOF_ENTRY entries[AEGIS_PROOF_TABLE_CAPACITY];
    ULONG count;
} AEGIS_PROOF_SNAPSHOT;

static NTSTATUS AegisWfpSnapshotProofFilter(const FWPM_FILTER0 *filter,
                                            PVOID context)
{
    AEGIS_PROOF_SNAPSHOT *snapshot = (AEGIS_PROOF_SNAPSHOT *)context;

    if (snapshot->count >= AEGIS_PROOF_TABLE_CAPACITY) {
        /* The caller deletes this batch, then enumerates again. Cleanup must
         * never stop at the 64-entry table capacity. */
        return STATUS_SUCCESS;
    }
    snapshot->entries[snapshot->count].key = filter->filterKey;
    snapshot->entries[snapshot->count].filterId = filter->filterId;
    snapshot->count++;
    return STATUS_SUCCESS;
}

NTSTATUS AegisWfpPrepareProofProvider(void)
{
    NTSTATUS status;

    if (g_WfpEngineHandle == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }
    status = AegisWfpAcquireProofLock();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_ProofEntryCount = 0;
    RtlZeroMemory(g_ProofEntries, sizeof(g_ProofEntries));
    AegisWfpClearProofGlobals();

    status = AegisWfpEnsureProofProvider();
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    status = AegisWfpDeleteLegacyProofFilter();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] legacy proof cleanup failed: 0x%08X\n", status);
        goto done;
    }
    status = AegisWfpEnumProofFilters(AegisWfpRecoverProofFilter, NULL);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] proof recovery failed: 0x%08X\n", status);
        goto done;
    }
    DbgPrint("[AEGIS WFP] proof provider ready; %lu persistent filter(s) recovered\n",
             g_ProofEntryCount);

done:
    AegisWfpReleaseProofLock();
    return status;
}

NTSTATUS AegisWfpCleanupProofFilters(void)
{
    NTSTATUS result = STATUS_SUCCESS;
    NTSTATUS status;

    if (g_WfpEngineHandle == NULL) {
        return STATUS_SUCCESS;
    }
    status = AegisWfpAcquireProofLock();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Enumerate/delete in batches until a full enumeration returns no
     * provider-owned filter. Snapshot capacity only limits one batch; it is
     * not a cleanup ceiling. */
    for (;;) {
        AEGIS_PROOF_SNAPSHOT snapshot;
        NTSTATUS enumStatus;
        ULONG resolved = 0;
        ULONG i;

        RtlZeroMemory(&snapshot, sizeof(snapshot));
        enumStatus = AegisWfpEnumProofFilters(AegisWfpSnapshotProofFilter,
                                              &snapshot);
        AegisWfpRecordFirstFailure(&result, enumStatus);
        if (snapshot.count == 0) {
            break;
        }

        for (i = 0; i < snapshot.count; ++i) {
            UINT64 filterId = snapshot.entries[i].filterId;
            FWPM_FILTER0 *filter = NULL;

            status = FwpmFilterGetById0(g_WfpEngineHandle, filterId, &filter);
            if (!NT_SUCCESS(status)) {
                if (AegisWfpFilterNotFound(status)) {
                    /* Already absent: the cleanup postcondition holds. */
                    AegisWfpRemoveProofById(filterId);
                    resolved++;
                } else {
                    DbgPrint("[AEGIS WFP] cleanup get id=%llu failed: 0x%08X\n",
                             filterId, status);
                    AegisWfpRecordFirstFailure(&result, status);
                }
                continue;
            }
            if (!AegisWfpFilterOwnedByProvider(filter)) {
                DbgPrint("[AEGIS WFP] cleanup ownership mismatch id=%llu\n",
                         filterId);
                AegisWfpRecordFirstFailure(&result,
                                           STATUS_OBJECT_TYPE_MISMATCH);
                FwpmFreeMemory0((void **)&filter);
                continue;
            }
            status = FwpmFilterDeleteById0(g_WfpEngineHandle, filterId);
            if (NT_SUCCESS(status) || AegisWfpFilterNotFound(status)) {
                AegisWfpRemoveProofById(filterId);
                resolved++;
            } else {
                DbgPrint("[AEGIS WFP] cleanup delete id=%llu failed: 0x%08X\n",
                         filterId, status);
                AegisWfpRecordFirstFailure(&result, status);
            }
            FwpmFreeMemory0((void **)&filter);
        }

        if (!NT_SUCCESS(enumStatus)) {
            /* The batch is gone, but enumeration failed, so absence of other
             * provider filters is unproven. Return the failure. */
            break;
        }
        if (resolved == 0) {
            DbgPrint("[AEGIS WFP] cleanup made no progress; failing closed\n");
            AegisWfpRecordFirstFailure(&result, STATUS_UNSUCCESSFUL);
            break;
        }
    }

    status = AegisWfpDeleteLegacyProofFilter();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] legacy proof cleanup failed: 0x%08X\n", status);
        AegisWfpRecordFirstFailure(&result, status);
    }

    if (g_ProofProviderReady) {
        status = FwpmProviderDeleteByKey0(g_WfpEngineHandle,
                                          &AEGIS_PROOF_PROVIDER_KEY);
        if (AegisWfpProviderNotFound(status)) {
            status = STATUS_SUCCESS;
        }
        if (!NT_SUCCESS(status)) {
            DbgPrint("[AEGIS WFP] proof provider delete failed: 0x%08X\n",
                     status);
            AegisWfpRecordFirstFailure(&result, status);
        } else {
            g_ProofProviderReady = FALSE;
        }
    }

    g_ProofEntryCount = 0;
    RtlZeroMemory(g_ProofEntries, sizeof(g_ProofEntries));
    AegisWfpClearProofGlobals();
    AegisWfpReleaseProofLock();

    if (NT_SUCCESS(result)) {
        DbgPrint("[AEGIS WFP] proof filters + provider removed\n");
    } else {
        DbgPrint("[AEGIS WFP] proof cleanup incomplete: 0x%08X\n", result);
    }
    return result;
}

// ====== DriverEntry ======
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AEGIS WFP] DriverEntry — Initializing WFP Callout Driver\n");

    /* The proof lock must exist before the device is exposed. WFP management
     * calls require PASSIVE_LEVEL, so this is a KMUTEX, not a FAST_MUTEX. */
    KeInitializeMutex(&g_ProofLock, 0);
    IoInitializeRemoveLock(&g_RemoveLock, 'AEGR', 0, 0);
    ExInitializeRundownProtection(&g_CalloutRundown);
    g_ProofEntryCount = 0;
    RtlZeroMemory(g_ProofEntries, sizeof(g_ProofEntries));
    AegisWfpClearProofGlobals();
    g_ProofProviderReady = FALSE;
    g_ProofLockReady = TRUE;

    // 1. Create a secured device object for IOCTL communication.
    // System and built-in Administrators may open the device; ordinary users
    // and unauthenticated callers are denied at the kernel object boundary.
    // This ACL is a baseline boundary, not a replacement for PEP policy and
    // receipt validation inside the IOCTL handlers.
    RtlInitUnicodeString(&g_DeviceName, AEGIS_WFP_DEVICE_NAME);
    UNICODE_STRING device_sddl;
    RtlInitUnicodeString(&device_sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_NETWORK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &device_sddl,
        &AEGIS_DEVICE_CLASS_KEY,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    // 2. Create symbolic link for user-mode access (\\.\AegisWfpDevice)
    RtlInitUnicodeString(&g_SymlinkName, AEGIS_WFP_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&g_SymlinkName, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // 3. Set up IOCTL dispatch functions
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AegisWfpCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = AegisWfpClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = AegisWfpDeviceControl;
    DriverObject->DriverUnload                          = AegisWfpUnload;

    // 4. Initialize ring buffer (spinlock-protected)
    KeInitializeSpinLock(&g_RingLock);
    /* Use the WDK-compatible non-paged allocator. The current WDK headers
     * do not declare ExAllocatePool2 for this target and previously caused
     * an implicit-int compiler warning in the production build. */
    g_RingBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, g_RingBufferSize, 'AEGS');
    if (!g_RingBuffer) {
        DbgPrint("[AEGIS WFP] Failed to allocate ring buffer\n");
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_RingBuffer, g_RingBufferSize);

    /* EVT-231: non-paged payload scratch for NdisGetDataBuffer. */
    g_PayloadScratch = ExAllocatePoolWithTag(NonPagedPoolNx,
        AEGIS_MAX_CAPTURE_WINDOW, 'AEGP');
    if (!g_PayloadScratch) {
        DbgPrint("[AEGIS WFP] Failed to allocate payload scratch\n");
        ExFreePool(g_RingBuffer);
        g_RingBuffer = NULL;
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 5. Register WFP callout and filter
    status = AegisWfpRegisterCallout(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] Callout registration failed: 0x%08X\n", status);
        ExFreePool(g_RingBuffer);
        g_RingBuffer = NULL;
        if (g_PayloadScratch) {
            ExFreePool(g_PayloadScratch);
            g_PayloadScratch = NULL;
        }
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    /* 6. Establish the proof provider and recover any persistent proof filters
     * before the device can service a block request. Failure is fatal: the
     * callout must not stay registered while proof cleanup is unowned. */
    status = AegisWfpPrepareProofProvider();
    if (!NT_SUCCESS(status)) {
        NTSTATUS cleanupStatus;
        NTSTATUS startupStatus;
        DbgPrint("[AEGIS WFP] Proof provider preparation failed: 0x%08X\n",
                 status);
        startupStatus = AegisWfpStartupFailure(AEGIS_STAGE_PROOF_PROVIDER,
                                               status);
        cleanupStatus = AegisWfpCleanupProofFilters();
        if (!NT_SUCCESS(cleanupStatus)) {
            DbgPrint("[AEGIS WFP] Proof cleanup after prepare failure failed: 0x%08X\n",
                     cleanupStatus);
        }
        AegisWfpUnregisterCallout();
        ExFreePool(g_RingBuffer);
        g_RingBuffer = NULL;
        if (g_PayloadScratch) {
            ExFreePool(g_PayloadScratch);
            g_PayloadScratch = NULL;
        }
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        return startupStatus;
    }

    DbgPrint("[AEGIS WFP] Driver initialized successfully — Device: \\Device\\AegisWfpDevice\n");
    return STATUS_SUCCESS;
}

// ====== Unload ======
VOID AegisWfpUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[AEGIS WFP] Unloading driver...\n");

    /* Stop new dispatches and wait for every in-flight create/close/IOCTL to
     * release before touching the engine handle, proof state, or ring. The
     * unload thread must hold its own acquisition first; ReleaseAndWait then
     * marks the lock removed and drains every other acquisition. */
    {
        NTSTATUS removeStatus = IoAcquireRemoveLock(&g_RemoveLock, NULL);
        if (NT_SUCCESS(removeStatus)) {
            IoReleaseRemoveLockAndWait(&g_RemoveLock, NULL);
        } else {
            DbgPrint("[AEGIS WFP] remove-lock acquire on unload failed: 0x%08X\n",
                     removeStatus);
        }
    }

    /* Proof filters are provider-owned persistent objects. Remove them while
     * the engine handle is still open, then tear down the capture callout. */
    {
        NTSTATUS cleanupStatus = AegisWfpCleanupProofFilters();
        if (!NT_SUCCESS(cleanupStatus)) {
            DbgPrint("[AEGIS WFP] Unload proof cleanup incomplete: 0x%08X\n",
                     cleanupStatus);
        }
    }

    // Unregister WFP callout and filter
    AegisWfpUnregisterCallout();

    // Free payload scratch (EVT-231)
    if (g_PayloadScratch) {
        ExFreePool(g_PayloadScratch);
        g_PayloadScratch = NULL;
    }

    // Free ring buffer
    if (g_RingBuffer) {
        ExFreePool(g_RingBuffer);
        g_RingBuffer = NULL;
    }

    // Delete symbolic link and device
    IoDeleteSymbolicLink(&g_SymlinkName);
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }

    DbgPrint("[AEGIS WFP] Driver unloaded\n");
}

// ====== IRP_MJ_CREATE / IRP_MJ_CLOSE ======
NTSTATUS AegisWfpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DeviceObject);

    status = IoAcquireRemoveLock(&g_RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS AegisWfpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DeviceObject);

    status = IoAcquireRemoveLock(&g_RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        /* Close is best-effort; a failed acquire after remove-wait only means
         * unload already drained the device. */
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ====== IOCTL Dispatch ======
NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status;

    status = IoAcquireRemoveLock(&g_RemoveLock, Irp);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    status = STATUS_UNSUCCESSFUL;
    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_AEGIS_READ_EVENTS:
        status = AegisWfpReadEvents(Irp);
        break;
    case IOCTL_AEGIS_BLOCK_FLOW:
        /* DETECTION-ONLY (issue #25): the confirmed product decision is that
         * this IDS observes traffic and never mutates it. The IOCTL code and
         * the legacy handler remain in the binary for ABI stability, but this
         * dispatch can never reach it, so no caller -- current or legacy --
         * can install an AEGIS-owned FWP_ACTION_BLOCK filter through the
         * driver. Filter cleanup stays available via UNBLOCK below. */
        KdPrint(("AEGIS WFP: BlockFlow refused - detection-only, no host effect\n"));
        status = STATUS_NOT_SUPPORTED;
        break;
    case IOCTL_AEGIS_UNBLOCK_FLOW:
        status = AegisWfpUnblockFlow(Irp);
        break;
    case IOCTL_AEGIS_QUERY_FILTER:
        status = AegisWfpQueryFilter(Irp);
        break;
    case IOCTL_AEGIS_GET_STATS:
        status = AegisWfpGetStats(Irp);
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    IoReleaseRemoveLock(&g_RemoveLock, Irp);
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ====== IOCTL_AEGIS_READ_EVENTS ======
NTSTATUS AegisWfpReadEvents(PIRP Irp)
{
    // Read whole event records from the ring into the user-mode buffer.
    // EVT-231: records are variable length (48-byte header + payload) and
    // this path never splits one: it stops before the first record that
    // would not fit the caller buffer (that record stays for the next
    // read). Alignment is by construction: writers store whole records
    // and readers consume whole records under g_RingLock.
    PVOID userBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG userBufferSize = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.OutputBufferLength;

    KIRQL oldIrql;
    SIZE_T copied = 0;

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    while (userBuffer != NULL &&
           copied + sizeof(AEGIS_EVENT_HEADER) <= userBufferSize) {
        AEGIS_EVENT_HEADER hdr;
        SIZE_T available = AEGIS_RING_USED();
        SIZE_T total;
        SIZE_T firstPart;

        if (available < sizeof(AEGIS_EVENT_HEADER)) {
            break;
        }

        // Peek the next record header without consuming it (wrap-aware).
        if (g_RingReadOffset + sizeof(hdr) <= g_RingBufferSize) {
            RtlCopyMemory(&hdr, (PUCHAR)g_RingBuffer + g_RingReadOffset,
                sizeof(hdr));
        } else {
            firstPart = g_RingBufferSize - g_RingReadOffset;
            RtlCopyMemory(&hdr, (PUCHAR)g_RingBuffer + g_RingReadOffset,
                firstPart);
            RtlCopyMemory((PUCHAR)&hdr + firstPart, g_RingBuffer,
                sizeof(hdr) - firstPart);
        }

        // Defensive: a payload length outside the write contract means the
        // ring lost alignment (impossible under g_RingLock). Reset to the
        // write head instead of emitting garbage downstream, and count it.
        if (hdr.payload_length > AEGIS_MAX_PAYLOAD_SIZE) {
            g_WfpTotalDrops++;
            g_RingReadOffset = g_RingWriteOffset;
            break;
        }

        total = sizeof(AEGIS_EVENT_HEADER) + (SIZE_T)hdr.payload_length;
        if (total > available || copied + total > userBufferSize) {
            // Writer bytes are whole records under the lock, so
            // total > available cannot happen once aligned; keep the check.
            break;
        }

        // Consume the whole record (wrap-aware) into the caller buffer.
        firstPart = g_RingBufferSize - g_RingReadOffset;
        if (firstPart >= total) {
            RtlCopyMemory((PUCHAR)userBuffer + copied,
                (PUCHAR)g_RingBuffer + g_RingReadOffset, total);
        } else {
            RtlCopyMemory((PUCHAR)userBuffer + copied,
                (PUCHAR)g_RingBuffer + g_RingReadOffset, firstPart);
            RtlCopyMemory((PUCHAR)userBuffer + copied + firstPart,
                g_RingBuffer, total - firstPart);
        }
        g_RingReadOffset = (g_RingReadOffset + total) % g_RingBufferSize;
        copied += total;
    }

    if (copied > 0) {
        g_WfpTotalBytesRead += (ULONG)copied;
    }

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    Irp->IoStatus.Information = (ULONG)copied;
    return (copied > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

// ====== Port-specific WFP block contract ======
NTSTATUS AegisWfpBlockFlow(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    AEGIS_WFP_FLOW_REQUEST *request;
    AEGIS_WFP_FLOW_RESPONSE *response;
    FWPM_FILTER_CONDITION0 condition[3];
    FWPM_FILTER0 filter;
    FWPM_FILTER0 *existing = NULL;
    AEGIS_PROOF_ENTRY *entry;
    GUID proofKey;
    UINT64 filterId = 0;
    BOOLEAN inbound;
    NTSTATUS status;

    if (inputLen < sizeof(AEGIS_WFP_FLOW_REQUEST) ||
        outputLen < sizeof(AEGIS_WFP_FLOW_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (AEGIS_WFP_FLOW_REQUEST *)Irp->AssociatedIrp.SystemBuffer;
    response = (AEGIS_WFP_FLOW_RESPONSE *)Irp->AssociatedIrp.SystemBuffer;

    /* Only bit 0 is defined. Reject unknown direction bits instead of
     * silently creating a filter whose layer does not match the caller. */
    if (request->direction > 1) {
        return STATUS_INVALID_PARAMETER;
    }
    inbound = (request->direction & 0x01u) != 0;

    if (g_WfpEngineHandle == NULL || !g_ProofLockReady) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* One proof operation at a time: the table, the provider state and the
     * exact-filter attestation must describe one coherent host state. The
     * WFP calls below require PASSIVE_LEVEL; the KMUTEX keeps us there. */
    status = AegisWfpAcquireProofLock();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AegisWfpEnsureProofProvider();
    if (!NT_SUCCESS(status)) {
        goto done;
    }

    proofKey = AegisWfpProofKey(request);
    entry = AegisWfpFindProofByKey(&proofKey);
    if (entry != NULL) {
        /* The driver already minted this exact filter. Re-attest it against
         * the provider before reusing the id; a filter deleted behind our
         * back is removed from the table and re-created below. */
        status = FwpmFilterGetById0(g_WfpEngineHandle, entry->filterId,
                                    &existing);
        if (NT_SUCCESS(status) && existing == NULL) {
            DbgPrint("[AEGIS WFP] proof id=%llu returned no object\n",
                     entry->filterId);
            status = STATUS_INVALID_PARAMETER;
            goto done;
        }
        if (NT_SUCCESS(status)) {
            UINT64 existingId = 0;
            if (AegisWfpFilterMatchesRequest(existing, request, &existingId)) {
                filterId = existingId;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_OBJECT_NAME_COLLISION;
            }
            FwpmFreeMemory0((void **)&existing);
            if (NT_SUCCESS(status)) {
                g_ProofFilterId = filterId;
                g_BlockedIp = request->remote_ipv4;
                g_BlockedPort = request->remote_port;
                g_BlockedProtocol = request->protocol;
                RtlZeroMemory(response, sizeof(*response));
                response->filter_id = filterId;
                response->provider_status = (UINT32)status;
                Irp->IoStatus.Information = sizeof(*response);
                goto done;
            }
            DbgPrint("[AEGIS WFP] proof id=%llu no longer matches tuple\n",
                     entry->filterId);
            goto done;
        }
        if (AegisWfpFilterNotFound(status)) {
            UINT64 staleId = entry->filterId;
            AegisWfpRemoveProofById(staleId);
            if (g_ProofFilterId == staleId) {
                AegisWfpClearProofGlobals();
            }
            status = STATUS_SUCCESS;
        } else {
            DbgPrint("[AEGIS WFP] proof re-attest failed: 0x%08X\n", status);
            goto done;
        }
    }

    if (g_ProofEntryCount >= AEGIS_PROOF_TABLE_CAPACITY) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    RtlZeroMemory(condition, sizeof(condition));
    condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_UINT32;
    condition[0].conditionValue.uint32 = request->remote_ipv4;
    /* The direction byte selects the service-port condition. Outbound
     * filters match the remote service port; inbound filters match the
     * local service port while the remote address remains the peer. */
    condition[1].fieldKey = inbound ? FWPM_CONDITION_IP_LOCAL_PORT
                                    : FWPM_CONDITION_IP_REMOTE_PORT;
    condition[1].matchType = FWP_MATCH_EQUAL;
    condition[1].conditionValue.type = FWP_UINT16;
    condition[1].conditionValue.uint16 = request->remote_port;
    condition[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition[2].matchType = FWP_MATCH_EQUAL;
    condition[2].conditionValue.type = FWP_UINT8;
    condition[2].conditionValue.uint8 = request->protocol;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = proofKey;
    filter.providerKey = (GUID *)&AEGIS_PROOF_PROVIDER_KEY;
    filter.displayData.name = L"AEGIS WFP TCP Port Proof Filter";
    filter.displayData.description = L"AEGIS PEP-authorized port-specific proof filter";
    /* Port-specific enforcement must select the layer that matches the
     * direction. Outbound connects use ALE_AUTH_CONNECT_V4 with a remote-port
     * condition; inbound accepts use ALE_AUTH_RECV_ACCEPT_V4 with a
     * local-port condition. Leaving layerKey ambiguous is forbidden. */
    filter.layerKey = inbound ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                              : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = 3;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;

    status = FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, &filterId);
    if (AegisWfpAlreadyExists(status) ||
        status == STATUS_OBJECT_NAME_COLLISION ||
        status == STATUS_OBJECT_NAME_EXISTS) {
        /* The table is the authoritative index. A duplicate with no table
         * entry means the object is not ours to alias (for example a filter
         * created by another component with the same derived key); fail
         * closed instead of attesting it. */
        DbgPrint("[AEGIS WFP] proof add collision without a tracked owner\n");
        status = STATUS_OBJECT_NAME_COLLISION;
    }
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] proof add failed: 0x%08X tuple dir=%u %08X:%u proto=%u\n",
                 status, request->direction, request->remote_ipv4,
                 request->remote_port, request->protocol);
        goto done;
    }

    if (!AegisWfpRecordProof(&proofKey, filterId)) {
        NTSTATUS deleteStatus = FwpmFilterDeleteById0(g_WfpEngineHandle,
                                                      filterId);
        if (!NT_SUCCESS(deleteStatus) &&
            !AegisWfpFilterNotFound(deleteStatus)) {
            DbgPrint("[AEGIS WFP] rollback of untracked proof id=%llu failed: 0x%08X\n",
                     filterId, deleteStatus);
            status = deleteStatus;
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        goto done;
    }

    g_ProofFilterId = filterId;
    g_BlockedIp = request->remote_ipv4;
    g_BlockedPort = request->remote_port;
    g_BlockedProtocol = request->protocol;
    RtlZeroMemory(response, sizeof(*response));
    response->filter_id = filterId;
    response->provider_status = (UINT32)status;
    Irp->IoStatus.Information = sizeof(*response);

done:
    AegisWfpReleaseProofLock();
    return status;
}
NTSTATUS AegisWfpGetStats(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG outputLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outputLen < sizeof(AEGIS_RING_STATS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    AEGIS_RING_STATS *stats = (AEGIS_RING_STATS *)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(stats, sizeof(*stats));

    /* GET_STATS is a read-only ring ABI: same 24-byte layout as
     * READ_EVENTS. EVT-231 populates every counter; all updates happen
     * under g_RingLock, so this snapshot is consistent. */
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    stats->totalEventsWritten = g_WfpTotalEventsWritten;
    stats->totalDrops = g_WfpTotalDrops;
    stats->totalBytesWritten = g_WfpTotalBytesWritten;
    stats->totalBytesRead = g_WfpTotalBytesRead;
    stats->currentUsedBytes = (ULONG)AEGIS_RING_USED();
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    /* METHOD_BUFFERED requires Information to describe valid output bytes. */
    Irp->IoStatus.Information = sizeof(*stats);
    return STATUS_SUCCESS;
}

NTSTATUS AegisWfpUnblockFlow(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status;

    if (inputLen < sizeof(UINT64)) {
        KdPrint(("AEGIS WFP: UnblockFlow - input too small (%lu)\n", inputLen));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PUINT64 requestedFilterId = (PUINT64)Irp->AssociatedIrp.SystemBuffer;
    UINT64 filterId = *requestedFilterId;

    if (filterId == 0) {
        KdPrint(("AEGIS WFP: UnblockFlow - filter ID is required\n"));
        return STATUS_NOT_FOUND;
    }

    KdPrint(("AEGIS WFP: UnblockFlow - removing filter ID %llu\n", filterId));

    if (g_WfpEngineHandle == NULL || !g_ProofLockReady) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = AegisWfpAcquireProofLock();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // The receipt ID is not sufficient authority by itself. Read the provider
    // object and require the AEGIS proof-provider marker before deletion.
    FWPM_FILTER0 *ownedFilter = NULL;
    status = FwpmFilterGetById0(g_WfpEngineHandle, filterId, &ownedFilter);
    if (!NT_SUCCESS(status)) {
        if (AegisWfpFilterNotFound(status)) {
            /* Absence is the postcondition cleanup asks for. Keep the table
             * coherent and report success so rollback is idempotent. */
            AegisWfpRemoveProofById(filterId);
            if (g_ProofFilterId == filterId) {
                AegisWfpClearProofGlobals();
            }
            status = STATUS_SUCCESS;
        }
        AegisWfpReleaseProofLock();
        return status;
    }
    if (!AegisWfpFilterOwnedByProvider(ownedFilter)) {
        FwpmFreeMemory0((void **)&ownedFilter);
        AegisWfpReleaseProofLock();
        KdPrint(("AEGIS WFP: UnblockFlow - ownership marker mismatch\n"));
        return STATUS_ACCESS_DENIED;
    }
    FwpmFreeMemory0((void **)&ownedFilter);

    // Remove the provider-owned filter by exact receipt ID.
    status = FwpmFilterDeleteById0(g_WfpEngineHandle, filterId);
    if (!NT_SUCCESS(status) &&
        !AegisWfpFilterNotFound(status)) {
        KdPrint(("AEGIS WFP: FwpmFilterDeleteById0 failed: 0x%08X\n", status));
        AegisWfpReleaseProofLock();
        return status;
    }

    AegisWfpRemoveProofById(filterId);
    if (g_ProofFilterId == filterId) {
        AegisWfpClearProofGlobals();
    }
    KdPrint(("AEGIS WFP: UnblockFlow removed filter ID %llu\n", filterId));

    AegisWfpReleaseProofLock();
    return STATUS_SUCCESS;
}

static BOOLEAN AegisWfpFilterMatchesProof(const FWPM_FILTER0 *filter,
                                          UINT8 direction,
                                          UINT32 *remoteIpv4,
                                          UINT16 *remotePort,
                                          UINT8 *protocol) {
    BOOLEAN hasRemoteIpv4 = FALSE;
    BOOLEAN hasRemotePort = FALSE;
    BOOLEAN hasLocalPort = FALSE;
    BOOLEAN hasProtocol = FALSE;
    BOOLEAN outboundLayer;
    BOOLEAN inboundLayer;
    BOOLEAN expectLocalPort;
    UINT16 servicePort = 0;
    UINT32 i;

    if (filter == NULL ||
        !AegisWfpFilterOwnedByProvider(filter) ||
        (filter->flags & FWPM_FILTER_FLAG_DISABLED) != 0 ||
        filter->action.type != FWP_ACTION_BLOCK ||
        /* The proof filter is exactly remote-IP + service-port + protocol.
         * Any extra condition narrows the filter and would make the attested
         * tuple only partially enforced, so it is not the filter we minted. */
        filter->numFilterConditions != 3 ||
        filter->filterCondition == NULL) {
        return FALSE;
    }

    /* Accept exactly the two layers the block path can mint. Direction 0 is
     * outbound (CONNECT + remote port), 1 is inbound (RECV_ACCEPT + local
     * port). Unknown directions fail closed; there is no any-direction
     * query path, because that would attest the wrong layer. */
    outboundLayer = RtlCompareMemory(&filter->layerKey,
                                     &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                                     sizeof(GUID)) == sizeof(GUID);
    inboundLayer = RtlCompareMemory(&filter->layerKey,
                                    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                                    sizeof(GUID)) == sizeof(GUID);
    if (!outboundLayer && !inboundLayer) {
        return FALSE;
    }
    if (direction == 0 && !outboundLayer) {
        return FALSE;
    }
    if (direction == 1 && !inboundLayer) {
        return FALSE;
    }
    if (direction != 0 && direction != 1) {
        return FALSE;
    }

    /* Read the service port from the condition that matches the layer. A
     * direction-specific filter must carry exactly that condition; a filter
     * with both port conditions is ambiguous and fails closed. */
    expectLocalPort = inboundLayer;

    for (i = 0; i < filter->numFilterConditions; ++i) {
        const FWPM_FILTER_CONDITION0 *condition = &filter->filterCondition[i];
        if (condition->conditionValue.type == FWP_EMPTY) {
            continue;
        }
        if (RtlCompareMemory(&condition->fieldKey,
                             &FWPM_CONDITION_IP_REMOTE_ADDRESS,
                             sizeof(GUID)) == sizeof(GUID) &&
            condition->conditionValue.type == FWP_UINT32 &&
            condition->matchType == FWP_MATCH_EQUAL) {
            *remoteIpv4 = condition->conditionValue.uint32;
            hasRemoteIpv4 = TRUE;
        } else if (RtlCompareMemory(&condition->fieldKey,
                                    &FWPM_CONDITION_IP_REMOTE_PORT,
                                    sizeof(GUID)) == sizeof(GUID) &&
                   condition->conditionValue.type == FWP_UINT16 &&
                   condition->matchType == FWP_MATCH_EQUAL) {
            hasRemotePort = TRUE;
            if (!expectLocalPort) {
                servicePort = condition->conditionValue.uint16;
            }
        } else if (RtlCompareMemory(&condition->fieldKey,
                                    &FWPM_CONDITION_IP_LOCAL_PORT,
                                    sizeof(GUID)) == sizeof(GUID) &&
                   condition->conditionValue.type == FWP_UINT16 &&
                   condition->matchType == FWP_MATCH_EQUAL) {
            hasLocalPort = TRUE;
            if (expectLocalPort) {
                servicePort = condition->conditionValue.uint16;
            }
        } else if (RtlCompareMemory(&condition->fieldKey,
                                    &FWPM_CONDITION_IP_PROTOCOL,
                                    sizeof(GUID)) == sizeof(GUID) &&
                   condition->conditionValue.type == FWP_UINT8 &&
                   condition->matchType == FWP_MATCH_EQUAL) {
            *protocol = condition->conditionValue.uint8;
            hasProtocol = TRUE;
        }
    }

    if (direction == 0 && (!hasRemotePort || hasLocalPort)) {
        return FALSE;
    }
    if (direction == 1 && (!hasLocalPort || hasRemotePort)) {
        return FALSE;
    }
    if (!hasRemoteIpv4 || !hasProtocol) {
        return FALSE;
    }
    *remotePort = servicePort;
    return TRUE;
}

static BOOLEAN AegisWfpFilterMatchesRequest(const FWPM_FILTER0 *filter,
                                            const AEGIS_WFP_FLOW_REQUEST *request,
                                            UINT64 *filterId) {
    UINT32 remoteIpv4 = 0;
    UINT16 remotePort = 0;
    UINT8 protocol = 0;

    if (filter == NULL || request == NULL || filterId == NULL) {
        return FALSE;
    }
    if (request->direction > 1 || filter->filterId == 0) {
        return FALSE;
    }
    if (!AegisWfpFilterMatchesProof(filter, request->direction,
                                    &remoteIpv4, &remotePort, &protocol)) {
        return FALSE;
    }
    if (remoteIpv4 != request->remote_ipv4 ||
        remotePort != request->remote_port ||
        protocol != request->protocol) {
        return FALSE;
    }
    *filterId = filter->filterId;
    return TRUE;
}

/* Read-only provider-backed postcondition attestation. The query identity is
 * filter_id; no IP-only lookup is accepted. The driver no longer treats its
 * globals as proof of host state. */
NTSTATUS AegisWfpQueryFilter(PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    HANDLE engineHandle = NULL;
    FWPM_SESSION0 session;
    FWPM_FILTER0 *filter = NULL;
    NTSTATUS status;
    UINT32 remoteIpv4 = 0;
    UINT16 remotePort = 0;
    UINT8 protocol = 0;
    UINT8 direction = 0;
    /* The legacy query was 8 bytes and meant the outbound layer. Accept it
     * for old bridges, but never infer a non-default direction: a 16-byte
     * query must name direction 0 or 1 explicitly. */
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(UINT64) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_WFP_FILTER_STATE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    AEGIS_WFP_FILTER_STATE *state = (AEGIS_WFP_FILTER_STATE *)Irp->AssociatedIrp.SystemBuffer;
    AEGIS_WFP_FILTER_QUERY *query = (AEGIS_WFP_FILTER_QUERY *)Irp->AssociatedIrp.SystemBuffer;
    UINT64 requested_filter_id = query->filter_id;
    if (stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(AEGIS_WFP_FILTER_QUERY)) {
        direction = query->direction;
        if (direction > 1) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    RtlZeroMemory(state, sizeof(*state));
    state->filter_id = requested_filter_id;
    if (requested_filter_id == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = L"AEGIS WFP Provider Query Session";
    /* Read-only, so this session adds no objects. Keep it non-dynamic for the
     * same kernel-mode contract as the management session; the WDK management
     * examples pass no session at all, and a read-only query has no need for
     * dynamic-session auto-delete semantics. The exact-filter read is still
     * isolated from the provider-owned proof session. */
    session.flags = 0;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmFilterGetById0(engineHandle, requested_filter_id, &filter);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(engineHandle);
        if (AegisWfpFilterNotFound(status)) {
            /* Preserve the provider's exact absence status; do not normalize
             * it to a different code than the one WFP returned. */
            state->provider_status = (UINT32)status;
            Irp->IoStatus.Information = sizeof(*state);
            return STATUS_SUCCESS;
        }
        return status;
    }

    if (AegisWfpFilterMatchesProof(filter, direction,
                                   &remoteIpv4, &remotePort, &protocol)) {
        state->remote_ipv4 = remoteIpv4;
        state->remote_port = remotePort;
        state->protocol = protocol;
        state->present = 1;
        state->provider_status = (UINT32)STATUS_SUCCESS;
    } else {
        state->provider_status = (UINT32)STATUS_OBJECT_TYPE_MISMATCH;
    }
    FwpmFreeMemory0((void **)&filter);
    FwpmEngineClose0(engineHandle);
    Irp->IoStatus.Information = sizeof(*state);
    return STATUS_SUCCESS;
}

// ====== WFP Callout Registration (see aegis_wfp_callout.c) ======
// Forward declarations — implemented in aegis_wfp_callout.c
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject);
VOID AegisWfpUnregisterCallout();
