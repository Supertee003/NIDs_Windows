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

// ====== GUID Definition ======
// {A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D}
DEFINE_GUID(AEGIS_CALLOUT_KEY,
    0xa1b2c3d4, 0xe5f6, 0x4a7b,
    0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d);

// Stable identity for the receipt-owned persistent proof filter.
DEFINE_GUID(AEGIS_PROOF_FILTER_KEY,
    0xb2c3d4e5, 0xf607, 0x4b8c,
    0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e);

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

// WFP engine handle
HANDLE g_WfpEngineHandle = NULL;
UINT32 g_CalloutId = 0;
UINT64 g_CaptureFilterId = 0;
UINT64 g_ProofFilterId = 0;
UINT32 g_BlockedIp = 0;
UINT16 g_BlockedPort = 0;
UINT8 g_BlockedProtocol = 0;

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

// ====== DriverEntry ======
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AEGIS WFP] DriverEntry — Initializing WFP Callout Driver\n");

    // 1. Create device object for IOCTL communication
    RtlInitUnicodeString(&g_DeviceName, AEGIS_WFP_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &g_DeviceName,
        FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
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

    // 5. Register WFP callout and filter
    status = AegisWfpRegisterCallout(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] Callout registration failed: 0x%08X\n", status);
        ExFreePool(g_RingBuffer);
        IoDeleteSymbolicLink(&g_SymlinkName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DbgPrint("[AEGIS WFP] Driver initialized successfully — Device: \\Device\\AegisWfpDevice\n");
    return STATUS_SUCCESS;
}

// ====== Unload ======
VOID AegisWfpUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[AEGIS WFP] Unloading driver...\n");

    // Unregister WFP callout and filter
    AegisWfpUnregisterCallout();

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
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS AegisWfpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ====== IOCTL Dispatch ======
NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_AEGIS_READ_EVENTS:
        status = AegisWfpReadEvents(Irp);
        break;
    case IOCTL_AEGIS_BLOCK_FLOW:
        status = AegisWfpBlockFlow(Irp);
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

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ====== IOCTL_AEGIS_READ_EVENTS ======
NTSTATUS AegisWfpReadEvents(PIRP Irp)
{
    // Read events from ring buffer into user-mode buffer
    // This is called by windows_capture.zig (Zig user-mode reader)
    PVOID userBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG userBufferSize = IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.OutputBufferLength;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    SIZE_T available = (g_RingWriteOffset - g_RingReadOffset) % g_RingBufferSize;
    SIZE_T toCopy = (available < userBufferSize) ? available : userBufferSize;

    if (toCopy > 0 && userBuffer) {
        // Copy from ring buffer to user buffer
        // Handle wrap-around case
        if (g_RingReadOffset + toCopy <= g_RingBufferSize) {
            RtlCopyMemory(userBuffer, (PUCHAR)g_RingBuffer + g_RingReadOffset, toCopy);
        } else {
            SIZE_T firstPart = g_RingBufferSize - g_RingReadOffset;
            RtlCopyMemory(userBuffer, (PUCHAR)g_RingBuffer + g_RingReadOffset, firstPart);
            RtlCopyMemory((PUCHAR)userBuffer + firstPart, g_RingBuffer, toCopy - firstPart);
        }
        g_RingReadOffset = (g_RingReadOffset + toCopy) % g_RingBufferSize;
    }

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    Irp->IoStatus.Information = toCopy;
    return (toCopy > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

// ====== Port-specific WFP block contract ======
NTSTATUS AegisWfpBlockFlow(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    AEGIS_WFP_FLOW_REQUEST *request;
    AEGIS_WFP_FLOW_RESPONSE *response;
    HANDLE engineHandle = NULL;
    FWPM_SESSION0 session;
    FWPM_FILTER_CONDITION0 condition[3];
    FWPM_FILTER0 filter;
    UINT64 filterId = 0;
    NTSTATUS status;

    if (inputLen < sizeof(AEGIS_WFP_FLOW_REQUEST) ||
        outputLen < sizeof(AEGIS_WFP_FLOW_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (AEGIS_WFP_FLOW_REQUEST *)Irp->AssociatedIrp.SystemBuffer;
    response = (AEGIS_WFP_FLOW_RESPONSE *)Irp->AssociatedIrp.SystemBuffer;

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = L"AEGIS WFP Port Proof Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(condition, sizeof(condition));
    condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_UINT32;
    condition[0].conditionValue.uint32 = request->remote_ipv4;
    condition[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition[1].matchType = FWP_MATCH_EQUAL;
    condition[1].conditionValue.type = FWP_UINT16;
    condition[1].conditionValue.uint16 = request->remote_port;
    condition[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition[2].matchType = FWP_MATCH_EQUAL;
    condition[2].conditionValue.type = FWP_UINT8;
    condition[2].conditionValue.uint8 = request->protocol;

    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey = AEGIS_PROOF_FILTER_KEY;
    filter.displayData.name = L"AEGIS WFP TCP Port Proof Filter";
    filter.displayData.description = L"AEGIS PEP-authorized port-specific proof filter";
    // Port-specific outbound enforcement belongs to the ALE connect layer.
    // Leaving layerKey unset makes the filter's effective layer ambiguous.
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = 3;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;

    status = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(response, sizeof(*response));
        response->filter_id = filterId;
        response->provider_status = (UINT32)status;
        Irp->IoStatus.Information = sizeof(*response);
        g_ProofFilterId = filterId;
        g_BlockedIp = request->remote_ipv4;
        g_BlockedPort = request->remote_port;
        g_BlockedProtocol = request->protocol;
    }
    FwpmEngineClose0(engineHandle);
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

    /* GET_STATS is a read-only ring ABI. Keep it independent of WFP filter
     * enumeration: callers need the same 24-byte layout as READ_EVENTS. */
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    stats->currentUsedBytes = (ULONG)AEGIS_RING_USED();
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    /* METHOD_BUFFERED requires Information to describe valid output bytes. */
    Irp->IoStatus.Information = sizeof(*stats);
    return STATUS_SUCCESS;
}

NTSTATUS AegisWfpUnblockFlow(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

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

    // Open WFP engine
    HANDLE engineHandle = NULL;
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    session.displayData.name = L"AEGIS WFP Unblock Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    NTSTATUS status = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &engineHandle
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("AEGIS WFP: FwpmEngineOpen0 failed: 0x%08X\n", status));
        return status;
    }

    // The receipt ID is not sufficient authority by itself. Read the provider
    // object and require the stable AEGIS proof marker before deletion.
    FWPM_FILTER0 *ownedFilter = NULL;
    status = FwpmFilterGetById0(engineHandle, filterId, &ownedFilter);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(engineHandle);
        return status;
    }
    if (RtlCompareMemory(&ownedFilter->filterKey, &AEGIS_PROOF_FILTER_KEY,
                         sizeof(GUID)) != sizeof(GUID)) {
        FwpmFreeMemory0((void **)&ownedFilter);
        FwpmEngineClose0(engineHandle);
        KdPrint(("AEGIS WFP: UnblockFlow - ownership marker mismatch\n"));
        return STATUS_ACCESS_DENIED;
    }
    FwpmFreeMemory0((void **)&ownedFilter);

    // Remove the provider-owned filter by exact receipt ID.
    status = FwpmFilterDeleteById0(engineHandle, filterId);

    if (!NT_SUCCESS(status)) {
        KdPrint(("AEGIS WFP: FwpmFilterDeleteById0 failed: 0x%08X\n", status));
        FwpmEngineClose0(engineHandle);
        return status;
    }

    KdPrint(("AEGIS WFP: UnblockFlow removed filter ID %llu\n", filterId));

    g_ProofFilterId = 0;
    g_BlockedIp = 0;
    g_BlockedPort = 0;
    g_BlockedProtocol = 0;

    FwpmEngineClose0(engineHandle);
    return STATUS_SUCCESS;
}

static BOOLEAN AegisWfpFilterMatchesProof(const FWPM_FILTER0 *filter,
                                          UINT32 *remoteIpv4,
                                          UINT16 *remotePort,
                                          UINT8 *protocol) {
    BOOLEAN hasRemoteIpv4 = FALSE;
    BOOLEAN hasRemotePort = FALSE;
    BOOLEAN hasProtocol = FALSE;
    UINT32 i;

    if (filter == NULL ||
        RtlCompareMemory(&filter->filterKey, &AEGIS_PROOF_FILTER_KEY,
                         sizeof(GUID)) != sizeof(GUID) ||
        RtlCompareMemory(&filter->layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                         sizeof(GUID)) != sizeof(GUID) ||
        filter->action.type != FWP_ACTION_BLOCK ||
        filter->numFilterConditions == 0 || filter->filterCondition == NULL) {
        return FALSE;
    }

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
            *remotePort = condition->conditionValue.uint16;
            hasRemotePort = TRUE;
        } else if (RtlCompareMemory(&condition->fieldKey,
                                    &FWPM_CONDITION_IP_PROTOCOL,
                                    sizeof(GUID)) == sizeof(GUID) &&
                   condition->conditionValue.type == FWP_UINT8 &&
                   condition->matchType == FWP_MATCH_EQUAL) {
            *protocol = condition->conditionValue.uint8;
            hasProtocol = TRUE;
        }
    }

    return hasRemoteIpv4 && hasRemotePort && hasProtocol;
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
    if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(AEGIS_WFP_FILTER_QUERY) ||
        stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_WFP_FILTER_STATE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    AEGIS_WFP_FILTER_STATE *state = (AEGIS_WFP_FILTER_STATE *)Irp->AssociatedIrp.SystemBuffer;
    UINT64 requested_filter_id = ((AEGIS_WFP_FILTER_QUERY *)Irp->AssociatedIrp.SystemBuffer)->filter_id;
    RtlZeroMemory(state, sizeof(*state));
    state->filter_id = requested_filter_id;
    if (requested_filter_id == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = L"AEGIS WFP Provider Query Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    if (!NT_SUCCESS(status)) return status;

    status = FwpmFilterGetById0(engineHandle, requested_filter_id, &filter);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(engineHandle);
        if (status == FWP_E_FILTER_NOT_FOUND || status == STATUS_NOT_FOUND) {
            state->provider_status = (UINT32)STATUS_NOT_FOUND;
            Irp->IoStatus.Information = sizeof(*state);
            return STATUS_SUCCESS;
        }
        return status;
    }

    if (AegisWfpFilterMatchesProof(filter, &remoteIpv4, &remotePort, &protocol)) {
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
