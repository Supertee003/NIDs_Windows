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

#include "aegis_wfp.h"
#include <ntddk.h>
#include <wfp.h>

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
UINT32 g_FilterId = 0;

// ====== DriverEntry ======
extern NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
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
    g_RingBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, g_RingBufferSize, 'AEGS');
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
    ULONG userBufferSize = Irp->CurrentIrpStackLocation->Parameters.DeviceIoControl.OutputBufferLength;

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

// ====== Stub implementations (to be expanded) ======
NTSTATUS AegisWfpBlockFlow(PIRP Irp) {
    // G16: Real WFP block flow implementation
    // Input: Irp->AssociatedIrp.SystemBuffer contains IP to block (4 bytes)
    // Action: Adds a WFP filter rule to block traffic from that IP

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (inputLen < sizeof(UINT32)) {
        KdPrint(("AEGIS WFP: BlockFlow - input too small (%lu)\n", inputLen));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PUINT32 blockIp = (PUINT32)Irp->AssociatedIrp.SystemBuffer;
    UINT32 ipToBlock = *blockIp;

    KdPrint(("AEGIS WFP: BlockFlow - blocking IP %d.%d.%d.%d\n",
        (ipToBlock >> 24) & 0xFF, (ipToBlock >> 16) & 0xFF,
        (ipToBlock >> 8) & 0xFF, ipToBlock & 0xFF));

    // Open WFP engine
    HANDLE engineHandle = NULL;
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    session.displayData.name = L"AEGIS WFP Session";
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

    // Create filter condition for remote IP address
    FWPM_FILTER_CONDITION0 condition[1];
    condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_UINT32;
    condition[0].conditionValue.uint32 = ipToBlock;

    // Create blocking filter
    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(filter));
    filter.displayData.name = L"AEGIS Block IP Filter";
    filter.displayData.description = L"AEGIS NIDS IP blocking filter";
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.action.blockType = FWP_BLOCK;
    filter.flags = FWPM_FILTER_FLAG_PERSISTENT;

    UINT64 filterId = 0;
    status = FwpmFilterAdd0(
        engineHandle,
        &filter,
        NULL,
        &filterId
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("AEGIS WFP: FwpmFilterAdd0 failed: 0x%08X\n", status));
        FwpmEngineClose0(engineHandle);
        return status;
    }

    KdPrint(("AEGIS WFP: BlockFlow added filter ID %llu for IP %d.%d.%d.%d\n",
        filterId,
        (ipToBlock >> 24) & 0xFF, (ipToBlock >> 16) & 0xFF,
        (ipToBlock >> 8) & 0xFF, ipToBlock & 0xFF));

    // Store filter ID for later removal (unblock)
    // TODO: Store in a global list for unblock operations

    FwpmEngineClose0(engineHandle);
    return STATUS_SUCCESS;
}
NTSTATUS AegisWfpGetStats(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG outputLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (outputLen < sizeof(WFP_STATS)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PUINT32 stats = (PUINT32)Irp->AssociatedIrp.SystemBuffer;

    // Open WFP engine to query statistics
    HANDLE engineHandle = NULL;
    FWPM_SESSION0 session;
    memset(&session, 0, sizeof(session));
    session.displayData.name = L"AEGIS WFP Stats Session";
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

    // Query filter statistics
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate;
    memset(&enumTemplate, 0, sizeof(enumTemplate));

    HANDLE enumHandle = NULL;
    status = FwpmFilterCreateEnumHandle0(
        engineHandle,
        &enumTemplate,
        &enumHandle
    );

    if (NT_SUCCESS(status)) {
        FWPM_FILTER0 **filters = NULL;
        UINT32 numFilters = 0;

        status = FwpmFilterEnum0(
            engineHandle,
            enumHandle,
            1, // Get one filter at a time
            &filters,
            &numFilters
        );

        if (NT_SUCCESS(status) && numFilters > 0) {
            // Count AEGIS filters
            UINT32 aegisFilterCount = 0;
            for (UINT32 i = 0; i < numFilters; i++) {
                if (filters[i] && filters[i]->displayData.name &&
                    wcsstr(filters[i]->displayData.name, L"AEGIS") != NULL) {
                    aegisFilterCount++;
                }
                FwpmFreeMemory0((void**)&filters[i]);
            }
            FwpmFreeMemory0((void**)&filters);
            stats[0] = aegisFilterCount; // Number of AEGIS filters
        } else {
            stats[0] = 0;
        }

        FwpmFilterFreeEnumHandle0(engineHandle, enumHandle);
    } else {
        stats[0] = 0;
    }

    FwpmEngineClose0(engineHandle);
    return STATUS_SUCCESS;
}

NTSTATUS AegisWfpUnblockFlow(PIRP Irp) {
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (inputLen < sizeof(UINT64)) {
        KdPrint(("AEGIS WFP: UnblockFlow - input too small (%lu)\n", inputLen));
        return STATUS_BUFFER_TOO_SMALL;
    }

    PUINT64 unblockFilterId = (PUINT64)Irp->AssociatedIrp.SystemBuffer;
    UINT64 filterId = *unblockFilterId;

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

    // Remove filter by ID
    status = FwpmFilterDeleteById0(engineHandle, filterId);

    if (!NT_SUCCESS(status)) {
        KdPrint(("AEGIS WFP: FwpmFilterDeleteById0 failed: 0x%08X\n", status));
        FwpmEngineClose0(engineHandle);
        return status;
    }

    KdPrint(("AEGIS WFP: UnblockFlow removed filter ID %llu\n", filterId));

    FwpmEngineClose0(engineHandle);
    return STATUS_SUCCESS;
}

// ====== WFP Callout Registration (see aegis_wfp_callout.c) ======
// Forward declarations — implemented in aegis_wfp_callout.c
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject);
VOID AegisWfpUnregisterCallout();
