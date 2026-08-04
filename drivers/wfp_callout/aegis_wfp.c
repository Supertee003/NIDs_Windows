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
NTSTATUS AegisWfpBlockFlow(PIRP Irp) { return STATUS_NOT_IMPLEMENTED; }
NTSTATUS AegisWfpGetStats(PIRP Irp) { return STATUS_NOT_IMPLEMENTED; }

// ====== WFP Callout Registration (see aegis_wfp_callout.c) ======
// Forward declarations — implemented in aegis_wfp_callout.c
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject);
VOID AegisWfpUnregisterCallout();
