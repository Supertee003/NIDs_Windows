/**
 * aegis_wfp.cpp — AEGIS NIDS WFP Callout Driver Entry Point (C++ Edition)
 *
 * Main driver file using Aegis::WFP namespace, RAII classes (DeviceGuard,
 * PoolAllocator, WfpEngineGuard), and RingBuffer<EventHeader> template.
 *
 * Architecture: C++ Kernel Driver (NETWORK layer of 3-Layer Architecture)
 * Build: WDK + Visual Studio 2022 (compile with /KernelDisableExceptions)
 * Runtime: Test Signing required (bcdedit /set testsigning on)
 *
 * Key C++ enhancements over C version:
 *   - DeviceGuard: RAII auto-cleanup for IoCreateDevice/IoDeleteDevice
 *   - RingBuffer<EventHeader>: Template ring buffer with built-in spinlock
 *   - SpinLockGuard: RAII spin lock — no manual KeReleaseSpinLock needed
 *   - PoolAllocator: RAII for ExAllocatePool2 → auto ExFreePool
 *   - WfpEngineGuard: RAII for FwpmEngineOpen0 → auto FwpmEngineClose0
 *   - Namespace Aegis::WFP: Clean separation, no global variable pollution
 */

#include "aegis_wfp.hpp"
#include <ntddk.h>
#include <wfp.h>

// ====== Global Driver State (managed by RAII guards) ======
namespace Aegis {
namespace WFP {

// RAII-managed objects
static DeviceGuard          g_deviceGuard;
static RingBuffer<EventHeader> g_ringBuffer;
static WfpEngineGuard       g_wfpEngine;

// Non-RAII state (managed manually in Register/Unregister)
static UINT32 g_calloutId = 0;
static UINT32 g_filterId  = 0;

// ====== Forward declarations (extern "C" for WDK compatibility) ======
extern "C" {
    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
    VOID     AegisWfpUnload(PDRIVER_OBJECT DriverObject);
    NTSTATUS AegisWfpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
    NTSTATUS AegisWfpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
    NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
    NTSTATUS AegisWfpReadEvents(PIRP Irp);
    NTSTATUS AegisWfpBlockFlow(PIRP Irp);
    NTSTATUS AegisWfpGetStats(PIRP Irp);
}

// ====== Forward declarations (C++ internal) ======
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject);
VOID     AegisWfpUnregisterCallout();

} // namespace WFP
} // namespace Aegis

// ====== DriverEntry (extern "C" — Windows kernel requires C linkage) ======
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[AEGIS WFP] DriverEntry — Initializing WFP Callout Driver (C++ Edition)\n");

    using namespace Aegis::WFP;

    // 1. Create device object + symlink (RAII-managed — auto-cleanup on failure)
    UNICODE_STRING deviceName, symlinkName;
    RtlInitUnicodeString(&deviceName, AEGIS_WFP_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, AEGIS_WFP_SYMLINK_NAME);

    NTSTATUS status = g_deviceGuard.Create(DriverObject, &deviceName, &symlinkName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] DeviceGuard::Create failed: 0x%08X\n", status);
        return status;  // RAII auto-cleans up partial state
    }

    // 2. Set up IOCTL dispatch functions
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AegisWfpCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = AegisWfpClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = AegisWfpDeviceControl;
    DriverObject->DriverUnload                          = AegisWfpUnload;

    // 3. Initialize ring buffer (RAII-managed — auto-free on failure)
    status = g_ringBuffer.Initialize(kRingBufferSize, 'AEGS');
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] RingBuffer::Initialize failed: 0x%08X\n", status);
        g_deviceGuard.Cleanup();  // RAII cleanup
        return status;
    }

    // 4. Register WFP callout and filter
    status = AegisWfpRegisterCallout(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] Callout registration failed: 0x%08X\n", status);
        g_ringBuffer.Destroy();       // RAII cleanup
        g_deviceGuard.Cleanup();      // RAII cleanup
        return status;
    }

    DbgPrint("[AEGIS WFP] Driver initialized (C++) — Device: \\Device\\AegisWfpDevice\n");
    return STATUS_SUCCESS;
}

// ====== Unload ======
extern "C" VOID AegisWfpUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[AEGIS WFP] Unloading driver (C++)...\n");

    using namespace Aegis::WFP;

    // Unregister WFP callout and filter
    AegisWfpUnregisterCallout();

    // RAII objects auto-cleanup on scope exit — but we call explicitly for order
    g_ringBuffer.Destroy();
    g_deviceGuard.Cleanup();

    DbgPrint("[AEGIS WFP] Driver unloaded (C++)\n");
}

// ====== IRP_MJ_CREATE / IRP_MJ_CLOSE ======
extern "C" NTSTATUS AegisWfpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS AegisWfpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ====== IOCTL Dispatch ======
extern "C" NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
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
extern "C" NTSTATUS AegisWfpReadEvents(PIRP Irp)
{
    using namespace Aegis::WFP;

    PVOID userBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG userBufferSize = IoGetCurrentIrpStackLocation(Irp)
        ->Parameters.DeviceIoControl.OutputBufferLength;

    // Use RingBuffer template's Read method (spinlock-protected via RAII SpinLockGuard)
    SIZE_T bytesRead = g_ringBuffer.Read(userBuffer, userBufferSize);

    Irp->IoStatus.Information = bytesRead;
    return (bytesRead > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

// ====== IOCTL_AEGIS_BLOCK_FLOW (IPS enforcement) ======
extern "C" NTSTATUS AegisWfpBlockFlow(PIRP Irp)
{
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = IoGetCurrentIrpStackLocation(Irp)
        ->Parameters.DeviceIoControl.InputBufferLength;

    if (!inputBuffer || inputLength < sizeof(UINT32)) {
        return STATUS_INVALID_PARAMETER;
    }

    UINT32 blockIp = *(PUINT32)inputBuffer;
    DbgPrint("[AEGIS WFP] IPS: Block request for IP %d.%d.%d.%d\n",
        (blockIp >> 0) & 0xFF, (blockIp >> 8) & 0xFF,
        (blockIp >> 16) & 0xFF, (blockIp >> 24) & 0xFF);

    // TODO: Add WFP filter (FWPM_FILTER_CONDITION0 for source IP)
    return STATUS_NOT_IMPLEMENTED;
}

// ====== IOCTL_AEGIS_GET_STATS ======
extern "C" NTSTATUS AegisWfpGetStats(PIRP Irp)
{
    using namespace Aegis::WFP;

    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outputLength = IoGetCurrentIrpStackLocation(Irp)
        ->Parameters.DeviceIoControl.OutputBufferLength;

    if (!outputBuffer || outputLength < sizeof(RingStats)) {
        return STATUS_INVALID_PARAMETER;
    }

    // Use RingBuffer template's GetStats method (spinlock-protected via RAII)
    RingStats stats = g_ringBuffer.GetStats();
    RtlCopyMemory(outputBuffer, &stats, sizeof(RingStats));

    Irp->IoStatus.Information = sizeof(RingStats);
    return STATUS_SUCCESS;
}
