// =====================================================================
// aegis_wfp.c — Driver lifecycle (DriverEntry / DriverUnload)
// ---------------------------------------------------------------------
//   Build: ต้องการ WDK และ Visual Studio ที่ support kernel-mode
//   ใช้ Visual Studio + WDK's "Windows Driver" project template
// =====================================================================

#include "aegis_wfp.h"

// =====================================================================
// GLOBAL STATE
// =====================================================================
KSPIN_LOCK g_ring_lock;
PVOID g_ring_buffer = NULL;       // NonPagedPool, AEGIS_RING_SIZE bytes
ULONG g_ring_write_offset = 0;    // head
ULONG g_ring_read_offset = 0;     // tail
LONGLONG g_event_count = 0;
LONGLONG g_dropped_count = 0;

PDEVICE_OBJECT g_device_obj = NULL;
HANDLE g_engine_handle = NULL;
UINT32 g_callout_id = 0;
UINT64 g_filter_id_inbound = 0;
UINT64 g_filter_id_outbound = 0;

// Forward declarations
DRIVER_DISPATCH AegisCreateClose;
DRIVER_DISPATCH AegisIoctl;

// =====================================================================
// DRIVER ENTRY
// =====================================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING dev_name, sym_name;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AEGIS-WFP] DriverEntry: loading...\n");

    // 1. Init ring buffer
    KeInitializeSpinLock(&g_ring_lock);
    status = AegisRingInit();
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] AegisRingInit failed: 0x%08X\n", status);
        return status;
    }

    // 2. Create device \Device\AegisWfpDevice
    RtlInitUnicodeString(&dev_name, AEGIS_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &dev_name,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_device_obj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] IoCreateDevice failed: 0x%08X\n", status);
        AegisRingCleanup();
        return status;
    }

    // 3. Create symbolic link \\.\AegisWfpDevice
    RtlInitUnicodeString(&sym_name, AEGIS_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&sym_name, &dev_name);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_device_obj);
        AegisRingCleanup();
        return status;
    }

    // 4. Set dispatch routines
    DriverObject->DriverUnload = AegisUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AegisCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AegisCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AegisIoctl;

    // Use direct I/O for large buffers (not strictly needed for buffered)
    g_device_obj->Flags |= DO_BUFFERED_IO;
    g_device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

    // 5. Open WFP engine and register callout
    status = AegisRegisterCallout(g_device_obj);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS-WFP] AegisRegisterCallout failed: 0x%08X\n", status);
        IoDeleteSymbolicLink(&sym_name);
        IoDeleteDevice(g_device_obj);
        AegisRingCleanup();
        return status;
    }

    DbgPrint("[AEGIS-WFP] Driver loaded successfully.\n");
    return STATUS_SUCCESS;
}

// =====================================================================
// DRIVER UNLOAD
// =====================================================================
void AegisUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING sym_name;
    DbgPrint("[AEGIS-WFP] Unloading...\n");

    // Unregister callout + filters (reverse order of DriverEntry)
    AegisUnregisterCallout();

    RtlInitUnicodeString(&sym_name, AEGIS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym_name);

    if (g_device_obj) {
        IoDeleteDevice(g_device_obj);
        g_device_obj = NULL;
    }

    AegisRingCleanup();
    DbgPrint("[AEGIS-WFP] Unloaded.\n");
}

// =====================================================================
// CREATE/CLOSE DISPATCH — allow user-mode to open device
// =====================================================================
NTSTATUS AegisCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
