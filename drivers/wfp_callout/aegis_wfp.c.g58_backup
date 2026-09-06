/**
 * aegis_wfp.c - AEGIS WFP Callout Driver Entry Point
 *
 * DriverEntry: device, symlink, ring buffer, callout registration.
 * AegisWfpUnload: unregisters callout, frees ring buffer, deletes device.
 *
 * C3 FIX: No duplicate stubs. Only DriverEntry, Unload, GUID, globals.
 */

#include <initguid.h>   /* must precede any header that refs guiddef.h */
#include "aegis_wfp.h"

/* ====== GUID Definition ====== */
DEFINE_GUID(AEGIS_CALLOUT_KEY,
    0x8e6c3d2a, 0x4f5b, 0x1a7e,
    0x9c, 0x3d, 0x5b, 0x8f, 0x2a, 0x4e, 0x6c, 0xd7);

/* ====== Global State ====== */
PDEVICE_OBJECT g_AegisDeviceObject = NULL;
PVOID          g_RingBuffer       = NULL;
SIZE_T         g_RingBufferSize   = AEGIS_RING_BUFFER_SIZE;
KSPIN_LOCK     g_RingLock;
SIZE_T         g_RingWriteOffset  = 0;
SIZE_T         g_RingReadOffset   = 0;
HANDLE         g_WfpEngineHandle  = NULL;
UINT32         g_CalloutId        = 0;
UINT64         g_FilterId         = 0;  /* FIX 5: was UINT32 */

/* FIX 1: Forward declaration (used in DriverEntry below) */
VOID AegisWfpUnload(PDRIVER_OBJECT DriverObject);

/* ====== DriverEntry ====== */
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS       status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[AEGIS WFP] DriverEntry - Initializing\n");

    /* 1. Create device object for IOCTL communication */
    RtlInitUnicodeString(&deviceName, AEGIS_WFP_DEVICE_NAME);
    status = IoCreateDevice(DriverObject, 0, &deviceName,
        FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE,
        &g_AegisDeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    /* 2. Create symbolic link (user-mode opens \\.\\AegisWfpDevice) */
    RtlInitUnicodeString(&symlinkName, AEGIS_WFP_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(g_AegisDeviceObject);
        return status;
    }

    /* 3. Dispatch routines */
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AegisWfpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AegisWfpCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = AegisWfpDeviceControl;
    DriverObject->DriverUnload                           = AegisWfpUnload;

    /* 4. Initialize 2 MB ring buffer (spinlock-protected).
     * Use ExAllocatePoolWithTag (classic API, available since Windows 2000)
     * rather than ExAllocatePool2 (Win10 2004+ only) so the driver builds
     * against any WDK version without forward-declaring the prototype. */
    KeInitializeSpinLock(&g_RingLock);
    g_RingBuffer = ExAllocatePoolWithTag(NonPagedPool,
        g_RingBufferSize, 'AEGS');
    if (!g_RingBuffer) {
        DbgPrint("[AEGIS WFP] Ring buffer alloc failed\n");
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(g_AegisDeviceObject);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_RingBuffer, g_RingBufferSize);

    /* 5. Register WFP callout + add filter (C2) */
    status = AegisWfpRegisterCallout(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[AEGIS WFP] Callout registration failed: 0x%08X\n",
            status);
        ExFreePool(g_RingBuffer);
        g_RingBuffer = NULL;
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(g_AegisDeviceObject);
        return status;
    }

    DbgPrint("[AEGIS WFP] Driver ready - \\Device\\AegisWfpDevice (%u bytes ring)\n",
        (ULONG)g_RingBufferSize);
    return STATUS_SUCCESS;
}

/* ====== Unload ====== */
VOID AegisWfpUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[AEGIS WFP] Unloading...\n");

    /* Unregister callout + close engine (dynamic session auto-cleans) */
    AegisWfpUnregisterCallout();

    /* Free ring buffer */
    if (g_RingBuffer) {
        ExFreePool(g_RingBuffer);
        g_RingBuffer = NULL;
    }

    /* Delete symlink + device */
    RtlInitUnicodeString(&symlinkName, AEGIS_WFP_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    if (g_AegisDeviceObject) {
        IoDeleteDevice(g_AegisDeviceObject);
        g_AegisDeviceObject = NULL;
    }

    DbgPrint("[AEGIS WFP] Driver unloaded\n");
}