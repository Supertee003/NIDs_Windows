/* aegis_wfp.c - DriverEntry, Unload, GUID definition */

#include <initguid.h>   /* must precede any header that includes guiddef.h */
#include "aegis_wfp.h"

DEFINE_GUID(AEGIS_CALLOUT_KEY,
    0xc5e643b7, 0x7d3a, 0x4f5e,
    0x9a, 0x8b, 0x2c, 0x1d, 0x3e, 0x4f, 0x5a, 0x6b);

static PDEVICE_OBJECT g_DeviceObject = NULL;

NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS        status;
    UNICODE_STRING  deviceName;
    UNICODE_STRING  symlinkName;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&deviceName,  AEGIS_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, AEGIS_SYMLINK_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_NETWORK,
        0,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("AegisWfp: IoCreateDevice failed 0x%08lX\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AegisWfp: IoCreateSymbolicLink failed 0x%08lX\n", status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AegisWfpCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AegisWfpClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = AegisWfpDeviceControl;
    DriverObject->DriverUnload                           = AegisWfpUnload;

    status = AegisWfpRegisterCallouts(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("AegisWfp: RegisterCallouts failed 0x%08lX\n", status);
        IoDeleteSymbolicLink(&symlinkName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DbgPrint("AegisWfp: driver loaded successfully\n");
    return STATUS_SUCCESS;
}

VOID
AegisWfpUnload(
    PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symlinkName;

    UNREFERENCED_PARAMETER(DriverObject);

    AegisWfpUnregisterCallouts();

    RtlInitUnicodeString(&symlinkName, AEGIS_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("AegisWfp: driver unloaded\n");
}