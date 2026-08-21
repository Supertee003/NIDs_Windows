#ifndef AEGIS_WFP_H
#define AEGIS_WFP_H

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

/* Callout GUID (storage allocated in aegis_wfp.c via INITGUID) */
extern const GUID AEGIS_CALLOUT_KEY;

/* Device names */
#define AEGIS_DEVICE_NAME    L"\\Device\\AegisWfp"
#define AEGIS_SYMLINK_NAME   L"\\DosDevices\\AegisWfp"

/* IOCTL */
#define IOCTL_AEGIS_GET_EVENTS  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

/* aegis_wfp.c */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID     AegisWfpUnload(PDRIVER_OBJECT DriverObject);

/* aegis_wfp_callout.c */
NTSTATUS AegisWfpRegisterCallouts(PDEVICE_OBJECT DeviceObject);
VOID     AegisWfpUnregisterCallouts(VOID);

void AegisWfpClassifyFn(
    IN const FWPS_INCOMING_VALUES0         *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                              *layerData,
    IN const void                           *classifyContext,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut
);

NTSTATUS AegisWfpNotifyFn(
    IN FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    IN const GUID              *filterKey,
    IN const FWPS_FILTER0      *filter
);

/* aegis_wfp_comm.c */
NTSTATUS AegisWfpCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS AegisWfpClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS AegisWfpDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#endif /* AEGIS_WFP_H */