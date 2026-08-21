/* aegis_wfp_comm.c - IRP dispatch (Create, Close, DeviceControl) */

#include "aegis_wfp.h"

NTSTATUS
AegisWfpCreate(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
AegisWfpClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS
AegisWfpDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP           Irp
)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS          status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR         info   = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {

    case IOCTL_AEGIS_GET_EVENTS:
        status = STATUS_SUCCESS;
        info   = 0;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}