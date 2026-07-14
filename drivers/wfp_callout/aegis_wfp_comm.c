// =====================================================================
// aegis_wfp_comm.c — Ring buffer + IOCTL dispatch
// ---------------------------------------------------------------------
//   Ring buffer: 2MB NonPagedPool, write at head, read at tail
//   ป้องกัน overflow: ถ้าเต็ม → drop event และนับ dropped_count
//
//   IOCTL:
//     IOCTL_AEGIS_READ_EVENTS: copy หลาย events ออกไป user-mode
//     IOCTL_AEGIS_BLOCK_FLOW : (future) เพิ่ม flow_id ลง block table
//     IOCTL_AEGIS_GET_STATS  : return stats ของ driver
// =====================================================================

#include "aegis_wfp.h"

// =====================================================================
// RING BUFFER INIT / CLEANUP
// =====================================================================
NTSTATUS AegisRingInit(void)
{
    g_ring_buffer = ExAllocatePoolWithTag(
        NonPagedPool,
        AEGIS_RING_SIZE,
        'AEGS');
    if (!g_ring_buffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(g_ring_buffer, AEGIS_RING_SIZE);
    g_ring_write_offset = 0;
    g_ring_read_offset = 0;
    g_event_count = 0;
    g_dropped_count = 0;
    return STATUS_SUCCESS;
}

void AegisRingCleanup(void)
{
    if (g_ring_buffer) {
        ExFreePoolWithTag(g_ring_buffer, 'AEGS');
        g_ring_buffer = NULL;
    }
}

// =====================================================================
// RING BUFFER WRITE — must be called with g_ring_lock held
// =====================================================================
ULONG AegisRingWrite(const void* data, ULONG size)
{
    if (!g_ring_buffer || size == 0 || size > AEGIS_RING_SIZE) {
        if (size > 0) g_dropped_count++;
        return 0;
    }

    ULONG used = (g_ring_write_offset - g_ring_read_offset) % AEGIS_RING_SIZE;
    ULONG free = AEGIS_RING_SIZE - used - 1; // keep 1 byte gap to distinguish full/empty
    if (size > free) {
        g_dropped_count++;
        return 0;
    }

    // Write with wrap-around
    ULONG first_chunk = min(size, AEGIS_RING_SIZE - g_ring_write_offset);
    RtlCopyMemory((PUCHAR)g_ring_buffer + g_ring_write_offset, data, first_chunk);
    if (size > first_chunk) {
        RtlCopyMemory(g_ring_buffer, (PUCHAR)data + first_chunk, size - first_chunk);
    }
    g_ring_write_offset = (g_ring_write_offset + size) % AEGIS_RING_SIZE;
    return size;
}

// =====================================================================
// RING BUFFER READ — must be called with g_ring_lock held
//   Returns bytes copied to out_buf (may be 0 if empty)
//   Reads up to out_size bytes (may include multiple events)
// =====================================================================
ULONG AegisRingRead(PVOID out_buf, ULONG out_size)
{
    if (!g_ring_buffer || !out_buf || out_size == 0) return 0;

    ULONG available = (g_ring_write_offset - g_ring_read_offset) % AEGIS_RING_SIZE;
    if (available == 0) return 0;

    ULONG to_read = min(available, out_size);
    ULONG first_chunk = min(to_read, AEGIS_RING_SIZE - g_ring_read_offset);

    RtlCopyMemory(out_buf, (PUCHAR)g_ring_buffer + g_ring_read_offset, first_chunk);
    if (to_read > first_chunk) {
        RtlCopyMemory((PUCHAR)out_buf + first_chunk, g_ring_buffer, to_read - first_chunk);
    }
    g_ring_read_offset = (g_ring_read_offset + to_read) % AEGIS_RING_SIZE;
    return to_read;
}

// =====================================================================
// IOCTL DISPATCH
// =====================================================================
NTSTATUS AegisIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;

    switch (code) {
        case IOCTL_AEGIS_READ_EVENTS: {
            PVOID out_buf = Irp->AssociatedIrp.SystemBuffer;
            ULONG out_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
            if (!out_buf || out_size == 0) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            KIRQL old_irql;
            KeAcquireSpinLock(&g_ring_lock, &old_irql);
            info = AegisRingRead(out_buf, out_size);
            KeReleaseSpinLock(&g_ring_lock, old_irql);
            break;
        }

        case IOCTL_AEGIS_BLOCK_FLOW: {
            // TODO (IPS): parse block request, add flow_id to block table
            //   For now: just accept the request and log
            DbgPrint("[AEGIS-WFP] IOCTL_AEGIS_BLOCK_FLOW (not yet implemented)\n");
            info = 0;
            break;
        }

        case IOCTL_AEGIS_GET_STATS: {
            if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(AEGIS_DRIVER_STATS)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PAEGIS_DRIVER_STATS stats = (PAEGIS_DRIVER_STATS)Irp->AssociatedIrp.SystemBuffer;
            stats->total_events = g_event_count;
            stats->events_dropped = g_dropped_count;
            stats->bytes_processed = 0; // TODO
            stats->ring_buffer_usage = (g_ring_write_offset - g_ring_read_offset) % AEGIS_RING_SIZE;
            stats->block_table_count = 0;
            info = sizeof(AEGIS_DRIVER_STATS);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
