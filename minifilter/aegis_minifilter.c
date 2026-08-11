/**
 * aegis_minifilter.c — AEGIS NIDS Minifilter Driver (Layer 1: KERNEL)
 *
 * File system minifilter that monitors file I/O for forensic evidence
 * collection (file creation, modification, deletion). Events are written
 * into a separate ring buffer consumed by the Rust forensic hash layer.
 *
 * Build: WDK + MSVC (kernel-mode)
 * Language: C (strict C11)
 *
 * Copyright (c) 2024 AEGIS NIDS Project
 */

#include <ntddk.h>
#include <fltkernel.h>

/* ─── Constants ─── */
#define AEGIS_MINI_ALTITUDE     L"370030"   /* Between network and scanner */
#define AEGIS_FILE_RING_SIZE    (16 * 1024 * 1024)  /* 16 MiB for file events */
#define MAX_PATH_CAPTURE        520        /* NT path max in chars */

/* ─── File Event Record ─── */
#pragma pack(push, 1)
typedef struct _AEGIS_FILE_EVENT {
    ULONG   size;               /* Total record size */
    ULONG64 timestamp;          /* KeQueryPerformanceCounter */
    ULONG   pid;                /* Process ID */
    ULONG   tid;                /* Thread ID */
    USHORT  event_type;         /* 0=create, 1=write, 2=delete, 3=rename, 4=read */
    USHORT  file_size_hi;       /* High 16 bits of file size */
    ULONG   file_size_lo;       /* Low 32 bits of file size */
    USHORT  path_len;           /* Path length in bytes (excluding null) */
    USHORT  _pad;
    WCHAR   path[MAX_PATH_CAPTURE]; /* Full NT path */
} AEGIS_FILE_EVENT;
#pragma pack(pop)

/* ─── Ring Buffer (same design as WFP driver) ─── */
#pragma pack(push, 1)
typedef struct _AEGIS_FILE_RING_HEADER {
    volatile ULONG write_pos;
    volatile ULONG read_pos;
    ULONG         capacity;
    ULONG         event_count;
    ULONG         dropped_count;
} AEGIS_FILE_RING_HEADER;
#pragma pack(pop)

typedef struct _AEGIS_FILE_RING {
    AEGIS_FILE_RING_HEADER header;
    UCHAR                  data[1];
} AEGIS_FILE_RING;

/* ─── Globals ─── */
static AEGIS_FILE_RING* g_file_ring = NULL;
static KSPIN_LOCK       g_file_ring_lock = {0};
static BOOLEAN          g_running = FALSE;

/* Minifilter instance */
FLT_PREOP_CALLBACK_STATUS aegis_pre_create(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx
);

FLT_PREOP_CALLBACK_STATUS aegis_pre_write(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx
);

FLT_POSTOP_CALLBACK_STATUS aegis_post_create(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _In_ PVOID completion_ctx,
    _In_ FLT_POST_OPERATION_FLAGS flags
);

/* ─── Callback Registration Table ─── */
static const FLT_OPERATION_REGISTRATION g_callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      aegis_pre_create,
      aegis_post_create },
    { IRP_MJ_WRITE,
      0,
      aegis_pre_write,
      NULL },
    { IRP_MJ_SET_INFORMATION,     /* Catches file deletion & rename */
      0,
      aegis_pre_write,
      NULL },
    { IRP_MJ_OPERATION_END }       /* Sentinel */
};

static const FLT_CONTEXT_REGISTRATION g_contexts[] = {
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION g_filter_registration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags */
    NULL,                           /* Context registration */
    g_callbacks,                    /* Operation callbacks */
    aegis_minifilter_unload,        /* FilterUnload */
    NULL,                           /* InstanceSetup */
    NULL,                           /* InstanceQueryTeardown */
    NULL,                           /* InstanceTeardownStart */
    NULL,                           /* InstanceTeardownComplete */
    NULL,                           /* GenerateFileName */
    NULL,                           /* NormalizeNameComponent */
    NULL,                           /* NormalizeContextCleanup */
    NULL,                           /* TransactionNotification */
    NULL,                           /* NormalizeNameComponentEx */
    NULL                            /* SectionNotification */
};

static PFLT_FILTER g_filter_handle = NULL;

/* ─── Ring Write Helper ─── */
static BOOLEAN aegis_file_ring_write(_In_ const AEGIS_FILE_EVENT* evt)
{
    KIRQL old_irql;
    ULONG total = evt->size;

    KeAcquireSpinLock(&g_file_ring_lock, &old_irql);

    ULONG wp = g_file_ring->header.write_pos;
    ULONG rp = g_file_ring->header.read_pos;
    ULONG cap = g_file_ring->header.capacity;
    ULONG free;

    if (wp >= rp) free = cap - (wp - rp) - 1;
    else          free = rp - wp - 1;

    if (free < total) {
        g_file_ring->header.dropped_count++;
        KeReleaseSpinLock(&g_file_ring_lock, old_irql);
        return FALSE;
    }

    /* Copy event (with wrap handling) */
    if (wp + total <= cap) {
        RtlCopyMemory(&g_file_ring->data[wp], evt, total);
    } else {
        ULONG c1 = cap - wp;
        RtlCopyMemory(&g_file_ring->data[wp], evt, c1);
        RtlCopyMemory(&g_file_ring->data[0], (UCHAR*)evt + c1, total - c1);
    }

    KeMemoryBarrier();
    g_file_ring->header.write_pos = (wp + total) % cap;
    g_file_ring->header.event_count++;

    KeReleaseSpinLock(&g_file_ring_lock, old_irql);
    return TRUE;
}

/* ─── Build File Event ─── */
static VOID aegis_build_file_event(
    _In_  PFLT_CALLBACK_DATA cbd,
    _In_  USHORT             event_type,
    _Out_ AEGIS_FILE_EVENT*  evt
)
{
    RtlZeroMemory(evt, sizeof(AEGIS_FILE_EVENT));

    evt->timestamp  = KeQueryPerformanceCounter(NULL).QuadPart;
    evt->pid        = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt->tid        = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    evt->event_type = event_type;

    /* Try to get file name from FLT_CALLBACK_DATA */
    if (cbd->Iopb->TargetFileObject && cbd->Iopb->TargetFileObject->FileName.Length > 0) {
        USHORT name_bytes = cbd->Iopb->TargetFileObject->FileName.Length;
        if (name_bytes > (MAX_PATH_CAPTURE - 1) * sizeof(WCHAR))
            name_bytes = (MAX_PATH_CAPTURE - 1) * sizeof(WCHAR);

        RtlCopyMemory(evt->path, cbd->Iopb->TargetFileObject->FileName.Buffer, name_bytes);
        evt->path_len = name_bytes / sizeof(WCHAR);
    }

    /* File size from I/O status or info class */
    if (event_type == 0) { /* Create — get allocation size */
        evt->file_size_lo = (ULONG)cbd->Iopb->Parameters.Create.AllocationSize.QuadPart;
        evt->file_size_hi = (USHORT)(cbd->Iopb->Parameters.Create.AllocationSize.QuadPart >> 32);
    }

    evt->size = sizeof(AEGIS_FILE_EVENT) - MAX_PATH_CAPTURE * sizeof(WCHAR) + (evt->path_len + 1) * sizeof(WCHAR);
}

/* ─── Pre-Create Callback ─── */
FLT_PREOP_CALLBACK_STATUS aegis_pre_create(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx
)
{
    UNREFERENCED_PARAMETER(flt_obj);

    if (!g_running) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    AEGIS_FILE_EVENT evt;
    USHORT etype = 0; /* create */

    /* Detect delete-on-close */
    if (cbd->Iopb->Parameters.Create.Options & FILE_DELETE_ON_CLOSE)
        etype = 2; /* delete */

    aegis_build_file_event(cbd, etype, &evt);
    aegis_file_ring_write(&evt);

    *completion_ctx = NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* ─── Post-Create Callback (capture actual creation result) ─── */
FLT_POSTOP_CALLBACK_STATUS aegis_post_create(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _In_ PVOID completion_ctx,
    _In_ FLT_POST_OPERATION_FLAGS flags
)
{
    UNREFERENCED_PARAMETER(flt_obj);
    UNREFERENCED_PARAMETER(completion_ctx);
    UNREFERENCED_PARAMETER(flags);

    /* If create succeeded and it was a new file, log as create event */
    if (g_running && NT_SUCCESS(cbd->IoStatus.Status) && cbd->IoStatus.Information == FILE_CREATED) {
        AEGIS_FILE_EVENT evt;
        aegis_build_file_event(cbd, 0, &evt);
        aegis_file_ring_write(&evt);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/* ─── Pre-Write / Set-Info Callback ─── */
FLT_PREOP_CALLBACK_STATUS aegis_pre_write(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx
)
{
    UNREFERENCED_PARAMETER(flt_obj);

    if (!g_running) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    AEGIS_FILE_EVENT evt;
    USHORT etype = 1; /* write by default */

    /* Detect file deletion via FileDispositionInformation */
    if (cbd->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        switch (cbd->Iopb->Parameters.SetFileInformation.FileInformationClass) {
        case FileDispositionInformation:
        case FileDispositionInformationEx:
            etype = 2; /* delete */
            break;
        case FileRenameInformation:
        case FileRenameInformationEx:
            etype = 3; /* rename */
            break;
        default:
            etype = 4; /* metadata change — treat as read/write */
            break;
        }
    }

    aegis_build_file_event(cbd, etype, &evt);
    aegis_file_ring_write(&evt);

    *completion_ctx = NULL;
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ─── Filter Unload ─── */
NTSTATUS aegis_minifilter_unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags,
    _In_ PFLT_INSTANCE instance
)
{
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(instance);

    g_running = FALSE;

    if (g_filter_handle) {
        FltUnregisterFilter(g_filter_handle);
        g_filter_handle = NULL;
    }

    if (g_file_ring) {
        ExFreePoolWithTag(g_file_ring, 'GfmA');
        g_file_ring = NULL;
    }

    DbgPrint("AEGIS Minifilter: Unloaded\n");
    return STATUS_SUCCESS;
}

/* ─── Driver Entry ─── */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path
)
{
    NTSTATUS status;

    /* Allocate file event ring buffer */
    g_file_ring = (AEGIS_FILE_RING*)ExAllocatePoolWithTag(
        NonPagedPool,
        AEGIS_FILE_RING_SIZE + sizeof(AEGIS_FILE_RING_HEADER),
        'GfmA'
    );
    if (!g_file_ring) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_file_ring, AEGIS_FILE_RING_SIZE + sizeof(AEGIS_FILE_RING_HEADER));
    g_file_ring->header.capacity = AEGIS_FILE_RING_SIZE;
    KeInitializeSpinLock(&g_file_ring_lock);

    /* Register minifilter */
    status = FltRegisterFilter(driver_obj, &g_filter_registration, &g_filter_handle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(g_file_ring, 'GfmA');
        return status;
    }

    status = FltStartFiltering(g_filter_handle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_filter_handle);
        ExFreePoolWithTag(g_file_ring, 'GfmA');
        return status;
    }

    g_running = TRUE;
    DbgPrint("AEGIS Minifilter: Started — file ring @ 0x%p\n", g_file_ring);
    return STATUS_SUCCESS;
}
