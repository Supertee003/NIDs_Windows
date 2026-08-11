/**
 * aegis_pipe_interceptor.c — AEGIS NIDS Named Pipe Interceptor (Layer 1: KERNEL)
 *
 * Minifilter-based Named Pipe interceptor that monitors:
 *   - Creation of Named Pipes (\pipe\*)
 *   - Connections to Named Pipes (IRP_MJ_CREATE on \Device\NamedPipe)
 *   - Writes to Named Pipes (data exfiltration / C2 channels)
 *   - Suspicious pipe names (Cobalt Strike, Meterpreter patterns)
 *
 * This is the THIRD capture vector alongside WFP (network) and
 * file minifilter (file I/O). Events flow into a dedicated ring
 * buffer consumed by the Zig normalization gateway.
 *
 * Build: WDK + MSVC (kernel-mode minifilter)
 * Language: C (strict C11)
 *
 * Copyright (c) 2024 AEGIS NIDS Project
 */

#include <ntddk.h>
#include <fltkernel.h>

/* ─── Constants ─── */
#define AEGIS_PIPE_ALTITUDE     L"370040"
#define AEGIS_PIPE_RING_SIZE    (8 * 1024 * 1024)
#define MAX_PIPE_NAME_LEN      256
#define MAX_PIPE_DATA_CAPTURE  4096

/* ─── Named Pipe Event Types ─── */
#define AEGIS_PIPE_EVENT_CREATE    0
#define AEGIS_PIPE_EVENT_CONNECT   1
#define AEGIS_PIPE_EVENT_WRITE     2
#define AEGIS_PIPE_EVENT_READ      3
#define AEGIS_PIPE_EVENT_CLOSE     4

/* ─── Pipe Risk Flags ─── */
#define AEGIS_PIPE_RISK_NONE             0x00
#define AEGIS_PIPE_RISK_SUSPICIOUS_NAME  0x01
#define AEGIS_PIPE_RISK_CROSS_PROCESS    0x02
#define AEGIS_PIPE_RISK_HIGH_DATA_RATE   0x04
#define AEGIS_PIPE_RISK_ANONYMOUS        0x08

/* ─── Named Pipe Event Record ─── */
#pragma pack(push, 1)
typedef struct _AEGIS_PIPE_EVENT {
    ULONG   size;
    ULONG64 timestamp;
    ULONG   pid;
    ULONG   tid;
    USHORT  event_type;
    USHORT  risk_flags;
    ULONG   creator_pid;
    ULONG   data_len;
    USHORT  pipe_name_len;
    USHORT  _pad;
    WCHAR   pipe_name[MAX_PIPE_NAME_LEN];
    UCHAR   data[MAX_PIPE_DATA_CAPTURE];
} AEGIS_PIPE_EVENT;
#pragma pack(pop)

/* ─── Ring Buffer ─── */
#pragma pack(push, 1)
typedef struct _AEGIS_PIPE_RING_HEADER {
    volatile ULONG write_pos;
    volatile ULONG read_pos;
    ULONG         capacity;
    ULONG         event_count;
    ULONG         dropped_count;
} AEGIS_PIPE_RING_HEADER;
#pragma pack(pop)

typedef struct _AEGIS_PIPE_RING {
    AEGIS_PIPE_RING_HEADER header;
    UCHAR                  data[1];
} AEGIS_PIPE_RING;

/* ─── Known C2 Pipe Name Patterns ─── */
static const WCHAR* g_suspicious_pipe_patterns[] = {
    L"\\pipe\\msagent",
    L"\\pipe\\mserv",
    L"\\pipe\\status_",
    L"\\pipe\\mojo.",
    L"\\pipe\\postex_",
    L"\\pipe\\msf",
    L"\\pipe\\meterpreter",
    L"\\pipe\\backdoor",
    L"\\pipe\\c2",
    L"\\pipe\\cmd",
    L"\\pipe\\remote",
    NULL
};

/* ─── Globals ─── */
static AEGIS_PIPE_RING* g_pipe_ring = NULL;
static KSPIN_LOCK       g_pipe_ring_lock = {0};
static BOOLEAN          g_running = FALSE;

/* ─── Pipe Creator PID Tracking ─── */
#define PIPE_CREATOR_TABLE_SIZE 256
typedef struct _PIPE_CREATOR_ENTRY {
    WCHAR   name[MAX_PIPE_NAME_LEN];
    ULONG   creator_pid;
    ULONG64 create_time;
    struct _PIPE_CREATOR_ENTRY* next;
} PIPE_CREATOR_ENTRY;

static PIPE_CREATOR_ENTRY* g_creator_table[PIPE_CREATOR_TABLE_SIZE] = {NULL};
static KSPIN_LOCK          g_creator_lock = {0};

/* ─── Forward declarations ─── */
FLT_PREOP_CALLBACK_STATUS aegis_pipe_pre_create(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx
);
FLT_POSTOP_CALLBACK_STATUS aegis_pipe_post_create(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _In_ PVOID completion_ctx,
    _In_ FLT_POST_OPERATION_FLAGS flags
);
FLT_PREOP_CALLBACK_STATUS aegis_pipe_pre_write(
    _Inout_ PFLT_CALLBACK_DATA cbd,
    _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx
);

/* ─── Callback Table ─── */
static const FLT_OPERATION_REGISTRATION g_pipe_callbacks[] = {
    { IRP_MJ_CREATE, 0, aegis_pipe_pre_create, aegis_pipe_post_create },
    { IRP_MJ_WRITE,  0, aegis_pipe_pre_write,  NULL },
    { IRP_MJ_READ,   0, aegis_pipe_pre_write,  NULL },
    { IRP_MJ_CLEANUP, 0, aegis_pipe_pre_create, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION g_pipe_contexts[] = { { FLT_CONTEXT_END } };

static const FLT_REGISTRATION g_pipe_filter_registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0,
    NULL, g_pipe_callbacks, aegis_pipe_interceptor_unload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static PFLT_FILTER g_pipe_filter_handle = NULL;

/* ─── Helpers ─── */

static BOOLEAN aegis_is_named_pipe(_In_ PFLT_CALLBACK_DATA cbd)
{
    if (!cbd->Iopb->TargetFileObject) return FALSE;
    PUNICODE_STRING name = &cbd->Iopb->TargetFileObject->FileName;
    if (name->Length < 6 * sizeof(WCHAR)) return FALSE;
    return (name->Buffer[0] == L'\\' && name->Buffer[1] == L'p' &&
            name->Buffer[2] == L'i' && name->Buffer[3] == L'p' &&
            name->Buffer[4] == L'e' && name->Buffer[5] == L'\\');
}

static VOID aegis_extract_pipe_name(
    _In_ PFLT_CALLBACK_DATA cbd, _Out_ WCHAR* out_name, _Out_ USHORT* out_len)
{
    *out_len = 0; out_name[0] = L'\0';
    if (!cbd->Iopb->TargetFileObject) return;
    PUNICODE_STRING name = &cbd->Iopb->TargetFileObject->FileName;
    USHORT copy_len = name->Length / sizeof(WCHAR);
    if (copy_len >= MAX_PIPE_NAME_LEN) copy_len = MAX_PIPE_NAME_LEN - 1;
    RtlCopyMemory(out_name, name->Buffer, copy_len * sizeof(WCHAR));
    out_name[copy_len] = L'\0';
    *out_len = copy_len;
}

static USHORT aegis_check_pipe_risk(_In_ const WCHAR* pipe_name, _In_ USHORT name_len)
{
    USHORT risk = AEGIS_PIPE_RISK_NONE;
    for (ULONG i = 0; g_suspicious_pipe_patterns[i] != NULL; i++) {
        const WCHAR* pat = g_suspicious_pipe_patterns[i];
        ULONG pat_len = 0;
        while (pat[pat_len]) pat_len++;
        if (name_len >= pat_len) {
            BOOLEAN match = TRUE;
            for (ULONG j = 0; j < pat_len; j++) {
                WCHAR a = pipe_name[j], b = pat[j];
                if (a >= L'A' && a <= L'Z') a += (L'a' - L'A');
                if (b >= L'A' && b <= L'Z') b += (L'a' - L'A');
                if (a != b) { match = FALSE; break; }
            }
            if (match) { risk |= AEGIS_PIPE_RISK_SUSPICIOUS_NAME; break; }
        }
    }
    if (name_len <= 7) risk |= AEGIS_PIPE_RISK_ANONYMOUS;
    return risk;
}

static ULONG aegis_pipe_name_hash(_In_ const WCHAR* name, _In_ USHORT len)
{
    ULONG hash = 5381;
    for (USHORT i = 0; i < len; i++) hash = ((hash << 5) + hash) + (ULONG)name[i];
    return hash % PIPE_CREATOR_TABLE_SIZE;
}

static VOID aegis_track_pipe_creator(_In_ const WCHAR* name, _In_ USHORT len, _In_ ULONG pid)
{
    KIRQL old_irql;
    KeAcquireSpinLock(&g_creator_lock, &old_irql);
    ULONG idx = aegis_pipe_name_hash(name, len);
    PIPE_CREATOR_ENTRY* e = (PIPE_CREATOR_ENTRY*)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(PIPE_CREATOR_ENTRY), 'CpaA');
    if (e) {
        RtlCopyMemory(e->name, name, (len + 1) * sizeof(WCHAR));
        e->creator_pid = pid;
        e->create_time = KeQueryPerformanceCounter(NULL).QuadPart;
        e->next = g_creator_table[idx];
        g_creator_table[idx] = e;
    }
    KeReleaseSpinLock(&g_creator_lock, old_irql);
}

static ULONG aegis_lookup_pipe_creator(_In_ const WCHAR* name, _In_ USHORT len)
{
    KIRQL old_irql; ULONG pid = 0;
    KeAcquireSpinLock(&g_creator_lock, &old_irql);
    ULONG idx = aegis_pipe_name_hash(name, len);
    for (PIPE_CREATOR_ENTRY* e = g_creator_table[idx]; e; e = e->next) {
        if (wcsncmp(e->name, name, len) == 0) { pid = e->creator_pid; break; }
    }
    KeReleaseSpinLock(&g_creator_lock, old_irql);
    return pid;
}

/* ─── Ring Write ─── */
static BOOLEAN aegis_pipe_ring_write(_In_ const AEGIS_PIPE_EVENT* evt)
{
    KIRQL old_irql; ULONG total = evt->size;
    KeAcquireSpinLock(&g_pipe_ring_lock, &old_irql);
    ULONG wp = g_pipe_ring->header.write_pos;
    ULONG rp = g_pipe_ring->header.read_pos;
    ULONG cap = g_pipe_ring->header.capacity;
    ULONG free = (wp >= rp) ? (cap - (wp - rp) - 1) : (rp - wp - 1);
    if (free < total) {
        g_pipe_ring->header.dropped_count++;
        KeReleaseSpinLock(&g_pipe_ring_lock, old_irql);
        return FALSE;
    }
    if (wp + total <= cap) {
        RtlCopyMemory(&g_pipe_ring->data[wp], evt, total);
    } else {
        ULONG c1 = cap - wp;
        RtlCopyMemory(&g_pipe_ring->data[wp], evt, c1);
        RtlCopyMemory(&g_pipe_ring->data[0], (UCHAR*)evt + c1, total - c1);
    }
    KeMemoryBarrier();
    g_pipe_ring->header.write_pos = (wp + total) % cap;
    g_pipe_ring->header.event_count++;
    KeReleaseSpinLock(&g_pipe_ring_lock, old_irql);
    return TRUE;
}

/* ─── Build Pipe Event ─── */
static VOID aegis_build_pipe_event(
    _In_ PFLT_CALLBACK_DATA cbd, _In_ USHORT etype,
    _In_ USHORT risk, _Out_ AEGIS_PIPE_EVENT* evt)
{
    RtlZeroMemory(evt, sizeof(AEGIS_PIPE_EVENT));
    evt->timestamp   = KeQueryPerformanceCounter(NULL).QuadPart;
    evt->pid         = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt->tid         = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    evt->event_type  = etype;
    evt->risk_flags  = risk;
    aegis_extract_pipe_name(cbd, evt->pipe_name, &evt->pipe_name_len);
    if (evt->pipe_name_len > 0) {
        evt->creator_pid = aegis_lookup_pipe_creator(evt->pipe_name, evt->pipe_name_len);
        if (evt->creator_pid != 0 && evt->creator_pid != evt->pid &&
            etype == AEGIS_PIPE_EVENT_CONNECT)
            evt->risk_flags |= AEGIS_PIPE_RISK_CROSS_PROCESS;
    }
    evt->size = sizeof(AEGIS_PIPE_EVENT) -
                (MAX_PIPE_NAME_LEN - (evt->pipe_name_len + 1)) * sizeof(WCHAR) -
                (MAX_PIPE_DATA_CAPTURE - evt->data_len);
}

/* ─── Callbacks ─── */

FLT_PREOP_CALLBACK_STATUS aegis_pipe_pre_create(
    _Inout_ PFLT_CALLBACK_DATA cbd, _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx)
{
    UNREFERENCED_PARAMETER(flt_obj);
    if (!g_running || !aegis_is_named_pipe(cbd)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    AEGIS_PIPE_EVENT evt;
    USHORT etype = (cbd->Iopb->MajorFunction == IRP_MJ_CLEANUP) ?
        AEGIS_PIPE_EVENT_CLOSE : AEGIS_PIPE_EVENT_CONNECT;

    aegis_build_pipe_event(cbd, etype, 0, &evt);
    if (evt.pipe_name_len > 0)
        evt.risk_flags |= aegis_check_pipe_risk(evt.pipe_name, evt.pipe_name_len);
    if (etype == AEGIS_PIPE_EVENT_CREATE)
        aegis_track_pipe_creator(evt.pipe_name, evt.pipe_name_len, evt.pid);

    aegis_pipe_ring_write(&evt);
    *completion_ctx = NULL;
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS aegis_pipe_post_create(
    _Inout_ PFLT_CALLBACK_DATA cbd, _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _In_ PVOID completion_ctx, _In_ FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(flt_obj); UNREFERENCED_PARAMETER(completion_ctx);
    UNREFERENCED_PARAMETER(flags);
    if (!g_running || !aegis_is_named_pipe(cbd)) return FLT_POSTOP_FINISHED_PROCESSING;

    if (NT_SUCCESS(cbd->IoStatus.Status)) {
        AEGIS_PIPE_EVENT evt;
        USHORT etype = (cbd->IoStatus.Information == FILE_CREATED) ?
            AEGIS_PIPE_EVENT_CREATE : AEGIS_PIPE_EVENT_CONNECT;
        aegis_build_pipe_event(cbd, etype, 0, &evt);
        if (evt.pipe_name_len > 0)
            evt.risk_flags |= aegis_check_pipe_risk(evt.pipe_name, evt.pipe_name_len);
        if (etype == AEGIS_PIPE_EVENT_CREATE)
            aegis_track_pipe_creator(evt.pipe_name, evt.pipe_name_len, evt.pid);
        aegis_pipe_ring_write(&evt);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS aegis_pipe_pre_write(
    _Inout_ PFLT_CALLBACK_DATA cbd, _In_ PCFLT_RELATED_OBJECTS flt_obj,
    _Outptr_result_maybenull_ PVOID* completion_ctx)
{
    UNREFERENCED_PARAMETER(flt_obj);
    if (!g_running || !aegis_is_named_pipe(cbd)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    AEGIS_PIPE_EVENT evt;
    USHORT etype = (cbd->Iopb->MajorFunction == IRP_MJ_WRITE) ?
        AEGIS_PIPE_EVENT_WRITE : AEGIS_PIPE_EVENT_READ;
    aegis_build_pipe_event(cbd, etype, 0, &evt);

    if (cbd->Iopb->MajorFunction == IRP_MJ_WRITE) {
        PMDL mdl = cbd->Iopb->Parameters.Write.MdlAddress;
        if (mdl) {
            ULONG dlen = cbd->Iopb->Parameters.Write.Length;
            if (dlen > MAX_PIPE_DATA_CAPTURE) dlen = MAX_PIPE_DATA_CAPTURE;
            PVOID buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (buf) { RtlCopyMemory(evt.data, buf, dlen); evt.data_len = dlen; }
        }
    }
    if (evt.pipe_name_len > 0)
        evt.risk_flags |= aegis_check_pipe_risk(evt.pipe_name, evt.pipe_name_len);
    aegis_pipe_ring_write(&evt);

    *completion_ctx = NULL;
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ─── Unload ─── */
NTSTATUS aegis_pipe_interceptor_unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags, _In_ PFLT_INSTANCE instance)
{
    UNREFERENCED_PARAMETER(flags); UNREFERENCED_PARAMETER(instance);
    g_running = FALSE;
    if (g_pipe_filter_handle) { FltUnregisterFilter(g_pipe_filter_handle); g_pipe_filter_handle = NULL; }
    if (g_pipe_ring) { ExFreePoolWithTag(g_pipe_ring, 'PpaA'); g_pipe_ring = NULL; }
    for (ULONG i = 0; i < PIPE_CREATOR_TABLE_SIZE; i++) {
        PIPE_CREATOR_ENTRY* e = g_creator_table[i];
        while (e) { PIPE_CREATOR_ENTRY* n = e->next; ExFreePoolWithTag(e, 'CpaA'); e = n; }
        g_creator_table[i] = NULL;
    }
    DbgPrint("AEGIS Pipe Interceptor: Unloaded\n");
    return STATUS_SUCCESS;
}

/* ─── Driver Entry ─── */
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driver_obj, _In_ PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);
    NTSTATUS status;

    g_pipe_ring = (AEGIS_PIPE_RING*)ExAllocatePoolWithTag(
        NonPagedPool, AEGIS_PIPE_RING_SIZE + sizeof(AEGIS_PIPE_RING_HEADER), 'PpaA');
    if (!g_pipe_ring) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_pipe_ring, AEGIS_PIPE_RING_SIZE + sizeof(AEGIS_PIPE_RING_HEADER));
    g_pipe_ring->header.capacity = AEGIS_PIPE_RING_SIZE;
    KeInitializeSpinLock(&g_pipe_ring_lock);
    KeInitializeSpinLock(&g_creator_lock);

    status = FltRegisterFilter(driver_obj, &g_pipe_filter_registration, &g_pipe_filter_handle);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(g_pipe_ring, 'PpaA'); return status; }

    status = FltStartFiltering(g_pipe_filter_handle);
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(g_pipe_filter_handle); ExFreePoolWithTag(g_pipe_ring, 'PpaA'); return status; }

    g_running = TRUE;
    DbgPrint("AEGIS Pipe Interceptor: Started — pipe ring @ 0x%p\n", g_pipe_ring);
    return STATUS_SUCCESS;
}
