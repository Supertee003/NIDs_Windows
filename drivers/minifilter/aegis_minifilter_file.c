/**
 * aegis_minifilter_file.c - File System Callbacks (C5)
 *
 * C5: PostCreate writes file event to ring buffer.
 * PreWrite / PreSetInfo: passthrough (future enhancement).
 *
 * FIM-WRITE-INTENT-001: every IRP_MJ_CREATE used to reach the ring, including
 * read-only opens. The path rules (R1001 "System32 Write Attempt", R1005
 * "hosts File Modification") therefore fired on a plain Get-Content. The
 * pre-create callback now classifies the open from DesiredAccess and
 * CreateDisposition and parks a one-bit sentinel in the callback context;
 * the post-op emits only for write/create intent. No record/ABI change.
 */

#include "aegis_minifilter.h"

static BOOLEAN AegisWriteIntent(PFLT_CALLBACK_DATA data)
{
    ACCESS_MASK access;
    ULONG disposition;

    if (data == NULL || data->Iopb == NULL ||
        data->Iopb->Parameters.Create.SecurityContext == NULL)
        return FALSE;

    access = data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    disposition = (data->Iopb->Parameters.Create.Options >> 24) & 0xFF;

    if (access & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                  DELETE | WRITE_DAC | WRITE_OWNER))
        return TRUE;

    switch (disposition) {
    case FILE_SUPERSEDE:
    case FILE_CREATE:
    case FILE_OVERWRITE:
    case FILE_OVERWRITE_IF:
        return TRUE;
    default:
        return FALSE;
    }
}

FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx)
{
    UNREFERENCED_PARAMETER(fltObjects);

    /* One-bit sentinel: the record struct stays unchanged, and the post-op
     * does not touch the (possibly freed) security context. */
    if (ctx != NULL)
        *ctx = AegisWriteIntent(data) ? (PVOID)(ULONG_PTR)1 : NULL;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS AegisPostOperation(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects,
    PVOID ctx, FLT_POST_OPERATION_FLAGS flags)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    WCHAR pathBuf[256];

    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(flags);

    /* FIM-WRITE-INTENT-001: a read-only open carries no sentinel and must
     * not become a "write attempt"/"modification" alert. */
    if (ctx == NULL)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!g_EventRing)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!NT_SUCCESS(data->IoStatus.Status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    status = FltGetFileNameInformation(data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status))
        return FLT_POSTOP_FINISHED_PROCESSING;

    status = FltParseFileNameInformation(nameInfo);
    if (NT_SUCCESS(status) && nameInfo->Name.Length > 0) {
        ULONG copyLen;
        RtlZeroMemory(pathBuf, sizeof(pathBuf));
        copyLen = nameInfo->Name.Length / sizeof(WCHAR);
        if (copyLen > 255) copyLen = 255;
        RtlCopyMemory(pathBuf, nameInfo->Name.Buffer,
            copyLen * sizeof(WCHAR));
        pathBuf[copyLen] = L'\0';

        AegisRingWriteEvent(
            AEGIS_EVT_FILE,
            (ULONG)(ULONG_PTR)PsGetCurrentProcessId(),
            0,
            data->IoStatus.Status,
            pathBuf);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}