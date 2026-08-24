/**
 * aegis_minifilter_file.c - File System Callbacks (C5)
 *
 * C5: PostCreate writes file event to ring buffer.
 * PreWrite / PreSetInfo: passthrough (future enhancement).
 */

#include "aegis_minifilter.h"

FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS fltObjects, PVOID* ctx)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(ctx);
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
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(flags);

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