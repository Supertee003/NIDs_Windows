// =====================================================================
// aegis_minifilter_file.c — Pre-operation callbacks สำหรับ file I/O
// ---------------------------------------------------------------------
//   ดัก IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION
//   ดึง file path แล้วส่ง event ไป user-mode ผ่าน communication port
//
//   ⚠️ กฎ Microsoft สำหรับ Minifilter:
//     - ห้าม fail IRP_MJ_CLEANUP / IRP_MJ_CLOSE — return SUCCESS_NO_CALLBACK
//     - ใช้ FLT_FILE_NAME_NORMALIZED ใน PreCreate เท่านั้น (PostCreate ใช้ OPENED)
//     - อย่า hold spinlock ข้าม callback boundaries
//     - ระวัง re-entrant calls
// =====================================================================

#include "aegis_minifilter.h"

// Maximum path length we'll handle
#define AEGIS_MAX_PATH_CHARS   1024
#define AEGIS_MAX_PATH_BYTES   (AEGIS_MAX_PATH_CHARS * sizeof(WCHAR))

// =====================================================================
// HELPER: Build event header + send to user-mode
// =====================================================================
static NTSTATUS AegisSendFileEvent(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    UINT16 operation)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION name_info = NULL;
    UNICODE_STRING normalized_name;

    // 1. Get normalized file name
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &name_info);
    if (!NT_SUCCESS(status)) return status;

    status = FltParseFileNameInformation(name_info);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(name_info);
        return status;
    }

    normalized_name = name_info->Name;

    // 2. Build AEGIS_EVENT_HEADER
    AEGIS_EVENT_HEADER header = {0};
    header.event_type = AEGIS_EVENT_KERNEL_FILE;
    header.event_size = sizeof(AEGIS_EVENT_HEADER) + normalized_name.Length;
    header.timestamp = KeQueryInterruptTime() * 100;
    header.process_id = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();
    header.path_offset = 0;
    header.path_length = (UINT16)normalized_name.Length;
    header.operation = operation;
    header.payload_length = (UINT16)normalized_name.Length;

    // 3. Send to user-mode
    status = AegisSendEvent(&header, normalized_name.Buffer, normalized_name.Length);

    FltReleaseFileNameInformation(name_info);
    return status;
}

// =====================================================================
// PRE-CREATE CALLBACK
// =====================================================================
FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // Skip if IRQL too high (PostCreate is safer, but PreCreate is fine for path)
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    AegisSendFileEvent(Data, FltObjects, AEGIS_OP_CREATE);

    // Always permit — log only (IDS mode)
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// =====================================================================
// PRE-WRITE CALLBACK
// =====================================================================
FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    AegisSendFileEvent(Data, FltObjects, AEGIS_OP_WRITE);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// =====================================================================
// PRE-SET-INFO CALLBACK (rename / delete)
// =====================================================================
FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Determine operation type from FILE_INFORMATION_CLASS
    UINT16 op = 0;
    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx) {
        op = AEGIS_OP_RENAME;
    } else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
               Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx) {
        op = AEGIS_OP_DELETE;
    } else {
        // Other info class — not interesting, skip
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    AegisSendFileEvent(Data, FltObjects, op);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
