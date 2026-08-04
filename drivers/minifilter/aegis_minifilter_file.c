@@ -0,0 +1,145 @@
/**
 * aegis_minifilter_file.c — AEGIS NIDS Minifilter File Operation Callbacks
 *
 * Pre-operation callbacks for IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION.
 * Extracts file path and operation details, then sends to communication port
 * for user-mode Zig minifilter_reader to process.
 *
 * Checks against KERNEL_FILE layer rules:
 *   R1001: System32 Write Attempt
 *   R1002: Ransomware Rename Pattern
 *   R1003: Startup Folder Modification
 *   R1004: DLL Drop in System32
 *   R1005: hosts File Modification
 */

#include "aegis_minifilter.h"

// ====== Suspicious file patterns (from Rules.json KERNEL_FILE rules) ======
static const WCHAR* SUSPICIOUS_FILE_PATTERNS[] = {
    L"\\Windows\\System32",       // R1001: System32 write
    L".locked",                   // R1002: Ransomware rename
    L".encrypted",                // R1002: Ransomware variant
    L"\\Startup\\",               // R1003: Startup folder
    L".dll",                      // R1004: DLL drop
    L"\\hosts",                   // R1005: hosts file
    NULL
};

static const WCHAR* SUSPICIOUS_RULE_IDS[] = {
    L"R1001", L"R1002", L"R1002", L"R1003", L"R1004", L"R1005",
    NULL
};

// ====== Check if file name matches suspicious pattern ======
static BOOLEAN IsSuspiciousFileName(PUNICODE_STRING fileName, PWSTR* matchedRuleId)
{
    if (!fileName || !fileName->Buffer) return FALSE;

    for (int i = 0; SUSPICIOUS_FILE_PATTERNS[i] != NULL; i++) {
        if (wcsstr(fileName->Buffer, SUSPICIOUS_FILE_PATTERNS[i]) != NULL) {
            *matchedRuleId = SUSPICIOUS_RULE_IDS[i];
            return TRUE;
        }
    }
    return FALSE;
}

// ====== IRP_MJ_CREATE Pre-operation ======
FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(completionContext);

    // Get file name information
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            PWSTR matchedRule = NULL;
            if (IsSuspiciousFileName(&nameInfo->Name, &matchedRule)) {
                DbgPrint("[AEGIS Minifilter] ALERT: File CREATE — Rule %wZ matched by %ws\n",
                    matchedRule, nameInfo->Name.Buffer);

                // Send event to communication port for Zig reader
                AEGIS_FILE_EVENT event = {0};
                event.event_type = 1;      // KERNEL_FILE
                event.operation = IRP_MJ_CREATE;
                event.process_id = FltGetRequestorProcessId(data);
                event.severity = 3;        // Critical (most KERNEL_FILE alerts are critical)
                event.timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

                // TODO: Send via communication port (AegisMinifilterPort)
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ====== IRP_MJ_WRITE Pre-operation ======
FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(completionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        status = FltParseFileNameInformation(nameInfo);
        if (NT_SUCCESS(status)) {
            PWSTR matchedRule = NULL;
            if (IsSuspiciousFileName(&nameInfo->Name, &matchedRule)) {
                DbgPrint("[AEGIS Minifilter] ALERT: File WRITE — Rule %ws matched by %ws\n",
                    matchedRule, nameInfo->Name.Buffer);
            }
        }
        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ====== IRP_MJ_SET_INFORMATION Pre-operation ======
FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(completionContext);

    // Check for file rename operations (ransomware pattern R1002)
    if (data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation) {
        DbgPrint("[AEGIS Minifilter] File RENAME detected — PID: %d\n",
            FltGetRequestorProcessId(data));
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ====== Post-operation (unused for now) ======
FLT_POSTOP_CALLBACK_STATUS AegisPostOperation(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID completionContext,
    FLT_POST_OPERATION_FLAGS flags)
{
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(completionContext);
    UNREFERENCED_PARAMETER(flags);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
