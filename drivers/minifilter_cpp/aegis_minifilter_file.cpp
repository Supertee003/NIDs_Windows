/**
 * aegis_minifilter_file.cpp — AEGIS NIDS File Operation Callbacks (C++ Edition)
 *
 * Pre-operation callbacks for IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION.
 * Uses Aegis::Minifilter::FileNameGuard for RAII file name management and
 * PatternMatcher class for structured rule matching.
 *
 * C++ enhancements over C version:
 *   - FileNameGuard: RAII auto-release for FltGetFileNameInformation
 *   - PatternMatcher::MatchFile(): Structured pattern matching with PatternRule
 *   - PatternRule struct: Maps pattern → ruleId + severity + eventType
 *   - No manual FltReleaseFileNameInformation — RAII handles it
 *   - Cleaner event construction using C++ struct initialization
 *
 * Rules checked (KERNEL_FILE):
 *   R1001: System32 Write Attempt
 *   R1002: Ransomware Rename Pattern
 *   R1003: Startup Folder Modification
 *   R1004: DLL Drop in System32
 *   R1005: hosts File Modification
 */

#include "aegis_minifilter.hpp"

// ====== IRP_MJ_CREATE Pre-operation ======
extern "C" FLT_PREOP_CALLBACK_STATUS AegisPreCreate(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(completionContext);

    using namespace Aegis::Minifilter;

    // RAII FileNameGuard — auto-releases FltReleaseFileNameInformation on scope exit
    FileNameGuard nameGuard;
    NTSTATUS status = nameGuard.Acquire(data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT);

    if (!nameGuard.IsValid()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;  // RAII auto-releases if partially acquired
    }

    // Match against KERNEL_FILE patterns using PatternMatcher class
    const PatternRule* matchedRule = nullptr;
    if (PatternMatcher::MatchFile(nameGuard.Name(), &matchedRule)) {
        DbgPrint("[AEGIS Minifilter] ALERT: File CREATE — Rule %ws severity %d matched by %wZ\n",
            matchedRule->ruleId, matchedRule->severity, nameGuard.Name());

        // Build FileEvent struct (C++ style — zero-init + explicit field assignment)
        FileEvent event = {};
        event.event_type    = matchedRule->eventType;   // From PatternRule (1=KERNEL_FILE)
        event.operation     = IRP_MJ_CREATE;
        event.rule_id       = 0;  // TODO: parse rule ID from string
        event.severity      = matchedRule->severity;     // From PatternRule
        event.process_id    = FltGetRequestorProcessId(data);
        event.timestamp     = KeQueryPerformanceCounter(NULL).QuadPart;

        // TODO: Send via CommPortGuard communication port
    }

    // nameGuard auto-releases via RAII destructor — no FltReleaseFileNameInformation needed!
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ====== IRP_MJ_WRITE Pre-operation ======
extern "C" FLT_PREOP_CALLBACK_STATUS AegisPreWrite(
    PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS fltObjects,
    PVOID* completionContext)
{
    UNREFERENCED_PARAMETER(fltObjects);
    UNREFERENCED_PARAMETER(completionContext);

    using namespace Aegis::Minifilter;

    FileNameGuard nameGuard;
    NTSTATUS status = nameGuard.Acquire(data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT);

    if (!nameGuard.IsValid()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    const PatternRule* matchedRule = nullptr;
    if (PatternMatcher::MatchFile(nameGuard.Name(), &matchedRule)) {
        DbgPrint("[AEGIS Minifilter] ALERT: File WRITE — Rule %ws severity %d matched by %wZ\n",
            matchedRule->ruleId, matchedRule->severity, nameGuard.Name());
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ====== IRP_MJ_SET_INFORMATION Pre-operation ======
extern "C" FLT_PREOP_CALLBACK_STATUS AegisPreSetInfo(
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
extern "C" FLT_POSTOP_CALLBACK_STATUS AegisPostOperation(
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
