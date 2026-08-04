@@ -0,0 +1,76 @@
/**
 * aegis_minifilter_proc.c — AEGIS NIDS Process Create/Exit Notification Callback
 *
 * Uses PsSetCreateProcessNotifyRoutineEx to monitor process creation and exit.
 * Checks against KERNEL_PROCESS layer rules:
 *   R2001: Mimikatz Execution
 *   R2002: svchost Process Hollowing
 *   R2003: PowerShell Cradle Download
 *   R2004: certutil Download Abuse
 *   R2005: procdump Credential Harvest
 */

#include "aegis_minifilter.h"

// ====== Suspicious process patterns ======
static const WCHAR* SUSPICIOUS_PROCESS_PATTERNS[] = {
    L"mimikatz",      // R2001
    L"procdump",      // R2005
    L"certutil",      // R2004
    NULL
};

static const WCHAR* SUSPICIOUS_PROCESS_RULES[] = {
    L"R2001", L"R2005", L"R2004",
    NULL
};

// ====== Process Create/Exit Callback ======
VOID AegisProcessCallback(
    PEPROCESS process,
    HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(process);

    if (createInfo != NULL) {
        // Process is being CREATED
        DbgPrint("[AEGIS Minifilter] Process CREATE: PID=%d Image=%ws CmdLine=%ws\n",
            (ULONG)(ULONG_PTR)processId,
            createInfo->ImageFileName ? createInfo->ImageFileName->Buffer : L"Unknown",
            createInfo->CommandLine ? createInfo->CommandLine->Buffer : L"");

        // Check against suspicious process patterns
        if (createInfo->ImageFileName && createInfo->ImageFileName->Buffer) {
            for (int i = 0; SUSPICIOUS_PROCESS_PATTERNS[i] != NULL; i++) {
                if (wcsstr(createInfo->ImageFileName->Buffer, SUSPICIOUS_PROCESS_PATTERNS[i])) {
                    DbgPrint("[AEGIS Minifilter] ALERT: Suspicious process — Rule %ws matched: %ws\n",
                        SUSPICIOUS_PROCESS_RULES[i], createInfo->ImageFileName->Buffer);

                    // Create event for user-mode Zig reader
                    AEGIS_FILE_EVENT event = {0};
                    event.event_type = 2;      // KERNEL_PROCESS
                    event.operation = AEGIS_PROCESS_CREATE;
                    event.process_id = (UINT32)(ULONG_PTR)processId;
                    event.severity = 3;        // Critical
                    event.timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
                    // TODO: Send via communication port
                    break;
                }
            }
        }

        // Check PowerShell cradle (R2003) — command line contains IEX/DownloadString
        if (createInfo->CommandLine && createInfo->CommandLine->Buffer) {
            if (wcsstr(createInfo->CommandLine->Buffer, L"IEX") ||
                wcsstr(createInfo->CommandLine->Buffer, L"DownloadString") ||
                wcsstr(createInfo->CommandLine->Buffer, L"DownloadFile")) {
                DbgPrint("[AEGIS Minifilter] ALERT: PowerShell Cradle — R2003 PID=%d\n",
                    (ULONG)(ULONG_PTR)processId);
            }
        }
    } else {
        // Process is EXITING
        DbgPrint("[AEGIS Minifilter] Process EXIT: PID=%d\n", (ULONG)(ULONG_PTR)processId);
    }
}
