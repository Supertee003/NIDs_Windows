/**
 * aegis_minifilter_proc.cpp — AEGIS NIDS Process Notification (C++ Edition)
 *
 * Uses PsSetCreateProcessNotifyRoutineEx to monitor process creation/exit.
 * PatternMatcher::MatchProcess() and MatchCommandLine() provide structured
 * rule matching against KERNEL_PROCESS patterns.
 *
 * C++ enhancements:
 *   - PatternMatcher class: Structured pattern → rule mapping
 *   - PatternRule struct: Each pattern maps to ruleId, severity, eventType
 *   - C++ struct initialization for FileEvent (zero-init + field assignment)
 *   - Cleaner flow control with early-return pattern
 *
 * Rules checked (KERNEL_PROCESS):
 *   R2001: Mimikatz Execution
 *   R2002: svchost Process Hollowing
 *   R2003: PowerShell Cradle Download
 *   R2004: certutil Download Abuse
 *   R2005: procdump Credential Harvest
 */

#include "aegis_minifilter.hpp"

// ====== Process Create/Exit Callback (extern "C" for WDK) ======
extern "C" VOID AegisProcessCallback(
    PEPROCESS process,
    HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo)
{
    UNREFERENCED_PARAMETER(process);
    using namespace Aegis::Minifilter;

    if (createInfo != nullptr) {
        // ====== Process is being CREATED ======
        DbgPrint("[AEGIS Minifilter] Process CREATE: PID=%d Image=%ws CmdLine=%ws\n",
            static_cast<ULONG>(static_cast<ULONG_PTR>(processId)),
            createInfo->ImageFileName ? createInfo->ImageFileName->Buffer : L"Unknown",
            createInfo->CommandLine ? createInfo->CommandLine->Buffer : L"");

        // Check against suspicious process patterns (KERNEL_PROCESS rules)
        if (createInfo->ImageFileName && createInfo->ImageFileName->Buffer) {
            const PatternRule* matchedRule = nullptr;
            if (PatternMatcher::MatchProcess(createInfo->ImageFileName, &matchedRule)) {
                DbgPrint("[AEGIS Minifilter] ALERT: Suspicious process — Rule %ws severity %d: %ws\n",
                    matchedRule->ruleId, matchedRule->severity,
                    createInfo->ImageFileName->Buffer);

                // Build FileEvent (C++ struct — even for process events, same layout)
                FileEvent event = {};
                event.event_type    = matchedRule->eventType;   // 2=KERNEL_PROCESS
                event.operation     = kProcessCreate;
                event.process_id    = static_cast<UINT32>(static_cast<ULONG_PTR>(processId));
                event.severity      = matchedRule->severity;
                event.timestamp     = KeQueryPerformanceCounter(nullptr).QuadPart;

                // TODO: Send via CommPortGuard communication port
            }
        }

        // Check PowerShell cradle (R2003) — command line contains IEX/DownloadString
        if (createInfo->CommandLine && createInfo->CommandLine->Buffer) {
            const PatternRule* matchedRule = nullptr;
            if (PatternMatcher::MatchCommandLine(createInfo->CommandLine, &matchedRule)) {
                DbgPrint("[AEGIS Minifilter] ALERT: PowerShell Cradle — Rule %ws PID=%d\n",
                    matchedRule->ruleId, static_cast<ULONG>(static_cast<ULONG_PTR>(processId)));
            }
        }
    } else {
        // ====== Process is EXITING ======
        DbgPrint("[AEGIS Minifilter] Process EXIT: PID=%d\n",
            static_cast<ULONG>(static_cast<ULONG_PTR>(processId)));
    }
}
