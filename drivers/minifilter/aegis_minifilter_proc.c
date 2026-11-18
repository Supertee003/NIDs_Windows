/**
 * aegis_minifilter_proc.c - Process Notify Callback (C5)
 *
 * C5: Writes PROC_CREATE / PROC_EXIT events to ring buffer.
 */

#include "aegis_minifilter.h"

VOID AegisProcessCallback(
    PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo)
{
    ULONG pidVal;
    ULONG parentPid = 0;
    WCHAR nameBuf[256];

    UNREFERENCED_PARAMETER(process);

    if (!g_EventRing)
        return;

    pidVal = (ULONG)(ULONG_PTR)pid;
    RtlZeroMemory(nameBuf, sizeof(nameBuf));

    if (createInfo) {
        /* PPS_CREATE_NOTIFY_INFO::ParentProcessId is typed HANDLE but is
         * documented as carrying the parent process ID value. Forward it so
         * the user-mode reader can populate canonical parent identity. */
        parentPid = (ULONG)(ULONG_PTR)createInfo->ParentProcessId;

        if (createInfo->ImageFileName &&
            createInfo->ImageFileName->Buffer &&
            createInfo->ImageFileName->Length > 0) {
            ULONG copyLen;
            copyLen = createInfo->ImageFileName->Length / sizeof(WCHAR);
            if (copyLen > 255) copyLen = 255;
            RtlCopyMemory(nameBuf, createInfo->ImageFileName->Buffer,
                copyLen * sizeof(WCHAR));
        }
        AegisRingWriteEvent(AEGIS_EVT_PROC_CREATE, pidVal, parentPid,
            STATUS_SUCCESS, nameBuf);
    } else {
        AegisRingWriteEvent(AEGIS_EVT_PROC_EXIT, pidVal, 0,
            STATUS_SUCCESS, NULL);
    }
}