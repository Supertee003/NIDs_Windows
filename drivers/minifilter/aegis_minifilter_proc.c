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
    WCHAR nameBuf[256];

    UNREFERENCED_PARAMETER(process);

    if (!g_EventRing)
        return;

    pidVal = (ULONG)(ULONG_PTR)pid;
    RtlZeroMemory(nameBuf, sizeof(nameBuf));

    if (createInfo) {
        if (createInfo->ImageFileName &&
            createInfo->ImageFileName->Buffer &&
            createInfo->ImageFileName->Length > 0) {
            ULONG copyLen;
            copyLen = createInfo->ImageFileName->Length / sizeof(WCHAR);
            if (copyLen > 255) copyLen = 255;
            RtlCopyMemory(nameBuf, createInfo->ImageFileName->Buffer,
                copyLen * sizeof(WCHAR));
        }
        AegisRingWriteEvent(AEGIS_EVT_PROC_CREATE, pidVal, 0,
            STATUS_SUCCESS, nameBuf);
    } else {
        AegisRingWriteEvent(AEGIS_EVT_PROC_EXIT, pidVal, 0,
            STATUS_SUCCESS, NULL);
    }
}