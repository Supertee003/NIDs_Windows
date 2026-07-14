// =====================================================================
// aegis_minifilter_proc.c — Process creation/exit notification
// ---------------------------------------------------------------------
//   ลงทะเบียนผ่าน PsSetCreateProcessNotifyRoutineEx
//   ถูกเรียกทุกครั้งที่มี process ถูกสร้างหรือ exit
//
//   CreateInfo != NULL → process created → ดึง image path + parent PID
//   CreateInfo == NULL → process exiting
// =====================================================================

#include "aegis_minifilter.h"

// =====================================================================
// PROCESS NOTIFY CALLBACK
// =====================================================================
VOID AegisProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    AEGIS_EVENT_HEADER header = {0};
    header.event_type = AEGIS_EVENT_KERNEL_PROCESS;
    header.timestamp = KeQueryInterruptTime() * 100;
    header.process_id = (UINT32)(ULONG_PTR)ProcessId;

    if (CreateInfo != NULL) {
        // === Process created ===
        header.operation = AEGIS_OP_CREATE;

        // ImageFileName is a UNICODE_STRING
        if (CreateInfo->ImageFileName) {
            header.path_offset = 0;
            header.path_length = (UINT16)CreateInfo->ImageFileName->Length;
            header.payload_length = header.path_length;
            header.event_size = sizeof(AEGIS_EVENT_HEADER) + header.path_length;

            AegisSendEvent(&header,
                CreateInfo->ImageFileName->Buffer,
                CreateInfo->ImageFileName->Length);
        }
    } else {
        // === Process exiting ===
        header.operation = AEGIS_OP_DELETE;
        header.event_size = sizeof(AEGIS_EVENT_HEADER);
        header.path_length = 0;
        AegisSendEvent(&header, NULL, 0);
    }
}
