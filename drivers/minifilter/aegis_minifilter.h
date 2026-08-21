/**
 * aegis_minifilter.h â€” AEGIS NIDS Minifilter Driver Shared Header
 *
 * Defines shared structures between kernel-mode minifilter driver
 * and user-mode Zig reader (minifilter_reader.zig) via FilterCommunicationPort.
 *
 * Architecture: Kernel-mode C++ driver (KERNEL_FILE/KERNEL_PROCESS layer
 * of 3-Layer Architecture)
 *
 * Monitors:
 *   - File operations: IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION
 *   - Process creation/exit: PsSetCreateProcessNotifyRoutineEx
 *   - Communication via FilterCommunicationPort kernelâ†’user mode
 */

#ifndef AEGIS_MINIFILTER_H
#define AEGIS_MINIFILTER_H

#include <fltKernel.h>

// ====== Minifilter Altitude ======
// 370000 = FSFilter Anti-Virus (between HSM and Encryption)
#define AEGIS_MINIFILTER_ALTITUDE  L"370000"

// ====== AEGIS File/Process Event ======
#pragma pack(push, 1)
typedef struct _AEGIS_FILE_EVENT {
    UINT32  event_type;     // 1=KERNEL_FILE, 2=KERNEL_PROCESS
    UINT32  operation;      // IRP_MJ_CREATE, IRP_MJ_WRITE, etc. or PROCESS_CREATE/EXIT
    UINT32  file_name_len;  // Length of file name string following this header
    UINT32  process_id;     // PID of the process performing the operation
    UINT32  rule_id;        // Matched rule ID (0 if no match yet)
    UINT32  severity;       // 0=Low, 1=Medium, 2=High, 3=Critical
    UINT32  reserved;
    UINT64  timestamp;      // Event timestamp
} AEGIS_FILE_EVENT;
#pragma pack(pop)

// ====== Process Event Types ======
#define AEGIS_PROCESS_CREATE    0x100
#define AEGIS_PROCESS_EXIT      0x101

// ====== Communication Port ======
#define AEGIS_FILTER_PORT_NAME  L"\\AegisMinifilterPort"

// ====== Max message sizes ======
#define AEGIS_MAX_MSG_SIZE      4096
#define AEGIS_MAX_FILE_NAME     260


/* Global filter handle (defined in aegis_minifilter.c) */
extern PFLT_FILTER g_FilterHandle;

#endif // AEGIS_MINIFILTER_H
