/* aegis_minifilter.h - AEGIS NIDS Minifilter Header (C5) */
#ifndef _AEGIS_MINIFILTER_H_
#define _AEGIS_MINIFILTER_H_

#include <fltKernel.h>

/* Altitude from INF: 370000 (Anti-Virus) */
#define AEGIS_MINIFILTER_ALTITUDE   L"370000"
#define AEGIS_FILTER_PORT_NAME      L"\AegisMinifilterPort"

/* C5: Event types */
#define AEGIS_EVT_FILE              1
#define AEGIS_EVT_PROC_CREATE       2
#define AEGIS_EVT_PROC_EXIT         3

/* C5: Ring buffer */
#define AEGIS_RING_SIZE             (64 * 1024)

/* C5: User->Kernel message commands */
#define AEGIS_MSG_READ_EVENTS       1
#define AEGIS_MSG_GET_STATS         2

/* C5: Event record - fixed size for ring buffer */
typedef struct _AEGIS_EVENT_RECORD {
    ULONG           EventType;
    ULONG           Size;
    ULONG           ProcessId;
    ULONG           ParentPid;
    LARGE_INTEGER   Timestamp;
    NTSTATUS        Status;
    USHORT          NameLen;
    WCHAR           Path[220];
} AEGIS_EVENT_RECORD, *PAEGIS_EVENT_RECORD;

/* C5: Ring buffer structure */
typedef struct _AEGIS_RING_BUFFER {
    PUCHAR              Data;
    ULONG               Size;
    volatile ULONG      Head;
    volatile ULONG      Tail;
    volatile ULONG      TotalEvents;
    volatile ULONG      DroppedEvents;
    KSPIN_LOCK          Lock;
} AEGIS_RING_BUFFER, *PAEGIS_RING_BUFFER;

/* C5: Ring used-bytes macro (handles wrap-around) */
#define AEGIS_RING_USED(r) ((r)->Head >= (r)->Tail ? \
    ((r)->Head - (r)->Tail) : ((r)->Size - (r)->Tail + (r)->Head))

/* Globals (defined in aegis_minifilter.c) */
extern PFLT_FILTER        g_FilterHandle;
extern PFLT_PORT          g_ServerPort;
extern PAEGIS_RING_BUFFER g_EventRing;

#endif /* _AEGIS_MINIFILTER_H_ */