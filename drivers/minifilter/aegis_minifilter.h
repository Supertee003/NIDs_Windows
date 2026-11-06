/* aegis_minifilter.h - AEGIS NIDS Minifilter Header (C5) */
#ifndef _AEGIS_MINIFILTER_H_
#define _AEGIS_MINIFILTER_H_

#include <fltKernel.h>

/* Altitude from INF: 370000 (Anti-Virus class) */
#define AEGIS_MINIFILTER_ALTITUDE   L"370000"
/* Port name. Must be written with a DOUBLE backslash in source so the
 * runtime string is a single-leading-backslash name ("\AegisMinifilterPort"),
 * matching the user-mode FilterConnectCommunicationPort argument (the WDK
 * minispy sample uses the identical L"\\MiniSpyPort" form). The previous
 * single-backslash form was an invalid escape sequence (MSVC C4129): the
 * backslash was dropped and the registered name had no leading backslash. */
#define AEGIS_FILTER_PORT_NAME      L"\\AegisMinifilterPort"

/* C5: Event types */
#define AEGIS_EVT_FILE              1
#define AEGIS_EVT_PROC_CREATE       2
#define AEGIS_EVT_PROC_EXIT         3

/* C5: Ring buffer.
 * EVT-230 hardening: sized for burst absorption, not demo traffic. The
 * original 64 KiB ring (139 records) overflowed on bursty hosts while the
 * user-mode reader was between pulls; EVT-230 measured cumulative drop
 * ~80%+ on this lab host with the counter non-silent (see EVIDENCE_INDEX
 * EVT-230). 1 MiB = ~2220 records = several seconds of burst headroom at
 * observed peak rates. No wire/layout change: the record struct and the
 * READ_EVENTS contract are unchanged.
 *
 * QLOSS-RING-001 (2026-11-06): once the diagnostic-log backpressure was
 * removed the queue stopped dropping entirely, and the only remaining loss
 * was this ring: 8,627 records shed in 157 s (~55/s) on a host draining
 * ~1,250 records/s, i.e. burst overflow while the reader was mid-pull, not
 * a sustained throughput deficit. 4 MiB absorbs four times the burst with
 * 4 MB non-paged memory and no other change. */
#define AEGIS_RING_SIZE             (4 * 1024 * 1024)

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

/* Ring buffer API (aegis_minifilter_comm.c). Prototypes are mandatory: the
 * file/proc callbacks previously compiled with C4013 ("assuming extern
 * returning int") because this header declared none of these. On x64 that
 * happened to link, but any future signature drift would be silently
 * accepted instead of rejected at compile time. */
NTSTATUS AegisRingInitialize(ULONG size);
VOID     AegisRingDestroy(void);
NTSTATUS AegisRingWriteEvent(ULONG type, ULONG pid, ULONG parentPid,
    NTSTATUS status, PWSTR path);
ULONG    AegisRingReadEvents(PUCHAR outBuf, ULONG outSize);
VOID     AegisRingGetStats(PULONG totalEvents, PULONG droppedEvents,
    PULONG usedBytes, PULONG capacity);

#endif /* _AEGIS_MINIFILTER_H_ */