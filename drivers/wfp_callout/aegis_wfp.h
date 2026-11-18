/**
 * aegis_wfp.h - AEGIS WFP Callout Driver Shared Header
 *
 * 48-byte AEGIS_EVENT_HEADER (packed; EVT-213 reserved2 aligns the stride
 * with the 8-byte-aligned Zig FFI consumer layout; timestamp @40),
 * IOCTL codes, device names, GUID decl, extern globals,
 * cross-file function declarations.
 *
 * EVT-231: a ring record is the 48-byte header followed by
 * payload_length raw transport payload bytes (bounded by
 * AEGIS_MAX_PAYLOAD_SIZE). Outbound WFP buffers start at the transport
 * header, which the producer strips before writing this field. READ_EVENTS
 * returns whole records only; it never splits one across reads.
 */

#ifndef AEGIS_WFP_H
#define AEGIS_WFP_H

#pragma warning(push)
#pragma warning(disable: 4201)

#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>

#pragma warning(pop)

/* Some WDK header layouts omit this user-mode WFP HRESULT alias. Keep one
 * shared bit-pattern for the kernel recovery path and compare status values
 * as ULONGs so signed/unsigned NTSTATUS representation cannot change the
 * missing-filter decision. */
#ifndef FWP_E_CALLOUT_NOT_FOUND
#define FWP_E_CALLOUT_NOT_FOUND ((NTSTATUS)0x80320001L)
#endif
#ifndef FWP_E_FILTER_NOT_FOUND
#define FWP_E_FILTER_NOT_FOUND ((NTSTATUS)0x80320003L)
#endif
#ifndef FWP_E_PROVIDER_NOT_FOUND
#define FWP_E_PROVIDER_NOT_FOUND ((NTSTATUS)0x80320005L)
#endif
#ifndef FWP_E_ALREADY_EXISTS
#define FWP_E_ALREADY_EXISTS ((NTSTATUS)0x80320009L)
#endif
#ifndef STATUS_FWP_CALLOUT_NOT_FOUND
#define STATUS_FWP_CALLOUT_NOT_FOUND ((NTSTATUS)0xC0220001L)
#endif
#ifndef STATUS_FWP_FILTER_NOT_FOUND
#define STATUS_FWP_FILTER_NOT_FOUND ((NTSTATUS)0xC0220003L)
#endif
#ifndef STATUS_FWP_PROVIDER_NOT_FOUND
#define STATUS_FWP_PROVIDER_NOT_FOUND ((NTSTATUS)0xC0220005L)
#endif
#ifndef STATUS_FWP_ALREADY_EXISTS
#define STATUS_FWP_ALREADY_EXISTS ((NTSTATUS)0xC0220009L)
#endif

/* Kernel-mode WFP returns STATUS_FWP_* while some wrappers expose the
 * user-mode FWP_E_* HRESULT bit-patterns. Both forms describe the same
 * object state; compare through these helpers so a clean startup never
 * mistakes absence for a fatal error. */
static __inline BOOLEAN AegisWfpFilterNotFound(NTSTATUS status)
{
    return status == (NTSTATUS)FWP_E_FILTER_NOT_FOUND ||
           status == STATUS_FWP_FILTER_NOT_FOUND ||
           status == STATUS_NOT_FOUND;
}

static __inline BOOLEAN AegisWfpCalloutNotFound(NTSTATUS status)
{
    return status == (NTSTATUS)FWP_E_CALLOUT_NOT_FOUND ||
           status == STATUS_FWP_CALLOUT_NOT_FOUND ||
           status == STATUS_NOT_FOUND;
}

static __inline BOOLEAN AegisWfpProviderNotFound(NTSTATUS status)
{
    return status == (NTSTATUS)FWP_E_PROVIDER_NOT_FOUND ||
           status == STATUS_FWP_PROVIDER_NOT_FOUND ||
           status == STATUS_NOT_FOUND;
}

static __inline BOOLEAN AegisWfpAlreadyExists(NTSTATUS status)
{
    return status == (NTSTATUS)FWP_E_ALREADY_EXISTS ||
           status == STATUS_FWP_ALREADY_EXISTS;
}

/* Duplicate proof-filter adds are idempotent. The block path derives one
 * stable key per (direction, tuple), so a repeated block can return the
 * filter it already owns instead of minting a second one. */

/* Proof filters are owned by a provider object, not by a single shared
 * filter key. The provider is the ownership marker: a filter matching a
 * proof tuple is only trusted when providerKey is this GUID. It also lets
 * driver restart/unload enumerate every filter this driver minted.
 *
 * AEGIS_PROOF_FILTER_KEY is the retired single-key identity. It remains only
 * so a driver start can remove the stale filter left by an older build. */
#define AEGIS_PROOF_TABLE_CAPACITY 64

/* ====== IOCTL Codes ====== */
#define IOCTL_AEGIS_READ_EVENTS  CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_BLOCK_FLOW   CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_GET_STATS    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_UNBLOCK_FLOW CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_QUERY_FILTER CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_READ_DATA)

/* EVT-231: READ_EVENTS copies whole records only. It stops before the
 * first record that would not fit the caller buffer; a partial record is
 * never consumed and never emitted. */

/* Port-specific enforcement contract. All multi-byte fields use the same
 * host representation across the Rust/C boundary; IPv4 is network order,
 * protocol is IANA (6=TCP, 17=UDP), and port is host-order UINT16.
 *
 * `direction` bit 0 selects the WFP layer. 0 keeps the historical outbound
 * ALE_AUTH_CONNECT_V4 filter (remote_ipv4/remote_port = peer/remote service
 * port). 1 selects inbound ALE_AUTH_RECV_ACCEPT_V4 (remote_ipv4 = peer
 * source address, remote_port = local service port). The byte was previously
 * reserved and the struct remains 8 bytes; the user-mode bridge forwards it
 * unchanged. Unknown direction bits are rejected by the driver. */
#pragma pack(push, 1)
typedef struct _AEGIS_WFP_FLOW_REQUEST {
    UINT32 remote_ipv4;
    UINT16 remote_port;
    UINT8  protocol;
    UINT8  direction;
} AEGIS_WFP_FLOW_REQUEST;

C_ASSERT(sizeof(AEGIS_WFP_FLOW_REQUEST) == 8);

typedef struct _AEGIS_WFP_FLOW_RESPONSE {
    UINT64 filter_id;
    UINT32 provider_status;
} AEGIS_WFP_FLOW_RESPONSE;

typedef struct _AEGIS_WFP_FILTER_QUERY {
    UINT64 filter_id;
    /* 0 = outbound ALE_AUTH_CONNECT_V4; 1 = inbound
     * ALE_AUTH_RECV_ACCEPT_V4. The query must name the layer it is
     * attesting; an 8-byte legacy input defaults to outbound. */
    UINT8  direction;
    UINT8  reserved[7];
} AEGIS_WFP_FILTER_QUERY;

C_ASSERT(sizeof(AEGIS_WFP_FILTER_QUERY) == 16);

typedef struct _AEGIS_WFP_FILTER_STATE {
    UINT64 filter_id;
    UINT32 remote_ipv4;
    UINT16 remote_port;
    UINT8  protocol;
    UINT8  present;
    UINT32 provider_status;
} AEGIS_WFP_FILTER_STATE;
#pragma pack(pop)

/* ====== Device Names ====== */
#define AEGIS_WFP_DEVICE_NAME  L"\\Device\\AegisWfpDevice"
#define AEGIS_WFP_SYMLINK_NAME L"\\DosDevices\\AegisWfpDevice"

/* ====== Ring Buffer ====== */
#define AEGIS_RING_BUFFER_SIZE     (2 * 1024 * 1024)   /* 2 MB */
/* EVT-231: max raw payload bytes copied per record. Records are variable
 * length (48-byte header + payload_length); consumers advance by
 * 48 + payload_length, never a fixed stride. */
#define AEGIS_MAX_PAYLOAD_SIZE     4096
#define AEGIS_MAX_TRANSPORT_HEADER_SIZE 60 /* maximum TCP header with options */
#define AEGIS_MAX_CAPTURE_WINDOW \
    (AEGIS_MAX_PAYLOAD_SIZE + AEGIS_MAX_TRANSPORT_HEADER_SIZE)

/* ====== O1 (plan §26 ทาง A): IPv6 identity sidecar-in-payload ======
 * A record flagged AEGIS_EVENT_FLAG_V6_SIDECAR leads its payload with
 * AEGIS_V6_SIDECAR_SIZE bytes (src16 ++ dst16, raw network order) before
 * the L7 body; payload_length claims sidecar + body and stays
 * <= AEGIS_MAX_PAYLOAD_SIZE (the body budget shrinks by the sidecar).
 * The 48-byte header layout is untouched. The flag is written only when
 * the full 32-byte sidecar is written with it, so the consumer's
 * fail-closed guard (payload_length >= 32 when bit0 set) never trips on
 * a record this driver emits. */
#define AEGIS_EVENT_FLAG_V6_SIDECAR 0x01
#define AEGIS_V6_SIDECAR_SIZE       32  /* src16 (16) ++ dst16 (16) */

/* Ring used-space helper (call under spinlock) */
#define AEGIS_RING_USED() \
    ((g_RingWriteOffset >= g_RingReadOffset) ? \
     (g_RingWriteOffset - g_RingReadOffset) : \
     (g_RingBufferSize - g_RingReadOffset + g_RingWriteOffset))

/* ====== Event Header (48 bytes, packed; EVT-213) ======
 * Explicit reserved2 keeps the packed stride identical to the 8-byte
 * aligned consumer layout (src/policy/wfp_ioctl.zig WfpEventHeader,
 * extern struct): payload_length @20, rule_id @24, timestamp @40,
 * total 48. The previous 44-byte packed stride shifted every record
 * after the first for the 48-byte consumer. Do not shrink. */
#pragma pack(push, 1)
typedef struct _AEGIS_EVENT_HEADER {
    UINT32  event_type;     /* 0=NETWORK, 1=FILE, 2=PROCESS, 3=PIPE */
    UINT32  source_ip;      /* IPv4 source (network byte order) */
    UINT32  dest_ip;        /* IPv4 destination */
    UINT16  source_port;    /* Source port */
    UINT16  dest_port;      /* Destination port */
    UINT8   protocol;       /* 6=TCP, 17=UDP, 1=ICMP */
    UINT8   direction;      /* 0=inbound, 1=outbound */
    UINT8   layer_id;       /* WFP layer ID (low byte) */
    UINT8   flags;          /* O1: bit0 = AEGIS_EVENT_FLAG_V6_SIDECAR; rest reserved */
    UINT32  payload_length; /* EVT-231: payload bytes (0=empty/unavailable/unsupported; <= AEGIS_MAX_PAYLOAD_SIZE) */
    UINT32  rule_id;        /* Matched rule ID (0=none) */
    UINT32  severity;       /* 0=Low 1=Med 2=High 3=Critical */
    UINT32  reserved;       /* Reserved */
    UINT32  reserved2;      /* Reserved - aligns timestamp to @40 (EVT-213) */
    UINT64  timestamp;      /* KeQueryPerformanceCounter */
} AEGIS_EVENT_HEADER;
#pragma pack(pop)
C_ASSERT(sizeof(AEGIS_EVENT_HEADER) == 48);  /* EVT-213: consumer stride */

/* ====== Ring Buffer Statistics (24 bytes, packed; populated since EVT-231) ====== */
#pragma pack(push, 1)
typedef struct _AEGIS_RING_STATS {
    ULONG totalEventsWritten;
    ULONG totalDrops;
    ULONG totalBytesWritten;
    ULONG totalBytesRead;
    ULONG currentUsedBytes;
    ULONG padding;
} AEGIS_RING_STATS;
#pragma pack(pop)

/* ====== GUID (defined via DEFINE_GUID in aegis_wfp.c) ====== */
extern const GUID AEGIS_CALLOUT_KEY;
/* O2 kernel capture: outbound IPv4 transport has its own callout key, runtime
 * id, and capture filter. It shares the inbound ring and 48-byte record; the
 * header direction byte (0=inbound, 1=outbound) is the only discriminator. */
extern const GUID AEGIS_OUTBOUND_CALLOUT_KEY;
/* O1 (plan §26 ทาง A): IPv6 transport capture pairs share the v4 ring and
 * the 48-byte record; header flags bit0 + direction mark the origin. */
extern const GUID AEGIS_INBOUND_V6_CALLOUT_KEY;
extern const GUID AEGIS_OUTBOUND_V6_CALLOUT_KEY;
extern const GUID AEGIS_PROOF_FILTER_KEY;
extern const GUID AEGIS_PROOF_PROVIDER_KEY;

/* ====== Globals (defined in aegis_wfp.c) ====== */
extern PVOID          g_RingBuffer;
extern SIZE_T         g_RingBufferSize;
extern KSPIN_LOCK     g_RingLock;
extern SIZE_T         g_RingWriteOffset;
extern SIZE_T         g_RingReadOffset;
extern PVOID          g_PayloadScratch;
extern ULONG          g_WfpTotalEventsWritten;
extern ULONG          g_WfpTotalDrops;
extern ULONG          g_WfpTotalBytesWritten;
extern ULONG          g_WfpTotalBytesRead;
extern HANDLE         g_WfpEngineHandle;
extern UINT32         g_CalloutId;
extern UINT64         g_CaptureFilterId;
extern UINT32         g_OutboundCalloutId;
extern UINT64         g_OutboundCaptureFilterId;
/* O1 (plan §26 ทาง A): IPv6 transport capture pairs. Zero means the pair
 * was never registered; teardown tolerates any prefix of failures. */
extern UINT32         g_InboundV6CalloutId;
extern UINT64         g_InboundV6FilterId;
extern UINT32         g_OutboundV6CalloutId;
extern UINT64         g_OutboundV6FilterId;
/* Classify-call rundown: unload waits here before the capture filter, runtime
 * callout, engine, or ring is torn down. */
extern EX_RUNDOWN_REF g_CalloutRundown;
extern UINT64         g_ProofFilterId;
extern UINT32         g_BlockedIp;
extern UINT16         g_BlockedPort;
extern UINT8          g_BlockedProtocol;
extern PDEVICE_OBJECT g_DeviceObject;

/* ====== Cross-file declarations ====== */

/* Startup failure stage IDs persisted in the System error log. */
enum {
    AEGIS_STAGE_ENGINE_OPEN = 1,
    AEGIS_STAGE_CALLOUT_ADD = 3,
    AEGIS_STAGE_CALLOUT_REGISTER = 4,
    AEGIS_STAGE_FILTER_ADD = 5,
    AEGIS_STAGE_PROOF_PROVIDER = 6
};

/* aegis_wfp_callout.c — inbound and outbound transport classify callbacks. */
void AegisWfpClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut);
void AegisWfpOutboundClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut);
/* O1 (plan §26 ทาง A): IPv6 transport classify callbacks. Same record and
 * fail-open contract as the v4 pair; layer_id 2=inbound-v6, 3=outbound-v6. */
void AegisWfpInboundV6ClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut);
void AegisWfpOutboundV6ClassifyFn(
    IN const FWPS_INCOMING_VALUES0          *inFixedValues,
    IN const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
    IN OUT void                             *layerData,
    IN const FWPS_FILTER0                   *filter,
    IN UINT64                               flowContext,
    IN OUT FWPS_CLASSIFY_OUT0               *classifyOut);
NTSTATUS AegisWfpRegisterCallout(PDRIVER_OBJECT DriverObject);
VOID     AegisWfpUnregisterCallout(void);
NTSTATUS AegisWfpStartupFailure(ULONG stage, NTSTATUS status);

/* aegis_wfp.c: provider registration + recovery of persistent proof filters.
 * Called after the callout/capture registration succeeds and before any user
 * IOCTL can mint a proof filter. The provider owns only proof filters; the
 * capture filter intentionally has no provider identity. */
NTSTATUS AegisWfpPrepareProofProvider(void);
/* Delete every proof filter this provider owns, the retired fixed-key filter,
 * and the provider itself. Returns the first failure: callers must not report
 * cleanup success when absence of the provider or its filters is unproven.
 * Must run before the engine handle is closed. */
NTSTATUS AegisWfpCleanupProofFilters(void);

#endif /* AEGIS_WFP_H */
