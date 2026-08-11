/**
 * aegis_wfp.c — AEGIS NIDS WFP Callout Driver (Layer 1: KERNEL)
 *
 * Windows Filtering Platform callout driver that intercepts network traffic
 * at AUTH_CONNECT/AUTH_RECV_ACCEPT layers and copies packet data into a
 * shared ring buffer for consumption by the Zig capture layer.
 *
 * Build: WDK + MSVC (kernel-mode)
 * Language: C (strict C11, no C++ features)
 *
 * Copyright (c) 2024 AEGIS NIDS Project
 */

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <ndis.h>

/* ─── Constants ─── */
#define AEGIS_WFP_DEVICE_NAME  L"\\Device\\AegisWfp"
#define AEGIS_WFP_SYMLINK_NAME L"\\DosDevices\\AegisWfp"
#define AEGIS_SUBLAYER_NAME    L"AEGIS NIDS Inspection SubLayer"
#define AEGIS_CALLOUT_NAME     L"AEGIS NIDS Packet Callout"
#define AEGIS_FILTER_NAME      L"AEGIS NIDS Packet Filter"

#define RING_BUF_SIZE          (64 * 1024 * 1024)  /* 64 MiB shared ring buffer */
#define MAX_PACKET_COPY        4096                 /* Max bytes to copy per packet (FIXED: was 65535 on stack!) */
#define AEGIS_CALLOUT_PRIORITY 0                     /* Inspect before other callouts */

/* ─── Semi-NIDS: Adaptive Drop Thresholds (Property 1 & 2) ─── */
/* These are read from userspace via IOCTL and control the kernel-level drop decision */
#define SEMI_NIDS_DEFAULT_BLOCK_THRESHOLD     60    /* Score >= 60 + High confidence = Block */
#define SEMI_NIDS_DEFAULT_RATELIMIT_THRESHOLD 40    /* Score >= 40 + Med confidence = Rate limit */
#define SEMI_NIDS_DEFAULT_ALERT_THRESHOLD     20    /* Score >= 20 = Alert (never block) */
#define SEMI_NIDS_BLOCK_DURATION_SEC         300   /* 5 min temp block */
#define SEMI_NIDS_MAX_TEMP_BLOCKS            1024  /* Max concurrent temp IP blocks */
#define SEMI_NIDS_FAIL_OPEN_CPU_THRESHOLD    85    /* CPU% above this = fail-open */
#define SEMI_NIDS_FAIL_OPEN_QUEUE_THRESHOLD  95    /* Queue fill% above this = fail-open */

/* ─── Ring Buffer Layout (shared with userspace via IOCTL) ─── */
#pragma pack(push, 1)
typedef struct _AEGIS_RING_HEADER {
    volatile ULONG write_pos;     /* Producer index (kernel) */
    volatile ULONG read_pos;      /* Consumer index (userspace/Zig) */
    ULONG         capacity;       /* Total ring capacity in bytes */
    ULONG         packet_count;   /* Packets written (monotonic) */
    ULONG         dropped_count;  /* Packets dropped due to full ring */
} AEGIS_RING_HEADER;
#pragma pack(pop)

typedef struct _AEGIS_RING_BUFFER {
    AEGIS_RING_HEADER header;
    UCHAR             data[1];    /* Flexible array — actual size = RING_BUF_SIZE */
} AEGIS_RING_BUFFER;

/* ─── Packet metadata header in ring ─── */
#pragma pack(push, 1)
typedef struct _AEGIS_PKT_META {
    ULONG   size;          /* Total packet bytes (including this header) */
    ULONG   orig_len;      /* Original packet length before truncation */
    ULONG64 timestamp;     /* KeQueryPerformanceCounter value */
    USHORT  layer_id;      /* WFP layer that captured this packet */
    USHORT  direction;     /* 0 = inbound, 1 = outbound */
    ULONG   process_id;    /* PID from WFP classify */
    USHORT  ip_proto;      /* IP protocol number (6=TCP, 17=UDP, etc.) */
    USHORT  _pad;
    ULONG32 src_ip;        /* Source IPv4 (network byte order) */
    ULONG32 dst_ip;        /* Dest IPv4 (network byte order) */
    USHORT  src_port;      /* Source port (host byte order) */
    USHORT  dst_port;      /* Dest port (host byte order) */
    /* Semi-NIDS fields (set by Rust correlation engine via shared memory) */
    LONG    threat_score;  /* Threat score 0-100 (x10 fixed-point: 600 = 60.0) */
    UCHAR   confidence;    /* 0=Unknown, 1=Low, 2=Medium, 3=High, 4=Critical */
    ULONG   risk_flags;    /* Bitfield of matched rules */
} AEGIS_PKT_META;
#pragma pack(pop)

/* ─── Driver globals ─── */
static PDEVICE_OBJECT    g_dev_obj     = NULL;
static UNICODE_STRING    g_sym_link    = {0};
static AEGIS_RING_BUFFER* g_ring       = NULL;
static PHYSICAL_ADDRESS  g_ring_phys   = {0};
static KSPIN_LOCK        g_ring_lock   = {0};

static HANDLE g_engine_handle   = NULL;
static UINT32 g_callout_id      = 0;
static UINT32 g_filter_id       = 0;
static GUID   g_sublayer_guid   = {0};
static GUID   g_callout_guid    = {0};
static GUID   g_filter_guid     = {0};

static BOOLEAN g_running = FALSE;

/* ─── Semi-NIDS: Adaptive State (shared with userspace via IOCTL) ─── */
typedef struct _SEMI_NIDS_IP_ENTRY {
    ULONG   ip;               /* Blocked IP (network byte order) */
    ULONG64 blocked_at;       /* KeQueryPerformanceCounter when blocked */
    ULONG64 expires_at;       /* 0 = permanent, else expire timestamp */
    ULONG   reason;           /* Reason code */
    UCHAR   confidence;       /* Confidence level when blocked */
} SEMI_NIDS_IP_ENTRY;

typedef struct _SEMI_NIDS_STATE {
    /* Property 1: Threshold-based dropping */
    LONG    block_threshold;      /* Default: 60 */
    LONG    ratelimit_threshold;  /* Default: 40 */
    LONG    alert_threshold;      /* Default: 20 */
    BOOLEAN fail_open_active;    /* Property 2: Fail-Open flag */
    UCHAR   load_cpu_pct;        /* Current CPU% from Go perf */
    UCHAR   load_queue_pct;      /* Current queue fill% */
    /* Temporary IP block table */
    SEMI_NIDS_IP_ENTRY temp_blocks[SEMI_NIDS_MAX_TEMP_BLOCKS];
    ULONG   temp_block_count;
    /* Permanent IP block table */
    ULONG   perm_blocks[SEMI_NIDS_MAX_TEMP_BLOCKS];
    ULONG   perm_block_count;
    /* Whitelisted IPs */
    ULONG   whitelist[256];
    ULONG   whitelist_count;
    /* Statistics */
    ULONG64 total_packets_seen;
    ULONG64 total_blocked;
    ULONG64 total_rate_limited;
    ULONG64 total_fail_open_passes;
} SEMI_NIDS_STATE;

static SEMI_NIDS_STATE g_semi_nids = {0};
static KSPIN_LOCK     g_semi_nids_lock = {0};

/* ─── Forward declarations ─── */
static NTSTATUS aegis_wfp_register_callout(_In_ HANDLE engine, _Out_ UINT32* callout_id);
static NTSTATUS aegis_wfp_add_filter(_In_ HANDLE engine, _In_ UINT32 callout_id, _Out_ UINT32* filter_id);
static VOID NTAPI aegis_classify(
    _In_ const FWPS_INCOMING_VALUES0*          in_fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* in_meta,
    _Inout_opt_ void*                          layer_data,
    _In_opt_ const void*                       classify_ctx,
    _In_ const FWPS_FILTER3*                   filter,
    _In_ UINT64                                flow_id,
    _Out_ FWPS_CLASSIFY_OUT0*                  classify_out
);
static NTSTATUS NTAPI aegis_notify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notify_type,
    _In_ const GUID*              filter_key,
    _Inout_ FWPS_FILTER3*         filter
);
static VOID NTAPI aegis_flow_delete(_In_ UINT16 layer_id, _In_ UINT32 callout_id, _In_ UINT64 flow_id);

/* ─── Ring Buffer Helpers ─── */

/**
 * aegis_ring_write - Write packet data into the shared ring buffer.
 * Lock-free single-producer (kernel) / single-consumer (userspace) design.
 * Returns TRUE on success, FALSE if ring is full (packet dropped).
 */
static BOOLEAN aegis_ring_write(
    _In_ const AEGIS_PKT_META* meta,
    _In_ const UCHAR*           payload,
    _In_ ULONG                  payload_len
)
{
    ULONG total_size = sizeof(AEGIS_PKT_META) + payload_len;
    KIRQL old_irql;

    if (total_size > MAX_PACKET_COPY) {
        payload_len = MAX_PACKET_COPY - sizeof(AEGIS_PKT_META);
        total_size = MAX_PACKET_COPY;
    }

    KeAcquireSpinLock(&g_ring_lock, &old_irql);

    ULONG write_pos = g_ring->header.write_pos;
    ULONG read_pos  = g_ring->header.read_pos;
    ULONG free_space;

    /* Calculate free space (ring buffer with power-of-2 sizing) */
    if (write_pos >= read_pos)
        free_space = g_ring->header.capacity - (write_pos - read_pos) - 1;
    else
        free_space = read_pos - write_pos - 1;

    if (free_space < total_size) {
        g_ring->header.dropped_count++;
        KeReleaseSpinLock(&g_ring_lock, old_irql);
        return FALSE;
    }

    /* Write metadata header */
    ULONG capacity = g_ring->header.capacity;
    ULONG to_write = sizeof(AEGIS_PKT_META);
    ULONG offset = write_pos;

    /* Copy meta header (may wrap) */
    if (offset + to_write <= capacity) {
        RtlCopyMemory(&g_ring->data[offset], meta, to_write);
    } else {
        ULONG chunk1 = capacity - offset;
        RtlCopyMemory(&g_ring->data[offset], meta, chunk1);
        RtlCopyMemory(&g_ring->data[0], (UCHAR*)meta + chunk1, to_write - chunk1);
    }
    offset = (offset + to_write) % capacity;

    /* Copy payload (may wrap) */
    to_write = payload_len;
    if (to_write > 0) {
        if (offset + to_write <= capacity) {
            RtlCopyMemory(&g_ring->data[offset], payload, to_write);
        } else {
            ULONG chunk1 = capacity - offset;
            RtlCopyMemory(&g_ring->data[offset], payload, chunk1);
            RtlCopyMemory(&g_ring->data[0], payload + chunk1, to_write - chunk1);
        }
    }

    /* Advance write position (memory barrier for consumerspace reader) */
    KeMemoryBarrier();
    g_ring->header.write_pos = (write_pos + total_size) % capacity;
    g_ring->header.packet_count++;

    KeReleaseSpinLock(&g_ring_lock, old_irql);
    return TRUE;
}

/* ─── WFP Classify Callback ─── */

static VOID NTAPI aegis_classify(
    _In_ const FWPS_INCOMING_VALUES0*          in_fixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* in_meta,
    _Inout_opt_ void*                          layer_data,
    _In_opt_ const void*                       classify_ctx,
    _In_ const FWPS_FILTER3*                   filter,
    _In_ UINT64                                flow_id,
    _Out_ FWPS_CLASSIFY_OUT0*                  classify_out
)
{
    UNREFERENCED_PARAMETER(classify_ctx);
    UNREFERENCED_PARAMETER(flow_id);

    if (!g_running || !g_ring) {
        classify_out->actionType = FWP_ACTION_PERMIT;
        return;
    }

    FWPS_CLASSIFY_OUT0 local_out = {0};
    local_out.actionType = FWP_ACTION_PERMIT;

    /* Extract packet data from NBL */
    const FWPS_INCOMING_PACKET0* packet = (const FWPS_INCOMING_PACKET0*)layer_data;
    if (!packet || !packet->netBufferList) {
        classify_out->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /* Build metadata */
    AEGIS_PKT_META meta = {0};
    meta.size      = sizeof(AEGIS_PKT_META);
    meta.timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    meta.layer_id  = (USHORT)in_fixed->layerId;
    meta.direction = (in_meta->direction == FWP_DIRECTION_OUTBOUND) ? 1 : 0;
    meta.process_id = (ULONG)(ULONG_PTR)in_meta->processId;

    /* Extract 5-tuple from WFP values */
    if (in_fixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32 != 0) {
        meta.src_ip = in_fixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
        meta.dst_ip = in_fixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        meta.src_port = in_fixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        meta.dst_port = in_fixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        meta.ip_proto = in_fixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    }

    /* Clone and copy payload from NBL */
    UCHAR payload_buf[MAX_PACKET_COPY];
    ULONG payload_len = 0;

    const NET_BUFFER_LIST* nbl = packet->netBufferList;
    for (const NET_BUFFER* nb = nbl->FirstNetBuffer; nb && payload_len < MAX_PACKET_COPY - sizeof(AEGIS_PKT_META); nb = nb->Next) {
        ULONG buf_len = NET_BUFFER_DATA_LENGTH(nb);
        ULONG to_copy = min(buf_len, (MAX_PACKET_COPY - sizeof(AEGIS_PKT_META)) - payload_len);

        PVOID buf_va = NdisGetDataBuffer((NET_BUFFER*)nb, to_copy, payload_buf + payload_len, 1, 0);
        if (buf_va && buf_va != payload_buf + payload_len) {
            RtlCopyMemory(payload_buf + payload_len, buf_va, to_copy);
        }
        payload_len += to_copy;
    }

    meta.orig_len = payload_len;
    meta.size = sizeof(AEGIS_PKT_META) + payload_len;

    /* Write to shared ring buffer */
    aegis_ring_write(&meta, payload_buf, payload_len);

    /* ═══════════════════════════════════════════════════════════
     * Semi-NIDS: Adaptive & Threshold-based Dropping Decision
     *
     * Property 1: Only block when score >= threshold AND confidence >= min
     * Property 2: If fail-open is active, permit clean traffic
     * Property 3: Human decisions come via IOCTL from Python console
     * ═══════════════════════════════════════════════════════════ */
    g_semi_nids.total_packets_seen++;

    /* ═══════════════════════════════════════════════════════════
     * Semi-NIDS: Adaptive & Threshold-based Dropping Decision
     *
     * NOTE: payload_buf is a STACK array (UCHAR [MAX_PACKET_COPY]).
     *       Do NOT call ExFreePoolWithTag on it — it auto-frees on return.
     *       Previous code had ExFreePoolWithTag(payload_buf_pool, 'pAeG')
     *       which would BSOD because payload_buf_pool was never allocated.
     * ═══════════════════════════════════════════════════════════ */

    /* ── Property 2: Fail-Open Check ── */
    if (g_semi_nids.fail_open_active) {
        /* If overloaded AND packet has no risk flags → pass through */
        if (meta.risk_flags == 0) {
            g_semi_nids.total_fail_open_passes++;
            classify_out->actionType = FWP_ACTION_PERMIT;
            return;
        }
        /* Has risk flags even in fail-open → continue to evaluate */
    }

    /* ── Check Whitelist (Property 3: Human whitelisted) ── */
    {
        ULONG i;
        for (i = 0; i < g_semi_nids.whitelist_count; i++) {
            if (g_semi_nids.whitelist[i] == meta.src_ip) {
                classify_out->actionType = FWP_ACTION_PERMIT;
                return;
            }
        }
    }

    /* ── Check Permanent Block (from console [Block] button) ── */
    {
        ULONG i;
        for (i = 0; i < g_semi_nids.perm_block_count; i++) {
            if (g_semi_nids.perm_blocks[i] == meta.src_ip) {
                g_semi_nids.total_blocked++;
                classify_out->actionType = FWP_ACTION_BLOCK;
                return;
            }
        }
    }

    /* ── Check Temporary Block (from Rust auto-block or [Temp Block]) ── */
    {
        ULONG64 now = KeQueryPerformanceCounter(NULL).QuadPart;
        ULONG i;
        for (i = 0; i < g_semi_nids.temp_block_count; i++) {
            if (g_semi_nids.temp_blocks[i].ip == meta.src_ip) {
                /* Check if expired */
                if (g_semi_nids.temp_blocks[i].expires_at != 0 &&
                    now >= g_semi_nids.temp_blocks[i].expires_at) {
                    /* Expired — remove by swapping with last */
                    g_semi_nids.temp_blocks[i] = g_semi_nids.temp_blocks[g_semi_nids.temp_block_count - 1];
                    g_semi_nids.temp_block_count--;
                    continue;
                }
                g_semi_nids.total_blocked++;
                classify_out->actionType = FWP_ACTION_BLOCK;
                return;
            }
        }
    }

    /* ── Property 1: Threshold-based Dropping ── */
    /* If threat score (from Rust correlation) >= block_threshold AND
     * confidence >= High (3), then BLOCK at kernel level.
     * Lower confidence threats are only ALERTED (permitted to pass).
     */
    if (meta.threat_score >= g_semi_nids.block_threshold &&
        meta.confidence >= 3) {  /* 3 = High, 4 = Critical */
        g_semi_nids.total_blocked++;

        /* Auto-add temporary block for this source IP */
        if (g_semi_nids.temp_block_count < SEMI_NIDS_MAX_TEMP_BLOCKS) {
            ULONG64 now = KeQueryPerformanceCounter(NULL).QuadPart;
            g_semi_nids.temp_blocks[g_semi_nids.temp_block_count].ip = meta.src_ip;
            g_semi_nids.temp_blocks[g_semi_nids.temp_block_count].blocked_at = now;
            g_semi_nids.temp_blocks[g_semi_nids.temp_block_count].expires_at =
                now + (ULONG64)SEMI_NIDS_BLOCK_DURATION_SEC * 10000000LL; /* QPC units ~100ns */
            g_semi_nids.temp_blocks[g_semi_nids.temp_block_count].reason = meta.risk_flags;
            g_semi_nids.temp_blocks[g_semi_nids.temp_block_count].confidence = meta.confidence;
            g_semi_nids.temp_block_count++;
        }

        classify_out->actionType = FWP_ACTION_BLOCK;
        return;
    }

    /* Rate limiting: score >= ratelimit_threshold AND confidence >= Medium(2) */
    if (meta.threat_score >= g_semi_nids.ratelimit_threshold &&
        meta.confidence >= 2) {
        g_semi_nids.total_rate_limited++;
        /* Soft block: permit but mark for rate limiting in userspace */
        classify_out->actionType = FWP_ACTION_PERMIT;
        /* (In production: probabilistically block a subset of packets
         *   to implement actual rate limiting rather than just permitting) */
        return;
    }

    /* Below block threshold OR low confidence → PERMIT (alert only) */
    classify_out->actionType = FWP_ACTION_PERMIT;
}

/* ─── WFP Notify / Flow Delete (stubs) ─── */
static NTSTATUS NTAPI aegis_notify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notify_type,
    _In_ const GUID*              filter_key,
    _Inout_ FWPS_FILTER3*         filter
)
{
    UNREFERENCED_PARAMETER(notify_type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI aegis_flow_delete(
    _In_ UINT16 layer_id,
    _In_ UINT32 callout_id,
    _In_ UINT64 flow_id
)
{
    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
    UNREFERENCED_PARAMETER(flow_id);
}

/* ─── Callout Registration ─── */
static NTSTATUS aegis_wfp_register_callout(_In_ HANDLE engine, _Out_ UINT32* callout_id)
{
    FWPS_CALLOUT3 s_callout = {0};
    s_callout.calloutKey         = g_callout_guid;
    s_callout.classifyFn         = aegis_classify;
    s_callout.notifyFn           = aegis_notify;
    s_callout.flowDeleteFn       = aegis_flow_delete;
    s_callout.flags              = 0;
    s_callout.providerKey        = NULL;
    s_callout.providerData       = NULL;
    s_callout.classifyFnClientCtx = NULL;

    return FwpsCalloutRegister3(engine, &s_callout, callout_id);
}

/* ─── Filter Addition ─── */
static NTSTATUS aegis_wfp_add_filter(_In_ HANDLE engine, _In_ UINT32 callout_id, _Out_ UINT32* filter_id)
{
    FWPM_FILTER0 filter = {0};
    filter.filterKey       = g_filter_guid;
    filter.layerKey        = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = (PWSTR)AEGIS_FILTER_NAME;
    filter.action.type     = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = g_callout_guid;
    filter.weight.uint8    = AEGIS_CALLOUT_PRIORITY;
    filter.subLayerKey     = g_sublayer_guid;

    return FwpmFilterAdd0(engine, &filter, NULL, filter_id);
}

/* ─── Ring Buffer Allocation ─── */
static NTSTATUS aegis_ring_alloc(VOID)
{
    /* Allocate contiguous non-paged memory for shared ring buffer */
    PHYSICAL_ADDRESS highest_acceptable;
    highest_acceptable.QuadPart = -1;

    g_ring = (AEGIS_RING_BUFFER*)MmAllocateContiguousMemorySpecifyCache(
        RING_BUF_SIZE + sizeof(AEGIS_RING_HEADER),
        highest_acceptable,
        highest_acceptable,
        highest_acceptable,
        MmNonCached
    );

    if (!g_ring) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_ring, RING_BUF_SIZE + sizeof(AEGIS_RING_HEADER));
    g_ring->header.capacity     = RING_BUF_SIZE;
    g_ring->header.write_pos    = 0;
    g_ring->header.read_pos     = 0;
    g_ring->header.packet_count = 0;
    g_ring->header.dropped_count = 0;

    KeInitializeSpinLock(&g_ring_lock);
    return STATUS_SUCCESS;
}

static VOID aegis_ring_free(VOID)
{
    if (g_ring) {
        MmFreeContiguousMemory(g_ring);
        g_ring = NULL;
    }
}

/* ─── IOCTL Handler ─── */

/* IOCTL codes for Semi-NIDS userspace control (Property 1 & 3) */
#define IOCTL_AEGIS_GET_RING_ADDR       0x800
#define IOCTL_AEGIS_GET_STATS           0x801
#define IOCTL_AEGIS_SEMI_BLOCK_IP       0x802  /* Input: ULONG ip → add to perm_block */
#define IOCTL_AEGIS_SEMI_UNBLOCK_IP     0x803  /* Input: ULONG ip → remove from blocks, add to whitelist */
#define IOCTL_AEGIS_SEMI_SET_THRESHOLDS 0x804  /* Input: SEMI_NIDS_THRESHOLDS struct */
#define IOCTL_AEGIS_SEMI_GET_STATE      0x805  /* Output: SEMI_NIDS_STATE struct */
#define IOCTL_AEGIS_SEMI_SET_FAILOPEN   0x806  /* Input: BOOLEAN → force fail-open on/off */
#define IOCTL_AEGIS_SEMI_WHITELIST_IP   0x807  /* Input: ULONG ip → add to whitelist only */

/* Threshold update structure (sent from Python console/Rust engine via IOCTL) */
#pragma pack(push, 1)
typedef struct _SEMI_NIDS_THRESHOLDS {
    LONG block_threshold;      /* Score >= this + High confidence = Block */
    LONG ratelimit_threshold;  /* Score >= this + Med confidence = Rate Limit */
    LONG alert_threshold;      /* Score >= this = Alert only */
} SEMI_NIDS_THRESHOLDS;
#pragma pack(pop)

static NTSTATUS aegis_dispatch_device_control(
    _In_ PDEVICE_OBJECT dev_obj,
    _In_ PIRP           irp
)
{
    UNREFERENCED_PARAMETER(dev_obj);

    PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(irp);
    ULONG ioctl_code = irp_stack->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;
    PVOID in_buf = irp->AssociatedIrp.SystemBuffer;
    PVOID out_buf = irp->AssociatedIrp.SystemBuffer;
    ULONG in_len = irp_stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_len = irp_stack->Parameters.DeviceIoControl.OutputBufferLength;

    switch (ioctl_code) {
    case IOCTL_AEGIS_GET_RING_ADDR:
        if (out_len >= sizeof(PVOID)) {
            *((PVOID*)out_buf) = (PVOID)g_ring;
            info = sizeof(PVOID);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_AEGIS_GET_STATS:
        if (out_len >= sizeof(AEGIS_RING_HEADER)) {
            RtlCopyMemory(out_buf, &g_ring->header, sizeof(AEGIS_RING_HEADER));
            info = sizeof(AEGIS_RING_HEADER);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ── Semi-NIDS: Block IP (Property 3 — from console [Block] button) ── */
    case IOCTL_AEGIS_SEMI_BLOCK_IP:
        if (in_len >= sizeof(ULONG)) {
            ULONG ip = *((ULONG*)in_buf);
            KIRQL old_irql;
            KeAcquireSpinLock(&g_semi_nids_lock, &old_irql);
            if (g_semi_nids.perm_block_count < SEMI_NIDS_MAX_TEMP_BLOCKS) {
                /* Check not already blocked */
                BOOLEAN found = FALSE;
                ULONG i;
                for (i = 0; i < g_semi_nids.perm_block_count; i++) {
                    if (g_semi_nids.perm_blocks[i] == ip) { found = TRUE; break; }
                }
                if (!found) {
                    g_semi_nids.perm_blocks[g_semi_nids.perm_block_count] = ip;
                    g_semi_nids.perm_block_count++;
                    DbgPrint("AEGIS WFP: Blocked IP 0x%08X (permanent, from userspace)\n", ip);
                }
            }
            KeReleaseSpinLock(&g_semi_nids_lock, old_irql);
            info = sizeof(ULONG);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ── Semi-NIDS: Unblock IP → remove from blocks, add to whitelist ── */
    case IOCTL_AEGIS_SEMI_UNBLOCK_IP:
        if (in_len >= sizeof(ULONG)) {
            ULONG ip = *((ULONG*)in_buf);
            KIRQL old_irql;
            KeAcquireSpinLock(&g_semi_nids_lock, &old_irql);
            /* Remove from permanent blocks */
            ULONG i;
            for (i = 0; i < g_semi_nids.perm_block_count; i++) {
                if (g_semi_nids.perm_blocks[i] == ip) {
                    g_semi_nids.perm_blocks[i] = g_semi_nids.perm_blocks[g_semi_nids.perm_block_count - 1];
                    g_semi_nids.perm_block_count--;
                    break;
                }
            }
            /* Remove from temporary blocks */
            for (i = 0; i < g_semi_nids.temp_block_count; i++) {
                if (g_semi_nids.temp_blocks[i].ip == ip) {
                    g_semi_nids.temp_blocks[i] = g_semi_nids.temp_blocks[g_semi_nids.temp_block_count - 1];
                    g_semi_nids.temp_block_count--;
                    break;
                }
            }
            /* Add to whitelist */
            if (g_semi_nids.whitelist_count < 256) {
                BOOLEAN already = FALSE;
                ULONG j;
                for (j = 0; j < g_semi_nids.whitelist_count; j++) {
                    if (g_semi_nids.whitelist[j] == ip) { already = TRUE; break; }
                }
                if (!already) {
                    g_semi_nids.whitelist[g_semi_nids.whitelist_count] = ip;
                    g_semi_nids.whitelist_count++;
                    DbgPrint("AEGIS WFP: Whitelisted IP 0x%08X (from userspace)\n", ip);
                }
            }
            KeReleaseSpinLock(&g_semi_nids_lock, old_irql);
            info = sizeof(ULONG);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ── Semi-NIDS: Add to whitelist only (don't remove from blocks) ── */
    case IOCTL_AEGIS_SEMI_WHITELIST_IP:
        if (in_len >= sizeof(ULONG)) {
            ULONG ip = *((ULONG*)in_buf);
            KIRQL old_irql;
            KeAcquireSpinLock(&g_semi_nids_lock, &old_irql);
            if (g_semi_nids.whitelist_count < 256) {
                BOOLEAN found = FALSE;
                ULONG i;
                for (i = 0; i < g_semi_nids.whitelist_count; i++) {
                    if (g_semi_nids.whitelist[i] == ip) { found = TRUE; break; }
                }
                if (!found) {
                    g_semi_nids.whitelist[g_semi_nids.whitelist_count] = ip;
                    g_semi_nids.whitelist_count++;
                }
            }
            KeReleaseSpinLock(&g_semi_nids_lock, old_irql);
            info = sizeof(ULONG);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ── Semi-NIDS: Update thresholds (Property 1) ── */
    case IOCTL_AEGIS_SEMI_SET_THRESHOLDS:
        if (in_len >= sizeof(SEMI_NIDS_THRESHOLDS)) {
            SEMI_NIDS_THRESHOLDS* t = (SEMI_NIDS_THRESHOLDS*)in_buf;
            KIRQL old_irql;
            KeAcquireSpinLock(&g_semi_nids_lock, &old_irql);
            g_semi_nids.block_threshold = t->block_threshold;
            g_semi_nids.ratelimit_threshold = t->ratelimit_threshold;
            g_semi_nids.alert_threshold = t->alert_threshold;
            KeReleaseSpinLock(&g_semi_nids_lock, old_irql);
            DbgPrint("AEGIS WFP: Thresholds updated: block=%d, rate_limit=%d, alert=%d\n",
                     t->block_threshold, t->ratelimit_threshold, t->alert_threshold);
            info = sizeof(SEMI_NIDS_THRESHOLDS);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ── Semi-NIDS: Get full state (for console/UI readback) ── */
    case IOCTL_AEGIS_SEMI_GET_STATE:
        if (out_len >= sizeof(SEMI_NIDS_STATE)) {
            KIRQL old_irql;
            KeAcquireSpinLock(&g_semi_nids_lock, &old_irql);
            RtlCopyMemory(out_buf, &g_semi_nids, sizeof(SEMI_NIDS_STATE));
            KeReleaseSpinLock(&g_semi_nids_lock, old_irql);
            info = sizeof(SEMI_NIDS_STATE);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    /* ── Semi-NIDS: Force fail-open on/off (Property 2 — for testing/emergency) ── */
    case IOCTL_AEGIS_SEMI_SET_FAILOPEN:
        if (in_len >= sizeof(BOOLEAN)) {
            KIRQL old_irql;
            KeAcquireSpinLock(&g_semi_nids_lock, &old_irql);
            g_semi_nids.fail_open_active = *((BOOLEAN*)in_buf);
            KeReleaseSpinLock(&g_semi_nids_lock, old_irql);
            DbgPrint("AEGIS WFP: Fail-open %s\n", g_semi_nids.fail_open_active ? "ACTIVATED" : "DEACTIVATED");
            info = sizeof(BOOLEAN);
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information  = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

/* ─── Driver Entry ─── */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path
)
{
    UNREFERENCED_PARAMETER(registry_path);
    NTSTATUS status;

    /* 1. Create device object + symlink for IOCTL access */
    UNICODE_STRING dev_name;
    RtlInitUnicodeString(&dev_name, AEGIS_WFP_DEVICE_NAME);

    status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN,
                           FILE_DEVICE_SECURE_OPEN, FALSE, &g_dev_obj);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&g_sym_link, AEGIS_WFP_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&g_sym_link, &dev_name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_dev_obj);
        return status;
    }

    /* 2. Set up dispatch routines */
    driver_obj->MajorFunction[IRP_MJ_CREATE]         = 
    driver_obj->MajorFunction[IRP_MJ_CLOSE]          = 
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = aegis_dispatch_device_control;

    /* 3. Allocate shared ring buffer */
    status = aegis_ring_alloc();
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_sym_link);
        IoDeleteDevice(g_dev_obj);
        return status;
    }

    /* 4. Generate GUIDs (deterministic from driver name hash) */
    RtlZeroMemory(&g_sublayer_guid, sizeof(GUID));
    RtlZeroMemory(&g_callout_guid, sizeof(GUID));
    RtlZeroMemory(&g_filter_guid, sizeof(GUID));
    /* In production, these come from a GUID table; using static for brevity */
    g_sublayer_guid.Data1 = 0xAEG10001;
    g_callout_guid.Data1  = 0xAEG10002;
    g_filter_guid.Data1   = 0xAEG10003;

    /* 5. Open WFP engine & register callout */
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; /* Auto-cleanup on close */

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_engine_handle);
    if (!NT_SUCCESS(status)) goto cleanup_ring;

    status = aegis_wfp_register_callout(g_engine_handle, &g_callout_id);
    if (!NT_SUCCESS(status)) goto cleanup_engine;

    /* 6. Add sublayer + filter */
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = g_sublayer_guid;
    sublayer.displayData.name = (PWSTR)AEGIS_SUBLAYER_NAME;
    sublayer.flags  = 0;
    sublayer.weight = 0xFFFF; /* High weight = inspect early */

    status = FwpmSubLayerAdd0(g_engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status)) goto cleanup_callout;

    status = aegis_wfp_add_filter(g_engine_handle, g_callout_id, &g_filter_id);
    if (!NT_SUCCESS(status)) goto cleanup_callout;

    g_running = TRUE;
    DbgPrint("AEGIS WFP: Driver loaded — ring @ 0x%p, callout ID %u\n", g_ring, g_callout_id);
    return STATUS_SUCCESS;

cleanup_callout:
    FwpsCalloutUnregisterById0(g_callout_id);
cleanup_engine:
    FwpmEngineClose0(g_engine_handle);
    g_engine_handle = NULL;
cleanup_ring:
    aegis_ring_free();
    IoDeleteSymbolicLink(&g_sym_link);
    IoDeleteDevice(g_dev_obj);
    return status;
}

/* ─── Driver Unload ─── */
VOID DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNREFERENCED_PARAMETER(driver_obj);
    g_running = FALSE;

    if (g_callout_id) FwpsCalloutUnregisterById0(g_callout_id);
    if (g_filter_id)  FwpmFilterDeleteById0(g_engine_handle, g_filter_id);
    if (g_engine_handle) FwpmEngineClose0(g_engine_handle);

    aegis_ring_free();
    IoDeleteSymbolicLink(&g_sym_link);
    if (g_dev_obj) IoDeleteDevice(g_dev_obj);

    DbgPrint("AEGIS WFP: Driver unloaded\n");
}
