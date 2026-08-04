/**
 * aegis_wfp_comm.cpp — AEGIS NIDS WFP Ring Buffer Communication Layer (C++ Edition)
 *
 * Uses RingBuffer<EventHeader> template for event storage and retrieval.
 * Provides IOCTL_AEGIS_BLOCK_FLOW for IPS enforcement — Python Brain can
 * request blocking of specific source IPs at kernel level via WFP filter.
 *
 * C++ enhancements:
 *   - RingBuffer::Write() / RingBuffer::Read() use RAII SpinLockGuard internally
 *   - No manual spinlock management (all through template methods)
 *   - PoolAllocator for kernel memory with auto-free
 *
 * Architecture: Kernel-mode C++ → Ring Buffer → Zig Reader (windows_capture.zig)
 */

#include "aegis_wfp.hpp"
#include <ntddk.h>

// This file is intentionally minimal — most functionality moved to
// RingBuffer<EventHeader> template methods in aegis_wfp.hpp.
// The explicit WriteEvent/ReadEvents functions below serve as
// C-compatible extern "C" wrappers for callers that don't use C++.

extern "C" {

// ====== C-compatible wrapper: Write event to ring buffer ======
NTSTATUS AegisWfpWriteEvent_C(PVOID eventData, SIZE_T eventSize)
{
    using namespace Aegis::WFP;
    return g_ringBuffer.Write(eventData, eventSize);
}

// ====== C-compatible wrapper: Read events from ring buffer ======
SIZE_T AegisWfpReadEvents_C(PVOID userBuffer, SIZE_T userBufferSize)
{
    using namespace Aegis::WFP;
    return g_ringBuffer.Read(userBuffer, userBufferSize);
}

// ====== C-compatible wrapper: Get ring buffer statistics ======
VOID AegisWfpGetStats_C(PVOID outputBuffer, SIZE_T outputSize)
{
    using namespace Aegis::WFP;
    RingStats stats = g_ringBuffer.GetStats();
    if (outputBuffer && outputSize >= sizeof(RingStats)) {
        RtlCopyMemory(outputBuffer, &stats, sizeof(RingStats));
    }
}

} // extern "C"

// ====== C++ direct API (for internal use within Aegis::WFP namespace) ======
namespace Aegis {
namespace WFP {

// Block a specific flow — IPS enforcement from Python Brain (Tier-2)
NTSTATUS AegisWfpBlockFlowImpl(UINT32 blockIp)
{
    DbgPrint("[AEGIS WFP] IPS: Block IP %d.%d.%d.%d (C++ API)\n",
        (blockIp >> 0) & 0xFF, (blockIp >> 8) & 0xFF,
        (blockIp >> 16) & 0xFF, (blockIp >> 24) & 0xFF);

    // TODO: Add WFP filter with FWP_ACTION_BLOCK for source IP
    // This requires:
    //   1. FWPM_FILTER_CONDITION0 with FWP_CONDITION_IP_SOURCE_ADDRESS
    //   2. FwpmFilterAdd0 to install the block filter
    //   3. Store filter ID for later removal (unblock)
    return STATUS_NOT_IMPLEMENTED;
}

// Unblock a previously blocked IP
NTSTATUS AegisWfpUnblockFlowImpl(UINT32 unblockIp)
{
    DbgPrint("[AEGIS WFP] IPS: Unblock IP %d.%d.%d.%d (C++ API)\n",
        (unblockIp >> 0) & 0xFF, (unblockIp >> 8) & 0xFF,
        (unblockIp >> 16) & 0xFF, (unblockIp >> 24) & 0xFF);

    // TODO: Remove WFP block filter by filter ID
    return STATUS_NOT_IMPLEMENTED;
}

} // namespace WFP
} // namespace Aegis
