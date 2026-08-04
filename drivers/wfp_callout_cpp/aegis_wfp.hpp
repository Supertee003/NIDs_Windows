/**
 * aegis_wfp.hpp — AEGIS NIDS WFP Callout Driver Shared Header (C++ Edition)
 *
 * Defines the AEGIS_EVENT_HEADER structure (40 bytes), RAII helpers,
 * RingBuffer class template, and namespace Aegis::WFP for the kernel-mode
 * WFP callout driver.
 *
 * Architecture: C++ Kernel Driver (WFP Callout) → Ring Buffer → Zig Reader
 * This is part of the NETWORK layer (3-Layer Architecture).
 *
 * C++ Kernel Constraints (WDK):
 *   - No exceptions (compile with /KernelDisableExceptions or /EHs-c-)
 *   - No STL containers (custom kernel-safe RingBuffer template)
 *   - No standard new/delete (use ExAllocatePool2 via PoolAllocator<T>)
 *   - DriverEntry and WFP classify callbacks must be extern "C"
 */

#ifndef AEGIS_WFP_HPP
#define AEGIS_WFP_HPP

#include <initguid.h>

// ====== Namespace ======
namespace Aegis {
namespace WFP {

// ====== IOCTL Codes ======
#define IOCTL_AEGIS_READ_EVENTS CTL_CODE(FILE_DEVICE_NETWORK, 0x800, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_AEGIS_BLOCK_FLOW  CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_AEGIS_GET_STATS   CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

// ====== AEGIS Event Header (40 bytes — matches Zig extern struct) ======
#pragma pack(push, 1)
struct EventHeader {
    UINT32  event_type;     // 0=NETWORK, 1=KERNEL_FILE, 2=KERNEL_PROCESS, 3=L2_PIPE
    UINT32  source_ip;      // IPv4 address of the packet source
    UINT32  dest_ip;        // IPv4 address of the packet destination
    UINT16  source_port;    // Source port number
    UINT16  dest_port;      // Destination port number
    UINT8   protocol;       // 6=TCP, 17=UDP, 1=ICMP
    UINT8   direction;      // 0=inbound, 1=outbound
    UINT8   layer_id;       // WFP layer ID
    UINT8   flags;          // Additional flags
    UINT32  payload_length; // Length of captured payload following this header
    UINT32  rule_id;        // Matched rule ID (if fast_pattern matched)
    UINT32  severity;       // 0=Low, 1=Medium, 2=High, 3=Critical
    UINT32  reserved;       // Reserved for future use
    UINT64  timestamp;      // Event timestamp (KeQueryPerformanceCounter)
};
#pragma pack(pop)

// Keep C-style typedef for ABI compatibility with Zig/Rust
typedef struct _AEGIS_EVENT_HEADER AEGIS_EVENT_HEADER;

// ====== Ring Buffer Statistics ======
struct RingStats {
    ULONG totalEventsWritten;
    ULONG totalEventsRead;
    ULONG totalBytesWritten;
    ULONG totalBytesRead;
    ULONG overflowCount;        // Events lost due to buffer full
};

// ====== Device Name ======
#define AEGIS_WFP_DEVICE_NAME  L"\\Device\\AegisWfpDevice"
#define AEGIS_WFP_SYMLINK_NAME L"\\DosDevices\\AegisWfpDevice"

// ====== WFP Callout GUID ======
DEFINE_GUID(AEGIS_CALLOUT_KEY,
    0x8e6c3d2a, 0x4f5b, 0x1a7e, 0x9c, 0x3d, 0x5b, 0x8f, 0x2a, 0x4e, 0x6c, 0xd7);

// ====== Ring Buffer Configuration ======
constexpr SIZE_T kRingBufferSize     = 2 * 1024 * 1024;  // 2MB
constexpr ULONG  kMaxEventsPerRead   = 100;
constexpr ULONG  kMaxPayloadSize     = 4096;

// ====== RAII: SpinLock Guard ======
// Auto-acquires on construction, auto-releases on destruction.
// Usage: { SpinLockGuard guard(&lock); ... critical section ... } // auto-release
class SpinLockGuard {
    PKSPIN_LOCK m_lock;
    KIRQL       m_oldIrql;
    bool        m_active;

public:
    explicit SpinLockGuard(PKSPIN_LOCK lock) : m_lock(lock), m_active(true) {
        KeAcquireSpinLock(m_lock, &m_oldIrql);
    }

    ~SpinLockGuard() {
        if (m_active) {
            KeReleaseSpinLock(m_lock, m_oldIrql);
        }
    }

    // Disallow copy — spin lock is not copyable
    SpinLockGuard(const SpinLockGuard&) = delete;
    SpinLockGuard& operator=(const SpinLockGuard&) = delete;

    // Allow early release (for complex flow control)
    void Release() {
        if (m_active) {
            KeReleaseSpinLock(m_lock, m_oldIrql);
            m_active = false;
        }
    }
};

// ====== RAII: Pool Allocator ======
// Manages kernel memory pool (ExAllocatePool2 / ExFreePool) with automatic cleanup.
// Usage: PoolAllocator<void> buf(POOL_FLAG_NON_PAGED, size, 'AEGS');
//        if (buf.Get()) { ... use buf.Get() ... } // auto-free on scope exit
template<typename T>
class PoolAllocator {
    PVOID  m_ptr;
    SIZE_T m_size;
    ULONG  m_tag;

public:
    PoolAllocator(POOL_FLAGS flags, SIZE_T size, ULONG tag)
        : m_ptr(nullptr), m_size(size), m_tag(tag)
    {
        m_ptr = ExAllocatePool2(flags, size, tag);
    }

    ~PoolAllocator() {
        if (m_ptr) {
            ExFreePool(m_ptr);
            m_ptr = nullptr;
        }
    }

    // Disallow copy
    PoolAllocator(const PoolAllocator&) = delete;
    PoolAllocator& operator=(const PoolAllocator&) = delete;

    // Allow move (for transferring ownership)
    PoolAllocator(PoolAllocator&& other) noexcept
        : m_ptr(other.m_ptr), m_size(other.m_size), m_tag(other.m_tag)
    {
        other.m_ptr = nullptr;
    }

    T* Get() const { return reinterpret_cast<T*>(m_ptr); }
    bool IsValid() const { return m_ptr != nullptr; }
    SIZE_T Size() const { return m_size; }
};

// ====== RAII: Device Object Guard ======
// Manages IoCreateDevice / IoDeleteDevice with automatic cleanup.
class DeviceGuard {
    PDEVICE_OBJECT  m_device;
    UNICODE_STRING  m_deviceName;
    UNICODE_STRING  m_symlinkName;
    bool            m_symlinkCreated;

public:
    DeviceGuard() : m_device(nullptr), m_symlinkCreated(false) {
        RtlInitUnicodeString(&m_deviceName, L"");
        RtlInitUnicodeString(&m_symlinkName, L"");
    }

    ~DeviceGuard() {
        Cleanup();
    }

    NTSTATUS Create(PDRIVER_OBJECT driverObj, PUNICODE_STRING deviceName,
                    PUNICODE_STRING symlinkName, DEVICE_TYPE deviceType = FILE_DEVICE_NETWORK)
    {
        NTSTATUS status = IoCreateDevice(driverObj, 0, deviceName,
            deviceType, FILE_DEVICE_SECURE_OPEN, FALSE, &m_device);
        if (!NT_SUCCESS(status)) return status;

        m_deviceName = *deviceName;
        m_symlinkName = *symlinkName;

        status = IoCreateSymbolicLink(symlinkName, deviceName);
        if (!NT_SUCCESS(status)) {
            IoDeleteDevice(m_device);
            m_device = nullptr;
            return status;
        }
        m_symlinkCreated = true;
        return STATUS_SUCCESS;
    }

    void Cleanup() {
        if (m_symlinkCreated) {
            IoDeleteSymbolicLink(&m_symlinkName);
            m_symlinkCreated = false;
        }
        if (m_device) {
            IoDeleteDevice(m_device);
            m_device = nullptr;
        }
    }

    PDEVICE_OBJECT Get() const { return m_device; }

    DeviceGuard(const DeviceGuard&) = delete;
    DeviceGuard& operator=(const DeviceGuard&) = delete;
};

// ====== RAII: WFP Engine Session Guard ======
// Manages FwpmEngineOpen0 / FwpmEngineClose0 with automatic cleanup.
class WfpEngineGuard {
    HANDLE m_handle;
    bool   m_active;

public:
    WfpEngineGuard() : m_handle(nullptr), m_active(false) {}

    ~WfpEngineGuard() {
        Close();
    }

    NTSTATUS Open() {
        FWPM_SESSION0 session = {0};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;  // Auto-cleanup on unload
        NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &m_handle);
        if (NT_SUCCESS(status)) m_active = true;
        return status;
    }

    void Close() {
        if (m_active && m_handle) {
            FwpmEngineClose0(m_handle);
            m_handle = nullptr;
            m_active = false;
        }
    }

    HANDLE Get() const { return m_handle; }
    bool IsActive() const { return m_active; }

    WfpEngineGuard(const WfpEngineGuard&) = delete;
    WfpEngineGuard& operator=(const WfpEngineGuard&) = delete;
};

// ====== RingBuffer Template ======
// Kernel-safe ring buffer with spinlock protection.
// Template parameter T is the event type (EventHeader for NETWORK events).
template<typename T>
class RingBuffer {
    PVOID       m_buffer;
    SIZE_T      m_bufferSize;
    KSPIN_LOCK  m_lock;
    SIZE_T      m_writeOffset;
    SIZE_T      m_readOffset;
    RingStats   m_stats;

public:
    RingBuffer() : m_buffer(nullptr), m_bufferSize(0),
                   m_writeOffset(0), m_readOffset(0)
    {
        RtlZeroMemory(&m_stats, sizeof(m_stats));
        KeInitializeSpinLock(&m_lock);
    }

    NTSTATUS Initialize(SIZE_T size, ULONG poolTag) {
        m_bufferSize = size;
        m_buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, poolTag);
        if (!m_buffer) return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(m_buffer, size);
        m_writeOffset = 0;
        m_readOffset = 0;
        RtlZeroMemory(&m_stats, sizeof(m_stats));
        return STATUS_SUCCESS;
    }

    void Destroy() {
        if (m_buffer) {
            ExFreePool(m_buffer);
            m_buffer = nullptr;
        }
    }

    // Write event data to ring buffer (spinlock-protected)
    NTSTATUS Write(PVOID eventData, SIZE_T eventSize) {
        SpinLockGuard guard(&m_lock);

        SIZE_T availableSpace = m_bufferSize -
            ((m_writeOffset - m_readOffset) % m_bufferSize);

        if (eventSize > availableSpace) {
            m_stats.overflowCount++;
            guard.Release();  // Early release before returning error
            return STATUS_BUFFER_OVERFLOW;
        }

        PUCHAR writePos = (PUCHAR)m_buffer + m_writeOffset;
        SIZE_T firstPart = m_bufferSize - m_writeOffset;

        if (firstPart >= eventSize) {
            RtlCopyMemory(writePos, eventData, eventSize);
            m_writeOffset = (m_writeOffset + eventSize) % m_bufferSize;
        } else {
            // Wrap-around: copy in two parts
            RtlCopyMemory(writePos, eventData, firstPart);
            RtlCopyMemory(m_buffer, (PUCHAR)eventData + firstPart, eventSize - firstPart);
            m_writeOffset = eventSize - firstPart;
        }

        m_stats.totalEventsWritten++;
        m_stats.totalBytesWritten += eventSize;

        return STATUS_SUCCESS;
    }

    // Read events from ring buffer into user buffer (spinlock-protected)
    SIZE_T Read(PVOID userBuffer, SIZE_T userBufferSize) {
        SpinLockGuard guard(&m_lock);

        SIZE_T available = (m_writeOffset - m_readOffset) % m_bufferSize;
        SIZE_T toCopy = (available < userBufferSize) ? available : userBufferSize;

        if (toCopy > 0 && userBuffer) {
            if (m_readOffset + toCopy <= m_bufferSize) {
                RtlCopyMemory(userBuffer, (PUCHAR)m_buffer + m_readOffset, toCopy);
            } else {
                SIZE_T firstPart = m_bufferSize - m_readOffset;
                RtlCopyMemory(userBuffer, (PUCHAR)m_buffer + m_readOffset, firstPart);
                RtlCopyMemory((PUCHAR)userBuffer + firstPart, m_buffer, toCopy - firstPart);
            }
            m_readOffset = (m_readOffset + toCopy) % m_bufferSize;
            m_stats.totalEventsRead++;
            m_stats.totalBytesRead += toCopy;
        }

        guard.Release();  // Release before returning
        return toCopy;
    }

    // Get statistics (spinlock-protected copy)
    RingStats GetStats() {
        SpinLockGuard guard(&m_lock);
        RingStats copy = m_stats;
        guard.Release();
        return copy;
    }

    PVOID Buffer() const { return m_buffer; }
    SIZE_T Size() const { return m_bufferSize; }
};

} // namespace WFP
} // namespace Aegis

// ====== C-compatible aliases for Zig/Rust interop ======
// These ensure the 40-byte struct layout remains identical for Zig extern struct alignment.
extern "C" {
    // Keep the old typedef name for ABI compatibility
    typedef Aegis::WFP::EventHeader AEGIS_EVENT_HEADER_C;
    // Ring stats
    typedef Aegis::WFP::RingStats AEGIS_RING_STATS_C;
}

#endif // AEGIS_WFP_HPP
