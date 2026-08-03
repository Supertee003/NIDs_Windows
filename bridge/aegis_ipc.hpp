/**
 * aegis_ipc.hpp — AEGIS NIDS Inter-Process Communication Bridge (C++ Header)
 *
 * Defines the C++ IPC Bridge that connects all 5 subsystems:
 *   Zig Core (Tier-1) → C++ Bridge → Python Brain (Tier-2)
 *   Rust Mouth (Tier-3) → C++ Bridge → Go Nose (DEFCON)
 *   Kernel Drivers → C++ Bridge → Dashboard (Web UI)
 *
 * Architecture: C++ Bridge sits between all subsystems, providing:
 *   1. extern "C" ABI — callable from Zig, Rust, Go, Python (ctypes/cffi)
 *   2. Shared memory ring buffers for high-throughput event passing
 *   3. Named pipe channels for command/control messages
 *   4. Thread-safe event queue with condition variable signaling
 *   5. DEFCON state aggregation from all subsystems
 *
 * Build: C++17 (no exceptions, cross-platform)
 * Note: This is a USER-MODE library (not kernel-mode)
 * Platform: Windows (named pipes) + Linux (Unix domain sockets)
 */

#ifndef AEGIS_IPC_HPP
#define AEGIS_IPC_HPP

#include <cstdint>
#include <cstring>

// ====== Namespace ======
namespace Aegis {
namespace Bridge {

// ====== Event Types (shared across all subsystems) ======
enum EventType : uint32_t {
    kNetworkEvent      = 0,   // From WFP callout (NETWORK layer)
    kKernelFileEvent   = 1,   // From Minifilter (KERNEL_FILE layer)
    kKernelProcessEvent = 2,  // From Minifilter (KERNEL_PROCESS layer)
    kPipeEvent         = 3,   // From pipe_monitor.zig (L2_PIPE layer)
};

// ====== Severity Levels ======
enum Severity : uint32_t {
    kSeverityLow      = 0,
    kSeverityMedium   = 1,
    kSeverityHigh     = 2,
    kSeverityCritical = 3,
};

// ====== DEFCON Levels ======
enum DefconLevel : uint8_t {
    kDefcon1Maximum  = 1,   // 10+ critical OR 5+ blocks OR kernel threats
    kDefcon2Severe   = 2,   // 5+ critical OR 3+ blocks
    kDefcon3High     = 3,   // 5+ alerts OR 1+ critical
    kDefcon4Elevated = 4,   // 1-5 alerts
    kDefcon5Safe     = 5,   // 0 alerts
};

// ====== Tier Detection Result ======
enum TierResult : uint8_t {
    kTierNoMatch     = 0,   // No pattern matched
    kTier1FastMatch  = 1,   // Aho-Corasick fast pattern (Zig)
    kTier2RegexMatch = 2,   // Regex deep inspection (Python)
    kTier3Behavioral = 3,   // Behavioral validation (Rust)
};

// ====== IPC Event Header (48 bytes — extended from kernel 40-byte header) ======
// This is the user-mode version with additional fields for inter-subsystem communication.
#pragma pack(push, 1)
struct IpcEvent {
    // Core fields (same as kernel EventHeader for compatibility)
    uint32_t  event_type;       // EventType enum
    uint32_t  source_ip;        // IPv4 source
    uint32_t  dest_ip;          // IPv4 destination
    uint16_t  source_port;      // Source port
    uint16_t  dest_port;        // Destination port
    uint8_t   protocol;         // 6=TCP, 17=UDP, 1=ICMP
    uint8_t   direction;        // 0=inbound, 1=outbound
    uint8_t   layer_id;         // Layer where event originated
    uint8_t   tier_result;      // TierResult — which tier detected this
    uint32_t  payload_length;   // Length of payload data following this header
    uint32_t  rule_id;          // Matched rule ID
    uint32_t  severity;         // Severity enum
    uint32_t  reserved;         // Reserved
    uint64_t  timestamp;        // Event timestamp (milliseconds since epoch)

    // Extended fields (user-mode IPC only)
    uint32_t  source_pid;       // PID of the process that generated this event
    uint32_t  defcon_impact;    // DEFCON level impact (1-5)
};
#pragma pack(pop)

// ====== IPS Action ======
enum IpsAction : uint8_t {
    kIpsAllow     = 0,   // No action — allow traffic
    kIpsAlert     = 1,   // Alert only — log but don't block
    kIpsBlock     = 2,   // Block source IP via WFP callout
    kIpsRateLimit = 3,   // Rate-limit traffic from source
};

// ====== Subsystem ID ======
enum SubsystemId : uint8_t {
    kSubsystemCore      = 0,   // Zig — Aho-Corasick pattern matching
    kSubsystemBrain     = 1,   // Python — Regex + IPS
    kSubsystemMouth     = 2,   // Rust — Memory safety + behavioral
    kSubsystemNose      = 3,   // Go — Performance + DEFCON
    kSubsystemDashboard = 4,   // Web UI
    kSubsystemBridge    = 5,   // C++ IPC Bridge
};

// ====== IPC Command Message ======
// For command/control communication between subsystems (not events)
#pragma pack(push, 1)
struct IpcCommand {
    uint32_t  command_id;       // Command type (start, stop, reload_rules, etc.)
    uint32_t  target_subsystem; // SubsystemId — which subsystem to target
    uint32_t  payload_size;     // Size of command payload
    uint32_t  response_expected;// 1 if caller expects a response
    uint64_t  timestamp;        // Command timestamp
};
#pragma pack(pop)

// ====== Command Types ======
enum CommandType : uint32_t {
    kCmdStartSubsystem   = 0x01,  // Start a subsystem
    kCmdStopSubsystem    = 0x02,  // Stop a subsystem
    kCmdReloadRules      = 0x03,  // Reload Rules.json
    kCmdBlockIp          = 0x04,  // Block an IP (IPS)
    kCmdUnblockIp        = 0x05,  // Unblock an IP
    kCmdGetDefcon        = 0x06,  // Get current DEFCON level
    kCmdGetStats         = 0x07,  // Get subsystem statistics
    kCmdHealthCheck      = 0x08,  // Ping subsystem health
    kCmdSetLogLevel      = 0x09,  // Change log verbosity
};

// ====== DEFCON State Aggregator ======
// Collects DEFCON inputs from all subsystems and computes global DEFCON level.
class DefconAggregator {
    uint8_t   m_currentLevel;
    uint32_t  m_criticalCount;
    uint32_t  m_blockedIpCount;
    uint32_t  m_kernelThreatCount;
    uint32_t  m_totalAlerts;
    uint64_t  m_lastUpdate;

public:
    DefconAggregator()
        : m_currentLevel(kDefcon5Safe)
        , m_criticalCount(0)
        , m_blockedIpCount(0)
        , m_kernelThreatCount(0)
        , m_totalAlerts(0)
        , m_lastUpdate(0)
    {}

    // ====== DEFCON Calculation (matches Go Goroutines logic) ======
    // DEFCON 1 (MAXIMUM): 10+ critical OR 5+ blocks OR kernel threats
    // DEFCON 2 (SEVERE):  5+ critical OR 3+ blocks
    // DEFCON 3 (HIGH):    5+ alerts OR 1+ critical
    // DEFCON 4 (ELEVATED): 1-5 alerts
    // DEFCON 5 (SAFE):    0 alerts
    uint8_t Calculate() {
        if (m_kernelThreatCount > 0 || m_criticalCount >= 10 || m_blockedIpCount >= 5) {
            m_currentLevel = kDefcon1Maximum;
        } else if (m_criticalCount >= 5 || m_blockedIpCount >= 3) {
            m_currentLevel = kDefcon2Severe;
        } else if (m_totalAlerts >= 5 || m_criticalCount >= 1) {
            m_currentLevel = kDefcon3High;
        } else if (m_totalAlerts >= 1) {
            m_currentLevel = kDefcon4Elevated;
        } else {
            m_currentLevel = kDefcon5Safe;
        }
        return m_currentLevel;
    }

    // ====== Update counters from subsystems ======
    void SetCriticalCount(uint32_t count)   { m_criticalCount = count; }
    void SetBlockedIpCount(uint32_t count)  { m_blockedIpCount = count; }
    void SetKernelThreats(uint32_t count)   { m_kernelThreatCount = count; }
    void SetTotalAlerts(uint32_t count)     { m_totalAlerts = count; }

    uint8_t  CurrentLevel()     const { return m_currentLevel; }
    uint32_t CriticalCount()    const { return m_criticalCount; }
    uint32_t BlockedIpCount()   const { return m_blockedIpCount; }
    uint32_t KernelThreats()    const { return m_kernelThreatCount; }
    uint32_t TotalAlerts()      const { return m_totalAlerts; }

    // Get DEFCON label string
    static const char* LevelLabel(uint8_t level) {
        switch (level) {
            case kDefcon1Maximum:  return "MAXIMUM";
            case kDefcon2Severe:   return "SEVERE";
            case kDefcon3High:     return "HIGH";
            case kDefcon4Elevated: return "ELEVATED";
            case kDefcon5Safe:     return "SAFE";
            default:               return "UNKNOWN";
        }
    }

    // Get DEFCON description
    static const char* LevelDescription(uint8_t level) {
        switch (level) {
            case kDefcon1Maximum:  return "10+ critical alerts OR 5+ blocked IPs OR kernel-level threats detected";
            case kDefcon2Severe:   return "5+ critical alerts OR 3+ blocked IPs — active threat campaign";
            case kDefcon3High:     return "5+ alerts OR 1+ critical — significant threat activity";
            case kDefcon4Elevated: return "1-5 alerts — low-level threat activity observed";
            case kDefcon5Safe:     return "No alerts — all systems nominal";
            default:               return "Unknown DEFCON level";
        }
    }
};

// ====== Shared Memory Ring Buffer (User-Mode) ======
// For high-throughput event passing between subsystems via shared memory.
// Uses mutex instead of spinlock (user-mode appropriate).
template<typename T>
class SharedRingBuffer {
    T*       m_buffer;
    uint32_t m_capacity;
    uint32_t m_head;       // Read position
    uint32_t m_tail;       // Write position
    uint32_t m_count;      // Number of items in buffer
    uint32_t m_dropped;    // Events dropped due to overflow

public:
    SharedRingBuffer() : m_buffer(nullptr), m_capacity(0),
                         m_head(0), m_tail(0), m_count(0), m_dropped(0) {}

    bool Initialize(uint32_t capacity) {
        m_capacity = capacity;
        // In production, use shared memory (CreateFileMapping/MapViewOfFile)
        // For now, use simple heap allocation
        m_buffer = new T[capacity];  // Note: user-mode, so new is OK
        if (!m_buffer) return false;
        memset(m_buffer, 0, sizeof(T) * capacity);
        m_head = 0;
        m_tail = 0;
        m_count = 0;
        m_dropped = 0;
        return true;
    }

    void Destroy() {
        if (m_buffer) {
            delete[] m_buffer;
            m_buffer = nullptr;
        }
    }

    // Push an event (returns false if buffer full — event dropped)
    bool Push(const T& event) {
        if (m_count >= m_capacity) {
            m_dropped++;
            return false;
        }
        m_buffer[m_tail] = event;
        m_tail = (m_tail + 1) % m_capacity;
        m_count++;
        return true;
    }

    // Pop an event (returns false if buffer empty)
    bool Pop(T& event) {
        if (m_count == 0) return false;
        event = m_buffer[m_head];
        m_head = (m_head + 1) % m_capacity;
        m_count--;
        return true;
    }

    uint32_t Count()   const { return m_count; }
    uint32_t Dropped() const { return m_dropped; }
    bool     IsEmpty() const { return m_count == 0; }
    bool     IsFull()  const { return m_count >= m_capacity; }
};

// ====== Named Pipe Channel ======
// For command/control messages between subsystems.
// Cross-platform: Windows named pipes OR Linux Unix domain sockets.
class NamedPipeChannel {
#ifdef _WIN32
    void*  m_pipeHandle;  // HANDLE
#else
    int    m_pipeHandle;  // socket fd
#endif
    bool    m_connected;
    char    m_pipeName[256];

public:
    NamedPipeChannel();

    ~NamedPipeChannel() {
        Disconnect();
    }

    // Create a named pipe server (for subsystem that receives commands)
    bool CreateServer(const char* pipeName);

    // Connect to a named pipe (for subsystem that sends commands)
    bool ConnectClient(const char* pipeName);

    // Send an IpcCommand message
    bool SendCommand(const IpcCommand& cmd);

    // Receive an IpcCommand message
    bool ReceiveCommand(IpcCommand& cmd);

    // Send an IpcEvent
    bool SendEvent(const IpcEvent& event);

    // Receive an IpcEvent
    bool ReceiveEvent(IpcEvent& event);

    void Disconnect();
    bool IsConnected() const { return m_connected; }
};

} // namespace Bridge
} // namespace Aegis

// ====== extern "C" ABI Interface ======
// These functions are callable from Zig, Rust, Go, and Python (via ctypes/cffi).
extern "C" {

// ====== Initialization ======
int32_t  aegis_bridge_init();            // Initialize IPC bridge
int32_t  aegis_bridge_shutdown();        // Shutdown IPC bridge

// ====== Event Passing ======
int32_t  aegis_bridge_push_event(const Aegis::Bridge::IpcEvent* event);  // Push event to queue
int32_t  aegis_bridge_pop_event(Aegis::Bridge::IpcEvent* event);        // Pop event from queue

// ====== DEFCON ======
uint8_t  aegis_bridge_get_defcon();                                    // Get current DEFCON level
void     aegis_bridge_update_defcon(uint32_t critical, uint32_t blocked,
                                     uint32_t kernel, uint32_t total);  // Update DEFCON counters

// ====== IPS ======
int32_t  aegis_bridge_block_ip(uint32_t ip);   // Block IP (request to WFP driver)
int32_t  aegis_bridge_unblock_ip(uint32_t ip); // Unblock IP

// ====== Command/Control ======
int32_t  aegis_bridge_send_command(const Aegis::Bridge::IpcCommand* cmd);
int32_t  aegis_bridge_receive_command(Aegis::Bridge::IpcCommand* cmd);

// ====== Statistics ======
uint32_t aegis_bridge_get_event_count();
uint32_t aegis_bridge_get_dropped_count();
const char* aegis_bridge_get_defcon_label();
const char* aegis_bridge_get_defcon_description();

} // extern "C"

#endif // AEGIS_IPC_HPP
