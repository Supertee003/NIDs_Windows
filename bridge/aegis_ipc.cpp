/**
 * aegis_ipc.cpp — AEGIS NIDS IPC Bridge Implementation (C++ Edition)
 *
 * Cross-platform: compiles on both Windows and Linux.
 *   - Windows: Uses named pipes (CreateNamedPipeA, CreateFileA)
 *   - Linux: Uses Unix domain sockets (AF_UNIX)
 *
 * Architecture: C++ IPC Bridge — central hub between all subsystems.
 * Build: C++17, no exceptions
 */

#include "aegis_ipc.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <cerrno>
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>

// ====== Platform-independent handle type ======
#ifdef _WIN32
    typedef void* aegis_handle_t;
    #define AEGIS_INVALID_HANDLE NULL
#else
    typedef int aegis_handle_t;
    #define AEGIS_INVALID_HANDLE (-1)
#endif

// ====== Global Bridge State ======
namespace Aegis {
namespace Bridge {

static SharedRingBuffer<IpcEvent>  g_eventQueue;
static DefconAggregator            g_defcon;
static bool                        g_initialized = false;

static const uint32_t kEventQueueCapacity = 8192;  // 8K events buffer

// ====== Named Pipe Names ======
#ifdef _WIN32
static const char* kBridgePipeName    = "\\\\.\\pipe\\aegis_bridge";
static const char* kCorePipeName      = "\\\\.\\pipe\\aegis_core";
static const char* kBrainPipeName     = "\\\\.\\pipe\\aegis_brain";
static const char* kMouthPipeName     = "\\\\.\\pipe\\aegis_mouth";
static const char* kNosePipeName      = "\\\\.\\pipe\\aegis_nose";
#else
static const char* kBridgePipeName    = "/tmp/aegis_bridge.sock";
static const char* kCorePipeName      = "/tmp/aegis_core.sock";
static const char* kBrainPipeName     = "/tmp/aegis_brain.sock";
static const char* kMouthPipeName     = "/tmp/aegis_mouth.sock";
static const char* kNosePipeName      = "/tmp/aegis_nose.sock";
#endif

// ====== NamedPipeChannel Implementation ======
NamedPipeChannel::NamedPipeChannel()
    : m_pipeHandle(AEGIS_INVALID_HANDLE), m_connected(false)
{
    memset(m_pipeName, 0, sizeof(m_pipeName));
}

bool NamedPipeChannel::CreateServer(const char* pipeName) {
    snprintf(m_pipeName, sizeof(m_pipeName), "%s", pipeName);

#ifdef _WIN32
    m_pipeHandle = (aegis_handle_t)CreateNamedPipeA(
        m_pipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, sizeof(IpcCommand) * 2, sizeof(IpcCommand) * 2,
        0, NULL);

    if (m_pipeHandle == NULL) {
        fprintf(stderr, "[AEGIS Bridge] CreateNamedPipeA failed: %lu\n", GetLastError());
        return false;
    }

    BOOL connected = ConnectNamedPipe((HANDLE)m_pipeHandle, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        fprintf(stderr, "[AEGIS Bridge] ConnectNamedPipe failed: %lu\n", GetLastError());
        CloseHandle((HANDLE)m_pipeHandle);
        m_pipeHandle = AEGIS_INVALID_HANDLE;
        return false;
    }
#else
    // Linux: Unix domain socket
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[AEGIS Bridge] socket() failed: %s\n", strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_pipeName, sizeof(addr.sun_path) - 1);

    // Remove existing socket file
    unlink(m_pipeName);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[AEGIS Bridge] bind() failed: %s\n", strerror(errno));
        close(sock);
        return false;
    }

    if (listen(sock, 1) < 0) {
        fprintf(stderr, "[AEGIS Bridge] listen() failed: %s\n", strerror(errno));
        close(sock);
        return false;
    }

    m_pipeHandle = (aegis_handle_t)(intptr_t)sock;
#endif

    m_connected = true;
    fprintf(stdout, "[AEGIS Bridge] Pipe server created: %s\n", m_pipeName);
    return true;
}

bool NamedPipeChannel::ConnectClient(const char* pipeName) {
    snprintf(m_pipeName, sizeof(m_pipeName), "%s", pipeName);

#ifdef _WIN32
    m_pipeHandle = (aegis_handle_t)CreateFileA(
        m_pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL,
        OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);

    if (m_pipeHandle == NULL) {
        fprintf(stderr, "[AEGIS Bridge] CreateFileA failed: %lu\n", GetLastError());
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState((HANDLE)m_pipeHandle, &mode, NULL, NULL);
#else
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[AEGIS Bridge] socket() failed: %s\n", strerror(errno));
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_pipeName, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[AEGIS Bridge] connect() failed: %s\n", strerror(errno));
        close(sock);
        return false;
    }

    m_pipeHandle = (aegis_handle_t)(intptr_t)sock;
#endif

    m_connected = true;
    fprintf(stdout, "[AEGIS Bridge] Connected to pipe: %s\n", m_pipeName);
    return true;
}

bool NamedPipeChannel::SendCommand(const IpcCommand& cmd) {
    if (!m_connected) return false;

#ifdef _WIN32
    DWORD bytesWritten = 0;
    BOOL result = WriteFile((HANDLE)m_pipeHandle, &cmd, sizeof(IpcCommand), &bytesWritten, NULL);
    if (!result || bytesWritten != sizeof(IpcCommand)) return false;
#else
    ssize_t sent = send((intptr_t)m_pipeHandle, &cmd, sizeof(IpcCommand), 0);
    if (sent != (ssize_t)sizeof(IpcCommand)) return false;
#endif

    return true;
}

bool NamedPipeChannel::ReceiveCommand(IpcCommand& cmd) {
    if (!m_connected) return false;

#ifdef _WIN32
    DWORD bytesRead = 0;
    BOOL result = ReadFile((HANDLE)m_pipeHandle, &cmd, sizeof(IpcCommand), &bytesRead, NULL);
    if (!result || bytesRead != sizeof(IpcCommand)) return false;
#else
    ssize_t recvd = recv((intptr_t)m_pipeHandle, &cmd, sizeof(IpcCommand), 0);
    if (recvd != (ssize_t)sizeof(IpcCommand)) return false;
#endif

    return true;
}

bool NamedPipeChannel::SendEvent(const IpcEvent& event) {
    if (!m_connected) return false;

#ifdef _WIN32
    DWORD bytesWritten = 0;
    BOOL result = WriteFile((HANDLE)m_pipeHandle, &event, sizeof(IpcEvent), &bytesWritten, NULL);
    if (!result || bytesWritten != sizeof(IpcEvent)) return false;
#else
    ssize_t sent = send((intptr_t)m_pipeHandle, &event, sizeof(IpcEvent), 0);
    if (sent != (ssize_t)sizeof(IpcEvent)) return false;
#endif

    return true;
}

bool NamedPipeChannel::ReceiveEvent(IpcEvent& event) {
    if (!m_connected) return false;

#ifdef _WIN32
    DWORD bytesRead = 0;
    BOOL result = ReadFile((HANDLE)m_pipeHandle, &event, sizeof(IpcEvent), &bytesRead, NULL);
    if (!result || bytesRead != sizeof(IpcEvent)) return false;
#else
    ssize_t recvd = recv((intptr_t)m_pipeHandle, &event, sizeof(IpcEvent), 0);
    if (recvd != (ssize_t)sizeof(IpcEvent)) return false;
#endif

    return true;
}

void NamedPipeChannel::Disconnect() {
    if (m_pipeHandle != AEGIS_INVALID_HANDLE) {
#ifdef _WIN32
        CloseHandle((HANDLE)m_pipeHandle);
#else
        close((intptr_t)m_pipeHandle);
        unlink(m_pipeName);  // Remove Unix socket file
#endif
        m_pipeHandle = AEGIS_INVALID_HANDLE;
    }
    m_connected = false;
}

} // namespace Bridge
} // namespace Aegis

// ====== extern "C" API Implementation ======
extern "C" {

int32_t aegis_bridge_init() {
    using namespace Aegis::Bridge;

    if (g_initialized) {
        fprintf(stdout, "[AEGIS Bridge] Already initialized\n");
        return 0;
    }

    if (!g_eventQueue.Initialize(kEventQueueCapacity)) {
        fprintf(stderr, "[AEGIS Bridge] Failed to initialize event queue\n");
        return -1;
    }

    g_defcon.SetCriticalCount(0);
    g_defcon.SetBlockedIpCount(0);
    g_defcon.SetKernelThreats(0);
    g_defcon.SetTotalAlerts(0);

    g_initialized = true;
    fprintf(stdout, "[AEGIS Bridge] Initialized — event queue: %u slots, DEFCON: SAFE\n",
        kEventQueueCapacity);
    return 0;
}

int32_t aegis_bridge_shutdown() {
    using namespace Aegis::Bridge;

    if (!g_initialized) return 0;

    g_eventQueue.Destroy();
    g_initialized = false;

    fprintf(stdout, "[AEGIS Bridge] Shutdown complete\n");
    return 0;
}

int32_t aegis_bridge_push_event(const Aegis::Bridge::IpcEvent* event) {
    using namespace Aegis::Bridge;

    if (!g_initialized || !event) return -1;

    if (!g_eventQueue.Push(*event)) {
        fprintf(stderr, "[AEGIS Bridge] Event queue full — dropped (total: %u)\n",
            g_eventQueue.Dropped());
        return -2;
    }

    // Auto-update DEFCON after each event push
    // severity >= 3 → critical, tier_result == 3 → kernel threat
    uint32_t total    = g_defcon.TotalAlerts() + 1;
    uint32_t critical = g_defcon.CriticalCount() + (event->severity >= 3 ? 1 : 0);
    uint32_t kernel   = g_defcon.KernelThreats() + (event->tier_result == 3 ? 1 : 0);
    uint32_t blocked  = g_defcon.BlockedIpCount();
    g_defcon.SetTotalAlerts(total);
    g_defcon.SetCriticalCount(critical);
    g_defcon.SetKernelThreats(kernel);
    g_defcon.SetBlockedIpCount(blocked);
    g_defcon.Calculate();

    return 0;
}

int32_t aegis_bridge_pop_event(Aegis::Bridge::IpcEvent* event) {
    using namespace Aegis::Bridge;

    if (!g_initialized || !event) return -1;

    if (!g_eventQueue.Pop(*event)) {
        return -2;  // Queue empty
    }

    return 0;
}

uint8_t aegis_bridge_get_defcon() {
    using namespace Aegis::Bridge;
    if (!g_initialized) return kDefcon5Safe;
    return g_defcon.Calculate();
}

void aegis_bridge_update_defcon(uint32_t critical, uint32_t blocked,
                                uint32_t kernel, uint32_t total) {
    using namespace Aegis::Bridge;

    if (!g_initialized) return;

    g_defcon.SetCriticalCount(critical);
    g_defcon.SetBlockedIpCount(blocked);
    g_defcon.SetKernelThreats(kernel);
    g_defcon.SetTotalAlerts(total);

    uint8_t level = g_defcon.Calculate();
    fprintf(stdout, "[AEGIS Bridge] DEFCON updated: %u (%s) — critical=%u blocked=%u kernel=%u total=%u\n",
        level, DefconAggregator::LevelLabel(level), critical, blocked, kernel, total);
}

int32_t aegis_bridge_block_ip(uint32_t ip) {
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&ip);
    fprintf(stdout, "[AEGIS Bridge] IPS: Block IP %d.%d.%d.%d\n",
        bytes[0], bytes[1], bytes[2], bytes[3]);
    return 0;
}

int32_t aegis_bridge_unblock_ip(uint32_t ip) {
    uint8_t* bytes = reinterpret_cast<uint8_t*>(&ip);
    fprintf(stdout, "[AEGIS Bridge] IPS: Unblock IP %d.%d.%d.%d\n",
        bytes[0], bytes[1], bytes[2], bytes[3]);
    return 0;
}

int32_t aegis_bridge_send_command(const Aegis::Bridge::IpcCommand* cmd) {
    if (!cmd) return -1;
    fprintf(stdout, "[AEGIS Bridge] Command sent: type=%u target=%u\n",
        cmd->command_id, cmd->target_subsystem);
    return 0;
}

int32_t aegis_bridge_receive_command(Aegis::Bridge::IpcCommand* cmd) {
    if (!cmd) return -1;
    return -2;
}

uint32_t aegis_bridge_get_event_count() {
    using namespace Aegis::Bridge;
    return g_eventQueue.Count();
}

uint32_t aegis_bridge_get_dropped_count() {
    using namespace Aegis::Bridge;
    return g_eventQueue.Dropped();
}

const char* aegis_bridge_get_defcon_label() {
    using namespace Aegis::Bridge;
    return DefconAggregator::LevelLabel(g_defcon.CurrentLevel());
}

const char* aegis_bridge_get_defcon_description() {
    using namespace Aegis::Bridge;
    return DefconAggregator::LevelDescription(g_defcon.CurrentLevel());
}

} // extern "C"
