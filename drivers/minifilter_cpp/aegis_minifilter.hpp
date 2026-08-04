/**
 * aegis_minifilter.hpp — AEGIS NIDS Minifilter Driver Shared Header (C++ Edition)
 *
 * Defines shared structures, RAII helpers, and namespace Aegis::Minifilter
 * for the kernel-mode minifilter driver and user-mode Zig reader
 * (minifilter_reader.zig) via FilterCommunicationPort.
 *
 * Architecture: C++ Kernel Driver (KERNEL_FILE/KERNEL_PROCESS layer
 * of 3-Layer Architecture)
 *
 * Monitors:
 *   - File operations: IRP_MJ_CREATE, IRP_MJ_WRITE, IRP_MJ_SET_INFORMATION
 *   - Process creation/exit: PsSetCreateProcessNotifyRoutineEx
 *   - Communication via FilterCommunicationPort kernel→user mode
 */

#ifndef AEGIS_MINIFILTER_HPP
#define AEGIS_MINIFILTER_HPP

#include <fltdefs.h>

// ====== Namespace ======
namespace Aegis {
namespace Minifilter {

// ====== Minifilter Altitude ======
// 370000 = FSFilter Anti-Virus (between HSM and Encryption)
#define AEGIS_MINIFILTER_ALTITUDE  L"370000"

// ====== File/Process Event (matches Zig extern struct layout) ======
#pragma pack(push, 1)
struct FileEvent {
    UINT32  event_type;     // 1=KERNEL_FILE, 2=KERNEL_PROCESS
    UINT32  operation;      // IRP_MJ_CREATE, IRP_MJ_WRITE, etc. or PROCESS_CREATE/EXIT
    UINT32  file_name_len;  // Length of file name string following this header
    UINT32  process_id;     // PID of the process performing the operation
    UINT32  rule_id;        // Matched rule ID (0 if no match yet)
    UINT32  severity;       // 0=Low, 1=Medium, 2=High, 3=Critical
    UINT32  reserved;
    UINT64  timestamp;      // Event timestamp
};
#pragma pack(pop)

// ====== Process Event Types ======
constexpr UINT32 kProcessCreate  = 0x100;
constexpr UINT32 kProcessExit    = 0x101;

// ====== Communication Port ======
#define AEGIS_FILTER_PORT_NAME  L"\\AegisMinifilterPort"

// ====== Max message sizes ======
constexpr ULONG kMaxMsgSize    = 4096;
constexpr ULONG kMaxFileName   = 260;

// ====== RAII: Filter Handle Guard ======
// Manages FltRegisterFilter / FltUnregisterFilter with automatic cleanup.
class FilterGuard {
    PFLT_FILTER m_handle;
    bool        m_registered;

public:
    FilterGuard() : m_handle(nullptr), m_registered(false) {}

    ~FilterGuard() {
        Unregister();
    }

    NTSTATUS Register(PDRIVER_OBJECT driverObj, const FLT_REGISTRATION* reg) {
        NTSTATUS status = FltRegisterFilter(driverObj, reg, &m_handle);
        if (NT_SUCCESS(status)) m_registered = true;
        return status;
    }

    void Unregister() {
        if (m_registered && m_handle) {
            FltUnregisterFilter(m_handle);
            m_handle = nullptr;
            m_registered = false;
        }
    }

    PFLT_FILTER Get() const { return m_handle; }
    bool IsRegistered() const { return m_registered; }

    FilterGuard(const FilterGuard&) = delete;
    FilterGuard& operator=(const FilterGuard&) = delete;
};

// ====== RAII: Communication Port Guard ======
// Manages FltCreateCommunicationPort / FltCloseCommunicationPort.
class CommPortGuard {
    PFLT_PORT m_serverPort;
    PFLT_PORT m_clientPort;
    bool      m_created;

public:
    CommPortGuard() : m_serverPort(nullptr), m_clientPort(nullptr), m_created(false) {}

    ~CommPortGuard() {
        Close();
    }

    void Close() {
        if (m_clientPort) {
            FltCloseCommunicationPort(m_clientPort);
            m_clientPort = nullptr;
        }
        if (m_serverPort) {
            FltCloseCommunicationPort(m_serverPort);
            m_serverPort = nullptr;
        }
        m_created = false;
    }

    PFLT_PORT* ServerPortPtr() { return &m_serverPort; }
    PFLT_PORT* ClientPortPtr() { return &m_clientPort; }
    PFLT_PORT  ServerPort() const { return m_serverPort; }
    PFLT_PORT  ClientPort() const { return m_clientPort; }

    void SetClientPort(PFLT_PORT port) { m_clientPort = port; }

    CommPortGuard(const CommPortGuard&) = delete;
    CommPortGuard& operator=(const CommPortGuard&) = delete;
};

// ====== RAII: File Name Information Guard ======
// Manages FltGetFileNameInformation / FltReleaseFileNameInformation.
class FileNameGuard {
    PFLT_FILE_NAME_INFORMATION m_info;
    bool                       m_parsed;

public:
    FileNameGuard() : m_info(nullptr), m_parsed(false) {}

    ~FileNameGuard() {
        Release();
    }

    NTSTATUS Acquire(PFLT_CALLBACK_DATA data, FLT_FILE_NAME_OPTIONS options) {
        NTSTATUS status = FltGetFileNameInformation(data, options, &m_info);
        if (NT_SUCCESS(status)) {
            status = FltParseFileNameInformation(m_info);
            if (NT_SUCCESS(status)) m_parsed = true;
        }
        return status;
    }

    void Release() {
        if (m_info) {
            FltReleaseFileNameInformation(m_info);
            m_info = nullptr;
            m_parsed = false;
        }
    }

    PFLT_FILE_NAME_INFORMATION Get() const { return m_info; }
    PUNICODE_STRING Name() const { return m_parsed ? &m_info->Name : nullptr; }
    bool IsValid() const { return m_parsed && m_info != nullptr; }

    FileNameGuard(const FileNameGuard&) = delete;
    FileNameGuard& operator=(const FileNameGuard&) = delete;
};

// ====== Suspicious Pattern Matcher (C++ class) ======
// Encapsulates file/process pattern matching logic with rule ID mapping.
// Replaces scattered static arrays with a structured, extensible approach.
struct PatternRule {
    const WCHAR* pattern;
    const WCHAR* ruleId;
    UINT32       severity;
    UINT32       eventType;  // 1=KERNEL_FILE, 2=KERNEL_PROCESS
};

class PatternMatcher {
public:
    // ====== KERNEL_FILE patterns (from Rules.json) ======
    static const PatternRule kFilePatterns[];

    // ====== KERNEL_PROCESS patterns ======
    static const PatternRule kProcessPatterns[];

    // ====== PowerShell cradle patterns ======
    static const PatternRule kPowerShellPatterns[];

    // Match a Unicode string against file patterns
    static bool MatchFile(PUNICODE_STRING name, const PatternRule** matched);

    // Match a Unicode string against process patterns
    static bool MatchProcess(PUNICODE_STRING name, const PatternRule** matched);

    // Match command line against PowerShell cradle patterns
    static bool MatchCommandLine(PUNICODE_STRING cmdLine, const PatternRule** matched);
};

// ====== File Pattern Rules (KERNEL_FILE) ======
// R1001: System32 Write Attempt
// R1002: Ransomware Rename Pattern
// R1003: Startup Folder Modification
// R1004: DLL Drop in System32
// R1005: hosts File Modification
const PatternRule PatternMatcher::kFilePatterns[] = {
    { L"\\Windows\\System32",  L"R1001", 3, 1 },  // System32 write
    { L".locked",              L"R1002", 3, 1 },  // Ransomware rename
    { L".encrypted",           L"R1002", 3, 1 },  // Ransomware variant
    { L"\\Startup\\",          L"R1003", 2, 1 },  // Startup folder
    { L".dll",                 L"R1004", 2, 1 },  // DLL drop
    { L"\\hosts",              L"R1005", 3, 1 },  // hosts file
    { nullptr, nullptr, 0, 0 }  // Sentinel
};

// ====== Process Pattern Rules (KERNEL_PROCESS) ======
// R2001: Mimikatz Execution
// R2002: svchost Process Hollowing
// R2003: PowerShell Cradle Download
// R2004: certutil Download Abuse
// R2005: procdump Credential Harvest
const PatternRule PatternMatcher::kProcessPatterns[] = {
    { L"mimikatz",             L"R2001", 3, 2 },
    { L"procdump",             L"R2005", 3, 2 },
    { L"certutil",             L"R2004", 2, 2 },
    { nullptr, nullptr, 0, 0 }  // Sentinel
};

// ====== PowerShell Cradle Patterns ======
const PatternRule PatternMatcher::kPowerShellPatterns[] = {
    { L"IEX",                  L"R2003", 3, 2 },
    { L"DownloadString",       L"R2003", 3, 2 },
    { L"DownloadFile",         L"R2003", 2, 2 },
    { nullptr, nullptr, 0, 0 }  // Sentinel
};

// ====== Pattern Matching Implementation ======
inline bool PatternMatcher::MatchFile(PUNICODE_STRING name, const PatternRule** matched) {
    if (!name || !name->Buffer) return false;
    for (int i = 0; kFilePatterns[i].pattern != nullptr; i++) {
        if (wcsstr(name->Buffer, kFilePatterns[i].pattern) != nullptr) {
            *matched = &kFilePatterns[i];
            return true;
        }
    }
    return false;
}

inline bool PatternMatcher::MatchProcess(PUNICODE_STRING name, const PatternRule** matched) {
    if (!name || !name->Buffer) return false;
    for (int i = 0; kProcessPatterns[i].pattern != nullptr; i++) {
        if (wcsstr(name->Buffer, kProcessPatterns[i].pattern) != nullptr) {
            *matched = &kProcessPatterns[i];
            return true;
        }
    }
    return false;
}

inline bool PatternMatcher::MatchCommandLine(PUNICODE_STRING cmdLine, const PatternRule** matched) {
    if (!cmdLine || !cmdLine->Buffer) return false;
    for (int i = 0; kPowerShellPatterns[i].pattern != nullptr; i++) {
        if (wcsstr(cmdLine->Buffer, kPowerShellPatterns[i].pattern) != nullptr) {
            *matched = &kPowerShellPatterns[i];
            return true;
        }
    }
    return false;
}

} // namespace Minifilter
} // namespace Aegis

// ====== C-compatible aliases ======
extern "C" {
    typedef Aegis::Minifilter::FileEvent AEGIS_FILE_EVENT_C;
}

#endif // AEGIS_MINIFILTER_HPP
