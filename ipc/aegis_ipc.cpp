/**
 * aegis_ipc.cpp — AEGIS NIDS IPC Bridge DLL (Layer 1: KERNEL → USERSPACE)
 *
 * Userspace DLL that maps the shared ring buffers created by the WFP driver
 * and minifilter driver into process address space. Provides C-ABI exports
 * for the Zig capture layer and Rust forensic layer to consume.
 *
 * Build: MSVC C++20 (userspace DLL, /MD)
 * Language: C++ (for RAII resource management, std::atomic, std::span)
 *
 * Copyright (c) 2024 AEGIS NIDS Project
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <atomic>
#include <span>
#include <memory>
#include <string>
#include <mutex>

/* ─── Ring Buffer Structures (must match kernel definitions exactly) ─── */
#pragma pack(push, 1)
struct AegisRingHeader {
    std::atomic<uint32_t> write_pos;
    std::atomic<uint32_t> read_pos;
    uint32_t              capacity;
    uint32_t              packet_count;
    uint32_t              dropped_count;
};

struct AegisFileRingHeader {
    std::atomic<uint32_t> write_pos;
    std::atomic<uint32_t> read_pos;
    uint32_t              capacity;
    uint32_t              event_count;
    uint32_t              dropped_count;
};

struct AegisPktMeta {
    uint32_t size;
    uint32_t orig_len;
    uint64_t timestamp;
    uint16_t layer_id;
    uint16_t direction;
    uint32_t process_id;
    uint16_t ip_proto;
    uint16_t _pad;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    // Semi-NIDS fields (set by Rust correlation, read by WFP kernel)
    int32_t  threat_score;  // 0-100 (x10 fixed-point: 600 = 60.0)
    uint8_t  confidence;   // 0=Unknown,1=Low,2=Medium,3=High,4=Critical
    uint32_t risk_flags;   // Bitfield of matched detection rules
};

struct AegisFileEvent {
    uint32_t size;
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint16_t event_type;
    uint16_t file_size_hi;
    uint32_t file_size_lo;
    uint16_t path_len;
    uint16_t _pad;
    wchar_t path[520];
};

/* ─── Pipe Event Structure (must match kernel pipe_interceptor) ─── */
struct AegisPipeRingHeader {
    std::atomic<uint32_t> write_pos;
    std::atomic<uint32_t> read_pos;
    uint32_t              capacity;
    uint32_t              event_count;
    uint32_t              dropped_count;
};

struct AegisPipeEvent {
    uint32_t size;
    uint64_t timestamp;
    uint32_t pid;
    uint32_t tid;
    uint16_t event_type;    // 0=create, 1=connect, 2=write, 3=read, 4=close
    uint16_t risk_flags;    // Bitfield of pipe risk indicators
    uint32_t creator_pid;   // PID that created the pipe
    uint32_t data_len;      // Captured data bytes
    uint16_t pipe_name_len;
    uint16_t _pad;
    wchar_t pipe_name[256]; // Pipe name (e.g., \pipe\msagent)
    uint8_t  data[4096];    // Captured pipe data
};
#pragma pack(pop)

/* ─── Mapped Ring Buffer Wrapper (RAII) ─── */
class AegisMappedRing {
public:
    AegisMappedRing() : handle_(INVALID_HANDLE_VALUE), mapped_(nullptr), header_(nullptr), data_(nullptr) {}

    ~AegisMappedRing() {
        unmap();
    }

    /* Non-copyable, movable */
    AegisMappedRing(const AegisMappedRing&) = delete;
    AegisMappedRing& operator=(const AegisMappedRing&) = delete;
    AegisMappedRing(AegisMappedRing&& o) noexcept
        : handle_(o.handle_), mapped_(o.mapped_), header_(o.header_), data_(o.data_) {
        o.handle_ = INVALID_HANDLE_VALUE;
        o.mapped_ = nullptr;
        o.header_ = nullptr;
        o.data_ = nullptr;
    }

    /**
     * open - Map the kernel ring buffer into this process.
     * @section_name  Global section name (e.g., "Global\\AegisWfpRing")
     * @return         true on success
     */
    bool open(const wchar_t* section_name) {
        std::lock_guard<std::mutex> lock(mutex_);

        handle_ = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, section_name);
        if (!handle_ || handle_ == INVALID_HANDLE_VALUE) return false;

        mapped_ = MapViewOfFile(handle_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (!mapped_) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
            return false;
        }

        header_ = static_cast<AegisRingHeader*>(mapped_);
        data_   = reinterpret_cast<uint8_t*>(mapped_) + sizeof(AegisRingHeader);
        return true;
    }

    void unmap() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (mapped_)  { UnmapViewOfFile(mapped_);  mapped_ = nullptr; }
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; }
        header_ = nullptr;
        data_   = nullptr;
    }

    /* ─── Read Interface (single-consumer, lock-free) ─── */

    /**
     * read_packet - Read next packet from ring into caller's buffer.
     * @out_meta    Receives packet metadata
     * @out_buf     Buffer for packet payload
     * @buf_size    Size of out_buf; receives actual bytes copied
     * @return      true if packet read, false if ring empty
     */
    bool read_packet(AegisPktMeta* out_meta, uint8_t* out_buf, uint32_t* buf_size) {
        if (!header_ || !data_) return false;

        uint32_t wp = header_->write_pos.load(std::memory_order_acquire);
        uint32_t rp = header_->read_pos.load(std::memory_order_relaxed);

        if (rp == wp) return false; /* Ring empty */

        uint32_t cap = header_->capacity;

        /* Read metadata (with wrap handling) */
        AegisPktMeta meta;
        uint32_t meta_size = sizeof(AegisPktMeta);

        if (rp + meta_size <= cap) {
            memcpy(&meta, data_ + rp, meta_size);
        } else {
            uint32_t c1 = cap - rp;
            memcpy(&meta, data_ + rp, c1);
            memcpy(reinterpret_cast<uint8_t*>(&meta) + c1, data_, meta_size - c1);
        }

        /* Validate meta */
        if (meta.size < meta_size || meta.size > 65535 + meta_size) {
            /* Corrupt record — skip to write position (recovery) */
            header_->read_pos.store(wp, std::memory_order_release);
            return false;
        }

        *out_meta = meta;

        /* Read payload */
        uint32_t payload_offset = (rp + meta_size) % cap;
        uint32_t payload_len = meta.size - meta_size;

        if (payload_len > 0 && out_buf && buf_size) {
            uint32_t to_copy = (payload_len < *buf_size) ? payload_len : *buf_size;
            if (payload_offset + to_copy <= cap) {
                memcpy(out_buf, data_ + payload_offset, to_copy);
            } else {
                uint32_t c1 = cap - payload_offset;
                memcpy(out_buf, data_ + payload_offset, c1);
                memcpy(out_buf + c1, data_, to_copy - c1);
            }
            *buf_size = to_copy;
        } else if (buf_size) {
            *buf_size = 0;
        }

        /* Advance read position */
        uint32_t new_rp = (rp + meta.size) % cap;
        header_->read_pos.store(new_rp, std::memory_order_release);
        return true;
    }

    /* ─── Stats ─── */
    uint32_t get_packet_count() const { return header_ ? header_->packet_count : 0; }
    uint32_t get_dropped_count() const { return header_ ? header_->dropped_count : 0; }
    uint32_t get_capacity() const { return header_ ? header_->capacity : 0; }

    bool is_valid() const { return mapped_ != nullptr; }

private:
    HANDLE            handle_;
    void*             mapped_;
    AegisRingHeader*  header_;
    uint8_t*          data_;
    std::mutex        mutex_;
};

/* ─── File Event Ring Wrapper ─── */
class AegisFileRingReader {
public:
    AegisFileRingReader() : handle_(INVALID_HANDLE_VALUE), mapped_(nullptr), header_(nullptr), data_(nullptr) {}
    ~AegisFileRingReader() { unmap(); }

    bool open(const wchar_t* section_name) {
        handle_ = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, section_name);
        if (!handle_ || handle_ == INVALID_HANDLE_VALUE) return false;
        mapped_ = MapViewOfFile(handle_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (!mapped_) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; return false; }
        header_ = static_cast<AegisFileRingHeader*>(mapped_);
        data_   = reinterpret_cast<uint8_t*>(mapped_) + sizeof(AegisFileRingHeader);
        return true;
    }

    void unmap() {
        if (mapped_) { UnmapViewOfFile(mapped_); mapped_ = nullptr; }
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; }
    }

    bool read_event(AegisFileEvent* out_evt) {
        if (!header_ || !data_) return false;
        uint32_t wp = header_->write_pos.load(std::memory_order_acquire);
        uint32_t rp = header_->read_pos.load(std::memory_order_relaxed);
        if (rp == wp) return false;

        uint32_t cap = header_->capacity;
        /* Read size field first to know total record length */
        uint32_t evt_size;
        if (rp + 4 <= cap) memcpy(&evt_size, data_ + rp, 4);
        else {
            uint32_t c1 = cap - rp;
            memcpy(&evt_size, data_ + rp, c1);
            memcpy(reinterpret_cast<uint8_t*>(&evt_size) + c1, data_, 4 - c1);
        }

        if (evt_size < 4 || evt_size > sizeof(AegisFileEvent)) {
            header_->read_pos.store(wp, std::memory_order_release);
            return false;
        }

        /* Copy full event */
        if (rp + evt_size <= cap) {
            memcpy(out_evt, data_ + rp, evt_size);
        } else {
            uint32_t c1 = cap - rp;
            memcpy(out_evt, data_ + rp, c1);
            memcpy(reinterpret_cast<uint8_t*>(out_evt) + c1, data_, evt_size - c1);
        }

        header_->read_pos.store((rp + evt_size) % cap, std::memory_order_release);
        return true;
    }

    bool is_valid() const { return mapped_ != nullptr; }

private:
    HANDLE               handle_;
    void*                mapped_;
    AegisFileRingHeader* header_;
    uint8_t*             data_;
};

/* ─── Pipe Event Ring Wrapper ─── */
class AegisPipeRingReader {
public:
    AegisPipeRingReader() : handle_(INVALID_HANDLE_VALUE), mapped_(nullptr), header_(nullptr), data_(nullptr) {}
    ~AegisPipeRingReader() { unmap(); }

    bool open(const wchar_t* section_name) {
        handle_ = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, section_name);
        if (!handle_ || handle_ == INVALID_HANDLE_VALUE) return false;
        mapped_ = MapViewOfFile(handle_, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (!mapped_) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; return false; }
        header_ = static_cast<AegisPipeRingHeader*>(mapped_);
        data_   = reinterpret_cast<uint8_t*>(mapped_) + sizeof(AegisPipeRingHeader);
        return true;
    }

    void unmap() {
        if (mapped_) { UnmapViewOfFile(mapped_); mapped_ = nullptr; }
        if (handle_ && handle_ != INVALID_HANDLE_VALUE) { CloseHandle(handle_); handle_ = INVALID_HANDLE_VALUE; }
    }

    bool read_event(AegisPipeEvent* out_evt) {
        if (!header_ || !data_) return false;
        uint32_t wp = header_->write_pos.load(std::memory_order_acquire);
        uint32_t rp = header_->read_pos.load(std::memory_order_relaxed);
        if (rp == wp) return false;

        uint32_t cap = header_->capacity;
        /* Read size field first */
        uint32_t evt_size;
        if (rp + 4 <= cap) memcpy(&evt_size, data_ + rp, 4);
        else {
            uint32_t c1 = cap - rp;
            memcpy(&evt_size, data_ + rp, c1);
            memcpy(reinterpret_cast<uint8_t*>(&evt_size) + c1, data_, 4 - c1);
        }

        if (evt_size < 4 || evt_size > sizeof(AegisPipeEvent)) {
            header_->read_pos.store(wp, std::memory_order_release);
            return false;
        }

        /* Copy full event (with wrap handling) */
        if (rp + evt_size <= cap) {
            memcpy(out_evt, data_ + rp, evt_size);
        } else {
            uint32_t c1 = cap - rp;
            memcpy(out_evt, data_ + rp, c1);
            memcpy(reinterpret_cast<uint8_t*>(out_evt) + c1, data_, evt_size - c1);
        }

        header_->read_pos.store((rp + evt_size) % cap, std::memory_order_release);
        return true;
    }

    bool is_valid() const { return mapped_ != nullptr; }

private:
    HANDLE                handle_;
    void*                 mapped_;
    AegisPipeRingHeader*  header_;
    uint8_t*              data_;
};

/* ─── Global Instances ─── */
static AegisMappedRing       g_wfp_ring;
static AegisFileRingReader   g_file_ring;
static AegisPipeRingReader   g_pipe_ring;
static std::once_flag        g_init_flag;
static bool                  g_initialized = false;

/* ─── C-ABI Exports (for Zig/Rust FFI) ─── */

extern "C" {

/**
 * aegis_ipc_init - Initialize IPC bridge, map ring buffers.
 * @return  0 on success, -1 on failure
 */
__declspec(dllexport) int32_t aegis_ipc_init(void) {
    std::call_once(g_init_flag, []() {
        g_initialized = g_wfp_ring.open(L"Global\\AegisWfpRing") &&
                        g_file_ring.open(L"Global\\AegisFileRing");
        // Pipe ring is optional — not fatal if missing
        g_pipe_ring.open(L"Global\\AegisPipeRing");
    });
    return g_initialized ? 0 : -1;
}

/**
 * aegis_ipc_read_packet - Read next packet from WFP ring buffer.
 * @out_meta  Pointer to AegisPktMeta (caller-allocated)
 * @out_buf   Buffer for packet payload
 * @buf_size  In: buffer size. Out: bytes copied
 * @return    1 if packet read, 0 if empty, -1 on error
 */
__declspec(dllexport) int32_t aegis_ipc_read_packet(
    AegisPktMeta* out_meta,
    uint8_t*      out_buf,
    uint32_t*     buf_size
) {
    if (!g_initialized) return -1;
    return g_wfp_ring.read_packet(out_meta, out_buf, buf_size) ? 1 : 0;
}

/**
 * aegis_ipc_read_file_event - Read next file event from minifilter ring.
 * @out_evt  Pointer to AegisFileEvent (caller-allocated)
 * @return   1 if event read, 0 if empty, -1 on error
 */
__declspec(dllexport) int32_t aegis_ipc_read_file_event(AegisFileEvent* out_evt) {
    if (!g_initialized) return -1;
    return g_file_ring.read_event(out_evt) ? 1 : 0;
}

/**
 * aegis_ipc_read_pipe_event - Read next pipe event from pipe interceptor ring.
 * @out_evt  Pointer to AegisPipeEvent (caller-allocated)
 * @return   1 if event read, 0 if empty, -1 on error
 */
__declspec(dllexport) int32_t aegis_ipc_read_pipe_event(AegisPipeEvent* out_evt) {
    if (!g_initialized) return -1;
    if (!g_pipe_ring.is_valid()) return -1; // Pipe ring not mapped
    return g_pipe_ring.read_event(out_evt) ? 1 : 0;
}

/**
 * aegis_ipc_get_stats - Get WFP ring buffer statistics.
 * @out_packets  Receives total packets captured
 * @out_dropped  Receives total packets dropped
 * @return       0 on success
 */
__declspec(dllexport) int32_t aegis_ipc_get_stats(uint32_t* out_packets, uint32_t* out_dropped) {
    if (!g_initialized) return -1;
    *out_packets = g_wfp_ring.get_packet_count();
    *out_dropped = g_wfp_ring.get_dropped_count();
    return 0;
}

/**
 * aegis_ipc_shutdown - Unmap ring buffers and cleanup.
 */
__declspec(dllexport) void aegis_ipc_shutdown(void) {
    g_wfp_ring.unmap();
    g_file_ring.unmap();
    g_pipe_ring.unmap();
    g_initialized = false;
}

} /* extern "C" */

/* ─── DLL Entry Point ─── */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    switch (ul_reason) {
    case DLL_PROCESS_ATTACH:
        /* Auto-initialize on load */
        aegis_ipc_init();
        break;
    case DLL_PROCESS_DETACH:
        aegis_ipc_shutdown();
        break;
    }
    return TRUE;
}
