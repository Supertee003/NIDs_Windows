/**
 * aegis_adapter.hpp — AEGIS NIDS Adapter Framework (C++ Edition)
 *
 * T2 (Steps 11-12): a Windows-adapter abstraction that the Zig core can
 * drive over a pure C ABI. The framework owns all direct Windows API
 * contact for host/network sources (ETW, FIM, Registry, Process,
 * Windows networking). Once this boundary exists, Zig MUST NOT call
 * Windows APIs directly for these sources.
 *
 * Model:
 *   - Each concrete adapter implements the Adapter vtable:
 *       start()/stop()/poll()/callback()/health()/error()
 *   - AdapterRegistry owns a set of adapters by kind.
 *   - C ABI (extern "C") exports a flat, opaque handle API to Zig:
 *       aegis_adapter_create / start / stop / poll / health / error / destroy
 *
 * Contract:
 *   - Acquisition-only. No policy decision, no enforcement (ADR-0001).
 *   - Events produced here MUST be encoded as the canonical event wire
 *     format owned by Zig (see nose/canonical.go + core/canonical_event.zig).
 *   - Handles are opaque void* to Zig; the framework type-checks on the
 *     C++ side.
 *
 * Build: C++17, no exceptions, MSVC/GCC/Clang. Library: aegis_adapter.
 */
#ifndef AEGIS_ADAPTER_HPP
#define AEGIS_ADAPTER_HPP

#include <cstdint>
#include <cstddef>

namespace Aegis {
namespace Adapter {

// Adapter kinds the framework can instantiate (matches canonical sources).
enum class Kind : uint8_t {
    Unknown    = 0,
    Etw        = 1,   // Windows Event Tracing
    Fim        = 2,   // File Integrity Monitoring (ReadDirectoryChangesW)
    Registry   = 3,   // Registry change notifications
    Process    = 4,   // Process lifecycle (CreateToolhelp32Snapshot/ETW)
    Network    = 5,   // Windows networking (WFP/ETW net events)
};

// Lifecycle / health states.
enum class State : uint8_t {
    Created     = 0,
    Started     = 1,
    Stopped     = 2,
    Error       = 3,
};

// poll() result.
enum class PollResult : uint8_t {
    NoEvent = 0,
    Event   = 1,
    Exhausted = 2,
};

// A single canonical event in wire form (109 bytes) plus its size.
// The wire layout is owned by Zig; we only shuttle the opaque bytes.
struct CanonicalFrame {
    uint8_t  data[109];   // = WIRE_PAYLOAD_SIZE
    uint32_t size;        // 109 on success
};

// Generic error/health snapshot for the Zig core.
struct AdapterStatus {
    State   state;
    uint32_t lastError;   // platform error code (GetLastError / errno)
    uint64_t eventsProduced;
};

// Abstract adapter interface. Each concrete adapter fills the vtable.
struct Adapter {
    void*     ctx;
    int32_t   (*start)(void* ctx);
    int32_t   (*stop)(void* ctx);
    PollResult (*poll)(void* ctx, CanonicalFrame* out);
    void      (*callback)(void* ctx, const CanonicalFrame& frame); // optional push path
    void      (*health)(void* ctx, AdapterStatus* out);
    int32_t   (*error)(void* ctx);
    void      (*destroy)(void* ctx);
};

// Registry of adapters (opaque to callers).
struct AdapterRegistry;

// ---- C++ API ----
AdapterRegistry* registry_create();
void             registry_destroy(AdapterRegistry* r);
/// Add an adapter of kind to the registry. Returns opaque handle != nullptr.
Adapter*         registry_add(AdapterRegistry* r, Kind kind, const char* name);
/// Convenience: build the default set (ETW, FIM, Registry, Process).
AdapterRegistry* build_default_registry();

} // namespace Adapter
} // namespace Aegis

// =====================================================================
// extern "C" ABI — callable from Zig (and any C ABI consumer).
// All handles are opaque void*.
// =====================================================================
#ifdef __cplusplus
extern "C" {
#endif

// Framework lifecycle.
void* aegis_adapter_registry_create(void);
void  aegis_adapter_registry_destroy(void* reg);

// Adapter lifecycle (handle from the registry).
void* aegis_adapter_start(void* reg, uint8_t kind);
int32_t aegis_adapter_stop(void* handle);
int32_t aegis_adapter_poll(void* handle, uint8_t* out, uint32_t maxOut,
                           uint8_t* canonicalBuf, uint32_t canonicalCap,
                           uint32_t* bytesPerEvent);
void  aegis_adapter_health(void* handle, uint8_t* state,
                           uint32_t* lastError, uint64_t* eventsProduced);

// Convenience single-shot helpers (for tests / Zig smoke):
int32_t aegis_adapter_selftest(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // AEGIS_ADAPTER_HPP