# Step 29 — Real ETW (Native Windows Real-Time Source)

**Status:** STUB (S2 framework) — Real-time verification missing (STEP 29 dependency: real Windows activity → ETW native APIs → Zig event normalization → Canonical Event → Fabric)
**Files:** `core/etw_realtime.zig` (legacy framework reference; `core/etw_realtime_config.json`; `core/etw_realtime_cli.zig` — CLI for ETW; NOT in production build; production framework: `src/windows/etw_realtime.zig`)
**Production Subsystem:** `src/windows/etw_realtime.zig` (production framework — framework exists; real-time event verification missing)

---

## Contract (Per ROADMAP STEP 29)

C++ owns native Windows ETW APIs:
- `StartTraceW`
- `EnableTraceEx2`
- `OpenTraceW`
- `ProcessTrace`
- `callback()` (C ABI boundary)
- `shutdown()` (resource lifetime)

Zig owns:
- Lifecycle (`core/lifecycle.zig` — framework verified)
- Event normalization (`core/canonical_event.zig` — REAL framework; wire encoding verified)
- Canonical Event emission (`src/contract/event.zig` — REAL framework)

Proof pipeline:
```
Real Windows Activity
    ↓
Real ETW Source (C++ adapter)
    ↓
C ABI Boundary (start/stop/poll/callback/health/error/last_error)
    ↓
Zig Normalization (`core/canonical_event.zig`)
    ↓
Canonical Event (immutable, 109-byte wire, AEG1 magic, v2.0.0)
    ↓
Event Fabric (`core/event_fabric.zig`)
```

---

## Native Handle Contract (Verified Structurally)

Every native handle from C++ adapter must have:
- `owner`: C++ adapter owns handle lifetime
- `lifetime`: start → poll → callback cycle → shutdown
- `threading contract`: callback runs on adapter thread; Zig normalizes asynchronously
- `shutdown`: `core/lifecycle.zig` handles graceful drain
- `error state`: adapter error reported through C ABI; Zig handles as `error_event`
- `health`: adapter health exposed; watchdog (`reliability/watchdog.zig`) monitors

---

## Exit Gate (STEP 29 Partial)

- [x] Native adapter framework present (`core/windows_adapters.zig` — production framework; C++ adapter framework verified structurally)
- [x] ETW framework defined (`core/etw_realtime.zig` — 36,192 lines; framework present; CLI framework verified)
- [x] Lifecycle shutdown covers adapter (`core/lifecycle.zig` — verified structurally)
- [ ] Real Windows event verification (requires real Windows activity captured via `StartTraceW` → `ProcessTrace` → `callback` → Zig normalization → Canonical Event)
- [ ] Real-time telemetry pipeline verified (Step 33 dependency — host telemetry aggregated; Step 38 dependency — Windows Golden Path)

---

## References

- `core/etw_realtime.zig` (legacy framework reference — 36,192 lines; NOT in production build per ADR)
- `core/etw_realtime_cli.zig` (CLI framework — 5,959 lines)
- `core/etw_realtime_config.json` (configuration framework)
- `core/windows_adapters.zig` (production C++ adapter framework — 34,912 lines)
- `docs/ARCHITECTURE-TRUTH.md` (Windows: framework REAL; real-time event verification unverified — STEP 29 dependency)
- `docs/SHIELD-AUTHORITY.md` (Cross-language: C++ adapter -> Zig; C ABI contract verified structurally; real event verification pending)
