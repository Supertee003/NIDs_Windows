# Step 29 — Real ETW (Native Windows Real-Time Source — ETW Adapter Lifecycle)

**Status:** STUB (S2 framework — framework present; real-time event verification requires STEP 38 Golden Path chain)
**Files:** `core/etw_realtime.zig` (legacy framework; 36,192 lines), `core/etw_realtime_cli.zig` (CLI framework; 5,959 lines), `core/etw_realtime_config.json` (867 bytes)
**Production Subsystem:** `windows/etw_realtime.zig` (production framework — 36,192 lines)
**Next Dependency:** STEP 38 (Golden Path exit gate — requires STEP 9 canonical event + STEP 10 Go acquisition + STEP 29 ETW real-time verification + STEP 34 forensics audit chain)

---

## Native Adapter Lifecycle (Verified Structurally — Not Production Verified)

Per `docs/ARCHITECTURE-TRUTH.md` (Windows ETW — framework REAL; real-time event verification missing):
- `windows/etw_realtime.zig` = production ETW adapter framework
- `core/etw_realtime.zig` = legacy framework (tracked; user's original work; NOT in production build per ADR-RUNTIME-CONVERGENCE.md and ARCHITECTURE-TRUTH.md)
- `core/windows_adapters.zig` = C ABI adapter framework (production — 34,912 lines; start/stop/poll/callback/health/error/last_error contract verified structurally; real-time event delivery verification missing)

---

## Exit Gate (STEP 29 — Requires STEP 38 Golden Path Chain)

- [x] Native adapter framework present (`core/etw_realtime.zig` — legacy; `windows/etw_realtime.zig` — production)
- [x] Lifecycle framework present (`core/lifecycle.zig` — init/start/run/drain/stop; shutdown covers adapter)
- [x] C ABI boundary framework (`core/windows_adapters.zig` — verified structurally; real-time event delivery to Zig event fabric unverified)
- [x] Canonical event framework (`contract/event.zig` — 109-byte wire; AEG1 magic; v2.0.0)
- [ ] Real Windows ETW source verified (requires real-time event capture: `StartTraceW` → `EnableTraceEx2` → `ProcessTrace` → `callback` → Zig normalization → Canonical Event → Fabric — STEP 38 requires full chain evidence package)
