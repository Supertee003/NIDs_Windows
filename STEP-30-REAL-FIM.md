# Step 30 — Real FIM (File Integrity Monitor — Native Windows Watcher Lifecycle)

**Status:** STUB (S2 framework — framework verified; multiple-watch lifecycle incomplete)
**Files:** `core/windows_fim.zig` (legacy framework reference — NOT in production build; production framework: `windows/fim.zig` — framework exists; lifecycle verification missing per STEP 30 contract)
**Production Subsystem:** `windows/fim.zig`

---

## Contract (Per ROADMAP STEP 30)

Native Windows APIs:
- `CreateFileW`
- `ReadDirectoryChangesW`
- `OVERLAPPED`

Events tracked:
- `create`
- `modify`
- `rename`
- `delete`
- `overflow`
- `re-arm`
- `shutdown`

Every active watcher must keep handle/resource separate.

---

## Lifecycle Verification (Partial — STEP 30 Dependency)

Per `core/windows_fim.zig` / `core/fim.zig` (production framework in `windows/fim.zig`):
- Handle created (`CreateFileW`) → framework verified
- Watcher lifecycle (`start/stop/shutdown`) → framework present; multiple active watcher lifecycle unverified
- OVERLAPPED I/O (async event handling) → framework defined; real-time event delivery to Zig event fabric unverified
- Resource separation (multiple active watchers) → framework supports multiple handles; isolation verification missing

---

## References

- `core/windows_fim.zig` (legacy framework — NOT in production build)
- `core/fim.zig` (legacy framework — NOT in production build)
- `docs/ARCHITECTURE-TRUTH.md` (FIM: framework REAL; real-time event verification unverified — STEP 30 dependency)
