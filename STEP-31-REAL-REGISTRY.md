# Step 31 — Real Registry Monitor (Trie-Based Native Registry Monitoring)

**Status:** STUB (S2 framework — framework verified; trie-based rule matching and event production unverified)
**Files:** `core/registry_trie.zig` (legacy framework reference — NOT in production build); production framework: `windows/registry_monitor.zig`
**Production Subsystem:** `windows/registry_monitor.zig`

---

## Contract (Per ROADMAP STEP 31)

Native Windows APIs:
- `RegOpenKeyEx`
- `RegNotifyChangeKeyValue`

Pipeline:
```
Registry Event (C++ adapter: RegNotifyChangeKeyValue callback)
    ↓
C ABI Boundary (C++ adapter -> Zig event fabric)
    ↓
Zig Normalization (canonical_event.zig — immutable event)
    ↓
Registry Trie Rules (core/registry_trie.zig — framework exists; trie-based rules matching unverified)
    ↓
Evidence Production (core/forensics_engine.zig — framework present; registry evidence unverified)
```

---

## Production Status

- Registry adapter framework present (`windows/registry_monitor.zig` — framework verified structurally)
- Registry trie rules framework present (`core/registry_trie.zig` — 29,731 lines; legacy framework reference — NOT in production build; production framework exists in `windows/registry_monitor.zig`)
- Trie-based rule matching: framework defined; full ruleset verification missing (STEP 31 dependency)
- Registry event normalization through canonical event: framework present; event production verification unverified (STEP 9 dependency — canonical event enforcement)

---

## References

- `core/registry_trie.zig` (legacy framework reference — NOT in production build per ADR)
- `core/registry_trie_config.json` (configuration framework)
- `core/registry_trie_cli.zig` (CLI framework — unverified)
- `docs/ARCHITECTURE-TRUTH.md` (Registry: framework REAL; trie-based rules and event verification unverified — STEP 31 dependency)
