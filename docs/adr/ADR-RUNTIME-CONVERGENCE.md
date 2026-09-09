# ADR-RUNTIME-CONVERGENCE

**Status:** Accepted
**Date:** 2026-09-09
**Supersedes:** â€”
**Superseded by:** â€”
**Owner:** AEGIS Core Team
**Related:** BLOCKER A (Runtime Truth), BLOCKER B (Build Truth), BLOCKER C (Repository Integrity)

---

## Context

The AEGIS NIDS Windows repository has accumulated multiple sources of truth:

1. **Duplicate Rust runtime:** `lib.rs` at root (7 lines, marked "OBSOLETE â€” DO NOT COMPILE") co-exists with `src/lib.rs` (321 lines, canonical). `Cargo.toml` defaults to `src/lib.rs`, but readers cannot tell which file is authoritative without inspecting every file.
2. **Generated artifacts committed to git:** 147 files under `.zig-cache/`, 16 under `target/`, 3 under `zig-out/`, 1 under `__pycache__/`, plus `.rcgu.o` files at root â€” all explicitly listed in `.gitignore` yet still tracked.
3. **Runtime state committed to git:** `logs/pids/*.pid` and `logs/anomalous.json` â€” runtime artifacts that should never be source-controlled.
4. **Duplicate rules:** `Back Rules.json` (21 KB) duplicates `Rules.json` (9.6 KB) with no clear authoritative version.
5. **No formal canonical-source declaration:** No ADR documents which directories are canonical, which are legacy, which are test fixtures, which are build outputs.

The Deep Remediation Report (Section 3, BLOCKER A) requires this be resolved before any feature work continues.

---

## Decision

Establish a single, documented, machine-checkable notion of canonical runtime.

### 1. Canonical Source Root

The repository root (`/`) is the **canonical source root**. There is no nested `core/` or `runtime/` directory.

### 2. Canonical Entrypoint

| Layer | Canonical Entrypoint | Language |
|---|---|---|
| Daemon manager | `aegis_daemon.py` | Python |
| NIDS core (Tier-1) | `nids_main.zig` | Zig |
| Brain (Tier-2) | `windows_brain.py` | Python |
| Memory Shield (Tier-3) | `src/lib.rs` (crate `sec_monitor`) | Rust |
| Nose (perf monitor) | `windows_perf.go` | Go |
| IPC Bridge | `bridge/aegis_bridge_main.cpp` | C++ |
| Dashboard | `Dashboard.py` | Python |
| Console UI | `aegis_console.py` | Python |

### 3. Canonical Runtime

```
aegis_daemon.py start
    â†“
spawn bridge/aegis_bridge.exe       (C++ IPC hub)
spawn zig build run                 (Zig Tier-1)
spawn python windows_brain.py       (Python Tier-2)
spawn cargo run --release           (Rust Tier-3)
spawn go run windows_perf.go        (Go Nose)
```

There is **ONE production runtime**. All other implementations must be marked `legacy`, `migration`, `experimental`, or `test`.

### 4. File Classification

| Class | Examples | Rule |
|---|---|---|
| `canonical-source` | `nids_main.zig`, `src/lib.rs`, `windows_brain.py`, `Rules.json` | Production source; built and shipped |
| `canonical-build` | `build.zig`, `Cargo.toml`, `CMakeLists.txt`, `go.mod`, `build_all.bat` | Build orchestration; not shipped |
| `canonical-config` | `Rules.json`, `configs/` | Runtime configuration |
| `canonical-docs` | `README.md`, `docs/adr/*` | Documentation |
| `canonical-test` | `test_e2e.py`, `bridge/aegis_bridge_test.cpp` | Tests; not shipped |
| `legacy` | `lib.rs` (root), `Back Rules.json` | Old code kept for reference; NEVER compiled |
| `build-output` | `*.exe`, `*.dll`, `*.pdb`, `.zig-cache/`, `target/`, `build/`, `*.rcgu.o` | Generated; NEVER tracked |
| `runtime-state` | `logs/pids/*.pid`, `logs/anomalous.json` | Runtime artifacts; NEVER tracked |
| `vendor` | `lib/bootstrap-*`, `lib/vis-*` | Third-party vendored assets |

---

## Verification

The following commands MUST return empty (or zero) after this ADR is applied:

```bash
git ls-files | grep -E "\.(exe|dll|pdb|obj|o|so|ilk|exp|lib)$" | wc -l   # 0
git ls-files | grep -E "^(\.zig-cache|target|__pycache__|zig-out|shield/target|build/|dist/)/" | wc -l   # 0
git ls-files | grep -E "^logs/" | wc -l   # 0
git ls-files | grep -E "\.rcgu\.o$" | wc -l   # 0
git ls-files lib.rs | wc -l   # 0
git ls-files "Back Rules.json" | wc -l   # 0
```

The following MUST exist:

```bash
test -f docs/adr/ADR-RUNTIME-CONVERGENCE.md
test -f inventory.json
test -f runtime_manifest.json
test -f build_truth.json
test -f reference_map.json
test -f AGENTS.md
```

---

## Stop-the-Line Triggers

- Duplicate runtime detected
- Build/runtime mismatch
- Stale evidence
- Production mock

---

## References

- Deep Remediation Report Sections 3 (BLOCKER A), 4 (BLOCKER B), 5 (BLOCKER C), 51 (STOP-THE-LINE)
- AI Command (Section 49): "Do not create a second runtime."