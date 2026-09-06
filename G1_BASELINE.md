# G1 Repository Baseline

**Commit:** pre-g1-cleanup-54044a8 (before) → post-g1-cleanup (after)
**Date:** 2026-09-07

## Cleanup Summary
- Removed 191 files (build artifacts, cache, duplicates, orphaned files)
- 243 → 52 tracked files

## File Classification
| Category | Count |
|---|---|
| Zig source | 7 |
| Rust source | 2 |
| Python source | 7 |
| Go source | 1 |
| C/C++/Header | 15 |
| Config/Build | 9 |
| Vendored libs | 8 |
| Other | 3 |

## Removed
- .zig-cache/ (100+ cache files)
- zig-out/ (build output)
- target/ (Rust build artifacts)
- __pycache__/ (Python cache)
- bridge/aegis_bridge, bridge/aegis_bridge_test (binaries)
- windows_sec_monitor.exe, *.rcgu.o (Rust binaries)
- logs/anomalous.json, logs/pids/*.pid (runtime data)
- Back Rules.json (backup duplicate)
- lib.rs at root (obsolete; src/lib.rs is canonical)
- bridge/aegis_bindings.zig (orphaned; replaced by runtime DynLib)
- bridge/aegis_bridge_ffi.rs (orphaned; not consumed by Cargo)
- drivers/wfp_callout_cpp/ (duplicate of C version)
- drivers/minifilter_cpp/ (duplicate of C version)
- threat_graph.html (generated file)

## .gitignore Updated
- Added: logs/pids/*.pid, *.rcgu.o, *.bak, *.backup, *.tmp, Back *.json

## Build Status
- Zig: build.zig present (aegis-nids.exe)
- Rust: Cargo.toml + src/lib.rs (sec_monitor.dll)
- C++: CMakeLists.txt (aegis_ipc.dll + bridge)
- Go: go.mod (windows_perf.go)
- Drivers: C versions only (wfp_callout/ + minifilter/)

## Next Gate
G2 — Canonical Event Contract
