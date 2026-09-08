# Build Truth (Step 4)

**Date:** 2026-09-08
**Baseline Commit:** 78b62be

## Invariant

```
source root  =  D:\NIDs_Windows
build root   =  D:\NIDs_Windows
test root    =  D:\NIDs_Windows
installer root = D:\NIDs_Windows
release root =  D:\NIDs_Windows
```

**ONE source root, ONE build root, ONE test root.**

## Build Commands (All Pass)

| Command | Status | Output | Time |
|---------|--------|--------|------|
| `zig build` | ✅ OK | `zig-out/bin/aegis_nids.exe` | ~3s |
| `zig build test` | ✅ OK | TrustStore, PEP, dispatcher tests | ~5s |
| `cargo build --release` | ✅ OK | `target/release/aegis_pep.dll` | ~4s |
| `cargo test --release` | ✅ OK | 5/5 tests passed | ~29s |
| `cmake -B build -S .` | ✅ OK | CMake configuration | <1s |
| `cmake --build build --config Release` | ✅ OK | 3 native helper DLLs | ~15s |

## Artifact Verification

| Artifact | Path | Size | Source |
|----------|------|------|--------|
| Core daemon | `zig-out/bin/aegis_nids.exe` | ~8MB | `src/main.zig` |
| Rust PEP | `target/release/aegis_pep.dll` | ~4MB | `src/pep/pep_enforce.rs` |
| WFP user | `build/Release/aegis_wfp_user.dll` | ~60KB | `src/windows/aegis_wfp.c` |
| ETW helper | `build/Release/aegis_etw_helper.dll` | ~13KB | `src/windows/etw_native.c` |
| FIM helper | `build/Release/aegis_fim_helper.dll` | ~13KB | `src/windows/fim_native.c` |

## Forbidden Patterns

| Pattern | Violation |
|---------|-----------|
| build → src | Build must not create source |
| installer → old core | Installer must not embed stale source |
| tests → another runtime | Tests must use same runtime |
| core/ → src/ | Root core/ must not import into src/ |

## Exit Gate

- [x] `zig build` succeeds
- [x] `zig build test` succeeds
- [x] `cargo build --release` succeeds
- [x] `cargo test --release` succeeds
- [x] `cmake -B build -S .` succeeds
- [x] `cmake --build build --config Release` succeeds
- [x] All 5 artifacts present
- [x] `build_manifest.json` matches artifacts
- [x] `tools/installer.py` consumes `build_manifest.json`
- [x] CI green (8/8 jobs)
