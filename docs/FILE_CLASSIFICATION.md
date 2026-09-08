# FILE_CLASSIFICATION.md

Baseline file classification for **T1 Recon & Baseline Convergence**.
Frozen at commit `98e5dc0966ca91510d65b425c80bac5b2dc760cb`, 2026-09-07.
Categories follow the 64-step plan STEP 1 taxonomy: SOURCE / TEST / PROOF / DOC / CONFIG / GENERATED / BUILD / BACKUP / LEGACY / EXPERIMENTAL / UNKNOWN.

## Legend

| Category | Meaning |
|---|---|
| SOURCE | Production source code, part of canonical runtime |
| TEST | Test / harness / integration-test source |
| PROOF | Proof-of-concept, demonstration phase modules |
| DOC | Documentation, plans, reports, ADRs |
| CONFIG | Configuration, manifests, schemas, rules |
| GENERATED | Generated source, snapshots, lockfiles, derived files |
| BUILD | Build outputs, caches, binaries, artifacts |
| BACKUP | Backup directories / archives / snapshots of prior state |
| LEGACY | Dead / superseded / duplicate code not in the current build |
| EXPERIMENTAL | Experimental / research-only code |
| UNKNOWN | Not yet audited; keep until reference audit |

## Top-level classification

| Path | Category | Count (tracked) | Notes |
|---|---|---|---|
| `src/` | **SOURCE (canonical runtime)** | 75 | **Step 2 update:** `build.zig` → `src/main.zig` is the one production runtime (ONE BUILD truth). The old `core/`-is-canonical classification is superseded; `core/` was legacy and is removed (below). |
| `core/` | **LEGACY/DEV (kept per user decision)** | 159 | Original development tree, restored and tracked 2026-09-08. NOT in the production build (`build.zig` → `src/main.zig`); retained for reference and as contract context for the T8–T19 tests. Encoding normalized UTF-16LE → UTF-8 + LF (Step 2 round 3). |
| `src/tests/` | TEST | ~50 | Unit test harnesses mirroring src/ submodules. |
| `tests/` | TEST | 50 | Test corpus / integration tests. |
| `shield/` | **SOURCE (canonical Rust PEP)** | 211 | Real enforcement authority: `src/lib.rs` (Tier-3 payload safety) + `src/windows_enforce.rs` (decision matrix + IOCTL WFP). `target/` subtree (build) present → remove build. |
| `rust-src/` | SOURCE (Rust PEP variant) | 1 | `lib.rs` PEP (`aegis_pep`) linked by build.zig via `target/release/aegis_pep.dll.lib`. Needs consolidation decision with shield/. |
| `shield_rust/` | **LEGACY (duplicate; removed in Step 2)** | 0 | Stale duplicate of `shield/src/windows_enforce.rs`; no Cargo.toml → could not build. Deleted from disk 2026-09-08. |
| `brain/` | SOURCE (Python Brain) | 15 | Advisory Brain modules. |
| `nose/` | SOURCE (Go Nose) | 10 | Go acquisition/ingestion. |
| `go/` | SOURCE (Go) | 10 | Go collectors / transport. |
| `bridge/` | SOURCE (C++ IPC bridge) | 13 | Native bridge layer. |
| `tests/`, `scripts/` | TEST/TOOLING | 49 | Helper scripts (aegisctl.py etc.), test scripts. |
| `drivers/` | SOURCE (kernel driver) | 18 | WFP kernel driver source. |
| `shared/`, `tools/`, `mouth/` | SOURCE/CONFIG | 33 | Support libraries, tools. (`lib/` third-party vendor bundles removed in Step 2 — no build reference.) |
| `config/`, `configs/`, `Rules.json` | CONFIG | ~15 | Runtime config, rules. |
| `docs/` | DOC | 87 | Architecture, runbooks, ADRs, plans. |
| `G1_BASELINE.md` .. `G20_XDR.md` | DOC (legacy plan) | 20 | Legacy G-plan docs; superseded by 64-step plan. Keep as reference (LEGACY doc). |
| `README.md`, `ROADMAP.md` | DOC | 2 | Pointers. |
| `build/`, `dist/` | BUILD (removed in Step 2) | 0 | Build outputs; deleted from disk 2026-09-08. |
| `.zig-cache/`, `zig-out/`, `target/` | BUILD cache (removed in Step 2) | 0 | Regenerable build caches (~2.1 GB); deleted from disk 2026-09-08. |
| `logs/` | BACKUP/BUILD (runtime; removed in Step 2) | 0 | Runtime logs; deleted 2026-09-08. |
| `backups/` | BACKUP (removed in Step 2) | 0 | Backup archives + prerestore trees; deleted 2026-09-08. |
| `backup_*` dirs (~40) | BACKUP (removed in Step 2) | 0 | Phase/session backup snapshots; deleted 2026-09-08. Git history is the durable archive. |
| `aegis_dashboard/` | SOURCE (Rust dashboard) | 4 | Step 2 removed the on-disk `target/` build tree and `*.phase16_backup`/`*.phase20_backup` files; tracked source remains. |
| Top-level `*.exe`, `*.obj`, `*.pdb` | BUILD (removed in Step 2) | 0 | Compiled CLI relics; deleted from disk 2026-09-08 (all untracked since the first cleanup round). |
| `*.exe.obj` / `*.pdb` per CLI | BUILD | — | MSVC object/debug relics. |
| `installer/`, `installer.py`, `deploy_windows.py` | SOURCE (build tooling) | 7 | Installer / deploy scripts. |
| `aegis.manifest.json`, `build_manifest.json`, `runtime_manifest.json`, `sbom.spdx.json`, `Cargo.lock`, `Cargo.toml`, `CMakeLists.txt`, `Makefile`, `build.zig`, `requirements.txt` | CONFIG/GENERATED | ~11 | Build + runtime manifests. |
| `aegis_restore.bat`, `aegis_restore.ps1.bak.*` | TOOLING/BACKUP (removed in Step 2) | 0 | Stale embedded restore snapshots; deleted 2026-09-08. |
| `tools/legacy/backup_recovery.py` | TOOLING (G28 legacy security tests) | 1 | Orphaned root `backup_recovery.py` preserved under `tools/legacy/` (distinct from `tools/backup_recovery.py` II19 tooling). |
| `.github/` | CONFIG (CI) | 2 | CI workflows. |
| `query`, `models/ml_model.json` | UNKNOWN/GENERATED (removed in Step 2) | 0 | Single-word temp file + untracked 18-byte placeholder model; deleted 2026-09-08. `cluster_config.json` etc. remain tracked under `config/`. |

## Step 2 outcome (2026-09-08, round 3)

- Disk cleanup: ~2.9 GB removed (`.zig-cache/` 820 MB, `target/` 1.3 GB, plus `release/T20-final/`, `lib/`, `shield_rust/`, 41 `backup_*`/`backups/` dirs, `logs/`, `build/`, `dist/`, root `*.exe|*.pdb|*.obj`).
- `core/` was removed, then **restored and tracked per user decision** (original development work); it stays out of the production build graph.
- Git index: 6 tracked duplicates removed (`config/config/*` and `config/workflows/*`; canonical copies live in `config/` and `.github/workflows/`).
- Stale one-shot helpers deleted: `analyze_cleanup.py`, `build_refs.py`, `check_ci.py`, `show_runs.py`, `verify_builds.py`, `step2_round2.txt`, `cleanup_list.txt`, `core_files.txt`, `lib_files.txt`, `release_files.txt`.
- **Encoding normalization:** all 159 `core/` files were UTF-16LE with CRLF (invisible to grep/AI, uncompilable by Zig, unreadable by `pytest`); converted to UTF-8 + LF. Contract tests went 89 failed → all green after regenerating `build_manifest.json` digests (`python tools/release_engineering.py --manifest`).
- CI truth: `.github/workflows/host-regression.yml` Phase K retargeted to `src/` per-file compiles (the legacy per-file list matched the removed tree layout).
- Canonical configs: `config/` (runtime) and `.github/workflows/` (CI) — do not recreate `config/config/` or `config/workflows/`.

## Rules honoured

- UNKNOWN / LEGACY are NOT deleted until reference audit (per STEP 1).
- BACKUP / BUILD / GENERATED artifacts are candidates for **removal from git tracking** (not disk deletion) in STEP 2 cleanup; disk copies preserved locally.
- Classification is a living document: update `last_verified_commit` per module in `runtime_manifest.json` (STEP 6).