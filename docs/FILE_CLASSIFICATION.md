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
| `src/` | **LEGACY → migrate** | 77 | Candidate legacy per canonical-runtime = `core/` decision (ADR). Contains its own modular runtime (`main.zig`) that build.zig currently builds. Classified LEGACY-TO-MIGRATE; do not delete until migration audit. |
| `core/` | **SOURCE (canonical)** | 150 | Canonical runtime per ADR-0001. Contains dispatcher.zig (orchestrator), canonical_event.zig, event_fabric.zig, flow_engine.zig, etc. Mixed with many `*_proof.zig` / `*_integration.zig`. |
| `src/tests/` | TEST | ~50 | Unit test harnesses mirroring src/ submodules. |
| `tests/` | TEST | 50 | Test corpus / integration tests. |
| `shield/` | **SOURCE (canonical Rust PEP)** | 211 | Real enforcement authority: `src/lib.rs` (Tier-3 payload safety) + `src/windows_enforce.rs` (decision matrix + IOCTL WFP). `target/` subtree (build) present → remove build. |
| `rust-src/` | SOURCE (Rust PEP variant) | 1 | `lib.rs` PEP (`aegis_pep`) linked by build.zig via `target/release/aegis_pep.dll.lib`. Needs consolidation decision with shield/. |
| `shield_rust/` | **LEGACY (duplicate)** | 1 | Stale duplicate of `shield/src/windows_enforce.rs`; no Cargo.toml → cannot build. Candidate for removal after audit. |
| `brain/` | SOURCE (Python Brain) | 15 | Advisory Brain modules. |
| `nose/` | SOURCE (Go Nose) | 10 | Go acquisition/ingestion. |
| `go/` | SOURCE (Go) | 10 | Go collectors / transport. |
| `bridge/` | SOURCE (C++ IPC bridge) | 13 | Native bridge layer. |
| `tests/`, `scripts/` | TEST/TOOLING | 49 | Helper scripts (aegisctl.py etc.), test scripts. |
| `drivers/` | SOURCE (kernel driver) | 18 | WFP kernel driver source. |
| `shared/`, `lib/`, `tools/`, `mouth/` | SOURCE/CONFIG | 45 | Support libraries, tools. |
| `config/`, `configs/`, `Rules.json` | CONFIG | ~15 | Runtime config, rules. |
| `docs/` | DOC | 87 | Architecture, runbooks, ADRs, plans. |
| `G1_BASELINE.md` .. `G20_XDR.md` | DOC (legacy plan) | 20 | Legacy G-plan docs; superseded by 64-step plan. Keep as reference (LEGACY doc). |
| `README.md`, `ROADMAP.md` | DOC | 2 | Pointers. |
| `build/`, `dist/` | BUILD | 39 | Build outputs. |
| `.zig-cache/` | BUILD (cache) | 78 | Zig build cache — should not be tracked. |
| `logs/` | BACKUP/BUILD (runtime) | 74 | Runtime logs — should not be tracked. |
| `backups/` | BACKUP | 210 | Backup archives + prerestore trees. |
| `backup_*` dirs (~40) | BACKUP | ~180 | Phase/session backup snapshots. |
| `aegis_dashboard/` | GENERATED+BACKUP (→ BUILD) | 1406 | Rust dashboard crate with a committed `target/` build tree (~1398 files) + `*.phase16_backup`/`*.phase20_backup` files. |
| Top-level `*.exe`, `*.obj`, `*.pdb` | BUILD | ~50 | Compiled CLI relics tracked (gitignored now but already tracked). |
| `*.exe.obj` / `*.pdb` per CLI | BUILD | — | MSVC object/debug relics. |
| `installer/`, `installer.py`, `deploy_windows.py` | SOURCE (build tooling) | 7 | Installer / deploy scripts. |
| `aegis.manifest.json`, `build_manifest.json`, `runtime_manifest.json`, `sbom.spdx.json`, `Cargo.lock`, `Cargo.toml`, `CMakeLists.txt`, `Makefile`, `build.zig`, `requirements.txt` | CONFIG/GENERATED | ~11 | Build + runtime manifests. |
| `aegis_restore.bat`, `aegis_restore.ps1.bak.*`, `backup_recovery.py` | TOOLING/BACKUP | 3 | Recovery tooling + a backup `.bak` relic. |
| `.github/` | CONFIG (CI) | 2 | CI workflows. |
| `query`, `models/`, `cluster_config.json` etc. | UNKNOWN/GENERATED | ~10 | Unidentified; hold for reference audit. |

## Rules honoured

- UNKNOWN / LEGACY are NOT deleted until reference audit (per STEP 1).
- BACKUP / BUILD / GENERATED artifacts are candidates for **removal from git tracking** (not disk deletion) in STEP 2 cleanup; disk copies preserved locally.
- Classification is a living document: update `last_verified_commit` per module in `runtime_manifest.json` (STEP 6).