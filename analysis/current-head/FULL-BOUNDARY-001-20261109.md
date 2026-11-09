# FULL-BOUNDARY-001 — the whole project, enumerated

- **Generated:** 2026-11-09 from `4e98d75` by `admin-evidence/full-boundary-20261109/full_boundary.py`
- **Scope:** every regular file under the project root (`.git` excluded), plus the host surface the project owns. Nothing is dropped: a file that no rule matches fails the run.

## Completeness proof

| quantity | value |
|---|---|
| files on disk (excl. .git) | 120,826 |
| tracked by git | 1,622 |
| untracked, not ignored | 2 |
| ignored by git | 119,203 |
| classified by a rule | 120,826 |
| unclassified | 0 |
| rule gaps | 0 |
| **partition holds** | **True** |

`sum_of_buckets == on_disk_files` and `unclassified == rule_gaps == 0`. A file that appears in no bucket makes the script exit non-zero.

## What the numbers say

- **The repository is 1.3% of the tree.** 1,620 tracked files vs 120,819 on disk: ~82k local scratch (`.work/`), ~26k build output, ~6.2k local evidence, ~2k runtime state, ~1.7k caches. Those 119k files are not the product; they are the working surface that produced it.
- **Tracked evidence coverage: 1,350 of 1,622 files (83%) are never named by any evidence entry.**
- **Ring 1 (contract/runtime) alone: 190 of 301 files (63%) are never named.**

## On-disk buckets (every file counted once)

| class | files | what it is |
|---|---:|---|
| `scratch-local` | 82,045 | `.work/` scratch scripts and run logs |
| `build-output` | 25,713 | zig-out, target, build, dist, per-crate target |
| `local-evidence` | 6,250 | evidence/, admin-evidence/, vm_test_kit_* |
| `runtime-state` | 1,950 | logs/, reports/, outputs/, pid/, powershell/ |
| `build-cache` | 1,657 | .zig-cache, __pycache__, .pytest_cache |
| `verification` | 601 | tests/ and src/tests/ |
| `tooling` | 579 | tools/, scripts/ |
| `dependency-cache` | 315 | ts_policy/node_modules |
| `native-source` | 272 | src/windows, src/platform, bridge |
| `release-artifact` | 243 | release/, installer/ |
| `analytics-source` | 209 | brain/ |
| `documentation` | 207 | docs/ and root handoff notes |
| `runtime-source` | 190 | src/, nose/, rust-src/ |
| `analysis-record` | 177 | analysis/, .analysis/, .archify/ |
| `support-source` | 154 | shield/, go/, mouth/, aegis_dashboard/ |
| `agent-config` | 112 | .agents, .claude, .freebuff, .manus, .cloud-attachments |
| `contract` | 46 | shared/ and contracts/ |
| `configuration` | 28 | configs/ and config/ |
| `root-file` | 21 | root scripts and data files |
| `authoring-source` | 18 | ts_policy/ |
| `record-map` | 13 | root JSON maps |
| `kernel-source` | 13 | drivers/ |
| `repo-metadata` | 5 | .gitattributes, .gitignore, .gitleaks.toml |
| `vendored-web` | 5 | lib/ (tom-select, vis) |
| `ci` | 3 | .github/workflows |
| **total** | **120,826** | |

## Tracked files by class (1,620 total)

| class | files | never named | ring |
|---|---:|---:|---|
| `verification` | 310 | 255 | ring2_support |
| `documentation` | 207 | 189 | ring3_out_of_contract |
| `tooling` | 199 | 158 | ring2_support |
| `runtime-source` | 188 | 108 | ring1_contract |
| `release-artifact` | 177 | 175 | ring3_out_of_contract |
| `analysis-record` | 155 | 136 | ring3_out_of_contract |
| `agent-config` | 101 | 101 | ring3_out_of_contract |
| `local-evidence` | 52 | 52 | ring3_out_of_contract |
| `analytics-source` | 45 | 41 | ring2_support |
| `native-source` | 38 | 23 | ring1_contract |
| `contract` | 35 | 26 | ring1_contract |
| `configuration` | 28 | 26 | ring1_contract |
| `support-source` | 26 | 25 | ring2_support |
| `authoring-source` | 18 | 14 | ring2_support |
| `record-map` | 13 | 1 | ring3_out_of_contract |
| `kernel-source` | 12 | 7 | ring1_contract |
| `repo-metadata` | 5 | 3 | ring3_out_of_contract |
| `root-file` | 5 | 3 | ring3_out_of_contract |
| `vendored-web` | 5 | 5 | ring3_out_of_contract |
| `ci` | 3 | 2 | ring2_support |

## Build units

| unit | manifest | present | in CI | command |
|---|---|---|---|---|
| zig | `build.zig` | True | False | `zig build` |
| zig_tests | `build.zig` | True | False | `zig build test` |
| rust_pep | `rust-src/Cargo.toml` | False | False | `cargo build --release` |
| cpp_native | `CMakeLists.txt` | True | False | `cmake -B build && cmake --build build` |
| cpp_bridge | `bridge/CMakeLists.txt` | True | False | `cmake -B bridge/build bridge && cmake --build bridge/build` |
| go_nose | `nose/go.mod` | True | False | `cd nose && go build -o aegis-nose.exe .` |
| go_aggregator | `go/aggregator/go.mod` | True | False | `cd go/aggregator && go build .` |
| shield | `shield/Cargo.toml` | True | True | `cd shield && cargo build --release` |
| mouth | `mouth/Cargo.toml` | True | True | `cd mouth && cargo build --release` |
| dashboard | `aegis_dashboard/Cargo.toml` | True | True | `cd aegis_dashboard && cargo build --release` |
| ts_policy | `ts_policy/package.json` | True | False | `cd ts_policy && npm run typecheck && npm run test:all` |
| python_brain | `brain/windows_brain.py` | True | False | `(interpreted)` |

## Host surface (measured 2026-11-09)

| object | state |
|---|---|
| service `AegisNids` | Running / Automatic |
| service `AegisAggregator` | Running / Automatic |
| driver `AegisWfp` | **Stopped** / Manual |
| driver `AegisMinifilter` | **Stopped** / Manual |
| processes | aegis_nids, aegis-aggregator-service, aegis-nose |
| install dir | `C:\Program Files\AEGIS NIDS` (11 runtime binaries incl. `.pre-wirev3` backup) |
| registry service keys | AegisNids, AegisAggregator, AegisWfp, AegisMinifilter |
| scheduled tasks | none |

Two of the four host objects are running; both kernel drivers are `Stopped (Manual)`, so no kernel-path claim can be made from this host today.

## What this enumeration cannot cover

Files, directories, host objects and build units are now exhaustively counted. These are not enumerable the same way, and no count here should be read as covering them:

1. **Behavioral coverage.** A named file is not a tested path; a tested path is not a host-verified path.
2. **Runtime states at a moment nobody sampled.** Only the states above were observed.
3. **Remote/deployed surfaces.** Builds on other hosts or VMs are outside this scan.
4. **Secrets hygiene.** This scan classifies the *file* `server.key`/`.env` presence, never their contents.

Regenerate with: `python admin-evidence/full-boundary-20261109/full_boundary.py`
