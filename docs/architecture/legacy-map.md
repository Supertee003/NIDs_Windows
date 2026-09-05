# AEGIS NIDs Windows -- Legacy Map

**Status:** Tracking  
**Date:** 2026-09-02  

## Legacy Modules Requiring Audit

### P0.6: nids_analyze.zig

| Field | Value |
|---|---|
| Path | core/nids_analyze.zig |
| Lines | 2,237 |
| Language | Zig |
| Role | Legacy analysis engine (pre-rewrite) |
| Runtime used? | YES -- nids_main.zig imports and spawns it as T1 thread |
| Competes with? | dispatcher.zig (404 lines) |
| Consumer(s) | nids_main.zig (T1 thread), brain (via UDP alerts) |
| Authority violation? | Potentially -- runs its own detection/analysis pipeline |
| Action | AUDIT: determine if nids_analyze provides functionality not in dispatcher |

### Other Legacy Candidates

| Module | Lines | Status | Action |
|---|---|---|---|
| event_queue.zig | 234 | Superseded by event_fabric.zig | Verify no consumers; remove if unused |
| priority_queue.zig | 290 | May overlap with event_fabric | Audit; merge or remove |
| fabric_accounting.zig | 719 | Used by event_fabric? | Verify consumer; document |
| contract_freeze.zig | 582 | One-time freeze tool | Move to tests/ if not runtime |
| legacy_removal.zig | 246 | Self-referential cleanup tool | Run once; remove |
| runtime_spine.zig | 596 | Proof module, not runtime | Move to tests/ |

## Migration Tracking

| ID | Module | From | To | Status | Owner |
|---|---|---|---|---|---|
| M001 | nids_analyze.zig | core/ | core/legacy/ or removed | PENDING AUDIT | P0.6 |
| M002 | event_queue.zig | core/ | removed if unused | PENDING | P1 |
| M003 | proof modules (26) | core/ | tests/proofs/ | PENDING | P0.5 |
| M004 | e2e_harness | core/ | tests/e2e/ | PENDING | P0.5 |
| M005 | performance_harness | core/ | tests/perf/ | PENDING | P0.5 |

## Backup Files (CLEANED)

As of G42 cleanup (2026-09-02):
- 80 backup files removed from git tracking
- 0 .bak / .phase*_backup files tracked
- Cython fast_scan.c untracked

## .zig-cache (CLEANED)

As of commit a80c598:
- 0 .zig-cache files tracked
- .gitignore covers .zig-cache/
