# ADR-0002: Runtime Convergence — `core/` is the canonical production runtime

**Status:** Accepted  
**Date:** 2026-09-07  
**Supersedes:** the implicit `src/`-as-entrypoint build reality (build.zig currently builds `src/main.zig`)

## Context

ADR-0001 declared `core/dispatcher.zig` the sole orchestrator and the `core/`
modules canonical, but the current `build.zig` compiles `src/main.zig` as the
`aegis_nids` executable and does not reference `core/` at all. The runtime is
therefore split across two trees (`core/` ~150 files, `src/` ~77 files), which is
a duplicate-runtime stop-the-line condition. The 64-step plan (authoritative over
the legacy G1-G23 plans) requires ONE runtime, ONE build, ONE event model.

## Decision

- **Canonical production runtime = `core/`**, per ADR-0001. `core/dispatcher.zig`
  is the sole orchestrator; `core/canonical_event.zig` is the event-schema
  authority; `core/nids_analyze.zig` must not compete.
- **`src/` is classified LEGACY-TO-MIGRATE**: its modular runtime
  (`src/main.zig`, `src/contract`, `src/capture`, `src/detection`, `src/policy`,
  `src/forensic`, `src/windows`, `src/reliability`, `src/federation`, `src/xdr`)
  is kept on disk and in git until the migration audit in T2/T3, then migrated
  into `core/` or removed.
- **The build switch is deferred to T2/T3** (this ADR records the decision only;
  T1 does not rewrite `build.zig`).
- **Enforcement authority = `shield/src/lib.rs`** (Rust PEP), unchanged per
  ADR-0001. `rust-src/lib.rs` (crate `aegis_pep`, the PEP FFI build.zig currently
  links) is a PEP FFI that must be redirected/merged into `shield/` in T8.
  `shield_rust/` is a stale near-duplicate and was untracked at T1 (kept on disk
  for reference audit).
- `runtime_manifest.json` was rewired (v3) to describe this canonical runtime and
  tag every module REAL / PARTIAL / STUB / MOCK / LEGACY with its
  `last_verified_commit`.

## Considered Options

- **A. `src/` = canonical** (follow the current build.zig). Rejected: contradicts
  ADR-0001, whose ownership map is the locked contract; would orphan the
  `core/` pipeline (canonical_event, event_fabric, flow, dispatcher) that all
  downstream 64-step tickets (T2-T20) depend on.
- **C. selective merge** (src spine + core modules). Rejected for T1: leaves two
  active trees and a long merge window; better to converge on one tree first.

## Consequences

1. T2/T3 must rewrite `build.zig` to build `core/` and run the migration audit on
   `src/` before removal.
2. T8 must merge `rust-src/lib.rs` (aegis_pep) into the `shield/` PEP crate so
   there is exactly one enforcement code path.
3. Any ownership change still requires a new ADR (ADR-0001 consequence 1).

## References

- ADR-0001 (architecture lock)
- docs/architecture/authority-map.md (T1 recon note)
- docs/FILE_CLASSIFICATION.md
- runtime_manifest.json (v3)
- docs/baseline.json, docs/environment.json