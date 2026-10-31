# 10 - Current Phase

## Status: Kernel NIDS Consolidation and Evidence Closure

G1-G21 rewrite complete. G22 final polish complete. G23 consolidation is being
closed against the current Kernel NIDS source and live evidence. The production
product is detection-only; enforcement activation is permanently out of scope.

Provider readiness, WFP transport, and retained PEP boundaries may exist for
diagnostics, fail-closed behavior, or historical/lab evidence, but they do not
authorize a production host effect.

## Current-Head Evidence Update — 2026-10-31

- `IDS-HOST-004` is implemented at source commit `940a6f8` (E2): ETW/FIM/Registry
  detector identities may flow to forensic evidence/IDS receipts, but host
  telemetry cannot enter threat scoring or policy/PEP/ActionDispatcher.
- At the `IDS-HOST-004` source commit, `zig build` and `zig build test` passed;
  that result is historical and is not the current full-suite status. The focused
  detection-authority and prevention-gate pytest contracts passed 20/20 then.
- This is source/build and unit/component evidence only. It is not Windows-host
  E5 proof, full ADR-0009 closure, kernel-driver production qualification, or
  release approval. See `admin-evidence/ids-host-004-20261031/closeout.md`.

## IDS-XDR-005 Current-Head Update — 2026-10-31

- Source commit `88466a6ec6f10c62b97cb0a171c4a90cb4f81645` selects
  `src/xdr/xdr_incident_fabric.zig` as the sole XDR correlation implementation;
  its result is advisory evidence only. `DecisionAction` and the PEP-dispatch
  claim were removed.
- XDR is LAB/test-only and not connected to `main.zig`/`daemon.zig`. The stale
  `xdr_engine` init/shutdown manifest entries and `xdr_harden_integration`
  optional runtime-spine entry were removed. Other XDR modules remain
  non-authoritative test/support candidates.
- Focused results: XDR 13/13, runtime-spine 27/27, T18 pytest 18 passed, and
  `zig build` PASS. Last full `zig build test` run before the final registry-only
  correction was 2247/2249 passed, 1 skipped, 1 failed at the performance
  threshold test; the full graph was not rerun after that correction.
- Test-scope audit still finds `src/capture/proto/l7_payload.zig` and
  `src/forensic/ids_evidence_receipt.zig` without execution-graph coverage.
  Windows E5, source-to-forensic receipt wiring, MAP-006, and GitHub issue #26
  remain open. See `admin-evidence/ids-xdr-005-20261031/closeout.md`.

## G23 Goals

1. Create canonical architecture documentation
2. Create FILE_REGISTRY.csv
3. Create AI context files (this directory)
4. Create cross-language CI matrix
5. Fix compliance wording
6. Create build manifest template
7. Create deprecation map
8. Remove tracked backup/build files (P0 cleanup)

## Completion Criterion

AEGIS is ready to leave consolidation when:

```
ONE EVENT
  -> ONE CANONICAL MODEL
  -> ONE RUNTIME SPINE
  -> ONE STATE AUTHORITY
  -> ONE EVIDENCE MODEL
  -> ONE DECISION AUTHORITY
  -> ONE ENFORCEMENT AUTHORITY
  -> ONE FORENSIC TRACE
  -> ONE REPLAY PATH
```

And CI proves: C/C++ + Zig + Go + Rust + Python/Cython + Drivers as one product.

## Remaining closure work

1. Complete `MAP-006`: reconcile runtime manifest, flow map, authority map, and
   evidence index against actual current code/runtime wiring; the XDR claims
   corrected by IDS-XDR-005 do not close the wider audit.
2. Produce supervised Windows-host evidence for applicable host telemetry and
   sensor paths; do not infer E5 from unit tests or a successful build.
3. Classify older IPS/WFP material as historical or lab-only without deleting
   it, and keep production host-effect capability false.
4. Complete supervised RB-017 Brain evidence without starting a second listener
   or changing the production detection-only gate.
5. Re-establish a green full Zig test graph and close the two test-scope coverage
   gaps; do not treat targeted tests as full-suite proof.
6. Wire the selected XDR advisory flow to canonical detection/forensic evidence
   only in a separate vertical slice with a validated receipt/replay contract.

Do not introduce an IPS activation phase into the production roadmap.

## Team Command

> Do not make the repository larger until you know which files are authoritative.

> Do not make a Phase "done" because the code compiles.

> Do not let AI infer architecture from source alone.

> Give AI the semantic position, ownership, contract, boundaries, allowed files and exit gate before it edits code.

> Every removed legacy path is progress. Every duplicate authority is technical debt.
