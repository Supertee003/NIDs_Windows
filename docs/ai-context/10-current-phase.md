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
  `zig build` PASS. The MAP-006/WFP/T12/T14 focused pytest set passes 38/38;
  current `zig build test` also passes (exit 0).
- Test-scope audit still finds `src/capture/proto/l7_payload.zig` and
  `src/forensic/ids_evidence_receipt.zig` without execution-graph coverage.
- MAP-006 source/map reconciliation is now verified at E2; it does not establish
  Windows E5/kernel qualification or release readiness. The base IDS receipt is
  source-wired; the separate XDR-to-forensic-receipt/replay flow remains open.
- Windows E5, the two execution-graph coverage gaps, and the separate XDR evidence
  integration remain open. See `admin-evidence/ids-xdr-005-20261031/closeout.md`.

## IDS-COV-001 Current-Head Update — 2026-11-01

- Commit `3fe2896` added direct `all_tests.zig` import edges for
  `src/capture/proto/l7_payload.zig` and
  `src/forensic/ids_evidence_receipt.zig`; both modules are now in the canonical
  Zig test execution graph.
- On checkout `cf2f1fca6aa25f72706d61734b1f361ba794c0dd`,
  `python -m pytest tests/security/test_zig_test_scope.py tests/security/test_map006_runtime_truth.py -q`
  passed 12/12 and `zig build test` exited 0.
- This closes the two execution-graph coverage gaps at E2. It does not establish
  supervised Windows E5/kernel qualification, XDR production integration, or
  release readiness. Evidence: `admin-evidence/ids-cov-001-20261101/closeout.md`.

## KIDS-002 Current-Head Update — 2026-11-01

- Source commit `8cb2afb` routes the normal gate-closed policy path through the
  Rust evidence-only assessment ABI. The lab gate-open branch is the only event
  processor path that calls PEP enforcement or ActionDispatcher.
- Focused assessment/gate/ABI contracts passed 14/14, the Rust-backed Zig
  assessment fallback unit passed 1/1, and `zig build` passed. The full
  `zig build test` was interrupted before completion because it includes a
  loopback TCP integration test blocked by this sandbox's network policy; this
  run is not counted as pass or product failure.
- Evidence is E2 source/build only. Windows E5, XDR receipt/replay
  integration, and release E7 remain open. See
  `admin-evidence/kids-002-20261101/closeout.md`.

## QLOSS-HEALTH-001 Update — 2026-11-01

- Source commit `1edb2b1a008614e21c39bb9b8a6044c316f3fd37` now counts minifilter EventQueue rejections separately and exposes them in `queue.stats` / health. Health reports `DEGRADED` when queue drops, Nose rejects/drops/pipe errors, or minifilter ring/pipeline loss is nonzero.
- `zig build test --summary all`: 2,004 passed, 10 skipped, 0 failed. `zig build`: PASS. Evidence level E2; no ABI, wire, policy-authority, or enforcement change.
- The live incident had 164,069 cumulative queue drops and 3,140 minifilter ring drops; this patch makes loss visible in readiness but does not eliminate overload. Counters are process-lifetime cumulative; qualify deltas after a clean deployment.
- Workspace build image SHA-256: `749784FE150076600DE09E2CF0926EEAE0F4483442E8E5A0B9C5EE849E17C610`. Rollback-capable installer is prepared at `admin-evidence/qloss-health-001-20261101/AEGIS-NIDS-5.0.0-1edb2b1-20261101.exe` (SHA-256 `488845A8A7D9B3648AF38A59E612074F933B4C6FA2E9A6C7BA9C31F01AC9DE7B`); release verification 616/616 and fresh_deploy plan pass. After restart of the old image, live health still said RUNNING despite queue drops=4,655 and depth=15,323/16,384 at 18.7s uptime (ETW=2,125, FIM=2,530); minifilter ring counter read 466,949 without an established delta. Service is now STOPPED; new installer is ready but uninstalled. Issue #29 remains OPEN until deployment and bounded Windows verification.
- The earlier Kali R9006 run scanned 10 ports, below its configured threshold of 20 distinct ports. It is not a valid detection-failure result. Resume the demo only after service is running and a current-source build is deployed; see `admin-evidence/qloss-health-001-20261101/closeout.md`.

## Verification, XDR, and Windows Preflight — 2026-11-01

- `VER-003` (source `ba92468`) fixed the compliance reporter's unbuffered
  byte-at-a-time file scan and repeated per-line allocations. The 80,000-event,
  19 MB focused test now passes in 4.04 seconds (baseline exceeded 120 seconds).
  A timing-ratio trie benchmark that failed once in the full graph but passed
  five isolated runs is now a deterministic prefix-correctness test. No trie
  speedup claim is made by the unit suite.
- `IDS-XDR-006` (source `091a968`) adds a lab/test-only vertical slice:
  multi-source XDR evidence -> versioned snapshot -> hash-chained forensic
  record -> recording-only IDS receipt -> integrity check -> deterministic
  replay. It is not wired into the production daemon. `FLOW_MAP.json` now
  records this exact boundary.
- Fresh canonical `zig build test`: **2,002 passed, 10 skipped, 0 failed**.
  Skips include opt-in real-loopback tests. The full `test-network-integration`
  target was not run.
- RB-021 Windows preflight is **BLOCKED before E5**: VMnet1 is up at
  `192.168.126.1`, Npcap and AegisNids are running, but no VMs are running,
  `AEGIS_DAEMON_IFACE` is unset, and this session is not elevated. RB-021 §2
  requires Admin to pin VMnet1 and restart the service. No host change or test
  traffic was performed. See
  `admin-evidence/e5-preflight-20261101/closeout.md`.
- `VER-003` and `IDS-XDR-006` close their E2 test slices only. Supervised
  Windows E5, production XDR runtime wiring, and release E7 remain OPEN.

## VER-004 Windows TCP Error Recovery — 2026-11-01

- Source commit `e233242` avoids Zig 0.13's Windows `std.posix.connect`
  `WSAEACCES => unreachable` mapping for the standalone federation transport.
  Winsock access denial now returns `TcpError.AccessDenied` after the failed
  socket is closed and transport state is reset.
- Focused mapping test passed 1/1; canonical Zig suite passed 2,003 tests,
  skipped 10 opt-in cases; network-scope pytest passed 2/2.
- Evidence is E2 only. Real loopback integration remains unrun in the
  restricted sandbox; this standalone federation module is not production
  runtime-wired. Windows E5 and release E7 remain open.
- See `admin-evidence/ver-004-20261101/closeout.md`.

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

1. `MAP-006` source/map reconciliation is **PASS at E2** (2026-11-01): runtime
   manifest, flow/authority/system/contract maps, and evidence index were checked
   against current source. This is not Windows E5, kernel qualification, or ADR-
   0009/release completion.
2. Produce supervised Windows-host evidence for applicable host telemetry and
   sensor paths. RB-021 recheck on 2026-11-01 confirmed both VMs are reachable,
   the operator pinned VMnet1, `AegisNids` is ready, and the raw capture device
   works. Stop-line remains OPEN: the installed service image hash differs from
   the current workspace build, and `fresh_deploy.py --plan` fails its release
   manifest preflight. No Kali canary was sent; do not claim E5 until a verified
   current-source deployment and rollback point are available. See
   `admin-evidence/e5-recheck-20261101/closeout.md`. REL-MANIFEST-001 now
   refreshes the existing 616-entry release digest set; `release_engineering
   --verify` and `fresh_deploy --plan` pass. This clears preflight only and
   does not install or qualify the current build.
3. Continue classifying remaining older IPS/WFP material as historical or
   lab-only without deleting it; the key WFP/host records GAP-002, GAP-005, and
   GAP-009 are now explicitly historical. Keep production host-effect capability false.
4. Complete supervised RB-017 Brain evidence without starting a second listener
   or changing the production detection-only gate.
5. The two Zig test execution-graph gaps are closed at E2; preserve that
   distinction from supervised Windows E5 host proof.
6. `IDS-XDR-006` proves a lab/test advisory XDR-to-forensic-receipt/replay
   slice at E2. Production runtime routing remains open and requires a separate
   scope/authority decision before any daemon wiring.

Do not introduce an IPS activation phase into the production roadmap.

## Team Command

> Do not make the repository larger until you know which files are authoritative.

> Do not make a Phase "done" because the code compiles.

> Do not let AI infer architecture from source alone.

> Give AI the semantic position, ownership, contract, boundaries, allowed files and exit gate before it edits code.

> Every removed legacy path is progress. Every duplicate authority is technical debt.
