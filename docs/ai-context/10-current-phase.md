# 10 - Current Phase

## Status: Kernel NIDS Consolidation and Evidence Closure

G1-G21 rewrite complete. G22 final polish complete. G23 consolidation is being
closed against the current Kernel NIDS source and live evidence. The production
product is detection-only; enforcement activation is permanently out of scope.

Provider readiness, WFP transport, and retained PEP boundaries may exist for
diagnostics, fail-closed behavior, or historical/lab evidence, but they do not
authorize a production host effect.

## QLOSS Loss Closure — 4 MiB Ring (`05ebba0`) — 2026-11-06

- Root cause chain, each step measured: the per-event allow audit rows were
  the original backpressure (fixed at `940714b`); with that gone the pipeline
  queue stopped dropping (0 drops over 143 s / 120 samples, max depth 3,988 of
  the 15,360 reserve boundary); the only remaining loss was the kernel ring
  (8,627 records / 157 s ≈ 55/s while draining ~1,250/s — burst overflow, not
  a throughput deficit).
- `AEGIS_RING_SIZE` 1 MiB -> 4 MiB (source `05ebba0`, driver
  `10C41E80...`, daemon unchanged `6B8183F4...`). No record layout, message, or
  `READ_EVENTS` contract change. Deployed with 27/27 checks and a verified
  rollback of both the install tree and the System32 driver
  (`082F6A43...`).
- Measured over a fresh 180 s driver load: ring drops **0**, pipeline drops
  **0**, queue drops **0**, 178,499 rows drained (~992/s).
- For ~3 minutes after the fresh load `readiness` reported
  `degraded=false`, `ready=true`, `overall_gate=true` with every
  `data_integrity` counter at 0 — the first non-degraded reading on this host
  derived from measurement.
- **Correction, same evening:** that clean window was NOT steady state. A later
  host burst pushed the queue to its reserve boundary and produced 10,408 queue
  drops (FIM 9,553, ETW 855) while `ring_dropped` stayed **0**; `readiness`
  returned to `degraded=true` (`QLOSS-QUEUE-BURST-20261106`).
- **Sized from measurement instead of guessed (`QLOSS-FIM-STORM-20261106`):**
  `queue.stats` now reports `depth_peak` (source `86024fb`, daemon
  `9582AA5C...`). Under a deliberate 20,000-file churn the boundary was hit:
  `depth_peak=15,364` of 15,360, `reserved_tail_shed=141,426`, FIM
  `131,065 dropped / 519,226 pushed` versus ETW `18,798 / 427,807`, ring 0.
  That kills the capacity hypothesis: absorbing this demand would need ~36x the
  queue (~950 MB), and +26 MB would only move the boundary. The lever is FIM
  ingress volume (aggregate or rate-shape repeated file operations) or per-
  source fair admission so one storm cannot consume the whole host tail — both
  are policy/detection decisions, so they are recorded rather than silently
  patched.
- QLOSS-HEALTH-001 is therefore **PARTIALLY CLOSED**: ring loss eliminated
  (0 drops), host admission under storm still open, readiness `degraded=true`
  until the ingress decision is taken.
- Limits: the driver is **test-signed** (production signing still open); zero
  loss holds at the current load, and a heavier burst can still overflow 4 MiB
  — the counter stays visible so any recurrence is measurable, not silent;
  4 MiB of non-paged pool is now held permanently.
- Evidence: `admin-evidence/e5-deploy-05ebba0-20261106/closeout.md`,
  `deploy-result-20261106_232534.json`, `ring-loss-20261106_232534.ndjson`,
  and `EVIDENCE_INDEX.json#E5-DEPLOY-05EBBA0-RING4M`.

## E5 Deploy — Quiet Per-Packet Audit (`940714b`) — 2026-11-06

- Bounding the log file did not bound the write load: the per-event `AUDIT`
  row was emitted for every processed event and every sampled row was
  `rule=0 policy=0 decision=allow` (~5,300 lines/s, ~55 GB/day, rotation every
  ~100 s). `auditLevelFor` now keeps matched-policy and non-allow rows at
  `info` and drops allow-with-no-match rows to `debug`; audit identity is
  unchanged (`audit_id` still increments, the decision trace still records the
  verdict, the forensic ring still receives the record).
- Source `940714b` is installed: daemon `6B8183F4...`, package `6071E80A...`,
  31/31 checks, rollback saved (prior daemon `F4BC3A85...`). No canary;
  `prevention_gate=closed`, detection-only, `tier3_enforcing=false`.
- Measured on the host: persisted growth per 60 s fell from ~34–41 MB to
  **3,439 bytes**, no rotation in the 3-minute window, and the log was
  16,869 bytes after ~4 minutes — roughly a 10,000× reduction.
- Scope limit recorded honestly: this window carried no policy-matching
  traffic, so the positive side (a matched row still persisted) is pinned by
  the unit test and by the earlier canary's `pep=quarantine confirmed=true`
  lines, not re-exercised live here.
- Evidence: `admin-evidence/e5-deploy-940714b-20261106/closeout.md` and
  `EVIDENCE_INDEX.json#E5-DEPLOY-940714B-QUIET-AUDIT`.

## E5 Deploy — Bounded Diagnostic Log (`a9e8de3`) — 2026-11-06

- Source `a9e8de3` is installed on the Windows host: daemon
  `F4BC3A85...`, `build_manifest.json` source `a9e8de3`, package
  `84FFC725...` (7,522,128 bytes). **42/42 checks passed** with a verified
  rollback point (`rollback-installed/`, prior daemon `EB9F44AB...`).
- The stale 41.0 GB `aegis-daemon-diagnostic.log` (41,042,778,303 bytes) was
  deleted with the service stopped; free space went from 4.26 GB to ~43 GB.
- The cap was proven live, not assumed: the daemon writes ~560-690 KB/s, so it
  filled 64 MiB within ~100 s, rotated (live file reset, backup 67,108,793
  bytes), refilled, and rotated again. The live file never exceeded the cap and
  total persisted growth stayed at two caps.
- Posture unchanged: `prevention_gate=closed`, `enforcement_mode=detection-only`,
  `tier3_enforcing=false`, `host_effect_capable=false`. No canary was sent.
  `QLOSS-DISK-001` is CLOSED at E5 for bounded growth.
- Correction recorded here because runtime wins over narrative: the earlier
  audit said the installed image was the restored `D34D350A...` (f7c626d). The
  host actually ran `EB9F44AB...` (fc108b0), verified by hash before the
  install. Nothing in the posture claims changes.
- Still open: the stream is loud (~55 GB/day of writes, rotation every ~100 s).
  Bounding the file stopped disk exhaustion; it did not reduce the churn, so
  log-verbosity reduction is tracked with the QLOSS admission work.
- Evidence: `admin-evidence/e5-deploy-a9e8de3-20261106/closeout.md`,
  `deploy-result-20261106_225417.json`, `log-cap-watch.txt`.

## QLOSS-DISK-001 — 2026-11-06

- The persisted diagnostic stream had no size bound. On this host
  `C:\Program Files\AEGIS NIDS\logs\aegis-daemon-diagnostic.log` reached
  **40.9 GB** (40,921,296,585 bytes) and drove `C:` to 0 bytes free, breaking
  unrelated tooling that stages output under the system temp directory.
- `FileSink` now rotates at 64 MiB (`DEFAULT_MAX_BYTES`) and keeps exactly one
  backup at `<path>.1`, bounding total growth to two caps. A legacy oversized
  file rotates on the first write after restart, so the built fix stops the
  growth without a manual delete; the stale backup then disappears on the next
  rotation (commit `a9e8de3`, evidence `QLOSS-DISK-001-E2-20261106`).
- Proven at E2: `zig build` exit 0, `zig build test --summary all` 2,036
  passed / 10 skipped / 0 failed, with tests pinning the cap, the single
  backup, and the legacy first-write rotation. **Deployed the same day (E5)**:
  see the section above — the 41.0 GB file is gone, free space is back to
  ~43 GB, and live rotation was observed twice.
- The raw growth rate also means the diagnostic stream was far too verbose per
  captured packet (~55 GB/day of writes); bounding the file did not reduce the
  churn. That verbosity was then fixed and deployed the same evening (source
  `940714b`): persisted growth fell to ~3.4 KB/min — see the section above.

## Project State Audit — 2026-11-06

- Read-only audit at records HEAD `f325ef6` (build source `572ff13`). Gates are
  green: `truth.py verify` `TRUTH_VALID`, release verify 651/651 artifacts, and
  `zig build test --summary all` 2,034 passed / 10 skipped / 0 failed (exit 0).
  E2 source/build truth only; no E5 claim.
- Live host: at audit time the installed daemon was reported here as the
  restored f7c626d image (`D34D350A...`); the 2026-11-06 deploy re-read the
  host and found `EB9F44AB...` (the fc108b0 candidate). Runtime wins — the
  audit line is corrected, and the host now runs `F4BC3A85...` (a9e8de3).
  At audit time: 7/7 subsystems RUNNING (pid 20668), driver present,
  `authority` invariant HELD, `readiness` `worker_gate=true` / `missing=[]`
  but `degraded=true` / `overall_gate=false`, `host_effect_capable=false`.
- `QLOSS-HEALTH-001` loss is live: `queue_dropped_total=1,377,719`,
  `minifilter_pipeline_dropped=1,154,171`, `minifilter_ring_dropped=37,011`,
  `nose_frames_dropped=221,956` of 851,219 frames read. The observability half
  stays closed; issue #29 (the overload itself) stays OPEN.
- `RB-017` is **not** satisfied: the only brain listener is pid 31516
  (`pythonw.exe`, session 0, created 2026-10-31, parent pid 16036 gone) with an
  unreadable command line, health `endpoint_ownership=FOREIGN`, and no SCM
  service or scheduled task supervising it. It is an unsupervised orphan, not
  a supervised bring-up; the return-path (`brain_tier2`) proof was not
  attempted. Closes only with an approved elevated stop plus a supervised run.
  *(Corrected 2026-11-08 — as of the audit date the observations were what the
  non-elevated shell could see. The supervisor is the `SYSTEM` scheduled task
  `AegisKeeper`, `out=0` was a dead counter, and the return path is now
  E5-proven; see open-register item 3.)*
- Host incident recorded: `C:` reached 0 bytes free and broke tools staging
  output on `C:\...\Temp` (Python `OSError: [Errno 28]`); only
  `%LOCALAPPDATA%\Temp` was cleared (~4.4 GB recovered). The repository lives
  on `D:` and no repository artifact was affected. The drive is still 99% used
  and reclaiming the rest is a host-owner task.
- Evidence: `admin-evidence/project-state-audit-20261106/closeout.md` with
  `truth-verify.txt`, `release-verify.txt`, `status.txt`, `health.txt`,
  `readiness.txt`, `authority.txt`, `bridge.txt`, `brain-pid-31516.txt`;
  index entry `PROJECT-STATE-AUDIT-20261106`.

## XDR-005 Multi-Source E5 — 2026-11-05

- `IDS-XDR-005-WIRING-OPEN` and `XDR-005-LIVE-MULTISOURCE-UNREACHABLE` are
  **CLOSED** at E5. A bounded elevated window installed candidate
  `EB9F44AB...` (build source `fc108b0`, records HEAD `13a9ad1`) and pinned
  the daemon to VMnet1.
- Real R9064 literal `;whoami` traffic from isolated Kali `192.168.126.10`
  joined observe-only host TCP evidence for the same entity: incident
  `v4:192.168.126.10`, `distinct_sources=2`, categories
  `[network,host]`, evidence 10, severity 2, confidence 70,
  `receipts_recorded=2`, `receipts_failed=0`, `receipts_skipped=0`.
- `aegisctl xdr verify` replayed persisted sequence `1060875` (source event
  51, evidence 10, categories `[network,host]`) with `verified=1`,
  `failed=0`. `forensics verify` returned `verified=true` / `integrity=ok`;
  `blocks=0`; `prevention_gate=closed`; `host_effect_capable=false`.
- Restore returned the daemon to `D34D350A...`, removed the machine
  `AEGIS_DAEMON_IFACE` and per-service `Environment` values, PEB-verified no
  daemon pin, kept Nose on the production device, and showed production
  packets advancing (1,868 -> 2,050) with no reboot.
- The first attempt is retained as functional evidence. Its route produced
  the same multi-source incident and receipts, but its single harness verify
  call ran after the 16,384-slot ring wrapped (~4 s retention at ~4,000
  records/s). A pinned tight loop captured 7 verified hits
  (sequences `2024863` and `2029076`). Only attempt 2 is the clean harness
  PASS (`XDR005_E5_PASS=True`).
- Evidence: `admin-evidence/xdr005-e5-20261105/closeout.md`,
  `e5-window.json`, `during/`, `post-restore-independent/`, `attempt1/`, and
  `EVIDENCE_INDEX.json#XDR-005-E5-20261105`.

## RB-021 Observe-Only Canary E5 — 2026-11-04

- `E5-CURRENT-RUNTIME-MISMATCH` is **CLOSED**. Two bounded elevated windows on
  the deployed `f7c626d` runtime (installed daemon `D34D350A...`, build source
  `f7c626d`, records HEAD `1afde37`) pinned the daemon to VMnet1, passed
  `RB021_PREFLIGHT_PASS` (all 16 named checks) in both rounds, and captured
  70 real rows from isolated Kali `192.168.126.10` against victim
  `192.168.126.20`.
- Per-rule attribution: `R9007` 60, `R0088` 2, `R9064` 2, `R9002` 1,
  `R9006` 1, `R0056` 1, `R0089` 1, `R9059` 1, plus one `R1005` cross-layer
  artifact (the literal `hosts` inside the `R0088` traversal payload). Real
  L4 traffic now fires `R9006`/`R9007`/`R9002`, unlike the 2026-10-20
  payload-token baseline; `R9002` needed `hping3` at 1000 pkt/s to cross
  50 packets/1000 ms, and `R9064` needed the rule's literal `;whoami` rather
  than the stock `;id`/`;cat` script.
- Every row is `src_ip=192.168.126.10`, `event=signature_match`,
  `enforcement_status=observed`, `host_effect_confirmed=false`;
  `blocks=0`, `prevention_gate=closed`, `tier3_enforcing=false` throughout.
  The restore removed the machine pin and the per-service `Environment`
  value, PEB-verified no daemon pin, and showed production packets advancing
  (44 -> 106 and 74 -> 110 in 12 s) with no reboot.
- The canary is single-source. `xdr.list` after the restore restart reports
  `evidence_total=0`, `receipts_recorded=0`, `incidents=[]`, and no frozen
  multi-source assessment or replay was exercised. The later 2026-11-05
  XDR-005 E5 run closed `IDS-XDR-005-WIRING-OPEN` (see the section above).
- Readiness remains `degraded=true` / `overall_gate=false` from the
  pre-existing data-loss counters (`QLOSS-HEALTH-001`), while all 7
  subsystems are RUNNING and every worker is ready.
- Evidence: `admin-evidence/rb021-canary-20261104/closeout.md`,
  `attribution.json` / `attribution.md`, and `EVIDENCE_INDEX.json` entry
  `RB-021-CANARY-F7C626D-20261104`.

## E5-DEPLOY-F7C626D Current-Head Update - 2026-11-03

- The current-source package (`AEGIS-NIDS-5.0.0-f7c626d-20261103.exe`,
  SHA-256 `983C9A5D...`) was installed silently with an elevated token after
  capturing a rollback point (`rollback-installed/`, `ROLLBACK.md`) of the
  installed d02261e runtime, configs, drivers, System32 copies and SCM
  definitions.
- Installed daemon `aegis_nids.exe` is SHA-256 `D34D350A...` (11,352,064
  bytes), identical to the workspace build from source `f7c626d`, and the
  installed `build_manifest.json` carries source `f7c626d`. Only the daemon and
  the manifest changed; every other payload file is byte-identical.
- 35 of 36 verification checks passed: install identity, all payload hashes,
  service ImagePath, System32 driver copies and Authenticode status,
  `fltmc` minifilter load, daemon/loaded-PEP paths and hashes, single nose
  instance, machine/process capture pins, and
  `prevention_gate=closed`, `enforcement_mode=detection-only`,
  `tier3_enforcing=false`, `host_effect_capable=false`.
- The blocked check was `rb021_preflight` (`RB021_PREFLIGHT_BLOCKED`): the
  preflight could not see the `192.168.126.10` / `192.168.126.20` ARP
  neighbors because the isolated lab VMs were not running. Every preflight
  identity and capture-pin check passed.
- No canary was sent, no prevention gate was opened, and no host effect was
  enabled. This is E5 for installation and installed-runtime verification, not
  detection, canary, or release evidence. The missing host proof of the
  recording-only receipt/replay route was later recorded on 2026-11-05
  (`XDR-005-E5-20261105`).
- Evidence: `admin-evidence/e5-current-source-20261103/closeout.md` and
  `EVIDENCE_INDEX.json` entry `E5-DEPLOY-F7C626D-20261103`.

## RB021-PREFLIGHT-PASS-20261103 Current-Head Update - 2026-11-03

- Both isolated lab guests were powered on (Kali `192.168.126.10`, Windows 11
  victim `192.168.126.20`) and `scripts/rb021_current_source_preflight.ps1`
  returned `RB021_PREFLIGHT_PASS` against the deployed `f7c626d` runtime
  (build and installed daemon both `D34D350A...`, manifest source `f7c626d`,
  pins matched and disjoint, both lab ARP neighbors seen). The script emits 16
  named checks; this record originally said "17/17" by miscount. Evidence
  level E1; no canary was sent in that window.
- The same window found a live production defect: the machine
  `AEGIS_DAEMON_IFACE` pin was still set to the VMnet1 device and inherited by
  the running daemon, so the deployed runtime had been capturing the isolated
  lab segment instead of the host interface. The pin was removed, `AegisNids`
  restarted, and host capture confirmed live (`packets_captured` 337 -> 677 in
  12 s). Filed and closed as `PROD-CAPTURE-PIN-LEFT-SET-20261103` (P1).
- `E5-CURRENT-RUNTIME-MISMATCH` was at that point narrowed to the observe-only
  canary, which required separate authorization; it was closed on 2026-11-04
  (see the section above). `prevention_gate=closed`,
  `host_effect_confirmed=false`, `enforcement_mode=detection-only` throughout.
- Evidence: `admin-evidence/rb021-window-20261103/` (`lab-window.log`,
  `preflight/preflight.json`, `closeout.md`) and `EVIDENCE_INDEX.json` entry
  `RB021-PREFLIGHT-PASS-20261103`.

## XDR-RECEIPT-002 Current-Head Update - 2026-11-03

- Source commit `f7c626df89bc18b31d0132181d0a4632d6b1e6f3` wires the
  recording-only advisory XDR bridge into the production detection pipeline.
  Detection-identity events feed the selected fabric; a frozen multi-source
  assessment is appended to the hash-chained forensic ring, an IDS Evidence
  Receipt is issued only after hash read-back, and replay verifies the
  assessment. `xdr.list` exposes `receipts_recorded`, `receipts_failed`, and
  `receipts_skipped`.
- The receipt value is discarded by the caller. No policy, PEP, DEFCON,
  ActionDispatcher, or host-effect consumer reads XDR output. The boundary is
  pinned by `tests/security/test_xdr_wire_advisory.py`.
- Evidence is E2 source/build only: `zig build` PASS; `zig build test
  --summary all` 2011/2021 passed, 10 skipped, 0 failed; focused pytest 50
  passed. E5-DEPLOY-F7C626D later deployed this source and the 2026-11-04
  RB-021 canary proved the current-source detection path on the host, but that
  canary was single-source. The Windows host proof of the receipt/replay route
  was recorded on 2026-11-05 as `XDR-005-E5-20261105`
  (`IDS-XDR-005-WIRING-OPEN` CLOSED).
- Earlier IDS-XDR-005/006 sections below describe the historical pre-wiring
  snapshot and are retained as history, not current truth.

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
- Workspace build image SHA-256: `749784FE150076600DE09E2CF0926EEAE0F4483442E8E5A0B9C5EE849E17C610`. Rollback-capable installer is prepared at `admin-evidence/qloss-health-001-20261101/AEGIS-NIDS-5.0.0-1edb2b1-20261101.exe` (SHA-256 `488845A8A7D9B3648AF38A59E612074F933B4C6FA2E9A6C7BA9C31F01AC9DE7B`); release verification 616/616 and fresh_deploy plan pass. After restart of the old image, live health still said RUNNING despite queue drops=4,655 and depth=15,323/16,384 at 18.7s uptime (ETW=2,125, FIM=2,530); minifilter ring counter read 466,949 without an established delta. At that snapshot the service was STOPPED and the new installer was uninstalled; issue #29 remained OPEN for deployment and bounded Windows verification. **Superseded for the deployment half by the 2026-11-04 E5 update below** — the loss itself is still OPEN.
- The earlier Kali R9006 run scanned 10 ports, below its configured threshold of 20 distinct ports. It is not a valid detection-failure result. Resume the demo only after service is running and a current-source build is deployed; see `admin-evidence/qloss-health-001-20261101/closeout.md`.

## QLOSS-HEALTH-001 E5 Update — 2026-11-04

- The `1edb2b1` observability fix is present in the deployed `f7c626d`
  runtime (`D34D350A...`). During the post-restore RB-021 checks, the live
  health payload at `2026-11-04T07:30:40Z` reported `state=DEGRADED`,
  `runtime_state=RUNNING`, `degraded=true`,
  `queue_dropped_total=65104`, `minifilter_ring_dropped=364820`, and
  `minifilter_pipeline_dropped=47775`, while 7/7 subsystems were RUNNING
  and every worker was ready. The readiness sample 30 s earlier already
  reported `degraded=true` / `overall_gate=false` with `worker_gate=true`
  and no missing workers or failure reasons.
- Network ingress dropped 0 in both canary rounds (`capture_npcap`
  `dropped=0`), so the counters are host-telemetry loss
  (ETW/FIM/minifilter), not canary-induced. This clears the
  deployment-pending half of QLOSS-HEALTH-001 at E5; the underlying data
  loss is not eliminated, readiness remains degraded, and issue #29 stays
  OPEN for the loss itself.
- Evidence: `admin-evidence/rb021-canary-20261104/post-restore/health-degradation.json`,
  `final-checks.txt`, and `EVIDENCE_INDEX.json#QLOSS-HEALTH-001-E5-20261104`.

## IDS-QUEUE-001 Update — 2026-11-02

- Source commit `56ac99f` reserves the final 1,024 slots of the shared
  16,384-slot pipeline queue for `capture_npcap` / `capture_wfp`. Host
  telemetry is refused at the reserve boundary so an ETW/FIM/registry flood
  cannot consume the network admission tail.
- Reserved-tail sheds increment the existing queue-drop counter (health still
  degrades) and a new `reserved_tail_shed` counter. `queue.stats` reports
  `reserved_network_slots` and `reserved_tail_shed`, so a refusal below
  `queue_size` is explainable rather than a bug.
- `zig build test --summary all`: 2,005 passed, 10 skipped, 0 failed.
  `zig build`: PASS. Evidence level E2; no wire, ABI, policy, PEP, driver, or
  enforcement change.
- The queue remains FIFO. A network event admitted into the reserve can still
  wait behind an existing host backlog; this slice prevents admission refusal,
  not queueing latency. No Windows E5 proof is claimed.

## RB013-LOG-E5-20261102 — 2026-11-02

- `G2-RB013-LOG-20261023` is **CLOSED** by a lab-kit E5 on the isolated Win11
  VM `192.168.126.20`. The deployed lab-gate kit (daemon `86D4DD77...`, PEP
  `C7F20079...`, bridge `9D5D7D46...`, signed driver `8A2B3F12...`, lab policy
  `DB67B1B5...`) accepted one inbound canary at `2026-11-02T00:17:47-08:00`
  and persisted 8 diagnostic lines at `00:17:52`:
  four `pep=quarantine confirmed=true filter_id=77892` and four
  `action=QUARANTINED_CONFIRMED rule=0 policy_id=3 filter_id=77892`.
- The line is emitted only inside the receipt-verified quarantine branch
  (`decision == quarantine`, receipt decision match, and
  `verifyEnforcementReceipt` true), so it is not a request echo. The P1
  observability gap is closed.
- Restore returned the exact baseline hashes (`E19C/617F/EF9B/AD23/B722`), both
  services Running, `prevention_gate=closed`, `tier3_enforcing=false`,
  `enforcement_mode=detection-only`, and removed the lab payload. The
  production host was not touched.
- Caveat: the kit predates current HEAD (it lacks the `53737e8`
  `AEGIS_NOSE_IFACE` marker; its daemon size matches a fresh `24d8d81`
  lab-gate build). This is lab-kit E5, not current-source E5. No second
  canary, no `metrics_after`, and no post-restore WFP enumeration were
  captured. At that snapshot `E5-CURRENT-RUNTIME-MISMATCH` and
  `IDS-XDR-005-WIRING-OPEN` were OPEN; both were later CLOSED
  (`RB-021-CANARY-F7C626D-20261104`, `XDR-005-E5-20261105`).
- Evidence: `admin-evidence/rb013-log-e5-20261030/closeout.md` and
  `EVIDENCE_INDEX.json` entry `RB013-LOG-E5-20261102`.

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
- `VER-003` and `IDS-XDR-006` close their E2 test slices only. At that
  snapshot supervised Windows E5, production XDR runtime wiring, and release
  E7 were open. Production XDR routing was later wired and proven at E5
  (`XDR-005-E5-20261105`); supervised Windows E5/kernel qualification and
  release E7 remain OPEN as broader scope.
- RB-021 remediation now has a fail-closed read-only gate at
  `scripts/rb021_current_source_preflight.ps1`. It must emit
  `RB021_PREFLIGHT_PASS` before any Kali canary; it checks current HEAD/build
  manifest, installed runtime SHA-256, service state, VMnet1, machine capture
  pin, and Kali/Victim ARP neighbors. The manifest is compared to the
  build-source commit, not a later records-only HEAD. A blocked preflight
  remains E1 and must not be promoted to E5 by reusing historical evidence.

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

## Current-Head Update — 2026-11-05: in-tree XDR-005 wiring + STIX export

- `XDR-005-HOSTNET-WIRING-E2-20261105` (E2): the scope decision is now code at
  commits `0d8d93e` + `fc108b0` — observe-only Windows TCP table polling
  (`src/windows/host_net.zig`, EventKind.host_socket_observed=78) joins a recent
  network incident or waits in a bounded pending table, and `xdr.verify` replays
  the persisted snapshot read-only. Proven in-tree: the slice's pytest 8/8
  (`tests/security/test_xdr_wire_advisory.py`), full `zig build test` exit 0,
  and both truth gates green (`truth.py verify` TRUTH_VALID, release verify
  651/651) at build source `fc108b0`. The slice was later deployed for the
  2026-11-05 E5 run (`XDR-005-E5-20261105`) and the daemon was restored to the
  installed f7c626d image afterwards.
- `STIX-EXPORT-ADAPTER-E2-20261105` (E2): read-only STIX 2.1 export adapter
  (`tools/stix_export.py`, commit `6b3c4ff`) maps `xdr.list` incidents to
  `observed-data` SDOs referencing deterministic `ipv4-addr`/`ipv6-addr` SCOs
  (fixed project UUIDv5 namespace), with AEGIS facts on `x_aegis_*` custom
  properties. Unvalidatable entities are skipped and counted, never guessed;
  no indicator objects because the control view carries no rule attribution.
  Proven: 33 unit tests, both import-hygiene pins, and a live read-only export
  from the running daemon (10 objects, 5 incidents, 0 skipped; artifact
  `admin-evidence/stix-export-20261105/xdr-20261105.stix.json`). No TAXII
  transport; the runtime and the detection-only gate are untouched.
- `XDR-005-LIVE-MULTISOURCE-UNREACHABLE` and `IDS-XDR-005-WIRING-OPEN` are
  **CLOSED** by the 2026-11-05 E5 run (`XDR-005-E5-20261105`): the `fc108b0`
  candidate was installed and produced a live network+host multi-source
  incident, receipt, and replay, then restored to the f7c626d image.

## Remaining closure work

Open register as of the 2026-11-06 audit, refreshed 2026-11-07 after the
hosted-CI hardening (build source `1b32eaf`). Items 1-3 below are the only
work that still blocks "finished"; the rest is documentation hygiene.

1. **`QLOSS-HEALTH-001` — PARTIALLY CLOSED (2026-11-06).** Measured in steps:
   per-event allow audit rows created the backpressure (`940714b`); after that
   the queue was clean for 143 s (0 drops, 120 samples, max depth 3,988); the
   kernel ring burst overflow was then fixed (`05ebba0`, 1 MiB -> 4 MiB) and
   stays at **0 drops**. But a later host burst still overflowed the 16,384-slot
   pipeline queue: **10,408 drops** (FIM 9,553, ETW 855) in one episode with
   `ring_dropped=0`, and readiness returned to `degraded=true`. Gate semantics
   were **not** relaxed at any point, so this is a real open loss, not a
   reporting artifact.
   Sizing was then measured rather than guessed (`86024fb` adds `depth_peak`): a
   churn burst demanded >157,000 events with FIM alone shedding 131,065, so slot
   count is the wrong lever (a ~36x queue, ~950 MB, would be needed).
   Per-source fair admission then landed (`fadc216`, cap = half the host tail):
   a storming source may own at most 7,680 slots, so every other host sensor
   keeps the other half reachable. The 80/20 split was measured first and
   rejected — FIM still drove total occupancy to the shared boundary and ETW
   dropped 25,666 — while the 50/50 build verifies at E5 with ETW holding 7,242
   of its 7,680 share while FIM sat at 7,554 (`QLOSS-FAIRSHARE-001-E5-20261107`,
   27/27 checks). **This is isolation, not loss reduction:** FIM still sheds its
   own excess (~181k rows under the synthetic burst) and ETW's residual drops
   are its own overflow from the same churn, so reducing either stream's volume
   (sensor-side aggregation/rate shaping) remains the recorded next decision.
   Critical admission then landed (`ad9733c`): the last 1,024 host slots belong
   to FIM writes under `Windows\System32`/`SysWOW64`, exempt from the per-source
   share, and ordinary telemetry stops at 14,336 so that reserve is free
   (`QLOSS-CRITICAL-001-E5-20261107`, 27/28 checks). Measured: `depth_peak`
   14,345 — above the working tail by exactly the protected rows admitted —
   `critical_pushed_total` 264 from real System32 activity, ring 0. Limits: the
   protection was not exercised adversarially (a System32 storm would be an
   unrequested host change), and the one failing check is a sampling artifact
   (`etw_active` read 0 at a drained moment while ETW pushed 245,343 in the
   window).
   A follow-up source fix (`12093dd`, `QLOSS-ISOLATION-002`) corrects the
   fair-share arithmetic: the cap was halves of the *whole* host tail (7,680),
   so two sources could claim 15,360 slots while the shared check refuses at
   `WORKING_HOST_TAIL` 14,336 — the second source was stopped at 6,656 before
   reaching its own share, which is the 80/20 failure at a smaller scale. The
   cap is now `WORKING_HOST_TAIL/2 = 7,168`, and a unit invariant pins
   `2 * cap == WORKING_HOST_TAIL`. This is E2 only (2,048 Zig tests and the
   full Python suite pass); the installed daemon is unchanged, so no E5 is
   claimed. It preserves pairwise isolation and does not lower total loss;
   N-way fairness and FIM ingress aggregation/rate shaping remain open.
   ADR-0012 (Proposed, 2026-11-07) now records that remaining decision instead
   of leaving it as a one-line TODO: coalesce exact duplicate `(path, kind)`
   observations inside one 500 ms FIM poll batch, count every suppressed
   duplicate in `fim_coalesced_total`, and implement nothing until a deployed
   measurement shows the duplicate ratio exceeds the measured FIM deficit
   (~10% at 2,930 rows/s capacity vs ~3,231 rows/s FIM demand). It changes no
   runtime behaviour and is not an E5 claim.
   **E5 delivered (`QLOSS-ISOLATION-002-E5-20261108`, 2026-11-08).** Source
   `12093dd` is now deployed: daemon `C5991397...` replaced the installed
   `6326AB5D...` image with a hash-verified rollback copy, one restart for the
   swap and one to restore the normal FIM scope, driver untouched. Live
   `queue.stats` reports `source_occupancy_cap=7168`, and a 90 s synthetic
   churn (6 workers × 900 files, 56 samples) measured `fim_active_max 7168`,
   `etw_active_max 7168`, `depth_peak 13,575` (working tail 14,336),
   `reserved_tail_shed 0`, `source_quota_shed 206,999`, FIM dropped 206,276 vs
   ETW 723, ring 0. The second source therefore reaches its **full** share and
   the shared boundary never refuses — the old 7,680 formula could only leave
   it 6,656. **This closes the isolation defect, not the loss:** every refusal
   is the storming source's own excess, so issue #29 stays OPEN on volume.
   Honesty notes: the churn is synthetic, `critical_pushed_total` was 0 (no
   System32 write in the window), readiness was already `degraded=true`, and
   the RB-021 preflight was **not** run for this deploy window.
   Also open: production driver signing (the ring change is test-signed).
2. **Supervised Windows E5 / kernel qualification — OPEN.** Any new
   current-source E5 must redeploy a verified candidate with a rollback point
   and pass the RB-021 preflight first (pattern: `E5-DEPLOY-F7C626D-20261103`,
   `RB-021-CANARY-F7C626D-20261104`, `XDR-005-E5-20261105`). The installed image
   is still the restored `D34D350A...` (f7c626d); the newer `fc108b0` candidate
   `EB9F44AB...` was proven at E5 and deliberately rolled back. This is a
   deployment decision, not drift.
   The bounded diagnostic log (`QLOSS-DISK-001`, `a9e8de3`) is already
   deployed and proven live (see the 2026-11-06 E5 section); the installed
   daemon is now `F4BC3A85...`. What remains open here is the broader kernel
   qualification, not the log bound.
3. **`RB-017` Brain supervised bring-up — CLOSED, E5 (2026-11-08).** The
   earlier register was wrong twice, and both corrections are measured.
   (a) *Supervision:* an elevated `schtasks /query /tn \AegisKeeper` shows
   scheduled task **AegisKeeper** (`SYSTEM`, action
   `pythonw.exe D:\NIDs_Windows\scripts\aegis_open.py keep`) converging
   service+nose+brain every five minutes — a non-elevated query is
   access-denied, which is why the listener looked orphaned. The orphan
   `pythonw` pid 31516 was stopped under elevation (`Stop-Process`
   non-elevated returned `Access is denied`), port 9999 was freed, and the
   supervised listener came back and survived an `AegisNids` restart.
   (b) *Return path:* `aegisctl brain` showing `out=0` did **not** mean a dead
   return path — `OUT_EVENT_COUNT` was never incremented anywhere. A
   MAC-authenticated fixture (300 identical bytes → `CYTHON-003`) produced
   a daemon `detection_brain` event (pushed 2→3, dropped 0), a forensic
   `python_brain` record with `rule_id 2587872532 = FNV-1a("CYTHON-003")`
   and `verified: true`, and — after the counter fix (74d6ac2) and a brain
   reload — `out_events 0→1`. Evidence:
   `RB-017-BRAIN-SUPERVISED-E5-20261108`,
   `RB-017-BRAIN-RETURN-PATH-E5-20261108`, gap `GAP-BRAIN-OUT-EVENTS`.
   Operating note: the keeper's five-minute tick bounds brain respawn
   latency (measured 3 m 41 s), so "brain died and did not come back" needs
   at least one full tick before it is a finding.
   (c) *Correction, 2026-11-08 (later the same day):* two more measured
   fixes. The ownership census called the supervised SYSTEM brain FOREIGN
   because an unelevated caller cannot read a session-0 command line, while
   `aegisctl bridge` already corroborated it from the listener's own HEALTH
   reply; the census now uses that corroboration and a listener that cannot
   corroborate still reads FOREIGN. And a red gate seen this session was not
   the brain at all: an ETW storm from build/test activity produced 97,916
   source-quota sheds (12.5%, `shed_overload` 0) that the daemon honestly
   reported as `data_loss_observed`; a clean restart read
   `degraded=false / ready=true / overall_gate=true`, `dropped_total` 0.
   The ~96% "drop" that looked like loss is now attributed and is not a
   defect: after the restart, HEALTH read `in 5,223 / dropped 5,023 /
   out 0` with `drops {bad_mac 0, no_mac 0, log_throttle 5,023}` and
   `sensor_pipe {enabled, cython, ok, failed 0}`. The cap is the 100/60 s
   append bound on `anomalous.json`, and the path it caps is Case 1: events
   Zig already matched and sent over UDP, which the brain logs as an echo
   and deliberately does not return through the sensor pipe. `out_events 0`
   is therefore the correct reading of a quiet return path, and the earlier
   "unexplained 96% loss" framing is withdrawn. Proven meanwhile: the daemon signs every offer (1,683 datagrams/20 s, all
   `hex.body`, HMAC recomputed from the machine secret matches exactly), the
   pipe accepts an admin/SYSTEM sender (`SENT`), and the daemon records it
   (`detection_brain` pushed 1). Evidence:
   `RB-017-ORPHAN-ATTRIBUTION-E5-20261108`,
   `RB-017-RETURN-PATH-OBSERVABILITY-E5-20261108`,
   `RB-017-DROP-ATTRIBUTION-E5-20261108`.
4. **Signed release package / E7 — OPEN.** Requires signing key material,
   provenance, and an owner decision. Nothing in the current evidence set
   changes this.
5. **CI hosted matrix — CLOSED (2026-11-07).** Run
   [`42347458980`](https://github.com/Supertee003/NIDs_Windows/actions/runs/42347458980)
   on `codex/o2-etw-context` at records head `ce522e5` (build source
   `1b32eaf`) completed: every gating job passed — Zig, Rust PEP, Rust Shield,
   C native, Python control plane, Brain, Cython, Go nose, Go aggregator,
   TypeScript, Mouth, Dashboard, Security Scan (Trivy pinned `v0.36.0`), and
   the cross-language `ci-matrix`. The run's overall `failure` comes only
   from `drivers-wdk-build`, the manual WDK job deliberately outside
   `ci-matrix.needs`; `Package Release` is skipped because this is not a
   tag/main run. The preceding run `42205944646` had exposed the hosted-runner
   gaps (Trivy tag, graph deps, native helper DLLs, daemon-live tests,
   gitignored Kali scripts, Zig 0.13 skip constant); the fixes are in source
   `1b32eaf` and records `b86c738` (marker `host_live`, conditional Kali skip,
   graph/DLL setup, Trivy tag, `SkipZigTest`, CRC test edge, pipe-fixture
   fidelity). WDK remains a manual, non-gating E5/driver item.
   Re-run [`42446770459`](https://github.com/Supertee003/NIDs_Windows/actions/runs/42446770459)
   (2026-11-08) on `codex/o2-etw-context` at `6840b4d` (build source
   `12093dd`) reproduced the same shape: every gating job green including
   `ci-matrix`, WDK the only red job, `Package Release` skipped. `250afb0`
   afterwards is records/docs only, so the verified build source is unchanged.
6. **Historical classification of older IPS/WFP material — on-going.** Keep
   classifying without deleting; GAP-002, GAP-005, and GAP-009 are explicitly
   historical. Production host-effect capability must stay false.

Completed and not to be re-opened as work items: `MAP-006` (PASS at E2), the two
Zig test execution-graph gaps (E2), `IDS-XDR-006` wiring (advisory, proven at E5
by `XDR-005-E5-20261105`), and the `E5-CURRENT-RUNTIME-MISMATCH` clearances.

Do not introduce an IPS activation phase into the production roadmap.

## Team Command

> Do not make the repository larger until you know which files are authoritative.

> Do not make a Phase "done" because the code compiles.

> Do not let AI infer architecture from source alone.

> Give AI the semantic position, ownership, contract, boundaries, allowed files and exit gate before it edits code.

> Every removed legacy path is progress. Every duplicate authority is technical debt.
