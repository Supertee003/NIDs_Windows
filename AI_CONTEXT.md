# AI_CONTEXT.md — AEGIS NIDS Windows

## Machine-Generated Current-HEAD Context Layer



**HEAD:** `02b4e5de7446af6e7ba99d66f93397b90ba6fdef` (build source commit — ADR-0008)

**BRANCH:** `codex/o2-etw-context`

**GENERATED:** 2026-11-03T14:45:00+07:00

**GENERATOR:** Manus + `tools/rebuild_truth.py` (ADR-0008 source-commit stamp)

> HISTORY REWRITE (2026-11-06): published history was rewritten to remove
> `aegis-audit-*/` (13.8 GB of scan dumps) and the local-only
> `admin-evidence/`. Pre-rewrite SHAs cited in older evidence remain
> resolvable through `analysis/HISTORY_REWRITE_20261106.md` and
> `analysis/history-rewrite-20261106/commit-map.txt` (for example
> `fc108b0` → `572ff13`, `f7c626d` → `e06fcc3`, `13a9ad1` → `db911c8`).
> The build source content is unchanged.

## Current Operational Truth — 2026-10-31

- Production mode is detection-only. Rust PEP remains the sole privileged authority, but production host-effect activation is out of scope; `src/policy/wfp_production.zig` fails closed and is not a production WFP enforcement route.
- Go Nose sends length-prefixed CanonicalEvent frames over `\\.\pipe\aegis_nose` to the Zig reader; C/C++ adapters use separate C ABI contracts.
- Python Brain inspection is optional. UDP offers are fire-and-forget; opt-in findings return only as advisory sensor events. The Phase-B BrainAdvisor dispatcher is test-harness-only. XDR is advisory recording-only at current HEAD: XDR-WIRE-001 feeds the selected fabric from detection-identity events, and XDR-RECEIPT-002 persists frozen multi-source assessments as IDS Evidence Receipts after forensic hash read-back with replay. The receipt value is discarded; no scoring, policy, PEP, DEFCON, ActionDispatcher, or host-effect consumer exists. Windows E5 remains open.
- Current evidence does not establish Windows E5/kernel qualification or release readiness. Treat older deployment/evidence narratives below as historical unless their source commit and current-head proof are explicitly verified.

**ARCHITECTURE:** Hub-and-Spoke with Plane Separation



> HISTORICAL NOTE: earlier revisions of this file referenced HEAD `48eb2a72…`

> (2026-09-12) and `2c7cb30…` (2026-09-10). Those revisions are HISTORICAL

> evidence only; `48eb2a72` is no longer current truth.



---



## 1. WHAT AEGIS IS



AEGIS is a **Security Operations Machine** — a Windows-native Network Intrusion Detection System with seven-language architecture. It is NOT a single-file project. It is a runtime with capture, detection, policy observation, forensics, and control planes; production host-effect activation is out of scope.



**Architecture:** Hub-and-Spoke with Plane Separation

- **Zig** = Runtime Spine (the hub)

- **Go/C++** = Acquisition (sensors, adapters)

- **Python/Cython** = Intelligence (Brain, RAG, analytics)

- **Rust** = Security (sole PEP/crypto authority; production host-effect activation out of scope)

- **TypeScript** = Control (policy authoring, CLI, UI)



**Cython is a Python-to-native performance bridge, NOT the system integration bus.**



## 2. ARCHITECTURE (Plane Separation)



```

                         ┌───────────────   
                         │ CLI / TUI /   │

                         │ WEB / TS      │

                         └───────┬───────┘

                                 │

                           Control Protocol

                                 │

                                 ▼

                     ┌────────────────────�

                     │       ZIG          │

                     │   RUNTIME SPINE    │

                     │                    │

                     │ Canonical Event    │

                     │ Event Fabric       │

                     │ Flow               │

                     │ Detection          │

                     │ Correlation        │

                     │ Runtime State      │

                     └──────┬──────┬──────┘

                            │      │

               ┌────────────┘      └────────────�

               │                                │

               ▼                                ▼

          GO / C / C++                       PYTHON

          Sensors                            Brain/RAG

               │                                │

               └───────────�      ┌────────────┘

                           ▼      ▼

                           CYTHON

                              │

                              ▼

                        Native Compute



                              │

                              ▼

                           POLICY

                              │

                              ▼

                         RUST PEP

                              │

                      Authorization

                              │

                              ▼

                    Host Effects: OUT OF SCOPE

                              │

                    WFP boundary: fail-closed

                              │

                              ▼

                     Audit / Forensics

                              │

                              ▼

                       Observability

```



## 3. PLANES



| Plane | Language | Role | Boundary |

|---|---|---|---|

| A: Acquisition | Go, C/C++ | Sensors, Windows adapters | Go Nose named pipe; C/C++ C ABI → Zig |

| B: Runtime | Zig | Spine, Event Fabric, Flow, Detection, Correlation | Hub |

| C: Intelligence | Python, Cython | Brain, RAG, Analytics | Optional Python UDP offer + opt-in advisory event return; no direct policy feedback |

| D: Security | Rust | PEP and crypto authority; production host effects disabled/out of scope | PEP ABI → Zig |

| E: Control | TypeScript | Policy authoring, CLI, UI | Control Protocol → Zig |



## 4. ONE RUNTIME



```

zig build                                   → aegis_nids.exe       (Tier-1: runtime spine)

cargo build --release                       → aegis_pep.dll        (Tier-3: Rust PEP)

cmake -B build && cmake --build build       → 3 C DLLs             (native adapters)

cd nose && go build -o aegis-nose.exe .     → aegis-nose.exe       (Go: packet acquisition)

python brain/windows_brain.py               → (interpreted)        (Tier-2: analytics)

cd ts_policy && npm run typecheck && npm run test:all   → (advisory only, no output)   (policy authoring, advisory)

```



**ONE production runtime. No duplicates.**



## 5. CONTRACTS (5 Core Contracts)



| Contract | ID | Description | Boundary |

|---|---|---|---|

| CONTRACT-01 | CANONICAL_EVENT | 109-byte event schema | All sensors → Zig |

| CONTRACT-02 | PEP_ABI | PEP request/response (64/16 bytes) | Zig ↔ Rust |

| CONTRACT-03 | RUNTIME_ABI | Module lifecycle + worker stages | Zig ↔ all |

| CONTRACT-04 | CONTROL_PROTOCOL | JSON over named pipe | TS/CLI → Zig |

| CONTRACT-05 | POLICY_IR | Policy AST (Action, Condition, Policy) | TS → Rust PEP |



## 6. LANGUAGE OWNERSHIP



| Language | Owns | Does NOT Own |

|---|---|---|

| Zig | Runtime fabric, event, flow, dispatcher, detection, correlation, forensics | Privileged enforcement, crypto |

| Go | Packet acquisition (Nose), collectors, I/O | Policy, enforcement |

| C++ | Windows native adapters (ETW, FIM, Registry, WFP) | Policy decision, enforcement |

| Python | Brain (Tier-2), analytics, RAG | Privileged OS calls, enforcement |

| Rust | Crypto, trust, sole PEP/authorization authority; production host-effect activation is out of scope | Detection logic |

| TypeScript | Policy authoring, simulation, compiler | Enforcement, runtime |

| Cython | Python-to-native performance bridge | New logic, system integration |



## 7. AUTHORITY BOUNDARIES



- **Final enforcement authority:** Rust PEP (`rust-src/lib.rs`)

- **Runtime orchestration:** Zig core (`src/main.zig`)

- **Packet acquisition:** Go Nose (`nose/`)

- **Policy authoring:** TypeScript (`ts_policy/`)

- **Brain analytics:** Python (`brain/`)

- **Native adapters:** C++ (`bridge/`, `src/windows/`)



**Never bypass Rust PEP. Never create a second runtime. Never create a second enforcement authority.**



## 8. LANGUAGE INTEGRATION (Correct Paths)



| Path | Boundary | Status |

|---|---|---|

| Go Nose → length-prefixed named pipe → Zig | Production acquisition | ✅ Correct |

| C++ → C ABI → Zig | Native adapters | ✅ Correct |

| Python ↔ Cython ↔ C/C++ | Performance bridge | ✅ Correct |

| Zig ↔ Rust PEP ABI | Sole privileged authority; production host-effect activation out of scope | ✅ Correct |

| TypeScript → Control Protocol → Zig | Policy/UI | ✅ Correct |



## 9. LANGUAGE INTEGRATION (Wrong Paths - NEVER DO)



| Path | Why Wrong |

|---|---|

| Go → Rust PEP | Wrong authority boundary |

| Python → WFP | Wrong security boundary |

| TypeScript → native WFP | Wrong security boundary |

| C++ → Rust → Zig → C++ | Cyclic architecture |

| All languages → all languages | Architectural mesh |



## 10. CURRENT PHASE



**ARCHITECTURE STABILIZATION** (Hub-and-Spoke + Plane Separation)



Current source/build slice (2026-11-03; source commit `f7c626df89bc18b31d0132181d0a4632d6b1e6f3`):

- E5-DEPLOY-F7C626D (2026-11-03): the current-source package (SHA-256 `983C9A5D...`) was installed silently on the Windows host after capturing a d02261e rollback point. The installed daemon is now `D34D350A...`, byte-identical to the workspace build from `f7c626d`, with `build_manifest.json` source `f7c626d`. 35/36 verification checks passed: all payload hashes, service image path, driver signatures/load, capture pins, single-nose instance, and `prevention_gate=closed` / `enforcement_mode=detection-only` / `tier3_enforcing=false`. The one blocked check was the RB-021 preflight, which could not see the Kali/Victim ARP neighbors because the isolated lab VMs were not running. Both guests were later powered on and the preflight returned `RB021_PREFLIGHT_PASS` on this deployment (RB021-PREFLIGHT-PASS-20261103, E1; 16 named checks — the earlier "17/17" was a miscount); the same run found the machine `AEGIS_DAEMON_IFACE` pin still pointing at lab VMnet1, removed it, and confirmed host capture live again (337 -> 677 packets in 12 s). That deployment event sent no canary and enabled no host effect.
- E5-DEPLOY-05EBBA0-RING4M (2026-11-06, E5; source `05ebba0`): the QLOSS loss chain was closed by measurement, not by clearing counters. The allow-row audit volume was the original backpressure (`940714b`); once removed the pipeline queue dropped nothing over 143 s/120 samples (max depth 3,988 of the 15,360 reserve boundary); the last loss was kernel ring burst overflow (8,627 records / 157 s ~55/s while draining ~1,250/s). `AEGIS_RING_SIZE` 1 MiB -> 4 MiB (driver `10C41E80...`, test-signed, daemon unchanged `6B8183F4...`), no layout or message change. Deployed with 27/27 checks plus verified rollback of the install tree and the System32 driver (`082F6A43...`). A fresh 180 s window reported ring/pipeline/queue drops all 0 over 178,499 drained rows and `readiness` `degraded=false` / `overall_gate=true`. **Correction: that window was not steady state** — a later host burst produced 10,408 pipeline-queue drops (FIM 9,553, ETW 855) with `ring_dropped` still 0, and readiness returned to `degraded=true`. The ring fix holds; queue burst headroom does not, so QLOSS-HEALTH-001 is PARTIALLY CLOSED (`QLOSS-QUEUE-BURST-20261106`). Sizing was then measured: `queue.stats` reports `depth_peak` (source `86024fb`), and a deliberate 20,000-file churn hit the boundary with 141,426 reserves-tail sheds, FIM 131,065 dropped of 519,226 pushed, ETW 18,798 of 427,807, ring 0 — capacity is the wrong lever (~36x the queue, ~950 MB, would be needed) (`QLOSS-FIM-STORM-20261106`). Per-source fair admission then landed and verifies at E5 (`fadc216`, daemon `1463BC10...`): a storming source may own at most half the host tail (7,680 of 15,360), so every other host sensor keeps the other half reachable — measured with ETW at 7,242 active of its share while FIM sat at 7,554, ring 0, 27/27 checks. The 80/20 split was measured first and rejected (ETW still lost 25,666 to FIM reaching the shared boundary). This is isolation, not loss reduction: FIM sheds its own excess and ETW's residual drops are its own overflow, so sensor-side aggregation/rate shaping remains the open decision (`QLOSS-FAIRSHARE-001-E5-20261107`). A critical admission class now protects FIM writes under `Windows\System32`/`SysWOW64` in a 1,024-slot reserve exempt from the per-source share (`ad9733c`, daemon `4F7FAEF7...`, measured `critical_pushed_total` 264 with `depth_peak` 14,345 and ring 0) — proven at unit level and by construction, not against a live System32 storm (`QLOSS-CRITICAL-001-E5-20261107`). Posture unchanged: gate closed, detection-only, `tier3_enforcing=false`. ReleaseSafe is now the default build: the previous binaries were unoptimized Debug, which put ~217 us of forensic append on the single consumer thread; after the change (`61ef9b2`) that mean fell to 38 us and a 60,000-file churn sustained 2,930 rows/s with 439 drops (0.12%), ring 0, depth drained to 0 (`QLOSS-CONSUMER-001-E5-20261107`). This corrects the earlier 1,325 rows/s capacity claim: that was a saturated drain rate, not the ceiling. Limits: test-signed driver (production signing open). Evidence: `admin-evidence/e5-deploy-05ebba0-20261106/closeout.md` and `EVIDENCE_INDEX.json#E5-DEPLOY-05EBBA0-RING4M`.
- E5-DEPLOY-940714B-QUIET-AUDIT (2026-11-06, E5; source `940714b`): bounding the log file did not bound the write load — the per-event `AUDIT` row was written for every processed event and every sampled row was `rule=0 policy=0 decision=allow` (~5,300 lines/s, ~55 GB/day, rotation every ~100 s). `auditLevelFor` keeps matched-policy and non-allow rows at `info` and drops allow-with-no-match rows to `debug`; audit identity, decision trace and forensic recording are unchanged. Deployed as daemon `6B8183F4...` (package `6071E80A...`) with 31/31 checks and a saved rollback (prior `F4BC3A85...`). Measured: persisted growth per 60 s fell from ~34–41 MB to **3,439 bytes**, no rotation in 3 minutes, 16,869 bytes after ~4 minutes. No policy-matching traffic in the window, so the positive side is pinned by unit test plus earlier canary lines rather than re-exercised live. Posture unchanged: gate closed, detection-only, `tier3_enforcing=false`. Evidence: `admin-evidence/e5-deploy-940714b-20261106/closeout.md` and `EVIDENCE_INDEX.json#E5-DEPLOY-940714B-QUIET-AUDIT`.
- E5-DEPLOY-A9E8DE3-LOGCAP (2026-11-06, E5; source `a9e8de3`): the bounded-log build is installed on the Windows host — daemon `F4BC3A85...`, package `84FFC725...`, `build_manifest.json` source `a9e8de3`, 42/42 checks with a verified rollback point (prior daemon `EB9F44AB...`, which was what the host actually ran, not the `D34D350A...` the audit narrative claimed). The 41.0 GB `aegis-daemon-diagnostic.log` was deleted with the service stopped (41,042,778,303 bytes; free space 4.26 GB -> ~43 GB). The cap was proven live: at ~560-690 KB/s the file reached 64 MiB in ~100 s, rotated (backup 67,108,793 bytes), and rotated again, never exceeding the cap. Posture unchanged: `prevention_gate=closed`, detection-only, `tier3_enforcing=false`, `host_effect_capable=false`, no canary. Log verbosity (~55 GB/day of writes) remains open work. Evidence: `admin-evidence/e5-deploy-a9e8de3-20261106/closeout.md` and `EVIDENCE_INDEX.json#E5-DEPLOY-A9E8DE3-LOGCAP`.
- QLOSS-DISK-001-E2-20261106 (2026-11-06, E2; source `a9e8de3`): the persisted diagnostic stream had no size bound — `C:\Program Files\AEGIS NIDS\logs\aegis-daemon-diagnostic.log` reached 40.9 GB and drove `C:` to 0 bytes free. `FileSink` now rotates at a 64 MiB cap and keeps one backup at `<path>.1`, so on-disk growth is bounded by two caps; a legacy oversized file rotates on the first write after restart. Proven at E2 only (`zig build` exit 0, `zig build test --summary all` 2,036 passed / 10 skipped / 0 failed, including cap/backup/legacy-rotation tests). The installed host still runs the unbounded f7c626d image and the 40.9 GB file remains; deploying the fix and deleting the stale file are owner-approved elevated actions. Evidence: `EVIDENCE_INDEX.json#QLOSS-DISK-001-E2-20261106`.
- PROJECT-STATE-AUDIT-20261106 (2026-11-06, E1; records HEAD `f325ef6`, build source `572ff13`): read-only audit of the repository gates and the live host. Gates green — `truth.py verify` `TRUTH_VALID`, release verify 651/651 artifacts, `zig build test --summary all` 2,034 passed / 10 skipped / 0 failed. The installed runtime was reported at audit time as the restored f7c626d image (`D34D350A...`); the later same-day deploy re-read the host and found `EB9F44AB...` (fc108b0), so that line is corrected here — 7/7 subsystems RUNNING (pid 20668), driver present, `authority` HELD, `host_effect_capable=false` with readiness `degraded=true` / `overall_gate=false`. The `QLOSS-HEALTH-001` loss is live (queue drops 1,377,719; minifilter pipeline 1,154,171; Nose frames dropped 221,956 of 851,219 read), so issue #29 stays OPEN. `RB-017` is NOT satisfied: the only brain listener (pid 31516, `pythonw.exe`, session 0, created 2026-10-31, parent gone) has an unreadable command line, `endpoint_ownership=FOREIGN`, and no SCM service or scheduled task — an unsupervised orphan, not a supervised bring-up. Remaining closure work is now: QLOSS overload elimination, supervised Windows E5/kernel qualification, blocked RB-017, signed release/E7, and the pending CI push. Evidence: `admin-evidence/project-state-audit-20261106/closeout.md` and `EVIDENCE_INDEX.json#PROJECT-STATE-AUDIT-20261106`.
- XDR-005-E5-20261105 (2026-11-05, E5; records HEAD `13a9ad1`, build source `fc108b0`): candidate `EB9F44AB...` was installed in a bounded elevated window and pinned to VMnet1. A real R9064 literal `;whoami` canary from Kali `192.168.126.10` produced a live `network+host` multi-source incident (`distinct_sources=2`, categories `[network,host]`, evidence 10, confidence 70) with `receipts_recorded=2`, `receipts_failed=0`; `aegisctl xdr verify` replayed persisted sequence 1060875 (source event 51) with `verified=1/failed=0`; `forensics verify` was `verified=true/integrity=ok`; `blocks=0`; gate closed; `host_effect_capable=false`. Restore returned `D34D350A...`, removed machine/service pins, PEB-verified no daemon pin, kept Nose on the production device, and production packets advanced (1,868 -> 2,050) without a reboot. Attempt 1 is retained as functional evidence; its single harness verify ran after the ~4 s ring retention, but a pinned tight loop captured 7 verified hits. `IDS-XDR-005-WIRING-OPEN` and `XDR-005-LIVE-MULTISOURCE-UNREACHABLE` are CLOSED. Evidence: `admin-evidence/xdr005-e5-20261105/closeout.md` and `EVIDENCE_INDEX.json#XDR-005-E5-20261105`.
- RB-021-CANARY-F7C626D (2026-11-04, E5; records HEAD `1afde37`, build source `f7c626d`): two bounded elevated windows produced 70 real rows from Kali `192.168.126.10` against victim `192.168.126.20` — R9007 60, R0088 2, R9064 2, R9002 1, R9006 1, R0056 1, R0089 1, R9059 1, plus one R1005 cross-layer artifact (literal `hosts` inside the traversal payload). All rows `signature_match` / `observed` / `host_effect_confirmed=false`; `blocks=0`; gate closed; no reboot. Real ICMP/SYN/XMAS now fire, unlike the 2026-10-20 payload-token baseline; R9002 needed hping3 at 1000 pkt/s and R9064 needed the rule's literal `;whoami`. Restore removed both pins, PEB-verified, and production packets advanced (44 -> 106 and 74 -> 110 in 12 s). `E5-CURRENT-RUNTIME-MISMATCH` is CLOSED. That canary was single-source; the later 2026-11-05 XDR-005 E5 run closed `IDS-XDR-005-WIRING-OPEN` (see above). Readiness stays `degraded=true` from pre-existing data-loss counters (QLOSS-HEALTH-001) while 7/7 subsystems are RUNNING.
- QLOSS-HEALTH-001-E5-20261104 (2026-11-04, E5; records HEAD `1afde37`, build source `f7c626d`): the deployed runtime contains the `1edb2b1` observability fix. A post-restore health snapshot reports `state=DEGRADED`, `degraded=true` with `queue_dropped_total=65104`, `minifilter_ring_dropped=364820`, and `minifilter_pipeline_dropped=47775` while 7/7 subsystems are RUNNING and every worker is ready; readiness reports `degraded=true` / `overall_gate=false`. Network ingress dropped 0 in both canary rounds, so the counters are host-telemetry loss (ETW/FIM/minifilter), not canary traffic. This proves visibility, not loss elimination: readiness stays degraded and issue #29 remains OPEN for the underlying loss. Evidence: `admin-evidence/rb021-canary-20261104/post-restore/health-degradation.json` and `EVIDENCE_INDEX.json#QLOSS-HEALTH-001-E5-20261104`.
- XDR-RECEIPT-002 (2026-11-03; source commit `f7c626d`) wires the recording-only advisory bridge into the production detection pipeline. A detection-identity event feeds the selected XDR fabric; when a multi-source assessment freezes, the batch is appended to the hash-chained forensic ring, an IDS Evidence Receipt is issued after hash read-back, and replay verifies the assessment. `xdr.list` exposes receipt counters. The receipt value is discarded; no policy/PEP/DEFCON/ActionDispatcher/host-effect consumer exists. Windows E5 for this route was recorded on 2026-11-05 (`XDR-005-E5-20261105`).
- HISTORICAL (source `88466a6`, 2026-10-31): IDS-XDR-005 made `src/xdr/xdr_incident_fabric.zig` advisory-only and removed enforcement-shaped fields. XDR was not yet connected to the production daemon at that snapshot.
- MAP-006 source/map reconciliation now reflects Go's named-pipe ingress, optional Brain advisory events, the fail-closed WFP boundary, advisory recording-only XDR, separate replay verification, and historical host/WFP evidence.
- Verification: MAP-006/WFP/T12/T14 focused pytest 38 passed; `zig build` PASS; full `zig build test` PASS (exit 0); truth rebuild and verification PASS. This is source/build and E2 evidence only.
- IDS-COV-001 (2026-11-01): commit `3fe2896` wired `l7_payload.zig` and `ids_evidence_receipt.zig` directly into `src/all_tests.zig`; on checkout `cf2f1fc`, the Zig test-scope/MAP-006 gates passed 12/12 and `zig build test` exited 0. The two execution-graph coverage gaps are CLOSED at E2.
- KIDS-002 (2026-11-01; source commit `8cb2afb`): the gate-closed policy path now uses Rust PEP's evidence-only assessment and skips ActionDispatcher; only the lab gate-open branch retains enforcement. Focused contracts passed 14/14, the assessment fallback unit passed 1/1, and `zig build` passed. Its full-suite attempt was incomplete at that time; VER-002 later isolated loopback tests and VER-003 established a fresh full-suite pass. Evidence level E2.
- VER-002 (2026-11-01; source commit `2826d27`): nine real-loopback TCP tests are opt-in through `zig build test-network-integration`; canonical test execution skips them without `AEGIS_TCP_INTEGRATION=1`. Focused scope gates passed 8/8 and the module's real-socket case skipped as expected. The opt-in integration target was not run. The full suite was incomplete at this slice; VER-003 later fixed the long compliance test and established a full-suite pass.
- VER-003 (2026-11-01; source commit `ba92468`): compliance NDJSON reads are buffered and line storage is reused; the 80,000-event / 19 MB stress test fell from >120 seconds to 4.04 seconds. The registry trie timing assertion was replaced by deterministic prefix correctness checks after it failed once in the full graph but passed in five isolated runs. Final `zig build test` at source `c709c91`: 2,002 passed, 10 skipped, 0 failed; E2.
- HISTORICAL: IDS-XDR-006 (2026-11-01; source commit `091a968`) proved the lab/test-only XDR evidence slice: correlate multi-source evidence, persist a versioned snapshot, issue an IDS receipt after forensic hash read-back, and reconstruct/replay the assessment. It was not imported by the production daemon at that snapshot; XDR-RECEIPT-002 later wired the same bridge as recording-only.
- HISTORICAL: Windows E5 preflight (2026-11-01): VMnet1 was up and the NIDS/Npcap services ran, but there were no running VMs, the machine capture pin was absent, and that session was not elevated. RB-021 §2 requires Admin for the pin/restart. No host state or traffic was changed. Superseded by RB021-PREFLIGHT-PASS-20261103 and RB-021-CANARY-F7C626D-20261104.
- Supervised Windows E5/kernel qualification and release readiness remain OPEN as broader qualification scope. `IDS-XDR-005-WIRING-OPEN` is CLOSED at E5 (2026-11-05): the recording-only multi-source receipt/replay route ran on the deployed candidate `EB9F44AB...` and restored to `D34D350A...` without host effect. Do not claim project completion, production kernel readiness, or full Windows E5 closure from these results; readiness remains `degraded=true` from `QLOSS-HEALTH-001`.


Previous phases:

- Phase 6 (Forensics): IMPLEMENTED, verification E2

- Phase 7 (FFI): IMPLEMENTED, verification E2

- Phase 8 (Testing): IMPLEMENTED, verification E2

- Phase 9 (Release): IMPLEMENTED, verification E2

- Truth Stabilization: COMPLETED

- Vol01–11 vertical slices (bdd9dc7, 2026-09-24): IMPLEMENTED, verification
  E2–E5 — contract parity (C/Go/Python/Zig), 9-step pipeline, federation.status,
  decoder parity, fail-closed test truth, bridge exports, brain suite, TS path
  refs, golden 10/10, e2e 38/0, live CLI proof, rule fixtures 22/22.
  Evidence: EVIDENCE_INDEX.json VOL01–VOL11 entries (49 total).

- HISTORICAL deployment/evidence narrative (2026-10-18/19; not current-head kernel/E5 proof): the prior kernel-level NIDS detection-loop report listed V6-QUEUE-DROP,
  SLICE-C-LAB (+ artifact rehearsal), BRAIN-FASTPATH-FIX, POLICY-EVAL-FULL, STALE-DOC-SWEEP,
  DEADCODE-QUARANTINE, CI-GAPS, RELEASE-TOOLING, LEFTOVER-SWEEP, REL-CLOSURE; operator
  cutover 2026-10-19 20:07 deployed daemon `dcb22a5` (sha256 `f223dcce…`) — live gate
  hard-closed (gate_source 'closed', detection-only), gate-check + v6 live verify PASS.
  Remaining queue: G2 lab campaign 2026-10-23 (PEP cache swap PASS; direction verify PASS; duplicate canary blocked by existing filter 78056 with confirmed_quarantines=0, so G2-DUPFILTER-REPEAT-20261022 was OPEN at that snapshot (closed 2026-10-28 by G2-DUPFILTER-HOST-PROOF-E5-20261028); G2-RB013-MIRROR-20261021 CLOSED on the first-canary metric 0 -> 1; G2-RB013-LOG-20261023 OPEN P2 (closed 2026-11-02 by RB013-LOG-E5-20261102); G2-INBOUND-VERIFIER-20261021 CLOSED; G2-ABSENCE-LAB-20261022 CLOSED; G2-INBOUND-RESTORE-20261021 CLOSED with the E19C host-production baseline, not 8FEB; G2 gate was NOT PASS at that snapshot; next direct PEP inbound duplicate harness), RB-014/015, RB-018 (PASS 2026-10-20), RB-021 (L4 close-out PASS 2026-10-20; rate/window E2 2026-10-20; install E5 24/24 verifier; R9002/R9006/R9007 live PASS; isolated Kali→Win11 rate E5 CLOSED 2026-10-20; DEPLOY-132 process-pin drift CLOSED 2026-10-21 — host reboot cleared SCM cache; post-reboot PEB dump no pin, R0088=0, verifier 24/24),
  RB-016/017, G4 signing, external review, CI first push (truth semantics fixed 2026-10-20; push approval pending).
  Evidence: EVI CUTOVER-DCB22A5 (E5) + entries V6-QUEUE-DROP..REL-CLOSURE.

- G2 inbound pipeline quarantine (2026-10-21 late): PASS functional / PARTIAL
  observable (E5 lab-only). Installed daemon 9D88..., PEP AC9B..., driver
  71D1... (signature Valid), lab policy DB67... (kind=1 + dst_port=443 ->
  quarantine). A lab-only PepRequest padding byte at offset 37 selects inbound
  recv-accept; the 64-byte ABI and ctx offset 40 are unchanged. Canary
  192.168.126.1 -> :443 was accepted at 05:29:14; WFP filter 73000
  (RECV_ACCEPT_V4, BLOCK, remote .1, local 443, proto 6) was present; the
  second canary was not accepted; PEP logged confirmed=true; unblock returned
  ROLLED_BACK/ABSENT; the post-rollback canary was accepted at 05:31:30 and
  re-triggered 73001, removed by 05:35:30 (VM-local log). Direct
  QUARANTINED_CONFIRMED/g_confirmed_quarantines were not captured and
  enforcement.verify returned null for the inbound filter. Host tree restored
  to HEAD 2b31198; truth verify PASS. Lab VM snapshot restore PENDING; a
  2026-10-22 recheck found TCP 443 open and made one TCP connect, which is
  canary-like and may have triggered the still-loaded lab policy; no further
  443 traffic was sent and the restore must enumerate/remove any new proof
  filter. Production detection-only, gate closed. Evidence: EVI
  G2-INBOUND-PIPELINE-20261021; vm-recheck-20261022.txt.

- G2 metrics observability patch (2026-10-22): IMPLEMENTED at E2 - metrics.snapshot
  now emits confirmed_blocks and confirmed_quarantines as read-only atomic loads
  of g_confirmed_blocks/g_confirmed_quarantines, so a future lab run can capture
  the receipt-verified counter through the control API without a persisted stderr
  stream. Unit tests cover key presence and full u64 width; zig build test PASS.
  This does not retroactively close G2-RB013-MIRROR-20261021. Production remains
  detection-only, gate closed. Evidence: EVI G2-METRICS-001.

- G2 direction/verifier patch (2026-10-22): IMPLEMENTED at E2 (FFI-001) - the
  lab-only WFP direction byte is now in HEAD at PepRequest offset 37 (64-byte
  ABI, ctx@40). capture_wfp uses the peer src_ip + local dst_port and the
  ALE_AUTH_RECV_ACCEPT_V4 local-port filter; outbound keeps dst_ip + CONNECT;
  unknown directions and zero inbound peers fail closed. enforcement.verify
  now accepts direction:1 + src_ip, and verifyEnforcementReceipt uses the
  inbound tuple. Zig 2209 pass/1 skip; Rust 48 pass/1 ignore; WDK driver and
  user bridge build PASS. The 2026-10-21 verify_73000=null is explained by the
  outbound target (203.0.113.10) vs the inbound peer (192.168.126.1); the gap
  stayed OPEN until the 2026-10-23 lab run closed it
  (EVI-G2-PEP-CACHE-001-LAB-20261023). Production detection-only, gate closed.
  Evidence: EVI G2-DIRECTION-001.

- G2 duplicate-filter idempotence (2026-10-22): IMPLEMENTED at E1 compile
  (G2-DUPFILTER-001) - on FWP_E_ALREADY_EXISTS / OBJECT_NAME_COLLISION the
  driver queries the fixed key and returns the existing filter ID only when
  direction/layer/tuple match; mismatches fail closed. The query matcher now
  requires the layer-appropriate port condition and rejects ambiguous filters.
  WDK driver BUILD OK (aegis_wfp.sys sha256 9476F609...); no lab host execution
  yet; the repeated-quarantine escalation was OPEN as
  G2-DUPFILTER-REPEAT-20261022 until the 2026-10-28 host proof closed it.
  Production detection-only, gate closed.

- G2 lab re-run preparation (2026-10-22): lab gate-open build staged at
  admin-evidence/g2-direction-20261022/lab-kit-20261022-v2 (daemon 0F3F866A...,
  PEP 8E11ED18..., bridge 9D5D7D46..., unsigned driver F54CFB7F...).
  lab-kit-20261022-v1 is SUPERSEDED: its query path could attest an inbound
  filter through the outbound layer. Current-HEAD tests re-passed: Zig
  2209/2210 pass + 1 skip; Rust release 49 pass, 1 ignored, keygen 3 pass.
  Production posture rechecked read-only: detection-only, gate closed,
  host_effect_capable false. Lab install is still blocked: SMB aegis-lab
  authentication is rejected, WinRM default credentials are refused by client
  policy, and the 2026-10-22 443 port check may have created a new proof
  filter. No further 443 traffic; operator must confirm restore/access and
  remove any filter before INSTALL.txt is followed. Use v2 only.

- G2 exact-not-found absence patch (2026-10-22): IMPLEMENTED at E1 compile
  (G2-ABSENCE-001) - the user bridge maps only FWP_E_FILTER_NOT_FOUND /
  ERROR_NOT_FOUND to a zeroed present=0 state with the requested filter_id;
  every other query failure stays -1. The Windows host ABI test now pins
  PepRequest.direction@37. User bridge BUILD PASS (aegis_wfp_user.dll sha256
  FD3A8FAB...); ABI and capability tests PASS. A mistaken full-file host test
  invocation skipped at host-effect-unavailable and the proof key was absent
  afterward (near-miss note). The exact-status branch is compile-only from
  this HEAD; lab re-proof pending as G2-ABSENCE-LAB-20261022. Production
  detection-only, gate closed.

- G2 direction-scoped verifier patch (2026-10-22): IMPLEMENTED at E2
  (G2-VERIFY-DIR-001) - the WFP postcondition query now names the layer
  (16-byte AEGIS_WFP_FILTER_QUERY: filter_id + direction@8 + reserved).
  Direction 0 keeps ALE_AUTH_CONNECT_V4 + remote port; direction 1 uses
  ALE_AUTH_RECV_ACCEPT_V4 + local port; unknown directions fail closed. The
  bridge adds aegis_wfp_ioctl_query_filter_dir and the PEP adds
  aegis_pep_query_filter_dir; a missing direction-aware export fails closed
  instead of falling back to the outbound query. enforcement.verify passes
  target.direction; enforcement.unblock proves absence on both layers. Zig
  2209/2210 + 1 skipped; Rust 49 pass + 1 ignored; WDK driver F54CFB7F...;
  bridge 9D5D7D46...; lab-gate daemon 0F3F866A.... This closes the v1
  false-positive path in source; at that snapshot the lab re-runs
  G2-INBOUND-VERIFIER-20261021 and G2-ABSENCE-LAB-20261022 were still open;
  both were closed on 2026-10-23 by EVI-G2-PEP-CACHE-001-LAB-20261023.
  Production detection-only, gate closed.
  Evidence: EVI G2-VERIFY-DIR-001.

- G2 pep-cache/duplicate lab run (2026-10-23): source patch G2-PEP-CACHE-001
  at HEAD ee1010e (PEP query/unblock use adapter_cache::with_adapter; the
  private Adapter::load whose Drop closed the shared WFP handle is gone).
  E2: cargo test 49 pass / 1 ignored + keygen 3; clean PEP build 735D772D...
  (release DLL hash is not byte-stable across rebuilds). E5 lab
  (192.168.126.20, lab-only, base restored): PEP swap OK; direction verify
  VERIFY_OK=true (filter 78056, direction 1, remote 3232267777, MATCH);
  duplicate canary BLOCKED_OR_TIMEOUT by the existing filter 78056, the
  listener had no new ACCEPT, and confirmed_quarantines stayed 0; the same
  filter / no new filter / no escalate reason=4 outcome is observable, but the
  duplicate PEP inbound path and receipt are NOT proven. Unblock
  UNBLOCK_OK/ROLLED_BACK/ABSENT, proof count 0. Base restore BASE_RESTORE_OK
  to host-production E19C/617F/EF9B/AD23/B722 (not the 8FEB snapshot; the
  deviation was accepted), detection-only, gate closed, host_effect_capable
  false, tier3_enforcing false, proof count 0; listener/firewall/lab
  policy/trust removed; G2ElevRun/G2LabNormal removed. Status:
  G2-DUPFILTER-REPEAT-20261022 was OPEN at that snapshot (closed
  2026-10-28 by G2-DUPFILTER-HOST-PROOF-E5-20261028); G2-RB013-MIRROR-20261021 CLOSED on the
  first-canary metric 0 -> 1; G2-RB013-LOG-20261023 OPEN P2 (closed 2026-11-02 by RB013-LOG-E5-20261102);
  G2-INBOUND-VERIFIER-20261021 CLOSED; G2-ABSENCE-LAB-20261022 CLOSED;
  G2-INBOUND-RESTORE-20261021 CLOSED. G2 gate was NOT PASS at that snapshot. The control-plane
  enforcement.quarantine/block verbs are outbound-only (PepRequest.direction
  defaults to 0; the handler read-back uses direction 0), so they cannot prove
  the inbound duplicate; the next proof is a direct PEP inbound harness (two
  aegis_pep_enforce calls with direction=1, a query between them, same filter
  ID / successful receipts / no escalate reason=4) or accepting the gap.
  No production enforcement. Evidence: EVI-G2-PEP-CACHE-001-LAB-20261023;
  admin-evidence/g2-direction-20261022/PATCH-PEP-CACHE.md;
  admin-evidence/g2-direction-20261022/vm-lab-run-20261023.txt.

- RB-013 persisted diagnostic lab-kit E5 (2026-11-02): G2-RB013-LOG-20261023
  CLOSED by RB013-LOG-E5-20261102. On isolated Win11 192.168.126.20 the
  lab-gate kit (daemon 86D4DD77..., PEP C7F20079..., bridge 9D5D7D46...,
  signed driver 8A2B3F12..., lab policy DB67B1B5...) accepted one inbound
  canary at 00:17:47 -08:00 and persisted 8 lines at 00:17:52
  (`pep=quarantine confirmed=true` and `action=QUARANTINED_CONFIRMED`,
  filter 77892). The line is emitted only after the quarantine receipt passes
  verifyEnforcementReceipt, so it is not a request echo. Restore returned
  E19C/617F/EF9B/AD23/B722 with both services Running, prevention_gate=closed,
  tier3_enforcing=false, detection-only, and the lab payload removed. The kit
  predates current HEAD (no AEGIS_NOSE_IFACE; its daemon size matches a fresh
  24d8d81 lab-gate build), so this is lab-kit E5, not current-source E5. No
  second canary, no metrics_after, and no post-restore WFP enumeration were
  captured. See admin-evidence/rb013-log-e5-20261030/closeout.md.

- RB-021 host-only lab proof (2026-10-20): L4 CLOSE-OUT PASS (E5, per-packet).
  Pre-fix run at e616bad/F223DCCE proved the capture path + 5/8 L7 rules but real
  nmap/hping3 produced 0 L4 rows. At fd7b424/47AB8085 the L4 matcher produced 706
  .10 rows: R9006 200, R9007 200, R9002 305 (5 preflight + 300 hping3), R0088 1
  (ACK capture-positive control); L4-token ACK negative controls were 0 rows
  (5->5 and 706->706). All rows observed, host_effect_confirmed=false, blocks 0,
  gate closed; restore PID 7420 pin absent. Those 706 rows were per-packet:
  R9006 any exact SYN, R9002 any ICMP, R9007 exact 0x29.
  Evidence: EVI RB-021-L4-20261020 (E5); kit
  admin-evidence/lab-session-20261020-l4/ (gitignored).

- RB-021 L4 rate/window semantics (2026-10-20): IMPLEMENTED at E2 - opt-in
  rate blocks in configs/Rules.json: R9002 count >=50 ICMP/source/1000 ms,
  R9006 >=20 distinct destination ports/source/10000 ms, one alert per
  window; R9007 remains exact FIN|PSH|URG per-packet. State is keyed by
  rule+full source+IPv4/IPv6, fixed 256-entry table, reset on rules reload.
  Zig tests cover positive thresholds, duplicate-port suppression, source
  separation, reset, and negative controls (single handshake, 49 ICMP,
  19 distinct ports). Gap RB-021-L4-RATE CLOSED at E2.
  Artifact 04F9E0DB63858AB3FDF4FC78692D34F87C983CD6FFCB0FA0F405468785F8A05C
  (7,425,672 B) was INSTALLED on 2026-10-20. Live verifier is
  LIVE_VERIFY_OK (22/22); live daemon D67267E2..., rules 87B97448...,
  manifest 1336453D... source 8a7f301, readiness RUNNING, gate closed. The
  post-install startup race was recovered by Restart-Service AegisNids; no
  code rollback. Install E5 is recorded separately.
  Live rate attempt (host-generated TEST-NET, independent dumpcap): R9002
  PASS - 10 pings produced 0 new rows and a 60-packet burst produced exactly
  one new row (one alert in the 1000 ms window). R9006/R9007 LIVE PASS
  (2026-10-20 19:53-19:54) after the operator restarted Nose. Source patch
  RB021-NOSE-FLAGS-001 (E2, source commit de574b6) carries the raw TCP
  flags byte in the existing ContextFlags lane (bits 16..23, valid bit24;
  wire remains 109/133 bytes) and extracts it in pushDecodedFrame. Go/Zig/
  Python tests and zig build pass. DEPLOY-131 (installer 7C4B2C19...,
  source de574b6) was installed; install verifier LIVE_VERIFY_OK (22/22).
  The hardened verifier now also gates process images and is 24/24. The first
  install left Nose PID 21568 (created 2026-10-15 08:09:13) running, before
  the patched binary build at 2026-10-20 17:20:01; a quiet 20-port control
  produced 0 R9006 and five exact FIN|PSH|URG produced 0 R9007 with zero
  queue drops. Operator stopped 21568 and started PID 3632 at 19:51:55 from
  the patched binary. Post-restart: R9006 one-port 0 / 20 distinct ports
  exactly 1; R9007 normal SYN 0 / five exact FIN|PSH|URG -> 5 rows; R9002
  10 ICMP 0 / 60 ICMP 1; queue dropped 10,337->10,337 and shed
  56,936->56,936; readiness RUNNING; prevention_gate closed; host_effect
  false. RB-021-NOSE-FLAGS is CLOSED at EVI
  RB-021-NOSE-FLAGS-LIVE-PASS-20261020. Gap DEPLOY-131-NOSE-STALE-PROCESS
  is also CLOSED at EVI DEPLOY-131-VERIFY-PROCESS-20261020: the verifier now
  rejects missing/duplicate/stale/mixed daemon or Nose process images and
  passes 24/24 on the current host; its self-test is stale=False fresh=True
  mixed=False empty=False. The installer still needs the operator restart
  step, but a future stale image now fails closed rather than passing. Those
  live rows were host-generated TEST-NET and are the canonical-Nose proof;
  the isolated Kali->Win11 lab is recorded separately below. Queue pressure is separately labeled: the pre-install
  60 s quiet sample held dropped=232,149 and shed=131,545 while pushed rose
  +20,008 with zero per-source drop delta; cumulative loss correlates with
  startup plus the 17:20 build/test storm, so controls must compare deltas
  (EVI QUEUE-PRESSURE-OBS-20261020).
  Evidence: EVI RB-021-L4-RATE-E2-20261020 (E2); EVI
  DEPLOY-130-L4-RATE-INSTALL-20261020 (E5 install);
  EVI DEPLOY-130-L4-RATE-E5-ATTEMPT-20261020 (E5 PARTIAL); EVI
  DEPLOY-130-L4-RATE-PKG-20261020 (E3 packaging); EVI
  DEPLOY-131-NOSE-FLAGS-PKG-20261020 (E3 packaging, installed);
  EVI DEPLOY-131-INSTALL-20261020 (E5 install PASS 22/22);
  EVI RB-021-NOSE-FLAGS-LIVE-ATTEMPT-20261020 (E5 FAIL, stale Nose);
  EVI RB-021-R9007-PRE-RESTART-20261020 (E5 FAIL baseline, 5/5 wire, 0 rows);
  EVI RB-021-NOSE-FLAGS-LIVE-PASS-20261020 (E5 PASS, R9006/R9007 live);
  EVI DEPLOY-131-VERIFY-PROCESS-20261020 (E5 PASS, process gates 24/24);
  EVI QUEUE-PRESSURE-OBS-20261020 (E5 observation, zero idle delta);
  tests in
  src/pipeline/l4_matcher.zig + tests/security/test_l4_rate_config.py;
  patch tests in nose/capture_hermetic_test.go,
  src/contract/canonical_event.zig, src/pipeline/event_queue.zig, and
  tests/contracts/test_canonical_context_flags.py.

- DEPLOY-130-L4-RATE-E5 isolated lab (2026-10-20 21:00-21:01): PASS at E5.
  Exact isolated segment: Kali 192.168.126.10 -> Win11 victim
  192.168.126.20 on VMnet1; NIDS host 192.168.126.1. Independent
  dumpcap on host VMnet1 saw the VM-to-VM ping pair. Deployed daemon
  PID 13108 (source de574b6, sha256 E19C76C3...) was not restarted.
  R9002 10 ICMP -> 0 / 60 ICMP -> exactly 1; R9006 one port -> 0 /
  40 distinct SYN ports -> exactly 1; R9007 normal SYN -> 0 / 30-port
  XMAS -> 60 rows (per-packet, retry/duplicate capture). All 62 rows
  observed, host_effect_confirmed=false; capture_npcap drops
  3181->3181; readiness RUNNING; prevention_gate closed; verifier
  LIVE_VERIFY_OK (24/24). Gap DEPLOY-130-L4-RATE-E5 is CLOSED at EVI
  DEPLOY-130-L4-RATE-E5-LAB-20261020.
  Capture-path caveat (historical for this lab): the daemon process used
  by the lab still had the direct Zig Npcap VMnet1 path active although
  registry AEGIS_DAEMON_IFACE was absent. The L7 R0088 probe
  `../../etc/passwd` from Kali .10 -> Win11 .20 hit the live process,
  proving full-packet direct capture. Go Nose also has a payload
  signature classifier, so R0088 alone is not exclusive to the direct
  path; however, Nose was pinned to the Wi-Fi device and the probe was on
  VMnet1. No pin was set/removed and no service was restarted during the
  lab. A service restart on 2026-10-20 21:24 produced PID 2772 but still
  carried AEGIS_DAEMON_IFACE=VMnet1; a read-only PEB dump confirmed the
  daemon pin, and Nose had no pin. The pin was cached in the SCM
  environment block, so a service restart was insufficient. This lab is
  E5 for the running artifact, not a claim that the canonical Nose path
  carried it.
  CLOSED 2026-10-21: a host reboot at 07:48:30 rebuilt the SCM
  environment. The post-reboot daemon PID 23632 PEB dump had no
  AEGIS_DAEMON_IFACE; the clear restart to PID 18276 produced 0 R0088
  rows; Nose PID 15500 reconnected; readiness was RUNNING/ready; the
  verifier passed 24/24; gate closed; no host effect. Demand-start
  AegisWfp/AegisMinifilter were started by the wrapper before readiness.
  Evidence: EVI DEPLOY-130-L4-RATE-E5-LAB-20261020 (E5 PASS); EVI
  DEPLOY-132-DAEMON-IFACE-ENV-DRIFT-20261020 (E5 FAIL invariant); EVI
  DEPLOY-132-SCM-ENV-CACHE-20261020 (E5 FAIL clear attempt); EVI
  DEPLOY-132-POST-REBOOT-20261021 (E5 PASS post-reboot clear);
  kit admin-evidence/lab-rate-e5-20261020/run-nopin-20261020-210026/,
  post-reboot-20261021-080531/ and clear-drift-20261021-080635/
  (gitignored).

- DEPLOY-132 post-reboot closure (2026-10-21): PASS at E5. Host reboot
  07:48:30 cleared the SCM-cached VMnet1 pin; daemon PID 23632 PEB dump
  had no AEGIS_DAEMON_IFACE; clear restart to PID 18276; Kali .10 -> host
  .1 L7 R0088=0; Nose PID 15500; readiness RUNNING/ready; verifier 24/24;
  gate closed; no host effect. The demand-start AegisWfp/AegisMinifilter
  drivers were started by the wrapper before readiness; without that step
  the daemon is fail-closed DEGRADED. Evidence: EVI
  DEPLOY-132-POST-REBOOT-20261021; kit
  admin-evidence/lab-rate-e5-20261020/post-reboot-20261021-080531/ and
  clear-drift-20261021-080635/ (gitignored).

- RB-018 host-only WFP observe-only (2026-10-20): PASS - L4_HOSTONLY_TRANSPORT_PASS at 865217b;
  live host VMnet1 .1 + Kali .10:58874 -> :49152; 4 expected-flow frames in 10 complete 48-byte
  frames; AegisWfp Running/GENERIC_READ; GET_STATS/READ_EVENTS only; no BLOCK_FLOW/UNBLOCK_FLOW;
  gate closed; host_effect none. Transport-only, not rule-match/L7/host-effect.
  Evidence: EVI RB-018-HOSTONLY-20261020 (E5); kit admin-evidence/lab-qualification-20261020/rb018/ (gitignored).

- DEPLOY-120 installer E5 (2026-10-20): PASS at 15:30:23, artifact 1593260B... x 7,424,345 B,
  proof 66/66. Final drill: upgrade install 22/22 -> uninstall removed all three services (1060),
  both System32 driver files, and both SysWOW64 stale copies, configs preserved 444F8956... ->
  reinstall C:\ returned 22/22, gate closed, readiness ready. E5_DRILL_OK recorded in
  admin-evidence/deploy120-uninstallfix-20261020/drill-uninstall-reinstall-20261020.log.
  Two defects were exposed and fixed en route: (1) the pre-guard E80352D7 artifact created a
  duplicate D:\ runtime (contained); DEPLOY-120-PATHFIX adopted the existing C:\ service path and
  guarded Uninstall; (2) the fixed uninstaller still left System32 drivers because 32-bit NSIS
  redirected $SYSDIR file I/O to SysWOW64. Commit 4dc9c09 uses $WINDIR\Sysnative for driver
  copy/delete/signature, keeps SCM ImagePath on literal System32, and cleans stale SysWOW64 copies.
  Old 10/19 kit, pre-guard E803, and the intermediate 65204BFF/D9CBB293 artifacts are historical.
  Evidence: EVI DEPLOY-120-REFRESH-20261020 (E3), DEPLOY-120-PATHFIX-20261020 (E3),
  DEPLOY-120-E5-ATTEMPT-20261020 (E5 FAIL), DEPLOY-120-E5-20261020 (E5 PASS);
  gap DEPLOY-120-E5 CLOSED; kit gitignored.

- CI truth source-commit semantics (2026-10-20): IMPLEMENTED - ADR-0008; truth.py keys on the last
  source/build commit (current ee1010e), verifies ancestry + clean source paths; maps/AI_CONTEXT/EVI/
  build_manifest/runtime_manifest carry the current build source commit (ee1010e); clean-checkout truth PASS + release PASS;
  full suite 963P/2S/27 subtests (exit 0); tests pinned at tests/release/test_truth_source_commit.py; EVI CI-TRUTH-SOURCE-COMMIT (E2). First
  hosted CI push still operator (no push).



## 11. ACTIVE BLOCKERS



> HISTORICAL NOTE (TRUTH-REBUILD c005ccf): the P0 list below is a 2026-09-12
> snapshot taken as of HEAD `60c76fe`. Entries marked FIXED/CLOSED describe
> that snapshot, not a fresh current-HEAD audit. Do not treat this list as
> current blockers without re-verification.

P0 risks as of HEAD `60c76fe` (2026-09-12) — HISTORICAL snapshot:



- P0-1: Zig bypasses the Rust PEP for WFP enforcement.

  **FIXED**: static audit (EVT-039) confirmed no bypass. wfp_ioctl.zig

  defines zero write IOCTLs. All block_ip() routes through rust_pep → PEP

  FFI. GENERIC_WRITE hardened. GAP-011 CLOSED.

- P0-2: Tier-3 fail-closed state is not surfaced truthfully. When

  `sec_monitor.dll` is absent the runtime logs "fail-closed" yet continues;

  `health.check` never reports the Tier-3 state. **FIXED**: tier3_state.zig

  tracks state machine; system.health pulls from state machine source.

- P0-3: CI is red by construction. `go-build-test` mixes the canonical Go

  sensor with the optional aggregator sidecar. **FIXED**: shield-build removed

  (shield/ deleted); go-aggregator classified SUPPORT non-required; canonical

  CI gates only canonical jobs (see ci_coverage.json).

- P0-4: Machine maps stale (HEAD mismatch) — **FIXED at snapshot time** (maps
  then carried `60c76fe`; current-HEAD stamps are re-synced by TRUTH-REBUILD).

- P0-5: CLI canonical path conflict (`scripts/aegisctl.py` vs

  `tools/aegisctl.py`) — **FIXED**: `scripts/aegisctl.py` does not exist;

  `tools/aegisctl.py` is the single canonical client.

- P0-6: `go/aggregator/` ownership — **RESOLVED**: classified SUPPORT

  (optional operator sidecar, REST :9200). It is NOT part of the acquisition

  authority and NOT part of the runtime path.

- P0-7: `shield/` ownership — **RESOLVED (PEP-001 COMPLETE, 2026-10-17)**: the

  crate is SUPPORT (advisory Tier-3 payload screening, single export

  `aegis_shield_screen`, DynLib-only load from `src/policy/shield_screen.zig`).

  The former duplicate PEP/WFP surface was formally removed by the PEP-001

  slice (EVT-228): `shield/src/pep.rs` stripped and renamed

  `shield/src/screen.rs` (screening predicate only), `shield/src/windows_enforce.rs`

  deleted, the `aegis_pep_evaluate` / `aegis_pep_status_count` /

  `aegis_pep_version` exports gone, the dormant `extern "sec_monitor"`

  declaration and the stale `ShieldPep*`/`ShieldScore*` contract mirrors

  removed from `src/forensic/policy_contract.zig`, and the T8/T16 expectations

  point at `rust-src/lib.rs`. Negative controls pin the removal

  (`tests/security/test_forbidden_edges.py`). See GAP-007.

- P0-8: `health.check` payload does not conform to `RUNTIME_CONTRACT.md` §4.1

  (missing `pid`, `last_event_ms`, `counters`) and reports capability flags

  (`etw`/`fim`/`wfp` = "available") instead of live subsystem state. OPEN at

  the time; the update below closes it.

  UPDATE (2026-10-17, EVT-219): remainder closed by EVT-097 (live metrics

  bound into `health.check`). Re-verified against the live daemon at HEAD

  `9f0df39`: all RUNTIME_CONTRACT §4.1 fields present -- `component`, `state`,

  `pid`, `uptime_ms`, `last_event_ms`, `defcon_level`/`defcon_label`,

  `counters` (in_events/out_events/errors/dropped) and `deps[]` live

  subsystem states (all RUNNING); capability flags are additive extra keys. One

  value-semantics nuance -- the control-surface `last_event_ms` is an epoch-ms

  stamp, not age -- is recorded in EVT-219. Not a current blocker.

- P0-9: Stale pytest dumps (`test_failures_full.txt`, `test_failed_lines.txt`,

  `test_failures_output.txt`) were tracked at repo root and described failures

  that no longer exist. **FIXED** (removed; test state is now reported by CI).



## 12. CURRENT BUILD COMMANDS



```powershell

zig build                                   # Zig core (aegis_nids.exe)

zig build test                              # Zig tests

cargo build --release                       # Rust PEP (aegis_pep.dll)

cd shield && cargo build --release          # Rust Shield (sec_monitor.dll)

cmake -B build && cmake --build build       # C++ native helpers

cd bridge && cmake -B build && cmake --build build  # C++ bridge

cd nose && go build -o aegis-nose.exe .     # Go Nose (packet acquisition)

cd go/aggregator && go build -o aegis-aggregator.exe .  # Go Aggregator (REST API sidecar)

cd ts_policy && npm run typecheck && npm run test:all   # TypeScript policy compiler

```



## 12b. COMPONENT CLASSIFICATION (TRUTH-002)



| Path | Class | Owner of | Not an owner of |

|---|---|---|---|

| `src/main.zig` | CANONICAL | Runtime spine (event fabric, flow, detection, correlation, dispatch, forensics, control pipe) | privileged enforcement, crypto |

| `rust-src/lib.rs` | CANONICAL | Final enforcement authority: PEP, Ed25519, TLS, authorization | detection logic |

| `nose/main.go` | CANONICAL | Packet acquisition, flow collection, IPC reader, canonical event production | policy, enforcement |

| `src/windows/*.c`, `bridge/` | CANONICAL | Windows native adapters (ETW, FIM, Registry, WFP user-mode) | policy decision, enforcement |

| `brain/` | CANONICAL | Tier-2 analytics, RAG, rules scanning | privileged OS calls, enforcement |

| `ts_policy/` | CANONICAL | Policy authoring + compilation to Policy IR (advisory, no artifact) | enforcement, runtime |

| `shield/` | SUPPORT | Advisory Tier-3 payload screening symbol (`aegis_shield_screen`) exported to Zig (DynLib-only) | **any enforcement decision or WFP action** |

| `go/aggregator/` | SUPPORT | Optional operator alert sidecar (NDJSON → REST :9200) | acquisition, policy, enforcement |

| `mouth/` | OPTIONAL | Standalone DEFCON monitor GUI | runtime, enforcement |

| `aegis_dashboard/` | OPTIONAL | Operator web UI backend | runtime, enforcement |

| `core/` (directory) | DOES NOT EXIST | — | — |

| `core/*.zig` (manifest keys) | ALIAS | Manifest module IDs that resolve through `real_path` to `src/**` | — |

| `core/nids_main.zig` | LEGACY | Superseded by `src/main.zig` + `src/daemon.zig` | — |



Rule: a component is **CANONICAL** only if it is built by the CI matrix AND

executed by the production runtime. SUPPORT builds in CI but is not on the

golden path. OPTIONAL is operator-only.



## 13. CURRENT RUNTIME ENTRYPOINTS



**Multi-process architecture:**



1. **Zig Core** (`src/main.zig` → `aegis_nids.exe`) — Runtime spine

   - Startup: main → init subsystems → start pipeline → start watchdog → start control pipe → start capture → run loop



2. **Go Nose** (`nose/main.go` → `aegis-nose.exe`) — Packet acquisition

   - Launches as separate process, connects to Zig via named pipe



3. **Go Aggregator** (`go/aggregator/main.go` → `aegis-aggregator.exe`) — SUPPORT: alert sidecar (optional)

   - REST API on port 9200, watches NDJSON logs via fsnotify. NOT on the golden path.



4. **Rust Shield** (`shield/src/lib.rs` → `sec_monitor.dll`) — SUPPORT: loaded in-process by Zig core (DynLib-only, `src/policy/shield_screen.zig`)

   - Advisory Tier-3 payload screening (single export `aegis_shield_screen`).

   - NOT an enforcement authority. The former duplicate PEP/WFP surface was

     formally removed by PEP-001 (2026-10-17; `shield/src/pep.rs` → `screen.rs`,

     `windows_enforce.rs` deleted); P0-7 resolved — see EVT-228.



5. **Rust PEP** (`rust-src/lib.rs` → `aegis_pep.dll`) — Loaded in-process by Zig core

   - Privileged action authorization



6. **C++ Bridge** (`bridge/aegis_ipc.cpp` → `aegis_ipc.dll`) — Loaded in-process by Zig core

   - Windows native adapters (ETW, FIM, WFP)



## 14. WHERE MACHINE-READABLE TRUTH IS STORED



| Artifact | Path | Role |

|---|---|---|

| AI Context | `AI_CONTEXT.md` | First document an agent reads |

| System map | `SYSTEM_MAP.json` | Component inventory + roles |

| Flow map | `FLOW_MAP.json` | Data/decision/enforcement flows |

| Authority map | `AUTHORITY_MAP.json` | Language ownership + security authority |

| Contract map | `CONTRACT_MAP.json` | Cross-language contracts + schemas |

| Evidence index | `EVIDENCE_INDEX.json` | All evidence artifacts |

| Build truth | `build_truth.json` | Build commands → artifacts |

| Runtime manifest | `runtime_manifest.json` | Canonical entrypoints |

| Inventory | `inventory.json` | File inventory + classifications |

| Reference map | `reference_map.json` | File → role mapping |



## 15. WHAT THE AI MUST NEVER DO



1. Do not patch files in isolation — identify the system flow first

2. Do not create a second runtime

3. Do not create a second Canonical Event

4. Do not create a second Policy Authority

5. Do not create a second Enforcement Authority

6. Do not bypass Rust PEP

7. Do not promote mocks/stubs/scaffolds to production

8. Do not use old reports as current truth (check HEAD SHA)

9. Do not trust README claims as implementation proof

10. Do not work around STOP-THE-LINE conditions silently

11. Do not change unrelated files

12. Do not use compilation as runtime proof

13. Do not use unit tests as Windows-host proof

14. Do not use Cython as the system integration bus

15. Do not create language-to-language mesh (use hub-and-spoke)

