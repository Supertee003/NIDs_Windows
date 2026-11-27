# Deep Technical Audit — build source `aa3b7b0` — 2026-11-27

**RECORD-ID:** `DEEP-TECHNICAL-AUDIT-AA3B7B0-20261127`
**RECORDS HEAD AT AUDIT TIME:** `848c924503fcd4d1881252ed0ed17d7b9a3e137d` (records-only artifact; build source does not move)
**BUILD SOURCE:** `aa3b7b0161e425e54155d5767737bffcde7939b5` (ADR-0008)
**AUDIT LEVEL:** E1 static/source audit. Existing E2/E5/E6 records are cited, not re-run.
**HOST STATE:** At audit time the final 24 h soak window was in progress under the SYSTEM finalizer. No host, service, driver, binary, soak or finalizer action was performed for this audit.
**BOARD AT AUDIT TIME:** 5/6 PASS, `soak_24h` OPEN, **NOT SHIPPABLE**. No E7 claim.

This report consolidates eight parallel read-only domain audits: architecture, network acquisition, kernel/WFP, runtime/event processing, detection, evidence/security, testing/release, and documentation/portfolio. It does not promote any documented gap to physical proof, and it does not relax any guard, test, gate, verdict, evidence level or pinned truth string.

---

## 1. Scorecard

| Domain | Score | Justification |
|---|---:|---|
| Architecture & Design | **7/10** | Coherent single build root and hub-and-spoke wiring; detection-only authority is enforced in code. Deducted for contradictory machine-map statements (PEP ABI size, control replay, XDR note, TCP fallback). |
| Code Quality | **8/10** | Precise invariants, fail-closed codecs and shape gates. Deducted for stale contract comments and modules labelled production that are not on the production call graph. |
| Network Engineering | **6/10** | Real narrow loopback BPF E6 proof and strict envelope validation. Deducted because the capable VLAN/IPv6 decoder is test-only, delivery counters overstate success, timeout detection is string-fragile, and shutdown is not joined. |
| Kernel Engineering | **5/10** | Fail-open callouts, rundown teardown, bounded user buffers and honest unsigned status. Deducted for unload UAF/race, wrong client-port close API, unbounded unregister retry, persistent-block recovery conflicting with detection-only, no signing/catalog gate, and zero current-source runtime proof. |
| Detection Engineering | **7/10** | Single verdict authority, honest 22/23 census, well-bounded R2003 narrow E5. Deducted for 21 fixture-only rules, no coverage-guided fuzz, no full host matrix, stale FN-1 wording and an unwired secondary correlation window. |
| Security Engineering | **7/10** | Release signature chain verifies (241/241 SHA256SUMS), key custody is disciplined, PEP has no host-effect path. Deducted because the release gate does not hash each shipped artifact, policy-signature verification is observe-only, replay state is process-local, and the forensic chain is unkeyed. |
| Reliability | **7/10** | Mutex discipline, reason-coded drops and bounded ingress resync. Deducted for uncancellable blocking I/O and misdeclared production fabric; bounded Windows shutdown is NOT_PROVEN. |
| Testing & Verification | **7/10** | CI is fail-closed, negative tests and import/tracked-state hygiene are strong. Deducted for OPEN soak, no measured code coverage, no coverage-guided fuzz, no byte-for-byte reproducible-build proof and no E7. |
| Documentation | **7/10** | Excellent evidence taxonomy and explicit HISTORICAL markers in the closeout. Deducted for the stale declared status source, contradictory labels and 48 unresolvable evidence pointers. |
| Portfolio & Professional Presentation | **7/10** | Unusually candid about limitations and voided attempts. Deducted for no curated “start here” path and showcase pages that still present historical proof as current. |

No 10/10 was awarded. Test count, document volume and a compile pass were not treated as proof of logic correctness.

---

## 2. KEEP — do not change without a new proof or decision

- **Single build root / hub-and-spoke.** `build.zig:28-33` roots one daemon at `src/main.zig:16-18`; Go enters over `\\.\pipe\aegis_nose` (`nose/pipe_writer.go:29,43`), C/C++ adapters via C ABI/DynLib (`CMakeLists.txt:23-55`, `bridge/CMakeLists.txt:47-50,106-108`, `src/core/bridge_init.zig:274`), Rust only through `src/policy/pep_bindings.zig:178-189`. `release/T20-final/` source snapshots are frozen records, not a second runtime.
- **Rust PEP is detection-only in compiled code.** `rust-src/lib.rs:916-933` rewrites BLOCK/QUARANTINE to ESCALATE, reason 8, `filter_id=0`; `src/policy/wfp_production.zig:16-20` returns `unavailable`; `src/policy/action_dispatcher.zig:70-87` emits no confirmed effect without a receipt. No second PEP remains in current source (`AUTHORITY_MAP.json#quarantined_duplicates[SHIELD_PEP].status = REMOVED`).
- **Fail-closed canonical codec.** v1=109, v2=133, v3=165..1189; version/length disagreement is rejected (`src/contract/canonical_event.zig:635-661,776-781`), mirrored in Go (`nose/canonical.go:294-323,675-711`) and Python (`brain/canonical_event.py:130-148,305-343`). `shared/schema/canonical_event_v1.h:122-124` pins 109 bytes. Wire magic `0x41454731` and internal `IpcEvent` magic `0xAE615011`/v5/96 bytes are separate namespaces, not drift.
- **Decoded-frame gate separated from strict validator.** `validate()` pins v1, while `validateDecodedFrame()` accepts v1/v2/v3 shapes and rejects mixed sidecars (`canonical_event.zig:350-355,685-717`); used at `src/pipeline/event_queue.zig:459-462`. This closes the historical 87.7%-frames-dropped regression.
- **Queue and loss accounting.** Producer mutex covers reserve+publish, consumer mutex covers pop and occupancy release (`event_queue.zig:188-194,224-304,1202-1215`); reason-coded drops appear as `data_integrity` keys and overlapping subsets are not summed (`src/control/state_machine.zig:487-512`). Ingress strips producer verdict claims (`event_queue.zig:411-447,464-473`).
- **Control v2 replay defence is active.** `src/control/replay_guard.zig:1-14,65-81` and `src/control/handler_registry.zig:184-209` enforce version, freshness and single-use nonce; the control pipe uses explicit SDDL and impersonated client token (`src/platform/win32_pipe.zig:66-76,160-181`). Scope is exact in-process replay only (narrow E5), not durable across restart.
- **Narrow loopback BPF proof.** `nose/capture.go:61-84` uses `ip or ip6` only on the exact Npcap loopback selector; default `vlan or ip or ip6`. Current-source E6 narrow PASS with attributable R9006 rows, `dropped=0` and verified restore: `analysis/current-head/MASTER-AUDIT-LOOPBACK-BPF-E6-AA3B7B0-20261126.md:22,64-103`.
- **Narrow host proofs at this source.** pipe-reader bounded shutdown (`PIPE-READER-SHUTDOWN-E5-AA3B7B0-20261126.md`), R2003 `CommandLine` re-measurement with one positive and two negative controls (`R2003-CMDLINE-HOST-PROOF-E5-AA3B7B0-20261126.md`), controlled 100 conn/s loopback load (`docs/portfolio/CURRENT_HEAD_FUZZ_BENCH-20261126.md`). All swapped current binaries and restored hash-identical baselines.
- **Fail-open kernel classify.** Four callbacks permit and clear `FWPS_RIGHT_ACTION_WRITE` (`drivers/wfp_callout/aegis_wfp_callout.c:251-328,334-398,418-490,493-560`), with rundown gate and `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` (`:685,746,804,859`). Bounded payload copies and IOCTL size guards exist (`aegis_wfp.c:970-1022,1050-1053,1223-1225,1252-1255,1470-1473`).
- **Release signature chain.** `release/T20-final/6c94b47/signatures.json:6-11` signs `SHA256SUMS` with anchor `DCNPphsqfklICz6MxxfS5jP005BOOGbug8Vxgpn8cZU=` and digest `94F65BCC…`; independent read-only verification recomputed the digest and matched 241/241 SHA256SUMS entries. This is E1/E2 public-data verification, not E5/E7 and not driver Authenticode.
- **Honest evidence infrastructure.** `REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md:34-63` separates PHYSICAL PROOF from CLOSED as documented gap; three voided soak attempts contribute no evidence; `tools/final_audit.py:361-446` rejects missing/mismatched anchors, stale lineage and digest/signature failures.
- **CI gating and hygiene.** `.github/workflows/ci.yml:18-386` and `ci_coverage.json:131-136` fail closed for required jobs; `tests/brain/test_import_hygiene.py:108-137`, `tests/security/test_tools_import_hygiene.py:69-127` and `tests/release/test_fresh_deploy.py:45-54` pin no import-time host effects and no test writes to tracked state. Both workflows were success at records HEAD `848c924`.

---

## 3. FIX — grouped by priority

### P0 — STOP-THE-LINE candidates (tracked in issue #47)

Per AGENTS.md, these are filed before product coding. Static source review is not a workaround and does not create proof.

1. **Minifilter unload UAF/race.** `drivers/minifilter/aegis_minifilter.c:127-142` removes process notify and calls `AegisRingDestroy` (`aegis_minifilter_comm.c:64-72`) without draining; callbacks check then use `g_EventRing` (`aegis_minifilter_proc.c:18`, `aegis_minifilter_comm.c:82-100`). Class: memory corruption / race condition.
2. **Wrong client-port close API.** `aegis_minifilter_comm.c:265-274` calls `FltCloseCommunicationPort` on a client connection; requires `FltCloseClientPort`. Class: driver contract mismatch.
3. **Persistent block filters re-adopted at startup.** `drivers/wfp_callout/aegis_wfp.c:426-459,527-563,779-802` keeps enabled `FWP_ACTION_BLOCK` filters, while new blocks return `STATUS_NOT_SUPPORTED` at `:923-932`. Class: unauthorized enforcement / detection-only conflict; lab residue concern at `AI_CONTEXT.md:506-517`.
4. **PEP ABI contradiction.** `CONTRACT_MAP.json#contracts[CONTRACT-02].types.PepResponse` = 24 bytes matches `rust-src/lib.rs:268-275` and `src/policy/pep_bindings.zig:80-86,725-728`; `AI_CONTEXT.md:301` and `FLOW_MAP.json#flows[FFI-001].layers[3].input:477` say 16 bytes, which is `PepAssessmentResponse` (`rust-src/lib.rs:280-289`). Class: ABI mismatch / contradictory source of truth; reconcile or explicitly label the 16-byte statement HISTORICAL.
5. **Stale status source-of-truth.** `release/release-status.json` reports `current_build_source = 4dd3393…` and calls `7822f4c` current; `AI_CONTEXT.md:9`, closeout line 4 and `docs/DOCS_LIFECYCLE.md:3,11` carry older commit labels. Actual build source is `aa3b7b0`; board is 5/6 with soak OPEN.
6. **Release gate does not verify shipped file bytes.** `tools/final_audit.py:811-828` hashes only `SHA256SUMS`; per-file verification is in `tools/release_candidate.py:233-242`. A tampered listed artifact can pass the board.

### P1 — correctness and security boundary

- `nose/capture.go:226-229` counts frames as canonical before delivery is known; `SendWithPayload` result is discarded. Enforce read = delivered + dropped + rejected.
- `nose/capture.go:207-216`, `:464-470`, `nose/talkers_live.go:201-204` detect timeouts by `strings.Contains(err, "timeout")`; use `pcap.NextErrorTimeout`.
- `nose/main.go:199-216` closes `stop` then returns immediately; `defer handle.Close()` at `nose/capture.go:177` may never run. Join the capture goroutine with bounded cancellation.
- Production capture does not use the capable decoder: `src/pipeline/packet_callback.zig:20-26` and `src/capture/npcap_capture.zig:542-582,693-700,735-742` handle only one VLAN tag; the 2-tag/8-hop decoder at `src/capture/packet_decoder.zig:118-165,170-308` is imported only by tests/fuzz (`src/all_tests.zig:21`, `src/tests/fuzz_main.zig:4`).
- `src/detection/correlation_engine.zig:25,270,399,447-454` declares `SLIDING_WINDOW_NS` but never uses it, uses wall-clock instead of `event.monotonic_ns`, and clears trackers only in `resetStats`; imported by `src/core/brain_engine.zig:17`, `src/policy/policy_engine.zig:19`, `src/forensic/forensics_engine.zig:22`. Production `src/detection/correlator.zig:89,119-129` is correct and remains the verdict authority.
- `src/capture/nose_pipe_reader.zig:4,14-16` says events go through `nose_contract.submitEvent()`, but `:539` calls `pushDecodedFrameDetailed`; `runtime_manifest.json:476` and `src/contract/runtime_spine.zig:100,146` mark the unused fabric production/golden-path. `nose_contract.zig:126-162` also uses v1-only `validate()` on wire frames.
- Blocking `ReadFile` has no `CancelIoEx`/`CancelSynchronousIo` (`nose_pipe_reader.zig:246-268,363-368`; `win32_pipe.zig:284-289`); supervisor joins have no deadline (`src/daemon.zig:109-134`). Bounded Windows shutdown is NOT_PROVEN.
- Policy signature verification only sets `g_policy_ir_verified` (`src/policy/policy_signing.zig:763-784`, `src/daemon.zig:551-575`); it never gates enforcement. Decide: enforce or describe strictly as observability.
- Replay guard is a process-local 1024-entry ring (`src/control/replay_guard.zig:11-21,77-80`); restart resets state and eviction can reuse nonces. Narrow E5 covers exact in-process replay only.
- `inFixedValues` is dereferenced without NULL guard in classify handlers (`aegis_wfp_callout.c:287-311,448-467,523-542`). Unregister retry loops at `:913-929,945-961,979-995,1025-1041` are unbounded.
- No production signing/catalog gate: `.sys` files are NotSigned; INFs reference catalogs never produced (`drivers/wfp_callout/aegis_wfp.inf:12`, `drivers/minifilter/aegis_minifilter.inf:11`); `scripts/wfp_sign.ps1:11-16,90-125` is a self-signed test path with fixed PFX password; `scripts/wfp_service.ps1:59-62` logs and continues.

### P2 — documentation and gate consistency

- `FLOW_MAP.json#flows[CONTROL-001].layers[3].file:232` points to test-only `src/policy/control_ipc.zig`; real authorization is `src/control/handler_registry.zig:184-209` and `src/platform/win32_pipe.zig:149-156`.
- `CONTRACT_MAP.json#contracts[CONTRACT-04].authorization.freshness/replay:187-188` says replay is NOT enforced on active v2, contradicted by S2 (`4bc8244`).
- `AUTHORITY_MAP.json#planes[PLANE-B].components[ZIG_RUNTIME].note:107` calls XDR flow open; contradicted by `SYSTEM_MAP.json:299`, `FLOW_MAP.json#flows[XDR-PROD-001].status` and `runtime_manifest.json:377`.
- `SYSTEM_MAP.json#components[go_nose].boundary:391` claims a loopback TCP fallback; `nose/pipe_writer.go:6,43` and `CONTRACT_MAP.json#contracts[CONTRACT-01].transport_notes` say there is none.
- Stale FN-1 wording: `docs/DETECTION_VALIDATION.md:42-44,107`, `docs/portfolio/DETECTION_CATALOG.md:91,95-98`, `docs/testing/RESULTS.md:73`, `docs/portfolio/SENSOR_COVERAGE.md:3,17,37`. Add narrow-E5 boundary notes; preserve the pinned 22/23 strings exactly.
- `docs/portfolio/ARCHITECTURE_EN.md:164-176,191-201` shows 6/6, 36.52 h, 674/674 and Windows E5 without a HISTORICAL-at-`a53eda8` label. `docs/portfolio/INTERVIEW_PREP.md:17,88` says nonce is unenforced (false since `4bc8244`). `docs/portfolio/DETECTION_MATRIX_CURRENT.md:1` names `aa3b7b0` but its table at `:29-52` still names `4dd3393`. `docs/portfolio/RESUME_PROJECT.md:17` says SHIPPED 6/6 while the current board is 5/6.
- `ci_coverage.json:110-113` says `drivers-wdk-build` is manual-only while `.github/workflows/ci.yml:324-361` runs it every push.
- `docs/gates/T20_100pct_audit.{json,md}` still stamp `8f01825`; regenerate only after the real final soak artifact. `docs/gates/PRODUCTION_READINESS.md:168-174` still points to `soak-24h-f4cde3c-final.json`.
- `EVIDENCE_INDEX.json:7` self-reports 48 unresolvable primary artifact pointers; pre-`aa3b7b0` E6/E7 entries at `:7926-7930,8315-8319,9910-9914,10099-10103` mostly lack explicit `historical`/`build_source` fields.

Tracked in issues #48 (maps/status), #49 (truth labels), #50 (kernel), #51 (network), #52 (release/evidence), #53 (testing maturity), #54 (post-soak rebaseline).

---

## 4. IMPROVE — works, but quality can be raised

- Add measured coverage (`pytest-cov` is installed at `requirements.txt:21`, but no `--cov` in `ci.yml` and no coverage artifact). Do not call it measured until the command and result are recorded.
- Replace the deterministic 1,000-case fuzz smoke (`docs/portfolio/CURRENT_HEAD_FUZZ_BENCH-20261126.md:19-28`; `aa3_fuzz.log` empty) with a real coverage-guided engine/corpus. Current status remains NOT_RUN.
- Prove reproducible build with two clean builds and byte comparison; `tools/release_engineering.py:250-260` records wall-clock date/host and historical B-15 (`.analysis/buildtest.md:221-261`) is not current proof.
- Synchronise `[CYTHON MATCH]` with log flush in `tests/brain/test_cython_prefilter.py:147-192` instead of accepting recurrence; no skip/xfail was used for the recorded flake.
- Range-check fields copied raw in `decodeFields` (`src/contract/canonical_event.zig:789-796`) as defence-in-depth; no current semantic escape was found.
- Add durable replay state or document the accepted post-restart/eviction threat boundary.
- Add periodic anchored checkpoints to the unkeyed CRC+SHA-256 forensic chain (`src/forensic/forensic_pipeline.zig:14-27,614-665`) if outbound tamper-evidence is claimed.
- Evaluate replacing hand-rolled SHA-256 (`rust-src/lib.rs:104-187`) with the already-present `ring` API without breaking ABI.
- Define a triage SLA before changing the advisory security scan (`ci.yml:246-263`, `exit-code: 0`) into a gate.
- Reduce global scratch/spinlock serialisation and `DbgPrint` under the DISPATCH-level lock (`aegis_wfp_callout.c:151-242,238`); avoid deprecated `ExAllocatePoolWithTag` (`aegis_wfp.c:740,750`) and document altitude `370000` (`drivers/minifilter/aegis_minifilter.inf:51-55`).
- Fix mojibake at `src/detection/detection_interface.zig:7` and `src/detection/signature_engine.zig:2,37,109`.
- Add malformed-frame counters (`packet.ErrorLayer()` is not checked in `nose/capture.go:217,310-395`) and a fixed-rate loss/latency benchmark; `OriginalLen` saturates at 0xFFFF (`nose/capture.go:281-288,298`) while completeness compares raw `ci.Length`.
- Establish Go IPv6 extension-header parity with Zig (`nose/capture.go:339-363`) and live-talker read-error counters (`nose/talkers_live.go:188-191,201-204`).
- Clarify that `src/detection/detection_engine.zig:211-256` built-ins are generic verdicts and `src/pipeline/event_processor.zig` is the sole `Rules.json` matcher, to avoid a “second engine” reading.

---

## 5. REMOVE / MOVE — duplicate or misplaced

- **MOVE** the tested decoder into the production capture path, or narrow `EVIDENCE_INDEX.json:11175-11215` wording to decoder-unit-only E2.
- **MOVE** `event_fabric`/`nose_contract` from `.production/.golden_path` (`src/contract/runtime_spine.zig:100,146`, `runtime_manifest.json:476`) to SUPPORT/TEST; they are imported only by harnesses (`src/all_tests.zig:104,208`).
- **MOVE** pre-`aa3b7b0` release/E6/E7 records out of `analysis/current-head` into a labelled historical namespace; do not delete them.
- **MOVE** root-dated `AEGIS_*_2026-09-*.md` and `AEGIS_DEVELOPMENT_HANDOFF_2026-09-18.md` into `docs/historical/`; they already carry HISTORICAL banners.
- **MOVE** ten transcoded raw text files under an explicit `transcoded/` path or add sidecars recording the original UTF-16LE digests; the transcode is already disclosed at `CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md:45` and originals remain outside the tree.
- **MOVE** stale duplicate `drivers/wfp_callout/quarantined/aegis_wfp_comm.c:1-13` out of the driver tree; consider a no-op ABI stub for unreachable `AegisWfpBlockFlow` (`aegis_wfp.c:1035-1218`).
- **REMOVE or QUALIFY** broad “IPv4/IPv6/VLAN/QinQ host capture support” claims; only narrow loopback IPv4/TCP is current-source host-proven.
- **REMOVE** legacy `tests/test_e2e.py:67-70,85-126,417-422` (silent skip for a bridge binary the canonical build never produces); retain `tests/e2e/test_t14_windows_golden_path.py`.
- **MERGE** case-only duplicate docs `LANGUAGE_OWNERSHIP.md`/`language-ownership.md` and `FAILURE_MODEL.md`/`failure-model.md`.
- **REPAIR** garbled `docs/AEGIS_Pro_Control_Center_Console.md:1-2`; declare `docs/architecture/ARCHITECTURE_CANONICAL.md` legacy/context-only consistently with its override.
- **DECLARE** `release/T20-final` (1,798 tracked files) as frozen records, not a second runtime; no build root references it.

---

## 6. NOT_PROVEN — must not be promoted

- `soak_24h` was OPEN at audit time. Accept only the real finalizer result with `verdict=PASS`, `elapsed_hours>=24`, `problems=[]`, `restore.verified=true` and consistent zero counter deltas. No `loss_budget=3500`.
- No E7: no HLK/E7 gate in `tools/final_audit.py`; soak PASS would not create E7 by itself.
- Full Windows E5 / kernel IDS qualification at `aa3b7b0`: NOT_PROVEN. Driver load/unload/cleanup at current source: NOT_PROVEN; `.sys` files NotSigned. Ed25519 record signature is not Authenticode.
- Full 23-rule host matrix: NOT_PROVEN. Current-source host proof is narrow R9006 E6 plus narrow R2003 E5; the remaining 22 rules were not re-measured.
- VLAN/QinQ and IPv6 extension-header host visibility, real-NIC Go capture shutdown, sustained burst conservation at `aa3b7b0`: NOT_PROVEN.
- Coverage-guided fuzz: NOT_RUN. Measured code coverage: NOT_RECORDED. Byte-for-byte reproducible build: NOT_PROVEN.
- Clean install/uninstall at `aa3b7b0` and federation TLS production wiring: NOT_PROVEN.
- Historical E3/E4/E5 at `7822f4c`, `43a8bcc` and earlier, and published `v1.1` / `466a226` / `a53eda8` evidence, remain HISTORICAL relative to `aa3b7b0`.

---

## 7. Can a senior reader answer the seven questions?

| Question | Status | Where |
|---|---|---|
| 1. How was the system designed? | Answered | `README.md:193-239`, `docs/portfolio/ARCHITECTURE_EN.md`, `docs/architecture/DIAGRAMS.md` |
| 2. What does each component do? | Answered | `SYSTEM_MAP.json`, `README.md:424-439`, `docs/portfolio/INTERVIEW_PREP.md:12-32` |
| 3. Why these technologies? | Answered | `docs/TECHNOLOGY_DECISIONS.md:8-53` |
| 4. What limitations are understood? | Answered | `README.md:65-77,680-702`, `docs/portfolio/OBSERVED_PERFORMANCE.md:66-88` |
| 5. What evidence proves the code runs? | Partial | Plenty of labelled evidence, but `release/release-status.json` is stale and some showcase pages blur HISTORICAL/current; see issues #48/#49 |
| 6. What remains unfixed? | Answered | `REMAINING-GAPS-DISPOSITION-AA3B7B0-20261126.md:34-63`, `EVIDENCE_INDEX.json#known_gaps`, issues #47-#54 |
| 7. Where to start further development? | Partial | `CURRENT-HEAD-CLOSEOUT-AA3B7B0-20261126.md:54-62` gives the exact next step, but there is no single developer onboarding index separate from the 5/6 board |

None is wholly unanswered; two are only partially answered because of stale status surfaces, not because proof is absent.

---

## 8. Issue index created from this audit

| Issue | Scope |
|---|---|
| [#47](https://github.com/Supertee003/NIDs_Windows/issues/47) | STOP-THE-LINE P0 findings — halt product coding until acknowledged |
| [#48](https://github.com/Supertee003/NIDs_Windows/issues/48) | Reconcile machine maps and status source-of-truth to `aa3b7b0` |
| [#49](https://github.com/Supertee003/NIDs_Windows/issues/49) | Fix stale current-facing truth labels without promoting evidence |
| [#50](https://github.com/Supertee003/NIDs_Windows/issues/50) | Kernel/WFP qualification — unload drain, client-port API, signing gate |
| [#51](https://github.com/Supertee003/NIDs_Windows/issues/51) | Network production parity — decoder wiring, counters, timeout, shutdown |
| [#52](https://github.com/Supertee003/NIDs_Windows/issues/52) | Release gate depth and evidence-index hygiene |
| [#53](https://github.com/Supertee003/NIDs_Windows/issues/53) | Testing maturity — coverage, fuzz, reproducible build, flake, advisory modules |
| [#54](https://github.com/Supertee003/NIDs_Windows/issues/54) | Post-soak rebaseline only after the real finalizer verdict |

---

## 9. Verification of this records-only artifact

Run locally after writing this report and before committing it; no host/soak action:

- `python tools/truth.py verify` → exit 0, `TRUTH_VALID — artifacts carry build source aa3b7b0 (ancestor of HEAD; source history and worktree clean)`.
- `python scripts/check_summary.py` → exit 0, `SUMMARY_VALID`.
- `python scripts/doc_checker.py` → exit 0, `0 FAIL, 0 WARN, 23 total`.
- `python tools/release_engineering.py --verify` → exit 0, `691 artifacts match their recorded digests (source_commit=aa3b7b0)`.
- `python -m pytest -q tests/docs/test_doc_truth_labels.py tests/docs/test_detection_truth_labels.py tests/release/test_known_gap_status.py tests/release/test_release_tooling.py` → `39 passed`.
- `python tools/final_audit.py --check` with the owner anchor → exit 0, still **5/6 PASS, `soak_24h` OPEN, NOT SHIPPABLE**. Generated `docs/gates/T20_100pct_audit.{json,md}` drift was reverted before commit; no gate verdict was changed.
- Encoding guard simulation: BOM `fffe/feff` in tracked files = 0. Tracked Zig files with CRLF = 0. The local worktree shows CRLF in `src/control/state_machine.zig` only because `core.autocrlf=true`; the tracked blob has `CR 0 / LF 987` and `.gitattributes` pins `eol=lf`, so the Linux CI guard is not affected.

---

## 10. Invariants preserved by this audit artifact

- Exact pinned strings untouched: `| Host-evaluable | 22/23 |`, `**22/23** — R2003 blocked by FN-1`, `host-evaluable coverage (R2003/FN-1)`.
- No evidence `status`, `level`, `result`, `status_basis` or gate verdict promoted.
- No guard, test, skip, xfail, waiver or threshold relaxed.
- No host, service, driver, binary, soak or finalizer action during the window.
- Records-only artifact: build source remains `aa3b7b0`; published release identity remains `v1.1` / `466a226` / `a53eda8`; signed record digest `94F65BCC…` and owner anchor unchanged; no private key in tree.
- A future soak PASS is still only a gate input. It does not confer E7, full Windows E5, kernel IDS qualification or signed-driver status.

---

## 11. Post-audit disposition (records-only, added after the audit)

**RECORDS TIP:** moves with records-only commits — read `git rev-parse HEAD` for the live value (this addendum was written at `1df890a`).  
**BUILD SOURCE:** still `aa3b7b0`.  
**BOARD:** still 5/6 PASS, `soak_24h` OPEN, NOT SHIPPABLE; the SYSTEM finalizer result was still absent when this was written.

This section records what was done in response to the audit without restating any gap as proof. No section above is rewritten; the findings remain the audit-time E1 truth.

| Audit item | Disposition now |
|---|---|
| §3 P0 #4 PEP ABI, #5 stale status source | Reconciled records-only in `5c69b6b`, `f9783fd`, `410aa6f`; `CONTRACT_MAP.json` 24-byte `PepResponse` is the contract, 16-byte statements are HISTORICAL. |
| §3 P0 #1–#3, #6 | Frozen under #47 STOP-THE-LINE. #6 is a gate change and needs owner authority; no `final_audit.py` logic was edited. |
| §3 P2 CONTROL-001 file, replay, XDR, TCP, `ci_coverage.json` | Reconciled in `512b3e7`, `5c69b6b`, `a77d1e0`; maps and evidence labels verified by `TRUTH_VALID` / `SUMMARY_VALID`. |
| §3 P2 stale FN-1 wording | Boundary notes already present in the four named docs; the three exact pinned strings are unchanged. |
| §3 P2 E6/E7 provenance and 48 pointers | `b08ca80` adds `build_source` / `historical` / `evidence_namespace` to all seven E6/E7 entries, ten transcode sidecars, and a logical historical namespace. All 48 unresolvable pointers were already explicitly marked; none became PASS. |
| §5 MOVE historical records / transcodes / root handoffs / signed-tree declaration | Done as declarations and sidecars in `b08ca80`, `dfc7822`; no file was physically moved where signed bytes or test pins reference the path. |
| §5 MERGE case-only duplicates | Declared canonical-vs-frozen in `1df890a`; physical merge deferred because `inventory.json` / `reference_map.json` classify all four paths. |
| §5 REPAIR console doc / canonical architecture | Byte check found valid UTF-8 with zero `?` in the console doc (console cp1252 artifact, not corruption); `ARCHITECTURE_CANONICAL.md` already declares HISTORICAL/CONTEXT-ONLY. |
| §5 MOVE decoder into production, event fabric classification, quarantined driver file; §5 REMOVE `tests/test_e2e.py` | Product/test changes frozen under #47; no skip, xfail or removal used. Interim dispositions are recorded on #50, #51 and #53. |
| §7 Q5 and Q7 partial | Addressed by the reconciled status surfaces and the single onboarding index `docs/START-HERE.md` (`410aa6f`) — an index, not new proof. |

Issue comments now exist on #47–#54. #50, #51 and #53 explicitly state that the source/kernel/network/testing items remain open and that no host claim was created. Nothing in this addendum promotes a level, result, verdict, signature, soak, driver-load or E7 claim.

---

## 12. Real finalizer outcome (records-only, added after the audit)

**BUILD SOURCE:** still `aa3b7b0`; records commits do not move it.  
**BOARD:** still 5/6 PASS, `soak_24h` OPEN, NOT SHIPPABLE.

Section 11 was written while the finalizer result was absent. It is not rewritten. The result now exists and was consumed:

- Run `225843` finalizer wrote `result.json` at `2026-11-27T22:59:23+07:00` with `verdict=FAIL`, `check_exit=3`, `elapsed_hours=24.0`, seven problems and `restore.verified=true`. The #54 acceptance rule is not met. Record: `SOAK-225843-FINALIZER-FAIL-AA3B7B0-20261127.md` with byte-exact `result.json` / `soak-final.json` / `finalize.log` and SHA-256 manifest.
- The previously voided `214622` finalizer was still alive and wrote its own real `FAIL` at `21:47:03`, restoring the pre-soak binaries over the live `225843` runtime. This is STOP-THE-LINE #55 and makes `225843` independently VOID for current-source soak evidence. Record: `SOAK-VOID-LATE-FINALIZER-GAPS-FIRST-AA3B7B0-20261127.md`.
- No PASS, E5 host proof, E6/E7 qualification, new signature, signed driver or driver-load claim follows. No gate, guard, test, verdict or threshold was changed. Product-source findings remain frozen pending owner authority.
- Owner prerequisites before a new window: remove stale finalizers/watchers, allow exactly one finalizer per window, then arm one clean 24 h window with no concurrent host work.
