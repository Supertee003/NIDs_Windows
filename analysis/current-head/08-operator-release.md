# AEGIS Windows-native NIDS/IPS — Operator, Packaging, and Release Security Review

**Review ID:** `08-operator-release`  
**Reviewed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Review date:** 2026-09-20  
**Reviewer posture:** senior production/security review; source and generated truth were read-only  
**Scope:** `mouth/`, `aegis_dashboard/`, `tools/`, `scripts/`, `installer/`, `installer.nsi`, `release/`, `configs/`, `docs/`, CI workflows, SBOM/signing/package scripts, operator tests, and the runtime/build references required to trace these paths.

## 1. Executive conclusion

AEGIS must remain **detection-only or explicitly degraded**. This review does **not** establish production readiness. The source contains useful safety-containment work, but the package, driver, control-plane authorization, UI evidence, and clean-Windows proof do not converge on a releaseable prevention path.

The most important result is a split between the intended contracts and the executable implementation:

```text
Zig daemon entrypoint
  -> daemon supervisor and worker readiness
  -> event_processor
  -> Rust PEP FFI
  -> dynamically loaded WFP user helper
  -> provider/driver attempt
  -> [no authoritative EnforcementReceipt in the active return ABI]
  -> forensic record / UI log parsing
```

The active source still has a correct high-level invariant in several places: Zig owns runtime orchestration and Rust PEP is intended to be the sole privileged enforcement authority. However, the final host-effect proof is absent. `PepResponse` contains only decision, reason, quota, and signer fields; it does not contain the required provider result, filter identity, host-effect confirmation, receipt version, or forensic linkage. `event_processor.zig` records the numeric PEP decision directly, and `ActionDispatcher` logs that WFP execution occurred. That is an intent/authorization record, not a proven host effect.

The UI is only partially receipt-gated. Mouth’s mitigation feed requires `ENFORCED` plus `host_effect_confirmed=true`, which is a useful local guard, but it accepts those two values from an untrusted JSON log and does not require the remaining receipt identity fields. Mouth’s DEFCON `blocked_count` is still computed from text containing `"Block"`/`"Drop"`. The egui dashboard likewise increments `total_blocked` from `entry.event == BLOCK` or `IP_BLOCKED`, without a validated receipt. Therefore an event or policy record can still influence a blocked counter and DEFCON even when no host block occurred.

The Windows security boundary is not proven. The control pipe is created with `lpSecurityDescriptor = null` in `src/platform/win32_pipe.zig:207-227`, despite the client/documentation describing it as ACL-protected. Its role routine calls `OpenProcessToken(GetCurrentProcess(), ...)` rather than impersonating the named-pipe client (`src/platform/win32_pipe.zig:171-195`). A caller can therefore reach a service-owned pipe whose authorization decision is based on the daemon token, not the caller token. The WFP device is created without a restrictive SDDL/security descriptor (`drivers/wfp_callout/aegis_wfp.c:58-70`), and mutating IOCTLs have no boundary caller validation beyond access flags (`drivers/wfp_callout/aegis_wfp.h:22-30`, `aegis_wfp.c:150-177`).

The release graph is not a single, reproducible graph. `tools/installer.py` does not accept the arguments used by CI (`--package --output`), hard-codes version/commit values, and emits file directives for paths that do not match the canonical `src/`, `configs/`, `zig-out/bin/`, and `target/release/` layout. `tools/release_engineering.py` excludes build outputs and the canonical `src/`, `configs/`, `drivers/`, `mouth/`, `aegis_dashboard/`, and `nose/` trees from its source artifact collection. `scripts/verify_release.ps1`, `installer.nsi`, `installer/aegis.nsi`, `scripts/package_release.ps1`, and `scripts/release_package.ps1` describe incompatible package layouts and versions. None proves Authenticode, driver catalog trust, ACLs, device identity, clean uninstall, or rollback of WFP state.

The repository itself confirms this conclusion. `python tools/truth.py verify --json` reports stale `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, and `AI_CONTEXT.md`; `build_manifest.json` is stamped `0a7418b`, not the reviewed HEAD. Only `runtime_manifest.json` passed its HEAD check. The stale artifacts are not used here as proof. The Handoff and README correctly state that clean Windows/VMware host evidence is still required.

## 2. Scope and method

### 2.1 In-scope questions

This review followed the requested boundaries:

1. Which operator/UI path is active, and whether it is receipt-driven.
2. Whether scripts remain thin clients or form a second supervisor.
3. Which source defines runtime status, action status, degraded state, and stale state.
4. Whether privilege boundaries are enforced by the OS at the control pipe, WFP device, service, and driver boundary.
5. Whether package dependencies, secure loading, SBOM, signing, and manifest hashes describe the artifacts that the active build actually produces.
6. Whether clean install, uninstall, upgrade, rollback, driver/service/device identity, and host effect are proven.
7. Which tests are unit/static/source-presence tests and which would constitute Windows/elevated/VMware proof.

### 2.2 Evidence priority

The review used this order: current source and symbols; `build.zig`, CMake, Cargo, NSIS, PowerShell, and CI build references; executable call paths visible in source; operator tests; current-head checks; then documents. File presence, generated manifests, comments, and `*.dll`/`*.sys` names were not treated as proof of loadability or execution.

The reviewed source was not modified. The requested report is the only new artifact written. Windows execution, elevation, WDK/SDK availability, driver loading, VMware isolation, clean install, and host-effect commands are **UNVERIFIED** in this Linux sandbox.

### 2.3 Current-head and truth checks

`git rev-parse HEAD` returned the requested `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`. A bounded `git status` attempt did not complete because of repository lock/timeout; no status result is used as evidence. `tools/truth.py verify --json` returned `valid: false` because the artifacts listed above are stale. `tools/release_engineering.py --verify` was started read-only but did not return within the bounded inspection window; it is not treated as a pass. No generated truth was refreshed.

## 3. Path classification

| Classification | Files/paths | Review result |
|---|---|---|
| **Active production runtime** | `build.zig`, `src/main.zig`, `src/daemon.zig`, `src/pipeline/event_processor.zig`, `src/policy/pep_bindings.zig`, `rust-src/lib.rs`, `src/platform/win32_pipe.zig` | This is the strongest source-level runtime path. It remains unproven on Windows and lacks a final receipt ABI. |
| **Active operator/control support** | `tools/aegisctl.py`, `tools/aegisctl/`, `scripts/aegis.ps1`, `mouth/windows_sec_monitor.rs`, `aegis_dashboard/src/main.rs` | Intended to be thin/control clients, but Mouth/dashboard still derive blocked counters from logs and status fallbacks. |
| **Canonical/support acquisition and native boundary** | `nose/`, `src/windows/*.c`, `drivers/wfp_callout/` | Go Nose is declared canonical ingress. C helper is linked by the Zig graph. Kernel driver is not part of the default CMake graph and has a separate, divergent lifecycle. |
| **Release/tooling path** | `tools/release_engineering.py`, `tools/installer.py`, `scripts/package_release.ps1`, `scripts/release_package.ps1`, `scripts/install_aegis.ps1`, `tools/upgrade_rollback.py`, `tools/release_candidate.py` | These paths do not form one compatible artifact graph. Several are source/package assemblers rather than release gates. |
| **Legacy/unsafe compatibility path** | `scripts/run_aegis.bat`, `scripts/stop_aegis.bat`, `scripts/aegis_status.py`, root `installer.nsi`, older `scripts/verify_release.ps1`, `docs/WFP_IOCTL_STATUS.md` | Explicitly deprecated or stale in comments, but runnable. They can start/kill processes, infer health, or describe a different package. They must be removed from operator distribution or hard-fail with a migration message. |

The presence of `installer/aegis.nsi`, `release/aegis-nids-windows-6.0.0-20260916_223148/`, a `*.sys`, or a DLL is not evidence that the corresponding graph was built from this HEAD, signed, loaded, or exercised.

## 4. Active call graph and authority flow

### 4.1 Runtime and lifecycle

The strongest source-level active graph is:

```text
src/main.zig:20-35
  -> platform/win32_service.mainEntry
  -> src/daemon.zig:85 runDaemon
       -> runtime state and security self-check
       -> capability probe
       -> Rules.json + policies.json load
       -> PepEnforcer.init
       -> bridge_init.initAll
       -> RuntimeSupervisor worker handles
            -> legacy sensor thread
            -> event_processor.pipelineLoop
            -> Go Nose pipe reader
            -> ETW thread
            -> FIM thread
            -> Registry thread
       -> win32_pipe.serveWindowsPipe
       -> supervisor shutdown/join in reverse order
```

`src/daemon.zig:51-82` is a meaningful improvement: the Zig daemon owns worker handles, stop signalling, and reverse-order joins. `src/daemon.zig:363-420` resets readiness flags and marks worker failures rather than treating thread creation as readiness. This is the correct runtime-owner direction.

The path is not yet a complete production proof. `src/daemon.zig:179-297` loads `configs/policies.json` directly as unsigned JSON, and `src/daemon.zig:308-326` treats successful PEP DLL initialization as enforcement mode. Provider readiness and host-effect capability are not returned as a receipt from the enforcement call. The runtime may correctly become degraded when dependencies are absent, but the acceptance condition for prevention is still missing.

### 4.2 Detection, policy, PEP, and action dispatch

The active data-plane path is:

```text
src/pipeline/event_processor.zig:32 processEvent
  -> detection and threat tracking
  -> PolicySet.evaluate
  -> PepEnforcer.enforce (src/policy/pep_bindings.zig:79-105)
  -> aegis_pep_enforce (rust-src/lib.rs:340-426)
  -> wfp_adapter::Adapter::load/block on Windows (rust-src/lib.rs:205-285, 404-420)
  -> PepDecision enum returned
  -> ActionDispatcher.dispatch (event_processor.zig:170-173)
  -> ForensicRing.append with numeric decision (event_processor.zig:198-200)
```

The intended single authority is visible in `action_dispatcher.zig:1-10` and `:56-92`: the dispatcher does not call WFP directly and says that privileged enforcement goes through Rust PEP. `pep_bindings.zig:80-104` also fails closed to `.escalate` when PEP is unavailable or FFI returns an error.

The actual result is not yet an `EnforcementReceipt`. `PepResponse` in `rust-src/lib.rs:178-184` has `decision`, `reason`, `quota_remaining`, and `signed_by`; no `filter_id`, `host_effect_confirmed`, `provider`, `event_id`, `trace_id`, `audit_id`, or receipt version is returned. `rust-src/lib.rs:353-356` initializes `signed_by` to zero, and `:422-426` returns the response with no host-effect observation. `action_dispatcher.zig:69-72` logs “WFP enforcement executed by Rust PEP” after the decision, while `event_processor.zig:198-200` stores the decision directly. This cannot prove `BLOCKED_CONFIRMED`.

The separate receipt contract is stronger than the active path. `src/policy/enforcement_receipt.zig:29-43` correctly requires `status == enforced` plus `host_effect_confirmed`, rejects host-effect confirmation for non-enforced states, and requires request/event identity and version for forensic linkage. `forensic_pipeline.zig:123-147` has `appendReceipt` with event/policy/linkage checks. The active event processor does not call `appendReceipt`. The existence of the stronger contract therefore documents a missing integration, not a production proof.

### 4.3 WFP/provider graph

There are at least three materially different WFP implementations:

1. **Canonical CMake user helper:** `src/windows/aegis_wfp.c` and `src/windows/wfp_ioctl.c`, built as `aegis_wfp_user.dll` by `CMakeLists.txt:22-36`. The Rust loader searches for this DLL and expects `aegis_wfp_ioctl_open`, `aegis_wfp_ioctl_block_ip`, and `aegis_wfp_ioctl_unblock_ip` (`rust-src/lib.rs:228-272`). The helper uses `CreateFileW("\\.\AegisWfpDevice", GENERIC_READ|GENERIC_WRITE, ...)` and sends mutating IOCTLs (`src/windows/wfp_ioctl.c:69-103`).
2. **Kernel driver source:** `drivers/wfp_callout/aegis_wfp.c`, `aegis_wfp_callout.c`, `aegis_wfp_comm.c`, and header/INF. It creates `\Device\AegisWfpDevice` and `\DosDevices\AegisWfpDevice` (`aegis_wfp.c:58-70`), registers an inbound transport callout, and its classify callback is explicitly fail-open (`aegis_wfp_callout.c:8-9`, `:111-114`).
3. **Direct user-mode WFP helper API:** `src/windows/aegis_wfp.c:32-165` opens a WFP engine and adds a block filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4`. This path uses a separate provider/sublayer/filter-key model from the driver source.

`CMakeLists.txt:64-69` leaves `BUILD_KERNEL_DRIVER` off by default and points to `kernel/wfp_callout`, while the reviewed driver lives under `drivers/wfp_callout`. This means the default CMake graph does not prove that the `.sys` used by the package is built. The driver and user helper also do not share one proven filter ownership/rollback model.

The kernel driver source itself has no restrictive device security descriptor and no caller-token validation. `aegis_wfp.h:23-26` puts `FILE_READ_DATA`/`FILE_WRITE_DATA` in the IOCTL codes, but `aegis_wfp.c:132-147` accepts create/close unconditionally and `:150-177` dispatches mutating IOCTLs without an explicit identity or authorization check. In `aegis_wfp.c:261-270`, the block filter construction does not set `filter.layerKey`, unlike the user helper and `aegis_wfp_comm.c`; whether that compiles and installs as intended is **UNVERIFIED** and must not be inferred from the source or a `.sys` filename.

## 5. File-level observations

### 5.1 Mouth: partial receipt guard, but blocked/DEFCON truth still event-derived

`mouth/windows_sec_monitor.rs` contains useful tests at `:912-947`:

- an `AUTHORIZED` block with `host_effect_confirmed=false` is not added to the mitigation feed;
- an `ENFORCED` block with `host_effect_confirmed=true` is rendered as `BLOCKED IP`;
- `PENDING` remains pending.

The implementation at `:396-428` and `:497-543` still has three production weaknesses:

- It parses raw log fields with a hand-written string extractor. It does not authenticate the record or validate the full `EnforcementReceipt` contract.
- It accepts only `receipt_status/status == ENFORCED` and `host_effect_confirmed == true`; it does not require nonzero `filter_id`, request/event/trace/audit identifiers, policy identity, or supported receipt version.
- It accepts `Terminate`/`Kill` as a mitigation without an equivalent host-effect receipt, despite the project invariant that operator claims require finalized evidence.

More importantly, `TailReader::read_new_entries` at `:607-617` increments `blocked_count` whenever a line contains `"Drop"`, `"Block"`, or `"BLOCK"`, independently of receipt status. `calculate_defcon` at `:341-362` then uses that count for DEFCON 1/2. Thus the mitigation list is stricter than the DEFCON counter. A policy intent can still raise DEFCON as if a host block occurred.

The deployment documentation is not a reliable active package description. `mouth/README_DEPLOY.txt:15-36` asks an operator to place source files in `D:\NIds_Windows\mouth`, compile with `rustc`, and run against `logs/anomalous.json`. `scripts/run_aegis.bat` instead starts `dist\windows_sec_monitor.exe` against the same legacy log while the current dashboard reads `logs/aegis_core.ndjson`. The source tree therefore has incompatible Mouth/log/package paths.

### 5.2 egui dashboard: control health is sourced correctly, enforcement counters are not

`aegis_dashboard/src/main.rs:115-129` queries `python tools/aegisctl.py snapshot` and records `control_available`. The health banner at `:215-239` does not claim green when control is unavailable; it shows yellow and says “Control Center unavailable”. This is directionally correct.

However, `refresh_data` at `:132-176` reads the event log directly and increments `total_blocked` at `:145-150` whenever `event` is `BLOCK` or `IP_BLOCKED`. The blocked card at `:271-283` and `:333-348` calls this “Blocked”/“policy outcomes”, but the dashboard does not display a receipt status, filter ID, provider, or host-effect confirmation for the count. A stale event file can therefore display blocked outcomes while current control is unavailable. This is incompatible with the required rule that a UI must be receipt-driven and must not collapse policy outcome into host effect.

The dashboard does label the table as evidence and tells the operator to use Control Center for authoritative health (`:328-332`), but that explanatory text does not neutralize the blocked card or DEFCON computation. The correct safe behavior is `BLOCKED_CONFIRMED` only from validated receipts, otherwise `BLOCK_REQUESTED`, `PENDING`, `UNAVAILABLE`, `FAILED`, or `NOT MEASURED`.

### 5.3 Control plane and status/stale behavior

The good path is explicit in `tools/aegisctl/client.py:1-10` and `:32-82`: named pipe is canonical, TCP is explicit, and automatic pipe-to-TCP fallback is rejected. `tools/aegisctl.py:122-195` keeps normal start/stop requests on the daemon control plane and reports `STOPPING` rather than claiming that workers already joined.

The high-risk implementation is `src/platform/win32_pipe.zig`:

- `serveWindowsPipe` passes `lpSecurityDescriptor = null` at `:207-227`, while the source comment admits the tested SDDL/ACL helper is not in use (`:207-211`).
- `getLocalRole` uses `GetCurrentProcess()` and `OpenProcessToken` at `:171-195`. It does not call `ImpersonateNamedPipeClient`, open the impersonation token, or bind capability to the connecting caller. The role is therefore the daemon’s role, not the operator’s role.
- The client module’s “SYSTEM-only” description (`tools/aegisctl/client.py:40-43`) is not source-proven by the server implementation.

`tools/aegisctl/api/control_api.py:532-589` is better about unavailable state: if the daemon query fails it returns `state=DEGRADED`, `degraded=true`, `runtime_available=false`, and says process data is diagnostic only. That is the correct stale-state direction. `get_all_status` at `:207-219` still falls back to PID/process state for diagnostics, which is acceptable only if every consumer preserves that distinction.

The legacy path does not preserve it. `scripts/aegis_status.py:113-176` uses UDP/process/log activity and reports `ACTIVE` when at least three of five checks are positive; it can treat log activity as core liveness. It exits successfully for `DEGRADED` (`:179-207`). This is not authoritative health and should not be distributed as an operator status command.

`tools/aegisctl.py:247-279` also returns exit code 0 for normal health output even when `degraded=true`; only `--strict` changes the exit code. The documented operator contract in `docs/AEGIS_Operator_UX_Specification.md:46-54` requires nonzero for degraded runtime. The default machine-facing health behavior therefore does not enforce the stated gate.

### 5.4 Scripts must not be a second supervisor

`run_aegis.bat` is marked deprecated at `:1-3`, but it remains a runnable supervisor. It cleans up processes (`:118-144`), builds components on demand (`:298-443`), starts bridge, Zig core, Python Brain, Go Nose, and Mouth in separate windows (`:503-625`), writes PID files (`:631-637`), runs process health checks (`:640-711`), and launches another dashboard (`:738-753`). This is exactly a second supervisor and a second start graph. It can start a different set of binaries than `src/daemon.zig` and can produce false readiness.

`stop_aegis.bat` has a similarly unsafe fallback. It globally runs `taskkill /IM` for names such as `aegis_nids.exe`, `windows_sec_monitor.exe`, and `aegis_bridge.exe` (`:10-24`) and deletes PID files. It does not prove process identity, installation root, service ownership, stop/join completion, or filter cleanup. `scripts/aegis.ps1` correctly delegates normal status/start/stop to `aegisctl` at `:42-51`, but its `tui`/`console`/`web` commands can still launch parallel presentation paths. The legacy batch files need removal or a hard refusal, not only a deprecation comment.

### 5.5 Privilege boundaries and secure loading

The Rust PEP performs a capability bit check at `rust-src/lib.rs:361-370`, but the caller-provided `PepContext` contains `caller_pid` and `caller_capability_mask` (`:156-162`) and Rust trusts those fields. The daemon sets `state.g_runtime_capability_mask = 0x01` in `src/daemon.zig:121-125`; this is not an OS-bound token/capability attestation. It is a value in the request ABI. A production design needs a trusted broker identity, authenticated IPC, or an OS-derived capability handle that the caller cannot select.

The Rust dynamic loader at `rust-src/lib.rs:228-267` uses `LoadLibraryW` on relative candidates `aegis_wfp_user.dll` and `build\\Release\\aegis_wfp_user.dll`. It does not use a trusted absolute install path, `LoadLibraryEx` restricted search flags, Authenticode verification, or a pinned digest. A working directory change can select a different DLL. The adapter does not verify an ABI version or module identity after loading.

Policy signature verification exists as a callable Rust function (`rust-src/lib.rs:21-54`) and has real Ed25519 verification tests (`:731-788`). It is not called from the active `src/daemon.zig:179-297` policy JSON load. `TrustStore.generate` at `src/policy/trust_store.zig:77-108` calls its non-AES key material a placeholder (`:95-104`) and comments that real CNG/OpenSSL is future work. Policy signature verification and trust-store presence therefore cannot be counted as runtime enforcement proof.

### 5.6 Package and installer graph

`tools/installer.py:37-103` emits a hard-coded NSIS template with version `5.0.0`, commit `2c7cb30`, root-level `aegis_nids.exe`, `aegis_pep.dll`, and `aegis_wfp_user.dll`, plus `config\\Rules.json`. The active build installs the Zig binary under `zig-out/bin`, uses `configs/Rules.json`, and builds the PEP under `target/release`. The manifest component loop only adds comments (`:106-117`); it does not generate validated, manifest-derived file directives.

Its CLI accepts only `--generate` and `--nsi` (`:120-139`). CI calls `python tools/installer.py --package --output aegis_setup.exe` in `.github/workflows/ci.yml:222-243`. That command is not supported by the script and is a deterministic packaging failure, not a Windows-runtime caveat.

The root `installer.nsi` is a legacy source bundle with version `1.0.0` and paths such as `nids_main.zig`, `windows_brain.py`, and root `Rules.json` (`:5-74`). It deletes broad file classes during uninstall and kills `python.exe` (`:111-145`). It is unsafe to present as the current installer.

`installer/aegis.nsi` is a separate 5.0.0 path with commit `0c74e3f` (`:12-24`). It installs a service and user DLLs (`:40-70`) but does not include the kernel driver, does not verify hashes or Authenticode, does not set installation ACLs, and does not prove WFP provider/device identity. Its uninstall deletes the service and a firewall rule but does not remove driver/provider filters (`:105-120`).

`scripts/package_release.ps1` builds a 6.0.0 bundle and expects `zig-out/bin`, `target/release`, `build/Release`, `configs`, and `drivers/wfp_callout` (`:21-31`). `release/aegis-nids-windows-6.0.0-20260916_223148/manifest.json` contains those same 6.0.0 artifacts, but its provenance is not tied to the reviewed HEAD and its README only parses JSON; it does not verify signatures or perform a clean install. `scripts/release_package.ps1` is an older 2.x-style layout and expects `src/release_info.zig`, `src/nids_main.zig`, and other historical source names (`:24-31`, `:75-98`). These are divergent support/legacy paths, not one production package graph.

### 5.7 SBOM and signing

`tools/release_engineering.py` is not a complete binary release gate:

- `collect_artifacts` scans `core`, `shield`, `scripts`, `tools`, `config`, `installer`, `go`, `brain`, `ts_policy`, and `bridge` (`:70-112`). It omits canonical `src`, `configs`, `drivers`, `mouth`, `aegis_dashboard`, and `nose` paths. It excludes `target`, `zig-out`, and `dist` (`:29-31`), so its package archive at `:388-402` is predominantly source/tooling material and may omit runtime outputs.
- `generate_sbom` assigns `SPDXID` from Python’s process-randomized `hash()` (`:249-265`). The same input can receive a different SPDX identifier across processes. It labels source files as packages, assigns a single release version and MIT license without dependency/license evidence, and uses `NOASSERTION` for download location. This is not sufficient binary/dependency provenance.
- The package operation does not sign the archive or binaries. It only writes `sbom.spdx.json` if explicitly requested and includes it if present.

`wfp_sign.ps1` explicitly identifies itself as a development path (`:1-5`), creates a self-signed certificate, uses a hard-coded default PFX password `aegis-test-2026` (`:11-16`), and optionally enables test signing (`:128-141`). `install_drivers.bat` enables test signing and accepts a missing `signtool` with a warning (`:100-123`, `:153-188`). This cannot be a production signing proof. `scripts/verify_release.ps1` makes its checksum file optional (`:42-55`), checks an old package layout (`:65-88`), and never verifies Authenticode, catalog trust, driver load, service identity, WFP filters, or uninstall cleanup.

`tools/release_candidate.py` is also not signing evidence. It writes a summary `signatures.json` containing policy and immutable-digest claims (`:124-129`) but does not create or verify a signature. Its `BINARIES` list contains both `aegis-pep.dll` and `aegis_pep.dll` (`:40-45`), and its known-limitations text references `core/wfp_production.zig` and `shield/src/pep.rs`, which are not the active single-authority path established above (`:150-163`).

### 5.8 Install, service, uninstall, upgrade, and rollback

`scripts/install_aegis.ps1` verifies per-file SHA-256 from `manifest.json` (`:28-37`) and creates a backup before copying (`:39-43`). This is useful as a bundle-integrity check, but it does not verify Authenticode, catalog signatures, ACLs, runtime dependencies, or the installed binary’s current-head identity. It creates or queries only `AegisWfp` (`:45-52`); it does not install/register the canonical Zig service, start the runtime, open `\\.\\AegisWfpDevice`, or prove the device’s identity. Rollback moves the backup directory back (`:19-25`) without verifying every expected postcondition, driver/filter cleanup, service generation, or receipt state.

`scripts/wfp_service.ps1` requires Administrator and checks a file signature status, but its default driver path is `build\\x64\\wfp\\aegis_wfp.sys` (`:52-61`), while `install_drivers.bat` uses `build\\drivers\\wfp\\aegis_wfp.sys` (`:153-158`) and `package_release.ps1` uses `drivers\\wfp_callout\\aegis_wfp.sys`. It creates a demand-start service by `sc.exe` (`:71-83`) but does not use the INF/catalog installation path, prove the device link, or verify WFP filter ownership after start.

`tools/upgrade_rollback.py` snapshots data paths only (`:44-53`). It does not stop the runtime or driver before copying, does not atomically swap all files, does not verify hashes after restore, and does not remove/recreate provider filters. It reports `ok` when at least one path restored and no copy error occurred (`:163-175`); that is not a clean system rollback proof.

The active lifecycle proof script is stronger at process level. `scripts/run_lifecycle_recovery_proof.ps1:53-175` checks old PID exit, control-pipe release, new PID generation, worker readiness, PEP readiness, and forensic verification. It explicitly allows the in-memory forensic count to reset after restart (`:153-170`). It is an observe-only lifecycle proof, not a driver/provider rollback proof, and it requires a Windows runtime/elevated environment; therefore execution is **UNVERIFIED** here.

### 5.9 CI and operator tests

`.github/workflows/ci.yml` runs most builds on `windows-latest`, but these are build/unit gates, not clean-host gates. The `security-scan` job uses Trivy with `exit-code: 0` (`:133-144`), so HIGH/CRITICAL findings cannot fail CI. The package job calls the unsupported installer arguments and has no sign/verify/clean-install/rollback stage (`:222-243`). There is no elevated driver install job, no real WFP observation, no standard-user boundary test, and no VMware isolated host job.

`.github/workflows/host-regression.yml` runs on `ubuntu-latest` and explicitly describes itself as logic-layer/runtime-contract testing (`:1-7`, `:136-154`). It is not Windows host proof. `ci_coverage.json` marks Shield as support/non-gating (`:74-80`) while `ci.yml:205-207` includes `shield-build` in the final gate’s `needs`; the classification and workflow dependency semantics are inconsistent.

The operator tests under `scripts/tests/` are mostly source-presence, formula, process-scan, and local-library tests. `aegis_mouth_test.py:109-170` checks strings and optional `sec_monitor.dll` loading; it does not validate an EnforcementReceipt. `aegis_nose_test.py:93-155` checks source architecture and JSON strings; it does not prove a Windows Npcap-to-pipe-to-Zig event. `tests/test_golden_path.py:54-201` explicitly reduces several “golden path” scenarios to file existence or references to Zig unit tests; `scenario_config_validation` writes a temporary test file (`:129-156`), so it is not a read-only release proof. The suite cannot establish that a real block reached WFP or was observed on the host.

## 6. Contract and authority impact

### 6.1 Receipt-driven UI contract

The receipt contract requires at least:

```text
status == ENFORCED
host_effect_confirmed == true
filter_id != 0
request_id != 0
 event_id != 0
trace_id != 0
audit_id != 0
receipt_version == supported version
```

`src/policy/enforcement_receipt.zig` encodes most of this. The active PEP ABI and UI do not carry or validate it end-to-end. A log line can supply `status=ENFORCED` and `host_effect_confirmed=true` without a provider signature, filter identity, or event linkage. Mouth’s local tests prove only its current two-field parser behavior. Dashboard blocked counters do not use even those two fields.

**Authority impact:** UI must not render `BLOCKED`, increment a blocked host-effect counter, or raise a block-based DEFCON from a policy/event line. Until integration is fixed, display the state as `BLOCK_REQUESTED`, `PENDING`, `UNAVAILABLE`, `FAILED`, or `UNVERIFIED`.

### 6.2 Runtime owner and scripts

The Zig supervisor direction is compatible with the invariant. `aegisctl` normal start/stop requests are also compatible. The deprecated batch path is not compatible because it starts independent workers, compiles on demand, kills by image name, writes PID files, and starts its own dashboards. The fallback status script is not compatible with authoritative health because it promotes process/log/UDP evidence to an `ACTIVE` conclusion.

**Authority impact:** ship one start/stop/recovery owner. Convert legacy scripts to hard-fail wrappers that state the canonical command, or remove them from the package. Never allow an operator to run both `run_aegis.bat` and the daemon/service path.

### 6.3 Rust PEP as sole enforcement authority

The source-level dispatcher and Rust PEP call direction respect the desired invariant better than older documentation suggests. `action_dispatcher.zig` contains no direct WFP call. However, the repository still contains multiple WFP implementations and the active PEP ABI does not produce the proof needed to distinguish authorization from host effect. The kernel driver and user helper also have separate filter lifecycle models.

**Authority impact:** keep Rust PEP as the only authorization/enforcement broker; isolate the C user helper and kernel driver behind one versioned provider ABI; remove or quarantine every second PEP/WFP implementation; make all other outcomes non-enforcing unless a validated receipt is returned.

### 6.4 Privilege boundary

The control pipe’s default security descriptor, daemon-token role calculation, caller-supplied PEP capability mask, and unauthenticated WFP device create path together prevent a production privilege claim. A named pipe ACL is not enough if the server never impersonates the client. An IOCTL access mask is not enough if any client who opens the device can issue it. A `caller_capability_mask` in a caller-controlled FFI structure is not an OS-bound identity.

**Authority impact:** use a tested SDDL on the control pipe and device. Impersonate the client for every privileged command. Bind the control request to the client PID/token and an allowlisted service identity. Validate capability server-side. Re-test as Administrator, standard user, low-integrity process, and a separate local account.

### 6.5 Package and release authority

No current manifest is a trustworthy single source for the complete runtime. The current-head truth gate is invalid and package scripts describe incompatible versions/layouts. SBOM and “signatures” files are descriptive artifacts, not cryptographic proof. A successful `makensis` or ZIP creation would not prove the package can install, load, enforce, or uninstall cleanly.

**Authority impact:** make one release manifest generated from the actual build outputs, signed or attested as a whole, and consumed by exactly one installer. The installer must reject missing/extra/unexpected files, unsigned binaries, driver/catalog mismatch, and source-commit mismatch.

## 7. Concrete defects and severity

Severity meanings: **P0 stop-the-line** means prevention must not be enabled; **P1 critical** means release/privilege/host-effect proof is invalid; **P2 high** means a materially misleading or incomplete operator/release behavior; **P3 medium** means tooling/documentation drift that still blocks reproducibility.

| ID | Severity | Defect | Evidence | Impact |
|---|---|---|---|---|
| OR-001 | **P0** | No end-to-end authoritative EnforcementReceipt | `rust-src/lib.rs:178-184, :404-426`; `event_processor.zig:198-200`; `action_dispatcher.zig:69-72` | Authorization is recorded as if WFP execution occurred; no proven host effect, filter identity, or forensic linkage. |
| OR-002 | **P0** | Control pipe uses default security descriptor and daemon token instead of caller token | `src/platform/win32_pipe.zig:171-195, :207-227` | Standard/untrusted clients may reach a privileged local endpoint; claimed ACL boundary is not proven. |
| OR-003 | **P0** | WFP device has no restrictive SDDL/caller authorization | `drivers/wfp_callout/aegis_wfp.c:58-70, :132-177`; `aegis_wfp.h:22-30` | Any process able to open the device may be able to issue mutating IOCTLs; driver privilege boundary is not proven. |
| OR-004 | **P0** | PEP capability/PID are request fields, not OS-bound identity | `rust-src/lib.rs:156-162, :361-370`; `src/daemon.zig:121-125` | A forged or confused caller context can be treated as authorized. |
| OR-005 | **P1** | Relative DLL loading without signature/hash/absolute-path validation | `rust-src/lib.rs:228-267` | DLL search hijacking and wrong-provider loading remain possible; presence of a DLL is not secure loading. |
| OR-006 | **P1** | Runtime loads unsigned policy JSON; Ed25519 helper is not wired into policy load | `src/daemon.zig:179-297`; `rust-src/lib.rs:21-54`; `trust_store.zig:95-104` | Policy authenticity and trust-store claims are not mandatory runtime gates. |
| OR-007 | **P1** | Mouth blocked/DEFCON count is substring/event-derived | `mouth/windows_sec_monitor.rs:607-617`; `:341-362` | Policy intent can raise DEFCON as a host block without a valid receipt. |
| OR-008 | **P1** | Dashboard blocked card counts event names, not receipts | `aegis_dashboard/src/main.rs:132-176, :271-283, :333-348` | Stale/evidence-only logs can present blocked host outcomes while Control Center is unavailable. |
| OR-009 | **P1** | CI package invocation is incompatible with installer CLI | `.github/workflows/ci.yml:222-243`; `tools/installer.py:120-139` | Release packaging fails or cannot be treated as a tested artifact. |
| OR-010 | **P1** | Default CMake graph does not build the kernel driver and uses a different path | `CMakeLists.txt:64-69`; actual driver under `drivers/wfp_callout/` | The package’s `.sys` is not proven to originate from the build graph. |
| OR-011 | **P1** | Driver/service/package paths diverge | `wfp_service.ps1:52-61`; `install_drivers.bat:153-158`; `package_release.ps1:21-31` | Clean install is non-reproducible and may sign/install a different file than the package contains. |
| OR-012 | **P1** | Signing path is test/self-signed and not a production gate | `wfp_sign.ps1:1-5, :11-16, :128-141`; `install_drivers.bat:100-123, :163-166` | Driver acceptance can depend on test mode; no EV/WHQL/catalog proof exists. |
| OR-013 | **P1** | Uninstall does not prove WFP/filter/device cleanup | `installer/aegis.nsi:105-120`; `install_aegis.ps1:19-25`; `wfp_service.ps1:106-121` | Orphan services, devices, provider filters, or firewall state may survive uninstall/rollback. |
| OR-014 | **P1** | Legacy batch path is a second supervisor and globally kills processes | `run_aegis.bat:118-144, :503-637`; `stop_aegis.bat:10-24` | Two runtime owners and wrong-process termination can invalidate status and recovery. |
| OR-015 | **P2** | Legacy status promotes process/log/UDP checks to ACTIVE | `aegis_status.py:113-176` | Operators can mistake diagnostic evidence or stale logs for authoritative health. |
| OR-016 | **P2** | Default `aegisctl health` returns success on degraded health | `aegisctl.py:247-279`; UX contract `docs/AEGIS_Operator_UX_Specification.md:46-54` | Automation can continue despite a degraded enforcement dependency unless it remembers `--strict`. |
| OR-017 | **P2** | SBOM is non-deterministic and not a dependency/binary SBOM | `release_engineering.py:249-278` | Reproducibility and supply-chain provenance are not reliable. |
| OR-018 | **P2** | Release manifest omits canonical runtime trees and build outputs | `release_engineering.py:70-112, :388-402` | ZIP/SBOM can pass its own internal loop while omitting the runtime actually needed. |
| OR-019 | **P2** | “signatures.json” is a claim file, not a signature | `release_candidate.py:124-129` | Operators may confuse an attestation-like JSON with cryptographic evidence. |
| OR-020 | **P3** | Generated truth is stale at current HEAD | `tools/truth.py verify --json`; `build_manifest.json:5`; `AUTHORITY_MAP.json:2` | Architecture/package claims cannot be used as current-head proof. |
| OR-021 | **P3** | “Golden path” operator scenarios are mostly existence/unit-reference tests | `tests/test_golden_path.py:54-201` | Test names overstate integration and host-effect coverage. |
| OR-022 | **P3** | `verify_release.ps1` checks obsolete layout and optional checksum | `scripts/verify_release.ps1:24-55, :65-112` | A “verification passed” message would not establish current package integrity or signatures. |

## 8. Missing tests and proofs

The following are mandatory before prevention or a production release can be considered. They are not present as executable evidence at the reviewed HEAD.

### 8.1 Control and privilege proofs

- A Windows named-pipe test that runs the daemon elevated, connects as a standard user, and proves that privileged commands are denied. The test must verify server-side impersonation and caller PID/token identity rather than a role supplied in JSON.
- An SDDL test that reads the control pipe security descriptor and WFP device security descriptor, compares them to the approved policy, and verifies no `Everyone`/untrusted write access.
- A low-integrity and separate-local-account test for read-only versus mutating commands.
- A PEP ABI conformance harness using the built DLL. It must reject malformed request lengths, unknown action ordinals, mismatched policy versions, invalid caller identity, and stale/duplicate request IDs.

### 8.2 Receipt and host-effect proofs

- A single provider ABI returning a complete `EnforcementReceipt` with request/event/policy/trace/audit identity, provider identity, filter ID, status, host-effect confirmation, and supported version.
- A real WFP test that adds one uniquely owned filter, records its provider/sublayer/filter identity, sends traffic that should match, observes the host effect, and then removes exactly that filter.
- A negative test where the provider returns success but the filter is absent or traffic still passes. The result must be `POSTCONDITION_FAILED`, never `BLOCKED_CONFIRMED`.
- A restart test that verifies filter ownership and removes stale filters from the prior generation without removing unrelated host rules.
- Receipt-linkage tests that call `ForensicRing.appendReceipt` from the active pipeline and reject wrong event, policy, trace, audit, status, version, and filter IDs.
- Mouth and dashboard tests with forged logs: `BLOCK`, `Drop`, `AUTHORIZED`, `ENFORCED` without IDs, `ENFORCED` with `host_effect_confirmed=false`, stale receipts, and receipts from another event. None may increment confirmed-block counters or show `BLOCKED`.

### 8.3 Packaging, signing, and clean-host proofs

- Build from a clean checkout of the exact release commit with no pre-existing `target`, `zig-out`, `dist`, or release directory.
- Verify that the manifest contains every shipped file and no unlisted file, including `aegis_nids.exe`, `aegis_pep.dll`, C helpers, Go Nose, configs, driver, INF, catalog, and runtime dependencies.
- Verify Authenticode on every EXE/DLL and `signtool verify /pa /kp` on the driver and catalog. Test signing must be rejected by the production gate.
- Verify each signed file’s signer chain, EKU, timestamp, and digest against the release manifest. Verify the driver’s catalog membership and INF identity.
- Install on a clean Windows VM with UAC/elevation, no prior AEGIS service, no prior device, and no prior WFP provider/filter. Capture before/after service, device, registry, ACL, file, and WFP inventories.
- Start only the canonical service/runtime owner and prove `--version`, health, worker readiness, PEP readiness, provider readiness, and control-pipe identity.
- Perform a real allow/deny/block request and capture `EnforcementReceipt`, WFP filter identity, traffic observation, forensic linkage, and UI rendering.
- Uninstall and prove the service, driver, device, provider filters, firewall rules, registry entries, shortcuts, ACLs, and installation files are cleaned while explicitly documented data is preserved.
- Reinstall, upgrade, interrupted-upgrade, and rollback from a known-good snapshot. Verify binary generation, service configuration, driver state, filter state, receipt state, and forensic integrity after every transition.

## 9. Prioritized fixes

### P0 — stop prevention and remove ambiguous authority

1. **Remove host-effect claims from the active UI and dispatcher.** Until the provider returns a validated receipt, render only non-enforcing states. Change Mouth blocked/DEFCON counters and the dashboard blocked card to consume one validated receipt stream, not event/action strings.
2. **Complete the receipt ABI.** Extend the PEP/provider boundary or define a versioned broker ABI that returns `EnforcementReceipt`; call `ForensicRing.appendReceipt` in the active pipeline. Do not reconstruct a receipt in Mouth from log text.
3. **Fix control-pipe identity.** Set an approved SDDL, impersonate the named-pipe client, derive role/capability from the client token, bind request identity to an OS-authenticated caller, and test standard/low-integrity users.
4. **Secure the WFP device.** Add restrictive SDDL and explicit caller validation for create and mutating IOCTLs. Define one device/service identity and one provider/filter ownership model.
5. **Make PEP capabilities non-forgeable.** Remove trust in caller-provided PID/capability fields or make them outputs of authenticated broker context. Reject requests whose identity is not bound to the server-observed token.

### P1 — converge the runtime and release graph

6. **Choose one WFP implementation.** Keep the C helper and driver only behind the Rust PEP provider contract. Retire or quarantine duplicate direct WFP implementations. Fix the driver build path (`drivers/wfp_callout` versus `kernel/wfp_callout`) and require WDK/INF/catalog output in the build graph.
7. **Use secure absolute loading.** Resolve DLLs from the signed installation root, use restricted Windows DLL search semantics, verify Authenticode and pinned digest before load, and require ABI/version handshake.
8. **Wire mandatory policy signature verification.** The active `policies.json` load must verify the signed canonical policy artifact against an installed trust root, version, expiry, and rollback policy before adding actions.
9. **Replace all release scripts with one manifest-driven pipeline.** One command must build, enumerate actual outputs, generate deterministic SBOM, sign all outputs, verify signatures/hashes, package, install, and test rollback. Remove unsupported CI arguments and hard-coded commits/versions.
10. **Reject test-signing artifacts in production mode.** Keep `wfp_sign.ps1` only as an explicitly named development tool. Production gates must require the approved certificate/catalog/chain and fail closed.
11. **Make uninstall/rollback state-aware.** Stop and join the runtime, stop/remove the exact service, remove only AEGIS-owned filters/provider objects, unload/delete the driver/device, verify no residual state, then restore or preserve data according to a signed manifest.

### P2 — remove misleading support paths and strengthen automation

12. **Delete or hard-fail `run_aegis.bat`, `stop_aegis.bat`, and `aegis_status.py`.** They must not remain runnable second supervisors or status authorities.
13. **Make health exit codes match the contract by default.** Degraded, failed, unavailable, stale, and integrity-failed states must return nonzero in automation mode.
14. **Make SBOM deterministic and meaningful.** Use stable SPDX IDs, actual dependency coordinates/versions/licenses, binary hashes, signer identity, source commit, build toolchain, and package file list. Never use Python’s randomized `hash()` for identity.
15. **Reclassify tests honestly.** Rename source-presence tests as static checks and add separate Windows integration/host tests. Do not let a scenario pass merely because a unit test exists elsewhere.

## 10. Exact Windows-only verification commands

The following commands are an acceptance runbook, not evidence that the
current HEAD has passed them. Run them only in an isolated Windows VM with a
revertible snapshot, a disposable test account, and an approved test plan.
The commands that install, start, stop, sign, or mutate WFP state require an
elevated PowerShell session and are therefore **UNVERIFIED** in this review.

### 10.1 Pin the source and capture a clean baseline

```powershell
$ErrorActionPreference = 'Stop'
$Root = 'C:\AEGIS\NIDs_Windows'
Set-Location $Root
git rev-parse HEAD
if ((git rev-parse HEAD) -ne '46b93dcf9cca17b323ddff7a4c71e33e81c37fb5') { throw 'wrong HEAD' }
git status --short --branch
Get-ChildItem Env:AEGIS*,Env:NPCAP_DIR -ErrorAction SilentlyContinue
Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture
Get-WindowsDriver -Online -All | Where-Object Driver -Match 'aegis|wfp' | Format-List
sc.exe query AegisNids
sc.exe query AegisWfp
pnputil.exe /enum-drivers | Select-String -Pattern 'AEGIS|aegis_wfp'
fltmc.exe filters | Select-String -Pattern 'AEGIS|aegis'
netsh.exe wfp show filters file="$Root\baseline-wfp.xml"
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' | Where-Object PSChildName -Match 'Aegis' | Select-Object PSChildName
Get-Acl '\\.\pipe\aegis_control' -ErrorAction SilentlyContinue
```

The baseline must show no AEGIS service, driver, device, provider, or filter.
If a prior installation exists, revert the VM or remove it through the tested
uninstall path before continuing. Do not interpret a successful command with
no output as proof that the object was absent; record explicit exit codes and
before/after inventories.

### 10.2 Build the canonical graph from a clean checkout

```powershell
Remove-Item -Recurse -Force target,zig-out,build,dist -ErrorAction SilentlyContinue
where.exe zig
where.exe cargo
where.exe cmake
where.exe go
where.exe signtool
zig version
cargo --version
cmake --version
go version
cargo build --release --manifest-path rust-src\Cargo.toml
cmake -S . -B build -DBUILD_KERNEL_DRIVER=ON
cmake --build build --config Release
$env:NPCAP_DIR = "$env:LOCALAPPDATA\NpcapSDK"
zig build -Doptimize=ReleaseSafe
zig build test -Doptimize=ReleaseSafe
go test .\nose\...
python -m pytest tests\ -v --ignore=tests/test_e2e.py
```

The exact Rust manifest path, CMake driver subdirectory, and output paths
must be confirmed before execution. If any command is adjusted because the
source layout differs, record that as a release defect; do not silently use a
legacy path. `BUILD_KERNEL_DRIVER=ON` is expected to fail until the build graph
points at the actual reviewed driver directory and WDK target. That failure is
evidence of the current graph defect, not a reason to copy a pre-existing
`.sys` into the package.

### 10.3 Verify package completeness, provenance, and signatures

```powershell
$Bundle = 'C:\AEGIS\bundle'
Set-Location $Root
python tools\truth.py verify --json
python tools\release_engineering.py --verify
Get-FileHash .\zig-out\bin\aegis_nids.exe -Algorithm SHA256
Get-FileHash .\target\release\aegis_pep.dll -Algorithm SHA256
Get-FileHash .\build\Release\aegis_wfp_user.dll -Algorithm SHA256
Get-FileHash .\drivers\wfp_callout\aegis_wfp.sys -Algorithm SHA256
Get-AuthenticodeSignature .\zig-out\bin\aegis_nids.exe | Format-List
Get-AuthenticodeSignature .\target\release\aegis_pep.dll | Format-List
Get-AuthenticodeSignature .\build\Release\aegis_wfp_user.dll | Format-List
Get-AuthenticodeSignature .\drivers\wfp_callout\aegis_wfp.sys | Format-List
signtool verify /pa /all .\zig-out\bin\aegis_nids.exe
signtool verify /pa /all .\target\release\aegis_pep.dll
signtool verify /pa /all .\build\Release\aegis_wfp_user.dll
signtool verify /kp /all .\drivers\wfp_callout\aegis_wfp.sys
pnputil.exe /enum-devices /class System | Select-String -Context 2,4 -Pattern 'AEGIS|AegisWfp'
```

Every shipped PE file must have the approved signer and timestamp. The driver
must verify through the kernel policy and its catalog/INF identity must match
the package. A self-signed certificate, test-signing mode, missing catalog, or
an artifact whose hash is not in the release manifest is a release failure.
`signatures.json` alone is not a substitute for these checks.

### 10.4 Install and verify service/device identity

```powershell
Set-Location $Bundle
Get-Content .\manifest.json -Raw | ConvertFrom-Json
Get-FileHash .\runtime\aegis_nids.exe -Algorithm SHA256
Get-FileHash .\drivers\aegis_wfp.sys -Algorithm SHA256
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot $Bundle -InstallRoot 'C:\Program Files\AEGIS NIDS'
sc.exe query AegisNids
sc.exe qc AegisNids
sc.exe query AegisWfp
sc.exe qc AegisWfp
pnputil.exe /enum-devices /connected | Select-String -Context 3,5 -Pattern 'AEGIS|AegisWfp'
Get-Item 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe' | Format-List FullName,Length,LastWriteTime
Get-Acl 'C:\Program Files\AEGIS NIDS' | Format-List
Get-Acl '\\.\pipe\aegis_control' | Format-List
```

Verify that service `ImagePath`, installed binary hash, driver service path,
INF/catalog identity, device symbolic link, and ACLs all refer to the same
bundle generation. `sc query` returning `STOPPED` or `RUNNING` is not enough;
the binary path and signer must be checked. The service should not be started
until the package gate passes.

### 10.5 Start the canonical owner and verify authoritative health

```powershell
Start-Service -Name AegisNids
Start-Sleep -Seconds 3
& "$Root\zig-out\bin\aegis_nids.exe" --version
python tools\aegisctl.py health --json
python tools\aegisctl.py readiness --pretty
python tools\aegisctl.py metrics --json
python tools\aegisctl.py forensics verify --json
Get-Process aegis_nids | Select-Object Id,Path,StartTime
Get-ChildItem '\\.\pipe\' | Where-Object Name -Match 'aegis_control|aegis_nose|aegis_sensor'
```

The health response must identify the expected process generation and return
`runtime_available=true`. It must distinguish `pep_ready`, `provider_ready`,
and `host_effect_capable`; PEP readiness alone is not host-effect proof. Do
not run `run_aegis.bat`, `stop_aegis.bat`, or `aegis_status.py` in this test.

### 10.6 Verify the privilege boundary as different Windows identities

Run the read-only health commands as a standard user and then attempt a
mutating request. Use a second local account and a low-integrity process where
the lab policy permits it:

```powershell
runas.exe /user:AEGIS-TEST\StandardUser powershell.exe
# In the standard-user window:
python C:\Program Files\AEGIS NIDS\bin\aegisctl.py health --json
python C:\Program Files\AEGIS NIDS\bin\aegisctl.py block 192.0.2.10 --rule-id TEST-DENY --reason boundary-test
sc.exe query AegisWfp
```

The mutating request must be denied by the server/PEP boundary. It must not
reach a successful IOCTL merely because the client supplied a capability bit.
Capture the request result, Windows security event, and service audit record.
The result is **UNVERIFIED** until the server is changed to impersonate and
inspect the actual client token.

### 10.7 Prove a real WFP effect and receipt linkage

Use a reserved test address and an isolated traffic generator. Do not use a
production peer. The exact `aegisctl` block command must match the built CLI;
the command below is the intended contract and must fail closed if unsupported:

```powershell
$Before = Join-Path $env:TEMP 'aegis-wfp-before.xml'
$After = Join-Path $env:TEMP 'aegis-wfp-after.xml'
netsh wfp show filters file=$Before
python tools\aegisctl.py block 192.0.2.10 --rule-id TEST-DENY --reason host-proof
python tools\aegisctl.py metrics --json
python tools\aegisctl.py forensics list --json
netsh wfp show filters file=$After
sc.exe query AegisWfp
Get-WinEvent -LogName 'Microsoft-Windows-WFP/Operational' -MaxEvents 50 |
  Format-List TimeCreated,Id,ProviderName,Message
Test-NetConnection 192.0.2.10 -Port 443 -InformationLevel Detailed
```

The acceptance record must include the exact request ID, event ID, policy ID,
trace ID, audit ID, provider name, filter ID, receipt version, WFP filter
ownership, and observed traffic result. A PEP `BLOCK` response without those
fields is `BLOCK_REQUESTED` or `ENFORCEMENT_UNVERIFIED`, never `BLOCKED`.
For a negative control, request a block with the provider stopped or the
device removed; the result must be `UNAVAILABLE`/`FAILED` and the UI must not
increment confirmed blocks.

### 10.8 Verify clean stop, filter cleanup, uninstall, and rollback

```powershell
python scripts\aegisctl.py stop --all
Start-Sleep -Seconds 5
Get-Process aegis_nids -ErrorAction SilentlyContinue
python tools\aegisctl.py health --json
Get-ChildItem '\\.\pipe\' | Where-Object Name -Match 'aegis_control'
Stop-Service AegisWfp -ErrorAction SilentlyContinue
sc.exe delete AegisWfp
netsh wfp show filters file="$env:TEMP\aegis-wfp-post-stop.xml"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot $Bundle -InstallRoot 'C:\Program Files\AEGIS NIDS' -Rollback
sc.exe query AegisNids
sc.exe query AegisWfp
pnputil.exe /enum-devices /connected | Select-String -Pattern 'AEGIS|AegisWfp'
netsh wfp show filters file="$env:TEMP\aegis-wfp-post-rollback.xml"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\wfp_service.ps1 uninstall
```

The clean result requires the old process to have exited, the control pipe to
be released, no AEGIS-owned WFP filters or device to remain after uninstall,
no unrelated filters to be removed, and preserved data to match the declared
rollback set. Any residual service, device, provider object, filter, ACL,
firewall rule, or executable is a failure. These commands are **UNVERIFIED**
in this environment and must be run on a disposable Windows VM.

## 11. Final disposition

**Disposition: STOP-THE-LINE for prevention and release.** The source-level
direction toward one Zig runtime owner, one Rust PEP authority, explicit
degraded health, and local Mouth receipt tests is valuable. It does not prove
that AEGIS can safely block traffic on a clean Windows host. The minimum gate
to reopen is a single current-head package with trusted absolute loading,
authenticated control/device boundaries, a complete provider-backed
`EnforcementReceipt`, receipt-linked forensic evidence, and an isolated
Windows install/block/observe/uninstall/rollback record. Until that record
exists, do not announce production-ready, do not enable prevention, and do
not let UI or scripts represent authorization or policy intent as host block.

## References

[1]: /home/ubuntu/upload/AEGISComprehensiveDevelopmentAnalysisandProductionHandoff.md "AEGIS Comprehensive Development Analysis and Production Handoff"
[2]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/README.md "AEGIS NIDS Windows README"
[3]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/docs/AEGIS_Operator_UX_Specification.md "AEGIS Operator UX Specification"
[4]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/truth.py "Truth Artifact Verifier"
[5]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/build.zig "Zig Build Graph"
[6]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/daemon.zig "Zig Daemon Runtime Supervisor"
[7]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/pipeline/event_processor.zig "Active Detection, Policy, PEP, and Forensic Pipeline"
[8]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/rust-src/lib.rs "Rust PEP and WFP Adapter"
[9]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/policy/enforcement_receipt.zig "EnforcementReceipt Contract"
[10]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/mouth/windows_sec_monitor.rs "Mouth Operator Monitor"
[11]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/aegis_dashboard/src/main.rs "Rust egui Dashboard"
[12]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/platform/win32_pipe.zig "Windows Control Named Pipe"
[13]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/installer.py "Installer NSIS Generator"
[14]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tools/release_engineering.py "Release Engineering and SBOM Tool"
[15]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.github/workflows/ci.yml "AEGIS CI Workflow"
[16]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/.github/workflows/host-regression.yml "Host Regression Workflow"
[17]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/install_aegis.ps1 "Windows Bundle Installer and Rollback Script"
[18]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/wfp_service.ps1 "WFP Driver Service Lifecycle Script"
[19]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/scripts/wfp_sign.ps1 "Development Driver Signing Script"
[20]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/drivers/wfp_callout/aegis_wfp.c "WFP Kernel Driver Entry and IOCTL Boundary"
[21]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/src/windows/wfp_ioctl.c "Userspace WFP IOCTL Helper"
[22]: /mnt/7e95cf32-1f55-43b0-8e52-61ade7757bda/NIDs_Windows/tests/test_golden_path.py "Golden Path Operator Test Harness"
