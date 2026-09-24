# AEGIS Current-Head Build Inventory and Production/Security Review

**Review type:** Read-only senior production/security review  
**Repository:** `NIDs_Windows`  
**Reviewed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Review state:** **Not production-ready; prevention/enforcement gate remains closed**  
**Evidence level:** E0–E1 for this sandbox review. Windows, elevated-token, native-linker, Npcap, WDK, service, driver, and VMware results are **UNVERIFIED**.

## 1. Executive conclusion

The current-head build graph is a set of separately orchestrated language builds, not one closed production graph. `zig build` owns the Windows Zig executable and its unit-test/fuzz/tool targets. The Rust root manifest builds the PEP DLL separately. Root CMake builds user-mode WFP, ETW, and FIM DLLs; `bridge/CMakeLists.txt` is a second CMake project that emits `dist` bridge and adapter artifacts. Go Nose and the Go aggregator are separate modules. TypeScript is typechecked and tested but emits no production artifact. CI coordinates these jobs, but the runtime does not start or supervise every artifact that the generated maps call “canonical.” [1] [2] [3] [4]

The source-confirmed runtime spine is:

```text
src/main.zig
  -> platform/win32_service.mainEntry()
       -> daemon.runDaemon()
            -> security/capability initialization
            -> Rules.json + policies.json loading
            -> PepEnforcer.init()
            -> Windows bridge initialization
            -> RuntimeSupervisor worker creation
                 -> legacy core/named-pipe sensor: aegis_sensor_pipe
                 -> Zig pipeline/event_processor
                 -> Go Nose reader: aegis_nose
                 -> ETW, FIM, Registry workers
            -> platform/win32_pipe.serveWindowsPipe()
```

The active pipeline does perform detection, policy evaluation, a Rust PEP FFI call, action dispatch, audit logging, and forensic-ring append. However, **the active source does not implement the required validated `EnforcementReceipt` contract**. The Rust response contains only decision, reason, quota, and signer fields. The Zig dispatcher logs that Rust PEP/WFP enforcement was executed after receiving a decision, but there is no filter ID, host-effect postcondition, receipt version, or complete request/event/trace/audit linkage. A PEP decision is therefore not evidence of a host block. [5] [6]

The generated-truth policy is itself failing: `python tools/truth.py verify` returns `TRUTH_INVALID`. `runtime_manifest.json` matches the reviewed HEAD, but `SYSTEM_MAP.json`, `FLOW_MAP.json`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, `EVIDENCE_INDEX.json`, `build_truth.json`, `build_manifest.json`, and `AI_CONTEXT.md` are stale or carry other commit identities. The current build truth even says that it is synchronized to `48eb2a7…` while its `head_sha` is `688ab566…`; neither is the reviewed HEAD. These artifacts must not be used as current-head authority. [7] [8]

The release directory has a separate problem. Its binary hashes and lengths match its own `manifest.json`, but the bundle is version `6.0.0`, dated 2026-09-16, has no current-head commit binding, and its binaries are ignored/untracked while only metadata/configuration files are committed. The repository’s build manifest is version `5.0.0` and names source commit `0a7418b`; the installer template embeds `2c7cb30`. Matching a stale bundle’s internal hashes does not prove that it was built from `46b93dcf…`.

## 2. Scope and method

The review was limited to `build.zig`, root and bridge CMake files, all relevant Rust/Go/TypeScript manifests, `src/main.zig` imports, the daemon and active worker imports, runtime/build/inventory/system/flow/authority/contract/evidence maps, CI and release metadata, build references, tests, fixtures, and generated truth tooling. The provided handoff and README were used as context only; source and build wiring were given priority when they disagreed. [9] [10]

The repository HEAD was rechecked with `git rev-parse HEAD` and returned:

```text
46b93dcf9cca17b323ddff7a4c71e33e81c37fb5
```

The worktree is dirty with material changes in build/runtime/manifest files, including `build.zig`, `src/daemon.zig`, `src/platform/win32_pipe.zig`, `src/capture/nose_pipe_reader.zig`, `rust-src/lib.rs`, `nose/main.go`, `runtime_manifest.json`, `inventory.json`, and `tools/create_manifest.py`. No source or generated truth file was modified by this review. Where a file is dirty, the report treats the committed HEAD version as the current-head source of truth and records the worktree state as a separate reproducibility risk.

The following distinction is used throughout:

| Classification | Meaning in this review |
|---|---|
| **Active production candidate** | Reachable from `src/main.zig`/`daemon.runDaemon()` or required as a directly loaded runtime dependency. This is not a production-readiness claim. |
| **Support/optional** | Buildable or loadable helper, sidecar, operator surface, or compatibility component that is not the sole runtime or enforcement authority. |
| **Tooling/test** | Build orchestration, generators, CI, fixtures, unit tests, proof harnesses, and release tools. |
| **Legacy/parallel** | Source that remains present or is called through a compatibility path but is not the selected canonical architecture, or a duplicate manifest/authority surface. |
| **UNVERIFIED** | Requires Windows, elevation, installed Npcap/WDK, service/driver state, or an isolated VMware lab and was not executed here. |

## 3. Actual current-head build graph

### 3.1 Zig graph: runtime owner and test/tool targets

`build.zig` defaults to Windows x86_64 and creates the `aegis_nids` executable from `src/main.zig` [1]. It links libc and Windows libraries including `ws2_32`, `advapi32`, `kernel32`, `user32`, `ole32`, `secur32`, `ntdll`, and `tdh`. It resolves Npcap include/library locations from `NPCAP_DIR`, `%LOCALAPPDATA%\NpcapSDK`, or `C:\Npcap`, then links `wpcap` and `Packet` [1:5-57]. This is a real Windows dependency, not a portable host build.

The Zig graph does not build Rust, C/C++, Go, or TypeScript. It conditionally adds the Rust PEP import library only when `target/release/aegis_pep.dll.lib` exists, and it conditionally adds ETW/FIM helper import libraries from `target/helpers` or `build/Release`; missing dependencies produce warnings rather than a hard graph failure [1:59-97]. This means artifact presence changes the link graph, and a missing required dependency can be reported as a warning until a later linker/runtime failure. The import-library copy from `aegis_pep.dll.lib` to `aegis_pep.lib` is also a build-side mutation of the artifact directory [1:59-71, 141-153].

The test graph is rooted at `src/all_tests.zig`, with embedded test configuration loaded from `configs/test/*.json`; it links Windows system libraries and optionally the same PEP/helper libraries [1:106-160]. The `fuzz` step builds `src/fuzz_entry.zig`. The `core-tools` step builds `src/perf_bench_main.zig` and `src/integration_test_main.zig` as operator/proof tools, not runtime owners [1:162-200].

### 3.2 `src/main.zig` and active daemon graph

`src/main.zig` imports `platform/win32_service.zig`, `platform/win32_pipe.zig`, and `pipeline/rule_loader.zig`. `main()` handles `--version`, then calls `service.mainEntry()` [11:15-35]. `mainEntry()` probes the Windows Service Control Manager and falls back to console mode; both paths call `daemon.runDaemon()` [12:77-127].

`daemon.runDaemon()` imports the active pipeline, policy, forensic, bridge, and control modules. Its startup sequence creates the runtime state, loads `configs/Rules.json`, parses `configs/policies.json`, initializes the PEP wrapper, initializes bridges, spawns workers, establishes readiness, and serves the control pipe [13:85-137, 148-329, 339-496]. The `RuntimeSupervisor` stores six worker handles and joins them in reverse order [13:51-82]. The readiness barrier is bounded at two seconds, and the daemon publishes `RUNNING` only when the pipeline is ready and not failed; other dependencies are represented as degraded subsystem state [13:427-482]. These are positive lifecycle properties at source level, but they remain unexecuted on Windows in this sandbox.

The active worker set is not exclusively Go Nose. `daemon.zig` starts `legacy_capture.capture_packets` on `aegis_sensor_pipe` at line 377 and separately starts `nose_reader.runPipeReaderLoop` for the Go Nose pipe at line 401 [13:375-405]. The source comment says Go Nose is the canonical network ingress and direct Zig Npcap capture is disabled [13:392-398], but the legacy sensor still runs and submits events to the same queue. This is a **dual ingress path**, with separate event-ID allocation and separate pipe contracts. It is not safe to call the current graph a single-ingress production path until the legacy sensor is removed from the production target or explicitly isolated and its identity semantics are proven.

The pipeline worker is concrete: `event_processor.processEvent()` performs flow lookup, signature matching, anomaly observation, threat tracking, policy evaluation, PEP enforcement, action dispatch, audit logging, and forensic append [14:26-43, 57-201]. `pipelineLoop()` marks pipeline readiness, drains the queue, and records processing metrics [14:203-252]. The event processor does not prove host effect; it records a PEP enum and appends a forensic record that lacks the complete receipt/postcondition contract.

### 3.3 Root CMake graph

Root `CMakeLists.txt` is a C project that builds three user-mode shared libraries: `aegis_wfp_user` from `src/windows/aegis_wfp.c` and `src/windows/wfp_ioctl.c`, `aegis_etw_helper` from `src/windows/etw_native.c`, and `aegis_fim_helper` from `src/windows/fim_native.c` [2:1-62]. It does not build the Zig executable, Rust PEP, Go Nose, or bridge project.

The optional kernel-driver block is not currently connected to the repository’s driver tree. With `BUILD_KERNEL_DRIVER=ON`, root CMake calls `add_subdirectory(kernel/wfp_callout)` [2:64-69], but the repository contains `drivers/wfp_callout/`, not `kernel/wfp_callout/`. The default is `OFF`, so ordinary CMake builds do not compile the WFP kernel driver. A pre-existing `drivers/wfp_callout/aegis_wfp.sys` file or release-bundle copy is not proof that this current graph can build, sign, install, or load the driver.

`bridge/CMakeLists.txt` is independent. It builds `aegis_ipc`, `aegis_bridge`, `aegis_bridge_test`, `aegis_adapter`, and `aegis_adapter_selftest` into `dist` [15:1-143]. Root CMake does not add this directory, and `build.zig` does not depend on it. The daemon dynamically searches for `aegis_ipc.dll` in `dist`, `bridge`, `build`, `build\Release`, and `build\Debug`, then falls back to a system search [16:226-287]. Therefore bridge loading is runtime-optional and path-dependent, not a closed build dependency.

### 3.4 Rust graphs

The root `Cargo.toml` is a standalone `aegis_pep` package whose library path is `rust-src/lib.rs` and whose crate types are `cdylib` and `rlib` [17:1-15]. This is the only manifest that maps directly to the intended PEP DLL.

`shield/Cargo.toml` is a separate support crate producing `sec_monitor` as a library [18:1-10]. `shield/src/lib.rs` exports `aegis_shield_screen` and imports a local module named `pep`, but the code currently uses that module for advisory payload screening [19:1-23]. The source is not evidence of final enforcement authority.

`rust-src/shield/Cargo.toml` is a duplicate nested manifest. It declares a library and a binary at `src/main.rs`, but the nested source tree contains no `rust-src/shield/src/main.rs` in the inspected repository. This manifest is not the CI-selected Shield graph, which uses `shield/Cargo.toml`, and should be treated as duplicate/legacy until either made valid or retired.

`mouth/Cargo.toml` explicitly describes a standalone optional operator component and says it must not depend on or link into the PEP [20:1-16]. `aegis_dashboard/Cargo.toml` is another independent optional GUI graph [21:1-20]. Neither is linked by the active Zig build.

### 3.5 Go graphs

`nose/go.mod` defines module `aegis-nose`, Go 1.22, and packet/UI dependencies including `gopacket` [22:1-28]. CI builds and tests Nose in a separate Windows job [4:146-163]. The Zig build does not compile or start this executable. Operationally, Nose must be deployed and started as an external process before the Zig reader can receive canonical events; this start/supervision contract is not represented in `build.zig`.

`go/aggregator/go.mod` is an optional Go 1.21 sidecar with `fsnotify` and `uuid` [23:1-10]. CI builds/tests it separately and the generated maps call it support-only. It is not on the active detector/enforcement path and must not be counted as a CanonicalEvent producer.

### 3.6 TypeScript graph

`ts_policy/package.json` declares typecheck and test scripts only; it produces no build output and explicitly describes the policy plane as advisory and non-enforcing [24:1-24]. `tsconfig.json` includes source and tests with strict checks [25:1-23]. CI runs `npm ci`, `npm run typecheck`, and `npm run test:all` [4:183-196]. The active daemon does not load a TypeScript artifact. It parses `configs/policies.json` directly with ad-hoc string-to-enum conversion [13:179-298]. Therefore TypeScript is policy-authoring/tooling support, not the current runtime policy loader.

## 4. File-level classification

### 4.1 Active production candidate

The production candidate runtime path is `src/main.zig`, `src/platform/win32_service.zig`, `src/platform/win32_pipe.zig`, `src/daemon.zig`, `src/pipeline/runtime_state.zig`, `src/pipeline/event_processor.zig`, `src/pipeline/event_queue.zig`, `src/pipeline/rule_loader.zig`, `src/capture/nose_pipe_reader.zig`, `src/detection/*` modules imported by the processor, `src/capture/flow_table.zig`, `src/policy/policy_ir.zig`, `src/policy/pep_bindings.zig`, `src/policy/action_dispatcher.zig`, and `src/forensic/*` modules imported by the processor. Their classification is **active candidate**, not proof of readiness.

The Rust PEP candidate is `rust-src/lib.rs`; it exports the actual `aegis_pep_*` ABI and dynamically loads `aegis_wfp_user.dll` on Windows [5:205-286, 322-450]. The native candidate is the root CMake WFP/ETW/FIM graph. Go Nose is a separate active candidate acquisition process, but its process lifecycle is external to the Zig supervisor. The bridge DLL is a dynamically loadable support dependency, not a statically closed part of the Zig target.

### 4.2 Support and optional paths

`shield/` is support-only payload screening. `go/aggregator/` is an optional alert sidecar. `brain/` and Cython are analytics/performance support in the repository but are not imported into the active `daemon.zig` pipeline shown above; the UDP brain logger in `bridge_init.zig` is an optional logging channel, not evidence of active policy authority [16:113-195, 314-343]. `ts_policy/` is advisory authoring/compiler/test tooling. `mouth/` and `aegis_dashboard/` are optional operator surfaces. None may claim host block without a validated receipt.

### 4.3 Tooling and test paths

`build.zig` fuzz/core-tools targets, `tools/truth.py`, `tools/rebuild_truth.py`, `tools/generate_truth_artifacts.py`, `tools/create_manifest.py`, `tools/release_engineering.py`, `tools/installer.py`, Python scripts under `scripts/`, `.github/workflows/ci.yml`, `.github/workflows/host-regression.yml`, contract fixtures, Zig tests under `src/tests`, Python tests under `tests/`, and TypeScript tests under `ts_policy/tests` are tooling/test paths. They can provide evidence at their actual execution level; they do not become production proof merely by existing or passing static checks.

`host-regression.yml` is specifically a Linux host workflow. Its Phase T runs Python runtime tests and Phase K runs per-file `zig ast-check`; the summary says “logic layer is green on Host” and points to a separate Windows deployment script [26:19-153]. It is not a Windows component, driver, WFP, service, Npcap, or VMware proof.

### 4.4 Legacy and parallel paths

`src/core/nids_capture.zig` is described in source comments as a legacy sensor path, but `daemon.zig:377` actively starts it. It is therefore **legacy-labelled but active**, which is more dangerous than a purely dead file. `src/core/rust_pep.zig` is a parallel Zig-side enforcement model and WFP wrapper. Its `RustPep` struct maintains an in-memory blocklist [27:101-251], while its `block_ip()` wrapper gates a WFP action through `src/policy/pep_bindings.zig` [27:278-396]. This is not the same ABI or receipt path as the root Rust PEP and should not be represented as a second authority.

`src/policy/dispatcher.zig`, `src/policy/dispatcher_phase_b.zig`, `src/contract/event_fabric.zig`, `src/contract/runtime_spine.zig`, and many generated-map modules are not imported by the active `daemon.zig` path inspected here. They are parallel/legacy architecture candidates until a current-head call graph proves reachability. The maps’ `core/*.zig` labels are aliases or historical descriptions; the actual source tree uses `src/core/`.

The nested `rust-src/shield/Cargo.toml` is a duplicate/invalid manifest candidate. The release bundle is a historical release artifact, not current-head production output. `configs/Rules.json.before-reload-test` and the inventory’s `zig_build.err` are unclassified files and must not be included in a production package without explicit disposition.

## 5. Contract and authority impact

### 5.1 Invariants supported by source

The following source-level directions are correct and should be preserved:

1. Zig owns startup orchestration, worker handles, readiness, control service, and reverse-order joins through `RuntimeSupervisor` [13:51-82].
2. Detection and policy evaluation occur before the PEP call in `event_processor.zig`; the action dispatcher does not call WFP directly [14:139-173] [28:1-92].
3. `PepEnforcer.enforce()` returns `.escalate` when the PEP is unavailable or its FFI call returns an error [6:79-105].
4. Rust PEP attempts to fail closed when the WFP adapter is unavailable by returning an escalation decision with reason `4` [5:350-426].
5. TypeScript declares itself advisory and non-enforcing [24:1-5].
6. The Shield library’s exported screen function is an advisory payload screen, not a documented block authority [19:3-23].

These are source-level properties only. They do not prove Windows ABI, service, driver, host effect, cleanup, or release correctness.

### 5.2 Authority breaks and contract gaps

**Runtime ownership is incomplete.** The Zig supervisor owns the threads it creates, but it starts both a legacy sensor pipe and the Go Nose reader. The project therefore has one lifecycle owner with multiple ingress authorities. Event IDs from the legacy sensor use a process-local atomic counter [29:16-18, 287-298], while the Go Nose reader explicitly resets monotonic comparison at each producer connection [30:227-295]. Cross-restart/global uniqueness is not proven.

**Control authorization is not caller-bound.** `win32_pipe.getLocalRole()` calls `OpenProcessToken(GetCurrentProcess(), ...)`, which derives the role from the daemon’s own token, not from the connecting client [12:171-195]. The server also passes a null security descriptor to `CreateNamedPipeW` and states that a tested SDDL/ACL helper is still needed [12:207-226]. A privileged client identity and pipe ACL are therefore **UNVERIFIED and source-incomplete**, despite comments describing local role authorization.

**Policy is not canonical or signed on the active path.** The daemon parses `configs/policies.json` directly and maps unknown action strings to `.pass` [13:228-230]. It only interprets the first clause and first predicate and maps `gte` to `gt` [13:240-287]. The Rust library contains an Ed25519 verification function [5:21-54], but the active daemon loader does not call it and the PEP request carries no policy digest/signature envelope. An invalid or unknown action can therefore become a non-enforcing pass before the PEP boundary rather than a rejected policy.

**Cross-language policy ordinals drift.** TypeScript tests assert `PolicyAction.BLOCK = 2` [31:112-118]. Rust PEP action constants assert `ACTION_BLOCK = 4` [5:196-203]. The active Zig JSON loader avoids this particular numeric input by parsing strings, but the repository contains multiple incompatible Policy IR representations. A generated map or test pass cannot make these representations one contract.

**PEP response is not an enforcement receipt.** `PepResponse` has `decision`, `reason`, `quota_remaining`, and `signed_by` only [6:46-51]. `aegis_pep_enforce()` returns success code `0` even when it places an escalation reason in the response [5:404-426]. `ActionDispatcher` emits “PEP validated block; WFP enforcement executed by Rust PEP” for a block decision [28:69-72]. There is no validated filter identity, host-effect observation, receipt version, or complete linkage to event/request/trace/audit IDs. This violates the rule that `PEP authorization != WFP host effect`.

**Native WFP ownership is not closed.** The Rust PEP dynamically loads `aegis_wfp_user.dll` and calls `aegis_wfp_ioctl_open`, `aegis_wfp_ioctl_block_ip`, and `aegis_wfp_ioctl_unblock_ip` [5:228-278]. The C source opens `\\.\AegisWfpDevice` and sends write IOCTLs [32:69-103]. Root CMake builds the user DLL, but does not build the driver because the optional path names a nonexistent `kernel/wfp_callout` directory [2:64-69]. The existence of `drivers/wfp_callout/aegis_wfp.sys` is not a build or service proof.

## 6. Generated truth and SHA reconciliation

| Artifact | Declared identity | Compared with reviewed HEAD | Disposition |
|---|---:|---:|---|
| `runtime_manifest.json` | `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5` | Match | Fresh SHA, but content still requires source-graph validation |
| `SYSTEM_MAP.json` | `688ab566d477105df5f868cee1571fbec77eedfd` | Mismatch | **STALE** |
| `FLOW_MAP.json` | `688ab566d477105df5f868cee1571fbec77eedfd` | Mismatch | **STALE** |
| `AUTHORITY_MAP.json` | `688ab566d477105df5f868cee1571fbec77eedfd` | Mismatch | **STALE** |
| `CONTRACT_MAP.json` | `688ab566d477105df5f868cee1571fbec77eedfd` | Mismatch | **STALE** |
| `EVIDENCE_INDEX.json` | `688ab566d477105df5f868cee1571fbec77eedfd` | Mismatch | **STALE** |
| `build_truth.json` | `688ab566d477105df5f868cee1571fbec77eedfd` | Mismatch | **STALE** |
| `build_manifest.json` | `source_commit = 0a7418b` | Mismatch | **STALE** |
| `AI_CONTEXT.md` | old markdown HEAD | Mismatch | **STALE** |
| `inventory.json` | no SHA by verifier design | Not comparable | Freshness not attested; generated for `D:\NIDs_Windows` |
| release `manifest.json` | no source commit | Not comparable | Historical/unbound to current HEAD |

`tools/truth.py` correctly checks the first eight SHA-bearing groups and returns failure for the stale list above [7:28-53, 98-207]. `inventory.json` is intentionally exempt from SHA checks, so its “PASS” means only “no SHA expected”; it does not mean current-head completeness. It reports 775 inventory records while `git ls-files` reports 827 tracked paths in this worktree, and it embeds a Windows path as `repo_root`. The difference requires an explicit generator scope decision before it can serve as release inventory.

The stale content is not merely cosmetic. `build_truth.json:104-110` calls itself `TRUTH-001_SYNCED`, names source truth including `bridge/CMakeLists.txt`, and says it is synchronized to `48eb2a7…` while the top-level `head_sha` is `688ab566…` [8]. That is internally contradictory and must be treated as untrusted. `SYSTEM_MAP.json` and `AUTHORITY_MAP.json` also describe Shield duplicate files and paths whose current source state differs from the map. A matching SHA is necessary, not sufficient; after regeneration, every path and edge still requires source reconciliation.

The release bundle’s own hashes were independently recomputed and all listed files matched their bundle manifest’s length and SHA-256. That result is limited to bundle self-consistency. The binary payloads are ignored by Git (`*.exe`, `*.sys`), and the committed release metadata contains no source commit. The bundle therefore cannot establish provenance to `46b93dcf…`. Its version `6.0.0` also conflicts with the current runtime manifest/build manifest version `5.0.0`. Treat the bundle as a historical artifact until regenerated and signed from the reviewed HEAD.

## 7. Concrete defects and severity

| ID | Severity | Defect | Evidence and impact |
|---|---|---|---|
| BUILD-001 | **P0 / stop-the-line** | Current-head truth is invalid | `tools/truth.py verify` fails for seven JSON/manifest groups plus `AI_CONTEXT.md`; stale maps may describe old graph/authority. |
| BUILD-002 | **P0 / stop-the-line** | Privileged control pipe is not caller-bound | `GetCurrentProcess()` is used instead of client impersonation/token inspection, and the control pipe passes a null security descriptor [12:171-226]. Unauthorized or incorrectly authorized control claims are not proven safe. |
| SEC-003 | **P0 / stop-the-line** | Block claim is emitted without a validated receipt/postcondition | `PepResponse` lacks filter/host-effect/request/event/trace/audit fields; dispatcher logs execution from a decision [5:156-184, 404-426] [28:63-83]. |
| SEC-004 | **P0 / stop-the-line** | Active policy loader is unsigned and fail-open for unknown action | Unknown action maps to `.pass`; active loader never invokes the Rust Ed25519 verifier [13:228-287] [5:21-54]. |
| BUILD-005 | **P0 for prevention release** | Kernel driver is not in the root CMake graph | `BUILD_KERNEL_DRIVER` is off and its enabled path `kernel/wfp_callout` does not exist; actual sources are under `drivers/wfp_callout`. |
| ARCH-006 | **P1** | Two ingress pipes are active | `legacy_capture.capture_packets` and `nose_reader.runPipeReaderLoop` are both spawned [13:375-405]. Duplicate/non-monotonic identity and ambiguous producer authority remain. |
| BUILD-007 | **P1** | Language builds are disconnected from the runtime graph | Zig does not build/start Rust, Go, CMake bridge, or TypeScript; CMake does not build Zig/Rust/Go; CI artifact handoff is external. Missing import libraries only warn in `build.zig` [1:59-97]. |
| CONTRACT-008 | **P1** | Policy IR/action ordinals drift | TypeScript asserts block ordinal 2 while Rust declares action block ordinal 4 [31:112-118] [5:196-203]. Direct JSON parsing bypasses a single canonical signed artifact. |
| RUST-009 | **P1** | Duplicate/invalid Shield manifest exists | `rust-src/shield/Cargo.toml` declares missing `src/main.rs`; `shield/Cargo.toml` is the separate CI-selected graph. Duplicate manifests can produce wrong artifact claims. |
| LIFE-010 | **P1** | Control accept/read uses blocking Win32 calls | `ConnectNamedPipe` and `ReadFile` run in the main control thread with `PIPE_WAIT`; the wake path is tied to the SCM stop handler [12:218-271, 275-285]. Console/control shutdown and stuck clients require Windows proof. |
| REL-011 | **P1** | Release metadata is not current-head bound | Release binary hashes match the historical bundle but no source commit is recorded; binary files are ignored/untracked; version/date conflict with current manifests. |
| TEST-012 | **P1** | Existing tests permit or assert weaker semantics than the safety contract | Rust PEP test accepts an allow-shaped outcome when WFP is unavailable [5:547-577]; many tests validate structure/static strings rather than actual DLL/driver/host postconditions. |
| OPS-013 | **P2** | Host regression is not a Windows production proof | Linux workflow runs Python contracts and `zig ast-check`, not service, Npcap, WFP, driver, elevation, or VMware tests [26:19-153]. |
| INV-014 | **P2** | Inventory is exempt from SHA and does not cover the full tracked index | `inventory.json` is 775 records versus 827 indexed paths and uses a Windows-root path. “No SHA expected” is not a current-head attestation. |

## 8. Missing tests and proofs

The following proofs are absent or **UNVERIFIED** at this review:

1. A clean Windows build from `46b93dcf…` using Zig 0.13, Rust 1.88, MSVC/CMake, Go 1.22, Node 20, and Npcap SDK.
2. A successful `python tools/truth.py verify --strict` after generator-based regeneration, with all generated map edges checked against source reachability.
3. A kernel-driver build with the actual `drivers/wfp_callout` tree, WDK/EWDK, signing, service installation, device creation, and restrictive device SDDL.
4. A real ABI harness loading the built PEP and native DLLs, checking symbols, calling convention, struct layout, error mapping, and version handshake.
5. A negative control proving a standard-user/low-integrity client cannot open or mutate the control/sensor/WFP device boundary.
6. A complete Go Nose → named pipe → Zig canonical validation → event queue → detector → policy → Rust PEP → receipt → forensic record test on Windows.
7. Cross-restart and cross-producer event identity tests proving no duplicate, collision, or non-monotonic identity when both pipes reconnect.
8. Unsigned, wrong-key, expired, malformed, unknown-action, unknown-enum, duplicate-policy, and rollback policy tests against the **active** daemon loader.
9. A receipt test requiring status, host-effect confirmation, filter ID, request ID, event ID, trace ID, audit ID, policy digest/version, provider identity, cleanup result, and supported receipt version.
10. A WFP isolated-lab proof on VMware VMnet1 showing target reachability before block, block during the authorized request, forensic linkage, filter cleanup, reachability after cleanup, and no stale filter after lifecycle recovery.
11. Clean install, upgrade, rollback, uninstall/reinstall, signature, SBOM/provenance, and package-content tests bound to the same current-head source digest.
12. A shutdown test that demonstrates bounded return from `ConnectNamedPipe`, `ReadFile`, worker joins, and control-client disconnects for both SCM and console launches.

## 9. Prioritized fixes

### P0 — keep prevention closed

1. Regenerate all truth artifacts with their canonical generators from the verified HEAD. Do not hand-edit SHA fields. Make CI fail when any SHA-bearing map, build manifest, Markdown context, release manifest, or inventory scope is stale or internally contradictory.
2. Replace the current PEP enum-only result with one versioned `EnforcementReceipt` contract. The receipt must be produced only after Rust authorization, provider response, host-effect observation, and required forensic linkage. Change Mouth, dashboard, CLI, audit, and dispatcher logs to display confirmed block only from receipt validation.
3. Fix control-pipe security at the OS boundary. Use a tested restrictive SDDL, impersonate the named-pipe client, derive SID/elevation/integrity from the client token, enforce command capability at the server, and add standard-user/low-integrity negative tests.
4. Make policy loading canonical and fail closed. Require signed canonical bytes, key/version/expiry/scope/digest validation, reject unknown actions and malformed predicates, and pass the verified policy digest/version into the PEP request and forensic record.
5. Correct the WFP driver CMake path or redesign the native build so the actual driver source, service, device name, IOCTLs, signing, and userspace DLL are one explicit Windows build/package graph. Do not infer readiness from a copied `.sys` or `.dll`.

### P1 — converge the runtime and contracts

6. Select one ingress authority. Remove the legacy sensor from the production target or isolate it as a separately named test adapter. Freeze producer identity, generation/epoch, sequence, and duplicate semantics across reconnects.
7. Make required artifact dependencies hard failures. `zig build` should fail when required PEP/helper/Npcap inputs are absent rather than emit warnings and continue. Add an explicit orchestration target or release script that builds and records Rust, CMake, Go, Zig, and policy inputs from one commit.
8. Choose one Policy IR and generate Zig/Rust/TypeScript bindings and golden vectors from it. Remove or quarantine the TypeScript/Rust ordinal drift and the ad-hoc runtime JSON parser.
9. Remove or clearly quarantine duplicate manifests and parallel authority files, including `rust-src/shield/Cargo.toml`, the legacy Zig enforcement model, and unused dispatcher/event-fabric paths. Add a graph lint that fails if a second enforcement authority or runtime owner becomes reachable.
10. Implement bounded, cancellable control and sensor I/O and prove reverse-order joins on Windows. Ensure all shutdown entry points wake the exact blocking handle they own.

### P2 — release and operational assurance

11. Generate a release manifest containing full source HEAD, dirty-tree state, toolchain versions, dependency hashes, binary hashes, signatures, and package file list. Refuse to package ignored binaries without a matching generated provenance record.
12. Split static/source tests from Windows component tests and VMware host-effect tests. Label each result E0–E7 and prevent lower-level evidence from being promoted to production claims.
13. Add a current-head inventory scope check that reconciles generated files with `git ls-files`, explicitly classifies unclassified paths, and records intentional exclusions.

## 10. Exact Windows-only verification commands

The following commands are the minimum reproducible verification sequence. They are commands to execute on the Windows host; this Linux sandbox did not execute them. A failure or timeout is evidence of failure, not evidence of readiness.

### 10.1 Current-head and truth gate

```powershell
$ErrorActionPreference = 'Stop'
Set-Location -Path 'D:\NIDs_Windows'
$expected = '46b93dcf9cca17b323ddff7a4c71e33e81c37fb5'
$actual = (git rev-parse HEAD).Trim()
if ($actual -ne $expected) { throw "Wrong HEAD: $actual" }
git status --short
git log -1 --oneline
python tools/truth.py verify --strict
```

The dirty-tree output must be archived with the evidence. Do not claim a clean release if `git status --short` is non-empty.

### 10.2 Toolchain and native dependency gate

Run from a Visual Studio Developer PowerShell with WDK/EWDK available for driver work:

```powershell
zig version
cargo --version
go version
cmake --version
node --version
npm --version
python --version
Get-ChildItem "$env:LOCALAPPDATA\NpcapSDK\Include\pcap.h"
Get-ChildItem "$env:LOCALAPPDATA\NpcapSDK\Lib\x64\wpcap.lib"
```

### 10.3 Language and build graph gate

```powershell
Set-Location -Path 'D:\NIDs_Windows'

cargo build --release
cargo test --release

cargo build --release --manifest-path .\shield\Cargo.toml
cargo test --release --manifest-path .\shield\Cargo.toml
# This nested duplicate manifest is expected to fail or be explicitly retired
cargo metadata --no-deps --manifest-path .\rust-src\shield\Cargo.toml

cmake -B .\build -S . -A x64
cmake --build .\build --config Release
cmake -B .\bridge\build -S .\bridge -A x64
cmake --build .\bridge\build --config Release

Set-Location .\nose
go test ./...
go build -o aegis-nose.exe .
Set-Location ..

Set-Location .\go\aggregator
go test ./...
go build -o aegis-aggregator.exe .
Set-Location ..\..

Set-Location .\ts_policy
npm ci
npm run typecheck
npm run test:all
Set-Location ..

zig build -Doptimize=ReleaseSafe
zig build test
```

For the WDK path, run the actual configured driver project under `drivers\wfp_callout`; do not substitute `kernel\wfp_callout` unless that path has been deliberately created and reviewed:

```powershell
Get-ChildItem .\drivers\wfp_callout
msbuild .\drivers\wfp_callout\aegis_wfp.vcxproj /p:Configuration=Release /p:Platform=x64
```

If the driver project is not an MSBuild project, use its checked-in WDK build command and archive the exact command, compiler output, signing output, and resulting service/device names. Do not treat a pre-existing `aegis_wfp.sys` as a build result.

### 10.4 Artifact and provenance gate

```powershell
$required = @(
  '.\zig-out\bin\aegis_nids.exe',
  '.\target\release\aegis_pep.dll',
  '.\build\Release\aegis_wfp_user.dll',
  '.\build\Release\aegis_etw_helper.dll',
  '.\build\Release\aegis_fim_helper.dll',
  '.\nose\aegis-nose.exe',
  '.\dist\aegis_ipc.dll',
  '.\drivers\wfp_callout\aegis_wfp.sys'
)
foreach ($p in $required) {
  if (-not (Test-Path -LiteralPath $p)) { throw "Missing required artifact: $p" }
  Get-FileHash -Algorithm SHA256 -LiteralPath $p
  Get-AuthenticodeSignature -FilePath $p | Format-List Path,Status,SignerCertificate
}
```

From a Developer Command Prompt, inspect imports and architecture:

```powershell
dumpbin /headers .\zig-out\bin\aegis_nids.exe
dumpbin /dependents .\zig-out\bin\aegis_nids.exe
dumpbin /exports .\target\release\aegis_pep.dll
dumpbin /exports .\build\Release\aegis_wfp_user.dll
```

### 10.5 Windows runtime and read-only preflight

Start the runtime in one elevated PowerShell window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
zig build run
```

In a second elevated PowerShell window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File '.\scripts\run_host_production_preflight.ps1' `
  -HealthRetries 1 `
  -RetryDelaySeconds 1
```

The safe pre-enforcement expectation is `runtime_state=RUNNING` or an explicitly explained degraded state, `pep_ready=true` only when the real PEP DLL initialized, `host_effect_capable=false`, `overall_gate=false`, `production_attested=false`, `attack_attempted=false`, and `enforcement_attempted=false`. A copied DLL, a live PID, or a green UI card is not a substitute for the structured health response.

Check the provider and service identity without changing state:

```powershell
Get-Service | Where-Object { $_.Name -match 'Aegis|Wfp' } | Format-List Name,Status,StartType,PathName
sc.exe query type= driver state= all
Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match 'Aegis|Wfp' } | Format-List Name,State,PathName,Started
fltmc filters
Get-Item '\\.\AegisWfpDevice' -ErrorAction SilentlyContinue
```

### 10.6 Isolated VMware host-effect proof

The host-effect proof is **not authorized by this report** and must be run only after the exact target, cleanup owner, and VMnet1 topology are independently confirmed. Use the project’s approved runbook and record the exact current HEAD, health-before, target reachability-before, PEP request, provider response, filter ID, validated receipt, forensic IDs, cleanup result, reachability-after, and lifecycle-recovery result. Do not use Wi-Fi, NAT/VMnet8, localhost, the VMware gateway, or an unconfirmed private address.

The proof is a pass only if the receipt says enforced with `host_effect_confirmed=true`, a nonzero filter/request/event/trace/audit identity is linked, the isolated target is blocked, cleanup removes the owned filter, reachability returns, and a new runtime generation has no stale filter. Until then, the host effect is **UNVERIFIED** and the prevention gate remains closed.

## 11. Final disposition

At `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`, AEGIS has a credible Zig-owned runtime candidate and a source-level Rust PEP boundary, but the build graph is not provenance-closed, generated truth is stale, the runtime has two active ingress pipes, the control authorization is not caller-bound, policy loading is not a single signed contract, and host-block claims are not receipt-driven. The system must be treated as **detection/alert-only or explicitly degraded**. No component, release bundle, DLL, SYS file, CI assertion, or UI state justifies a production-ready prevention claim.

## References

[1]: `../../build.zig` "Zig build graph and runtime/test/tool targets"
[2]: `../../CMakeLists.txt` "Root native CMake graph"
[3]: `../../Cargo.toml` "Rust PEP manifest"
[4]: `../../.github/workflows/ci.yml` "Windows cross-language CI and release workflow"
[5]: `../../rust-src/lib.rs` "Rust PEP ABI, WFP adapter, and response semantics"
[6]: `../../src/policy/pep_bindings.zig` "Zig-side Rust PEP FFI binding"
[7]: `../../tools/truth.py` "Current-head truth verifier"
[8]: `../../build_truth.json` "Generated build truth artifact"
[9]: `../../README.md` "Repository source-of-truth hierarchy and build baseline"
[10]: `../../runtime_manifest.json` "Generated runtime manifest"
[11]: `../../src/main.zig` "Zig process entrypoint"
[12]: `../../src/platform/win32_service.zig` "Windows service/console dispatch"
[13]: `../../src/daemon.zig` "Daemon startup, workers, readiness, and shutdown"
[14]: `../../src/pipeline/event_processor.zig` "Active detection/policy/PEP/forensic pipeline"
[15]: `../../bridge/CMakeLists.txt` "Independent bridge and adapter CMake graph"
[16]: `../../src/core/bridge_init.zig` "Dynamic bridge initialization and legacy WFP wrapper"
[17]: `../../Cargo.toml` "Root PEP Cargo package"
[18]: `../../shield/Cargo.toml` "Shield support Cargo package"
[19]: `../../shield/src/lib.rs` "Shield advisory screening implementation"
[20]: `../../mouth/Cargo.toml` "Optional Mouth Cargo package"
[21]: `../../aegis_dashboard/Cargo.toml` "Optional dashboard Cargo package"
[22]: `../../nose/go.mod` "Go Nose module manifest"
[23]: `../../go/aggregator/go.mod` "Go aggregator support module manifest"
[24]: `../../ts_policy/package.json` "TypeScript policy authoring manifest"
[25]: `../../ts_policy/tsconfig.json` "TypeScript compiler configuration"
[26]: `../../.github/workflows/host-regression.yml` "Linux host regression workflow"
[27]: `../../src/core/rust_pep.zig` "Parallel Zig-side PEP/WFP wrapper and model"
[28]: `../../src/policy/action_dispatcher.zig` "Action dispatcher authority boundary"
[29]: `../../src/core/nids_capture.zig` "Legacy sensor pipe and local event identity"
[30]: `../../src/capture/nose_pipe_reader.zig` "Go Nose pipe reader and producer identity handling"
[31]: `../../ts_policy/tests/cross_language_contract.test.ts` "TypeScript policy ordinal contract tests"
[32]: `../../src/windows/wfp_ioctl.c` "Userspace WFP device and IOCTL transport"

<!-- Review artifact generated for the requested analysis only; no source or generated truth artifact was modified. -->
