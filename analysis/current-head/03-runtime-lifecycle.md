# AEGIS Current-HEAD Runtime, Lifecycle, and Control-Plane Review

**Repository:** `NIDs_Windows`  
**Reviewed HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**Review mode:** read-only source, build-graph, and test/script inspection; no source or generated truth was modified.  
**Conclusion:** **Not production-ready. Prevention must remain closed.**

## 1. Executive conclusion

The current build graph identifies `build.zig -> src/main.zig -> src/daemon.zig` as the active Zig executable path. The Windows service and console entrypoints converge on `daemon.runDaemon()`. The daemon does create one local `RuntimeSupervisor` and stores worker handles for the sensor, pipeline, Go Nose reader, ETW, FIM, and Registry workers. The pipeline worker has an initialization flag and the daemon has a bounded two-second startup wait.

That improvement does not yet establish a safe production lifecycle. The control pipe has no explicit restrictive security descriptor: `SECURITY_ATTRIBUTES.lpSecurityDescriptor` is null. More importantly, the code derives the caller role from the **daemon process token**, not from the connecting client token. An elevated daemon therefore maps every local pipe client to `privileged`, including commands such as `daemon.shutdown`, forensic export/replay, and lifecycle commands. This is a stop-the-line authorization defect.

Shutdown is also not bounded end to end. The control server uses synchronous `PIPE_WAIT` `ConnectNamedPipe` and synchronous `ReadFile`; the Go Nose reader changes a connected pipe to blocking reads and uses `ReadFile` with a null `OVERLAPPED`. `RuntimeSupervisor.shutdown()` calls unbounded `std.Thread.join()` in reverse order. The service stop wake-up only opens the control pipe to wake a pending connect; it does not cancel an active control-pipe read, a client that has stopped reading, or a connected Nose reader. A Windows proof is required before claiming orderly stop or recovery.

The state and health surfaces contain both good containment and false authority. `runtime.stop` and `runtime.restart` correctly return `NOT_IMPLEMENTED`, and the canonical CLI does not normally create or kill processes. However, `daemonShutdown` directly writes the state machine to `STOPPED` and returns `{"shutdown":true}` before any worker has joined. The CLI reports that shutdown was requested, which is appropriately weaker, but the daemon's own health state can become stopped while workers are still unwinding. The Python API also has a PID-file fallback that checks only whether a PID exists. It does not bind the PID to the expected executable, command line, runtime generation, or control-pipe owner.

Several handler responses remain mocked or overly optimistic: policy verification returns `signatures_valid=true` without validating a signature, forensic export and replay return success without performing the operation, and enforcement verification returns `verified=true` without a host-effect receipt or postcondition. These responses violate the invariant that only Rust PEP authorization plus a verified provider effect may support an enforcement claim. Counters and heartbeat fields are not consistently bound to the running workers. The watchdog is initialized and the pipeline calls `beat`, but no active daemon path was found that calls the watchdog check or publishes worker heartbeat freshness into the health reducer.

The correct product state at this HEAD is **detection-only/degraded, with the enforcement gate closed**. Windows, elevated-token, named-pipe ACL, DLL/provider, lifecycle join, and VMware host-effect claims are **UNVERIFIED** in this Linux sandbox.

## 2. Scope and method

The review covered the requested runtime and lifecycle boundary: `src/main.zig`, `src/daemon.zig`, `src/control/`, `src/pipeline/`, `src/core/`, `src/platform/`, `src/reliability/`, `tools/aegisctl.py`, the modular Python control clients, lifecycle/health tests, operational scripts, and build references. The repository README and the primary handoff were used as declared architecture context only. Source behavior and the current build graph take priority over those documents.

The review traced five questions through source:

1. Which executable and function are the real production entrypoint?
2. Which component creates workers, publishes readiness, signals cancellation, and joins workers?
3. Which pipe security and request fields are actually enforced rather than merely declared?
4. Which state, health, heartbeat, and metric fields are mutated by live runtime code?
5. Which tests execute a real Windows daemon and which only validate models, text, fixtures, or local files?

Static searches were also used to separate active production imports from support and legacy paths. The only attempted local runtime test command was:

```text
python -m pytest -q tests/runtime/test_lifecycle_authority.py tests/runtime/test_health.py tests/runtime/test_restart.py tests/runtime/test_timeouts.py tests/runtime/test_aegisctl.py
```

It could not start because this sandbox's `/usr/bin/python` has no `pytest` module. Zig, Rust, Windows APIs, elevated-token checks, named-pipe ACL inspection, Npcap, WFP, service state, and VMware behavior were not executed here and are reported as **UNVERIFIED**.

## 3. Active call graph and ownership

### 3.1 Active production path

```text
build.zig (Windows x86_64 default)
  -> executable aegis_nids, root src/main.zig
  -> main()
  -> platform/win32_service.mainEntry()
       -> StartServiceCtrlDispatcherW()
       -> serviceMain() when launched by SCM
            -> daemon.runDaemon()
       -> daemon.runDaemon() in console/foreground mode
            -> initialize state/config/PEP/forensic/watchdog
            -> bridge_init.initAll()
            -> create RuntimeSupervisor
            -> spawn legacy sensor worker
            -> spawn pipeline/event_processor worker
            -> spawn Go Nose named-pipe reader
            -> spawn ETW, FIM, and Registry workers
            -> wait up to 2 seconds for pipeline readiness/failure
            -> mark subsystem states and primary runtime state
            -> serve control pipe on the daemon thread
            -> signal stop and defer RuntimeSupervisor.shutdown()
                 -> reverse-order std.Thread.join()
```

`build.zig:5-20` sets the default target to Windows x86_64 and makes `src/main.zig` the executable root. `src/main.zig:31-35` dispatches to `platform/win32_service.mainEntry()`. `src/platform/win32_service.zig:77-126` contains both SCM service dispatch and console fallback. Both paths call `daemon.runDaemon()`.

`src/daemon.zig:51-83` is the active local supervisor. Its ownership is real for the thread handles it creates, and its reverse join order is explicit. `src/daemon.zig:353-425` starts the Windows workers. The direct Zig Npcap path is explicitly disabled in this path; Go Nose is declared the canonical network ingress. `src/daemon.zig:484-488` serves the control pipe on the daemon's main thread and requests stop when the control loop returns.

### 3.2 Active, support, and legacy classification

| Area | Classification at current HEAD | Evidence and impact |
|---|---|---|
| `src/main.zig`, `src/daemon.zig`, `src/platform/win32_service.zig` | **Active production build path** | Root executable and both service/console entrypoints converge on `runDaemon()`. |
| `src/platform/win32_pipe.zig`, `src/control/*` | **Active control path** | Imported by `src/main.zig`/`src/daemon.zig`; handler registry is initialized when the pipe starts. |
| `src/pipeline/event_processor.zig`, `event_queue.zig`, `telemetry_threads.zig`, `runtime_state.zig` | **Active worker/data path** | Imported and spawned from `runDaemon()`. |
| `src/capture/nose_pipe_reader.zig` | **Active Go Nose ingress support within daemon** | Spawned by `RuntimeSupervisor`; owns `\\.\pipe\aegis_nose`. |
| `src/core/bridge_init.zig`, diagnostics, Rust PEP integration | **Active dependency boundary** | Bridges and PEP are initialized from `runDaemon()`, but provider readiness and host effect remain unverified. |
| `src/reliability/watchdog.zig` | **Initialized active support, incomplete health authority** | Registered in `runDaemon()` and beaten by pipeline; no active health reducer/check path was found. |
| `src/reliability/lifecycle.zig` | **Support/legacy lifecycle model unless explicitly wired later** | No current `build.zig`/`src/main.zig`/`src/daemon.zig` production call was found. Its integration lifecycle is not evidence of daemon ownership. |
| `src/core/nids_main.zig`, older fabric/dispatcher lifecycle models | **Legacy or alternate support path** | The current executable root does not select them as the lifecycle owner. Their existence must not be treated as runtime proof. |
| `tools/aegisctl.py` and `tools/aegisctl/*` | **Canonical operator client and diagnostic support path** | Normal start/stop requests go through the control pipe; health has an explicit degraded fallback. |
| `scripts/aegis_daemon.py`, `scripts/aegis_console.py`, batch stop scripts | **Legacy/operational compatibility path** | They contain process spawning, PID files, taskkill, and watchdog logic. They are a second supervisor if invoked and must be removed from normal runbooks or quarantined. |

## 4. Lifecycle and worker observations

### 4.1 Startup, readiness, and failure publication

The daemon resets all readiness and worker-failure flags before creating workers (`src/daemon.zig:363-373`). Worker creation failures call `state.markWorkerFailure()` and set a bit in the failure mask (`src/pipeline/runtime_state.zig:43-67`). This is useful containment, and the `workers` health object includes per-worker flags, a primary failure reason, and a mask (`src/control/state_machine.zig:341-371`).

The readiness barrier is only partially authoritative. `runDaemon()` waits while `g_pipeline_ready` is false, while no worker failure is reported, and for at most 2,000 ms (`src/daemon.zig:427-437`). The pipeline sets `g_pipeline_ready=true` at the start of `pipelineLoop`, before the loop has processed an event (`src/pipeline/event_processor.zig:216-220`). The Nose worker sets `g_nose_ready=true` after creating its pipe server, which proves listener creation, not Go producer connectivity or event flow (`src/capture/nose_pipe_reader.zig:178-188`).

After the wait, the daemon marks the primary system `RUNNING` when only the pipeline flag is true and the pipeline failure bit is clear (`src/daemon.zig:472-480`). ETW, FIM, Registry, and WFP/provider states are published separately, but their failure does not prevent the primary state from becoming `RUNNING`. This may be a valid detection-only degraded policy, but the contract must say explicitly that `RUNNING` means the control/pipeline spine is serving rather than all required data-plane capabilities being live. The current source and Python reducer do not use a single, independently verified definition.

There is no corresponding active startup transaction that waits for a heartbeat, tests a queue transition, validates an event postcondition, or proves that a worker remains alive after readiness. A worker can set its flag and then exit; the state machine is not automatically transitioned to `FAILED` by the worker's deferred flag reset.

### 4.2 Heartbeat and watchdog

`RuntimeState.heartbeat()` updates `last_heartbeat_ms` (`src/control/state_machine.zig:220-230`), but a source search found only the method definition and no active daemon call that periodically updates subsystem heartbeat. `subsystemStarted()` initializes `last_heartbeat_ms` to startup time (`src/control/state_machine.zig:179-189`). This makes the field a startup timestamp rather than a live liveness signal unless another path is added.

The reliability watchdog is registered for pipeline, capture, ETW, FIM, and Registry in `src/daemon.zig:331-336`. The pipeline calls `g_wd.beat()` on each loop (`src/pipeline/event_processor.zig:220-227`), but no active daemon path was found that calls `g_wd.check()` and reduces a stall into runtime health or a stop/recovery action. Therefore watchdog registration and a pipeline beat are not proof of worker liveness, restart, or health publication.

The `src/control/health/runtime_health.zig` functions `recordHealthbeat`, `recordPacket`, `recordDetection`, `recordIncident`, and `recordAction` are global counter helpers. The active pipeline uses its own `runtime_state` counters and diagnostic metrics instead of consistently calling these helpers. `tools/update_health_cmd.py` can call `recordHealthbeat`, but that is tooling rather than proof that the Windows daemon owns and updates the health state.

### 4.3 Cancellation and join

`RuntimeSupervisor.shutdown()` sets the shared stop flag, requests bridge shutdown, and joins Registry, FIM, ETW, Nose, sensor, and pipeline in reverse order (`src/daemon.zig:62-82`). This is the correct ownership shape, but the join has no deadline and is only as cancellable as each worker's Win32 API.

The Go Nose reader is specifically unsafe for a bounded join when a producer is connected. Its server is created with `PIPE_NOWAIT` for connection polling, but after connection it changes the handle to blocking byte-mode reads (`src/capture/nose_pipe_reader.zig:97-141`, `:207-216`). `readExact()` calls `ReadFile(..., null)` in a loop and checks the stop flag only between complete reads (`src/capture/nose_pipe_reader.zig:129-141`, `:234-306`). If the peer sends a partial frame and remains connected, setting `g_stop_requested` does not cancel the current `ReadFile`. The supervisor can then block indefinitely at `nose_reader.join()`.

The control pipe has the same class of problem. `serveWindowsPipe()` creates `PIPE_WAIT` and performs blocking `ConnectNamedPipe` and blocking `ReadFile` (`src/platform/win32_pipe.zig:218-271`). `wakeControlPipe()` opens the endpoint to wake a pending connect (`src/platform/win32_pipe.zig:275-285`), but it does not cancel an in-progress `ReadFile` or `FlushFileBuffers`. A client that connects and stops sending data can prevent the daemon from returning to the join path. The service control callback calls the stop flag, bridge shutdown, and `wakeControlPipe`, but does not close/cancel the active control handle (`src/platform/win32_service.zig:64-72`).

FIM and Registry loops sleep for up to 500 ms between stop checks (`src/pipeline/telemetry_threads.zig:104-115`, `:146-158`), which is bounded in isolation. The overall shutdown proof is still **UNVERIFIED** because one unbounded pipe read defeats the supervisor's nominal reverse-order join.

### 4.4 State mutation and lifecycle semantics

The positive containment is that `runtimeStart` does not create a second worker set. It returns idempotent success only when the daemon-owned state is `READY` or `RUNNING`; otherwise it returns `RUNTIME_NOT_READY` (`src/control/handler_registry.zig:512-530`). `runtimeStop` and `runtimeRestart` intentionally return `NOT_IMPLEMENTED`/`UNAVAILABLE` until a real transaction exists (`:533-549`). The canonical CLI follows this boundary: `cmd_start` sends `runtime.start`, `cmd_stop` sends `daemon.shutdown`, and `cmd_restart` refuses the operation (`tools/aegisctl.py:122-205`).

The main defect is `daemonShutdown`. The handler acquires the state mutex and immediately sets `system_state=.stopped`, clears `started_at_ms` and `uptime_ms`, sets the stop flag, requests bridge shutdown, and returns `{"shutdown":true}` (`src/control/handler_registry.zig:551-569`). Worker join occurs later in the `defer supervisor.shutdown()` path after the control loop exits. This is a **mocked/optimistic state transition**: `STOPPED` is published before the postcondition “all workers terminated and all owned handles joined” is true. It also bypasses the state machine's declared transition graph, which expects `STOPPING -> STOPPED` rather than a direct mutation from any state.

A second state-authority risk remains in the legacy scripts. `scripts/aegis_daemon.py` starts subsystem processes, writes PID files, uses `taskkill`, and implements a watchdog auto-restart loop. `scripts/aegis_console.py` calls process-kill and `Popen` launch paths. These are not selected by `build.zig`, but they remain executable support paths and can create a second owner or stale PID truth if an operator follows an old runbook.

## 5. Named-pipe security and control contract

### 5.1 ACL and caller authentication

The control pipe is `\\.\pipe\aegis_control` with one instance and message mode constants (`src/platform/win32_pipe.zig:21-33`). The source declares a custom ACL construction API, but the active call passes a `SECURITY_ATTRIBUTES` structure with `lpSecurityDescriptor=null` (`src/platform/win32_pipe.zig:207-226`). The code comment explicitly says this is a temporary OS-default security descriptor and must be replaced by tested SDDL/ACL before exposure.

The active authorization path is not caller-bound. `handleControlRequest()` creates a new `Authorizer`, calls `getLocalRole()`, and stores that result in the request context (`src/platform/win32_pipe.zig:155-168`). `getLocalRole()` calls `OpenProcessToken(GetCurrentProcess())` and `GetTokenInformation(TokenElevation)` on the **daemon process**, not on the client pipe handle (`src/platform/win32_pipe.zig:171-196`). If the daemon is elevated, any client that can open the pipe receives `privileged`; if token inspection fails, the code falls back to `operate` rather than denying access.

The role table itself is structurally reasonable: read, operate, and privileged are ordered, and `daemon.shutdown` is marked privileged and mutating (`src/control/protocol.zig:134-179`, `:232-234`). The problem is the identity source and the unspecified ACL. Role metadata cannot compensate for an unauthenticated named pipe.

**Severity: Critical / stop-the-line.** Until a restrictive SDDL is applied and the server validates the connecting client's token/SID/integrity/elevation at the pipe boundary, no privileged lifecycle or enforcement command is safe.

### 5.2 Envelope, replay, and deadline enforcement

`protocol.Envelope` declares `request_id`, `caller_role`, `protocol_version`, `issued_at_ms`, and optional `nonce` (`src/control/protocol.zig:241-249`). The active client sends only `{"command": ..., "payload": ...}` (`tools/aegisctl/api/control_api.py:67-72`). The Zig dispatcher parses only the JSON object, command/op, and payload; it does not validate a protocol version, issued time, nonce, deadline, or client-supplied request ID (`src/control/handler_registry.zig:143-178`). The server creates its own request ID from `g_pipeline_audit_id` (`src/platform/win32_pipe.zig:159-166`).

No replay cache, nonce uniqueness check, freshness window, per-request deadline, or cancellation token was found. A repeated `daemon.shutdown`, `forensics.export`, or `forensics.replay` request is not rejected as a replay. A request can also wait behind blocking pipe I/O without a request deadline. The audit ring records the server-generated request ID and caller role but not authenticated caller SID/token identity (`src/control/audit.zig:9-20`, `:33-42`).

**Severity: High.** The declared fields are not an enforced security contract. Implement and test the envelope at the transport boundary before treating audit IDs as authorization evidence.

### 5.3 Response framing and pipe resource behavior

The handler response writer correctly loops over partial `WriteFile` results (`src/control/handler_registry.zig:80-107`). This addresses partial writes. The control server uses one message-mode server instance and disconnects after each request. These are useful transport properties, but they do not establish request deadlines or prevent a blocked client from holding the server in a synchronous read/flush.

The Python client opens the pipe with `CreateFileW` and performs synchronous `WriteFile`/`ReadFile` with no timeout in its Win32 calls (`tools/aegisctl/api/control_api.py:67-130`). `_query_daemon_retry()` retries three times with a 50 ms delay, but that is not a read deadline; a single blocked call can still hang. This is especially important because the daemon itself uses blocking operations.

## 6. Health reducer, fallback, and stale PID truth

### 6.1 Daemon health

The active Zig health handler obtains the current process ID, reads worker readiness/failure flags, reads bridge capability state, and serializes the state-machine health payload (`src/control/handler_registry.zig:320-347`). The payload includes subsystem entries, worker flags, failure reason/mask, bridge fields, and data-plane counters from `src/control/state_machine.zig:281-356`. This is preferable to a hard-coded `RUNNING` response.

The reducer still has important gaps:

- `system_state` is set during startup and is not automatically reduced from worker heartbeat freshness or post-start worker exit.
- `last_heartbeat_ms` is initialized at subsystem start and no active periodic update path was found.
- `g_pipeline_ready` means the pipeline thread entered its loop, not that the pipeline processed an event or that its queue is healthy.
- The primary system state becomes `RUNNING` when the pipeline is ready even when Nose, ETW, FIM, Registry, or provider capability is degraded (`src/daemon.zig:472-480`). This can be safe only if every consumer treats the separate worker/provider fields as mandatory for the relevant capability; the contract is not currently enforced at one authority.
- Python health computes Tier-3 availability from artifact presence before combining it with status (`tools/aegisctl/api/control_api.py:592-642`). The function's comments say artifact presence is not readiness, but `compute_health_state()` still uses `tier3_loaded` in the overall state decision. A DLL on disk therefore influences the reducer even though it cannot prove loading, ABI compatibility, PEP readiness, or WFP host effect.

### 6.2 Unavailable-daemon fallback

When the control daemon cannot be queried, `get_health_payload()` returns an explicit `DEGRADED` diagnostic payload with `runtime_available=false`, zero counters, and `rust_shield.error=control_daemon_unavailable` (`tools/aegisctl/api/control_api.py:530-589`). This is a correct fail-safe direction and must be retained.

The fallback's subsystem list is nevertheless built from `get_all_status()`. If daemon status and health queries fail, `get_all_status()` reads PID files and returns `RUNNING` when the PID merely exists (`tools/aegisctl/api/control_api.py:155-219`). On Windows it calls `OpenProcess(1, 0, pid)`; it does not verify the executable image, command line, service identity, creation time, control-pipe ownership, or runtime generation. PID reuse can therefore make an unrelated process appear as a running subsystem in diagnostic fields. The fallback correctly sets `runtime_available=false`, but every consumer and UI must be forced to honor that field and never promote its subsystem entries to operational truth.

The fallback also reports `pid=os.getpid()` for the Python control API process (`tools/aegisctl/api/control_api.py:556-561`), not the Zig daemon. That is acceptable only when clearly labelled as diagnostic client identity; it is unsafe if a generic health consumer treats the top-level PID as runtime owner.

**Severity: High.** Remove PID-derived operational status from the health contract. Keep it only under a clearly named diagnostic field with executable/generation validation.

## 7. State, metrics, and authority observations by file

| File/symbol | Observation | Contract/authority impact |
|---|---|---|
| `src/main.zig:14-35` | Imports `win32_service` and calls `mainEntry`; the source test at `:89-114` includes a `try std.testing.expect(true)` response-format placeholder and describes CLI-only process management that no longer matches the canonical CLI. | Tests and comments can preserve stale expectations even after ownership moved to Zig. |
| `src/daemon.zig:54-83` | `RuntimeSupervisor` owns six worker handles and reverse-order joins, but joins have no deadline and no join result/postcondition record. | Single owner is present, but bounded shutdown is not proven. |
| `src/daemon.zig:363-480` | Flags are reset, workers are spawned, readiness waits 2 seconds, and primary state is set from pipeline readiness only. | Readiness is not a full dependency/heartbeat barrier. |
| `src/control/handler_registry.zig:320-347` | Health obtains current daemon PID and worker flags. | Better than stale PID for live queries, but it does not publish heartbeat age, join state, generation, or control-pipe owner identity. |
| `src/control/handler_registry.zig:367-375` | `rulesReload` mutates `g_rules_loaded` and reports `status=reloaded` without a serialized policy/rules generation or independently verified postcondition. | The command is an operational mutation whose result is optimistic. |
| `src/control/handler_registry.zig:429-438` | `policyValidate` always returns `valid=true`; `policyVerify` always returns `signatures_valid=true`; simulation is fixed output. | Cannot support signed-policy or policy-authority claims. |
| `src/control/handler_registry.zig:445-487` | Forensic show/export/replay and enforcement verify return placeholders or fixed success. | Direct violation of receipt-driven enforcement and evidence invariants. |
| `src/control/handler_registry.zig:489-505` | Metrics snapshot casts 64-bit counters to `u32`; `packets_captured` is `g_nose_frames_submitted`; blocks/errors come from separate diagnostic counters. | Values are truncated and not a single runtime metric model. |
| `src/control/handler_registry.zig:551-569` | `daemonShutdown` writes `STOPPED` before signal/join. | Stale lifecycle truth during shutdown. |
| `src/pipeline/runtime_state.zig:69-105` | Most pipeline and Nose counters are mutable globals, many non-atomic; Nose counters are separate from pipeline counters. | Cross-thread snapshots can race, and conservation is not one authoritative ledger. |
| `src/pipeline/event_queue.zig:30-120` | Queue-full events increment `g_queue_drops`, but producers often ignore the boolean return. | Emitted counters can increase even when events are dropped; drop reason is incomplete. |
| `src/pipeline/event_processor.zig:216-250` | Pipeline marks ready at loop entry and calls watchdog `beat`; it sleeps when empty. | Beat is not exposed to health, and readiness does not prove processing. |
| `src/pipeline/telemetry_threads.zig:54-82` | ETW event IDs derive from `diag.metrics.events_emitted`; push failure is ignored while emitted metric increments. | IDs are process-local/metric-derived and accepted-vs-dropped accounting diverges. |
| `src/capture/nose_pipe_reader.zig:229-305` | Explicitly scopes duplicate/non-monotonic checks to one connection and documents that cross-generation identity continuity is still a separate task. | Restart/reconnect event identity is not proven unique. |
| `src/platform/win32_pipe.zig:207-226` | Active control pipe uses null security descriptor. | ACL is not a tested privileged boundary. |
| `src/platform/win32_pipe.zig:155-196` | Role is derived from daemon process token; failures default to `operate`. | Unauthenticated privileged commands and fail-open authorization. |
| `src/platform/win32_pipe.zig:239-285` | Synchronous connect/read/flush; wake-up only opens the endpoint. | No bounded request/shutdown I/O. |
| `tools/aegisctl/api/control_api.py:155-219` | Daemon query falls back to PID-file/process-existence status. | Stale PID and PID reuse can contaminate diagnostics. |
| `tools/aegisctl/api/control_api.py:530-642` | Explicit degraded unavailable payload exists, but artifact presence and PID fallback still influence derived fields. | Correct fail-closed intent is undermined by mixed sources. |
| `tools/aegisctl.py:122-205` | Canonical start/stop are thin control clients; restart is refused; no normal process-kill fallback. | Good ownership containment; restart recovery remains unavailable. |
| `scripts/aegis_daemon.py`, `scripts/aegis_console.py`, `scripts/stop_aegis.bat` | Legacy process supervisor, PID files, taskkill, watchdog, and local launch remain executable. | Risk of a second owner and stale process truth if used. |
| `src/reliability/lifecycle.zig` | Rich lifecycle model exists but is not the active `runDaemon()` owner. | Must not be cited as runtime proof unless wired into build/call graph. |

## 8. Concrete defects and severity

### R-LIFE-001 — Elevated daemon token grants privileged role to pipe clients (**Critical / stop-the-line**)

**Evidence:** `src/platform/win32_pipe.zig:155-196`, especially `OpenProcessToken(GetCurrentProcess())`, and active ACL construction at `:207-226` with `lpSecurityDescriptor=null`.

**Failure:** The server authenticates itself, not the connecting client. An elevated daemon maps any client able to open the pipe to `privileged`; token-query failure falls back to `operate`. The OS-default pipe ACL is not a reviewed SDDL policy.

**Impact:** Unauthorized local callers may invoke `daemon.shutdown`, privileged lifecycle commands, forensic export/replay, or future privileged operations. This breaks the authenticated control endpoint invariant and makes the enforcement boundary unsafe.

**Required correction:** Apply tested restrictive SDDL at pipe creation; obtain the client token using the pipe impersonation APIs; validate SID, elevation/integrity, service identity, and command capability at the boundary. Any identity or ACL error must deny, not downgrade to operate.

### R-LIFE-002 — Control and Nose blocking I/O can defeat shutdown join (**High**)

**Evidence:** `src/platform/win32_pipe.zig:218-271`; `src/capture/nose_pipe_reader.zig:97-141`, `:190-216`, `:234-306`; `src/daemon.zig:67-82`.

**Failure:** Blocking `ReadFile` calls do not observe the stop flag until they return. `RuntimeSupervisor.shutdown()` has no deadline, cancellation API, or join watchdog. `wakeControlPipe()` only wakes a pending control connection.

**Impact:** A stalled control client or partial Nose frame can leave the process in `STOPPING` while a thread remains blocked. A service manager or recovery script can then start a second process or report false recovery.

**Required correction:** Use overlapped I/O with a cancellation event and bounded waits, or close/cancel the exact active handle on stop. Add a join deadline, per-worker stop acknowledgement, and a final `all_workers_joined` postcondition. Do not start a new owner until the pipe handles are demonstrably released.

### R-LIFE-003 — Envelope fields for version, freshness, nonce, and replay are declared but not enforced (**High**)

**Evidence:** `src/control/protocol.zig:241-249` declares fields; `src/control/handler_registry.zig:143-178` parses only command/op/payload; `tools/aegisctl/api/control_api.py:67-72` sends only command/payload.

**Failure:** No protocol-version rejection, issued-at/deadline check, nonce cache, request signature, or replay detection is active. Server-generated audit IDs reset with process state and are not caller identities.

**Impact:** Replayed privileged requests are accepted as new requests; stuck clients have no bounded command deadline; audit records cannot establish caller authenticity.

**Required correction:** Define one canonical envelope, require version/request ID/nonce/deadline, bind it to the authenticated token, reject stale and duplicate requests, and record the authenticated SID/token hash plus runtime generation in the audit entry.

### R-LIFE-004 — `daemonShutdown` publishes STOPPED before worker postcondition (**High**)

**Evidence:** `src/control/handler_registry.zig:551-569` writes the state and returns success before `src/daemon.zig:67-82` performs joins.

**Failure:** The lifecycle state is directly mutated to `STOPPED`; the state-machine transition graph and worker join do not own the transition.

**Impact:** Health/status can claim stopped while workers, pipe handles, or bridge resources are still live. Recovery can race the old owner and create stale-pipe/PID conditions.

**Required correction:** Use `STOPPING` plus request ID/generation, return “accepted/stopping” only, and publish `STOPPED` only after all cancellation, joins, handle closure, pipe release, and evidence flush postconditions pass. A failed join must produce `FAILED` or `DEGRADED`, never `STOPPED`.

### R-LIFE-005 — Health liveness is not reduced from live heartbeat/stall state (**High**)

**Evidence:** `src/control/state_machine.zig:179-189`, `:220-230`; `src/daemon.zig:331-336`, `:472-480`; `src/pipeline/event_processor.zig:216-227`.

**Failure:** Subsystem heartbeat is initialized at startup; only the pipeline watchdog beat was found in the active path. No active `g_wd.check()` or heartbeat-age reducer was found. A worker can exit after readiness without a state transition.

**Impact:** `RUNNING` can persist after a stalled or exited worker. Operational health does not answer which worker stopped or how stale its last beat is.

**Required correction:** Add daemon-owned periodic heartbeat publication for every worker, a watchdog check loop, atomic worker lifecycle records, stale thresholds, and a reducer that transitions to `DEGRADED`/`FAILED` with a reason and generation.

### R-LIFE-006 — PID fallback can report an unrelated process as a runtime subsystem (**High**)

**Evidence:** `tools/aegisctl/api/control_api.py:155-219`; unavailable fallback at `:530-589`.

**Failure:** PID files are trusted if the PID exists. There is no executable identity, command-line, service, creation-time, generation, or pipe-owner check.

**Impact:** PID reuse or stale PID files can make diagnostics claim a subsystem is `RUNNING` when the daemon is unavailable. Top-level fallback PID is the Python client process, not the runtime owner.

**Required correction:** Do not use PID files for operational health. Keep them only as diagnostic hints and validate image path, command line, process creation time, runtime generation, and control endpoint ownership. Require `runtime_available=true` for any operational status claim.

### R-LIFE-007 — Mocked handlers claim verification, export, replay, and policy signatures (**High**)

**Evidence:** `src/control/handler_registry.zig:429-438`, `:445-487`.

**Failure:** `policyValidate` returns `valid=true`; `policyVerify` returns `signatures_valid=true`; `forensicsExport` returns exported success; `forensicsReplay` returns replayed success; `enforcementVerify` returns `verified=true`. These paths do not validate the requested artifact, produce a receipt, or check a provider postcondition.

**Impact:** Operators and automation can treat intent or a fixed response as evidence. This directly conflicts with Rust PEP as sole enforcement authority and receipt-driven host-block claims.

**Required correction:** Return `NOT_IMPLEMENTED`/`UNAVAILABLE` until each handler executes a real operation and independently verifies its postcondition. Enforcement verification must require a supported `EnforcementReceipt`, filter identity, host-effect observation, audit linkage, and forensic linkage.

### R-LIFE-008 — Runtime metrics are split, lossy, and not consistently bound to accepted events (**Medium/High**)

**Evidence:** `src/control/handler_registry.zig:489-505`; `src/pipeline/runtime_state.zig:69-105`; `src/pipeline/event_queue.zig:30-120`; `src/pipeline/telemetry_threads.zig:54-82`.

**Failure:** Snapshot casts 64-bit counters to `u32`, calls Nose submissions `packets_captured`, increments ETW emitted metrics even when queue insertion fails, and uses process-local diagnostic emission counts as event IDs. Most state counters are non-atomic globals. Queue drops are recorded in a separate counter and producer return values are often ignored.

**Impact:** Health and metrics can disagree with actual accepted, processed, dropped, and forensic events. Large counters truncate. Event identity and conservation across restart are unproven.

**Required correction:** Define one atomic runtime ledger with accepted/rejected/capacity/lifecycle drops, per-source identity, generation, and forensic sequence. Serialize 64-bit values without narrowing and increment “emitted” only after the relevant postcondition.

### R-LIFE-009 — Cross-restart/reconnect event identity remains process-local (**Medium/High**)

**Evidence:** `src/capture/nose_pipe_reader.zig:229-232` explicitly limits monotonic checks to one connection; `:285-305` updates the last ID and submits frames; ETW uses `diag.metrics.events_emitted` at `src/pipeline/telemetry_threads.zig:57-81`.

**Failure:** A new producer connection may restart its sequence, and ETW event IDs derive from a process-local metric. Runtime generation/producer epoch is not carried through the active 109-byte path.

**Impact:** Duplicate, collision, or non-monotonic identity across restart can break evidence linkage and exactly-once assumptions.

**Required correction:** Add producer identity, runtime generation, producer epoch, and local sequence to a versioned canonical contract or authoritative ingress envelope. Test reconnect, restart, duplicate, and replay vectors.

### R-LIFE-010 — Legacy scripts preserve a second supervisor and force-kill path (**Medium**)

**Evidence:** `scripts/aegis_daemon.py` contains PID files, process launch, taskkill, watchdog auto-restart; `scripts/aegis_console.py` contains `_kill_all_subsystems()` and `Popen` launch paths; `scripts/stop_aegis.bat` invokes `taskkill`.

**Failure:** These paths can independently start/stop/restart processes even though the active Zig daemon is intended to own lifecycle.

**Impact:** Operators can create two runtime owners, stale PID truth, or a new process before the old named pipes are released.

**Required correction:** Mark these scripts hard-deprecated, make them delegate only to the authenticated daemon/service manager, or remove them from deployable/operator surfaces. Add a test that no normal command can call `taskkill` or write runtime PID truth.

## 9. Contract and authority impact

The intended authority model remains valid only in part:

- **Zig runtime owner:** Mostly present in the active build path. The local supervisor owns worker handles, but stop completion and restart transactions are not authoritative yet.
- **Rust PEP as the only enforcement authority:** The pipeline calls PEP before dispatch in `event_processor`, and the CLI's connected enforcement helper describes the PEP path. However, the control handlers' fixed `enforcementVerify`/`enforcementSimulate` responses and local tooling state files can still create misleading enforcement claims. No host block may be claimed from these responses.
- **Detection/policy/UI cannot claim host block:** Not satisfied by the control API mock responses or any consumer that treats `enforcement.verify` as true without a receipt. The current safe state remains detection-only/degraded.
- **Health must describe reality:** Live health has useful worker flags, but it lacks a live heartbeat reducer and is supplemented by PID/artifact heuristics in Python. The unavailable path is explicitly degraded, which is correct, but its diagnostic process statuses must never be promoted to runtime truth.
- **Audit/evidence:** The audit ring records request IDs, commands, role enum, PID, result, and timing, but not authenticated caller identity, nonce, deadline, runtime generation, provider result, filter identity, or verified postcondition. It is not sufficient evidence for privileged actions.

## 10. Missing tests and proofs

The current test set contains useful model and schema tests, but it does not close the production risks above.

1. **Windows build and binary proof — missing/UNVERIFIED.** `zig build`, `zig build test`, Rust PEP build/tests, native helper build, and runtime launch were not executed on Windows in this sandbox.
2. **Named-pipe ACL proof — missing/UNVERIFIED.** No elevated and standard-user matrix proves that only the intended SID/group can open `\\.\pipe\aegis_control`.
3. **Client-token proof — missing.** No test opens the pipe from a standard user while the daemon is elevated and verifies that `daemon.shutdown`, export, replay, and future enforcement requests are rejected.
4. **Replay/freshness/deadline proof — missing.** No negative vectors reuse a nonce/request ID, submit stale `issued_at_ms`, omit protocol version, or exceed a command deadline.
5. **Blocking-I/O cancellation proof — missing.** No test holds a control read open, sends a partial Nose frame, stops the service, and proves every join completes within a fixed bound.
6. **Shutdown postcondition proof — missing.** No test distinguishes `STOPPING` from `STOPPED`, confirms all worker handles joined, checks pipe release, and records the old runtime generation as exited before starting a new one.
7. **Worker heartbeat proof — missing.** No live test stalls each worker and verifies a health transition with a worker-specific failure reason.
8. **PID reuse proof — missing.** No test places a stale PID or a PID for an unrelated executable and confirms health remains `runtime_available=false`/diagnostic-only.
9. **Metric conservation proof — incomplete.** Queue-full, malformed, rejected, accepted, processed, lifecycle-dropped, and forensic-written events are not tested as one conservation equation across every producer.
10. **Event identity continuity proof — missing.** No current active-path test proves identity uniqueness across Go Nose reconnect, producer restart, daemon restart, ETW/FIM/Registry sources, and forensic records.
11. **Mock-handler negative proof — missing.** No test asserts that export, replay, policy verification, and enforcement verification return unavailable/failed when artifacts or providers are absent.
12. **PEP/WFP host-effect proof — missing/UNVERIFIED.** No Windows elevated VMware proof confirms a real reversible filter effect, receipt, forensic linkage, cleanup, and recovery. File or DLL presence is not evidence.
13. **Legacy-surface exclusion proof — missing.** No packaging/runbook test prevents `scripts/aegis_daemon.py`, `scripts/aegis_console.py`, or batch taskkill paths from being used as the normal lifecycle owner.

The local pytest attempt did not execute because the `pytest` module is absent. This is an environment limitation, not a passing result.

## 11. Prioritized fixes

### P0 — close the security and ownership gates before feature work

1. Replace the null control-pipe security descriptor with a reviewed, tested restrictive SDDL. Add client-token impersonation and explicit SID/integrity/capability checks. Deny on any token/ACL ambiguity.
2. Freeze one control envelope and enforce protocol version, request ID, nonce, freshness, deadline, maximum payload, and replay cache at the pipe boundary. Bind audit to authenticated caller identity and runtime generation.
3. Replace synchronous control/Nose reads with cancellable overlapped I/O or an equivalent close/cancel design. Add a bounded supervisor join transaction and publish `STOPPING` until every join and handle-release postcondition passes.
4. Make all privileged, export, replay, and enforcement handlers fail closed until they execute real operations and return validated evidence. Remove fixed `verified`, `exported`, `replayed`, and `signatures_valid` successes.

### P1 — make health and metrics truthful

1. Add a daemon-owned heartbeat/check loop for every worker, with atomic last-beat timestamps, stale thresholds, worker exit reasons, and generation IDs in health.
2. Define `RUNNING`, `READY`, `DEGRADED`, `FAILED`, `STOPPING`, and `STOPPED` once. Derive state from the same reducer rather than direct handler writes or Python artifact/PID heuristics.
3. Remove PID files from operational health. Retain them only as non-authoritative diagnostics after image, command-line, creation-time, generation, and pipe-owner validation.
4. Replace split mutable counters with a single atomic ingress ledger. Preserve 64-bit values, count push success/failure correctly, and link processed/forensic counters to event IDs and runtime generations.
5. Implement cross-restart producer identity and test duplicate/collision/non-monotonic cases across all active producers.

### P2 — converge tools and lifecycle support

1. Make `aegisctl restart` use one daemon-owned transaction or an explicitly authenticated Windows service manager; do not leave a partial stop/start gap.
2. Remove or quarantine legacy supervisors and taskkill scripts from normal packaging and runbooks.
3. Add live Windows integration tests for ACL/auth, blocking cancellation, worker readiness, postconditioned shutdown, PID reuse, health fallback, and degraded PEP/provider separation.
4. Regenerate and verify build/runtime truth artifacts only after source changes are complete; do not use stale manifests as evidence.

## 12. Exact Windows-only verification commands

The following commands are the minimum verification sequence. They must be run on the intended Windows host, with the privilege level stated for each step. Results are **UNVERIFIED** from this sandbox.

### 12.1 Baseline and build graph

Run from an elevated PowerShell in the repository checkout:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
git rev-parse HEAD
git status --short
git log -1 --oneline
zig version
cargo --version
cmake --version
python --version

zig build
zig build test
cargo build --release
cargo test --release
cmake -B build -S .
cmake --build build --config Release
Set-Location .\nose
go test ./...
go build -o aegis-nose.exe .
Set-Location ..
python -m pytest -q tests\runtime\test_health.py tests\runtime\test_lifecycle_authority.py tests\runtime\test_rust_shield_lifecycle.py
```

A build result is not a runtime or host-effect result. Preserve the exact commit, toolchain versions, and binary hashes.

### 12.2 Start and live health

In an elevated PowerShell window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
zig build run
```

In a second elevated PowerShell window:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
python tools\aegisctl.py health --json
python tools\aegisctl.py status --json
python tools\aegisctl.py metrics --json
Get-Process -Name aegis_nids -ErrorAction SilentlyContinue | Select-Object Id,Path,StartTime
Get-Service -Name AegisNids -ErrorAction SilentlyContinue | Format-List Name,Status,StartType
```

Confirm that the top-level PID is the Zig daemon PID, `runtime_available=true`, worker readiness reflects actual workers, the generation is present if supported, and provider readiness is distinct from PEP readiness. Do not treat a DLL path or a PID-file result as proof.

### 12.3 Named-pipe ACL and client identity

With Sysinternals `accesschk64.exe` available in the test tools directory:

```powershell
accesschk64.exe -nobanner -l \\Device\NamedPipe\aegis_control
Get-Acl -Path '\\.\pipe\aegis_control' | Format-List
```

From a **standard, non-elevated user** while the daemon is elevated, run:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
python tools\aegisctl.py stop --all
$LASTEXITCODE
```

The expected result is an authorization failure and no shutdown. Repeat for any export/replay/enforcement command exposed by the current CLI. Then run the same commands from the explicitly authorized elevated service/operator identity in a disposable lab. The current source is expected to fail this matrix because role derivation uses `GetCurrentProcess()` rather than the connecting client's token; do not weaken the test to make it pass.

### 12.4 Replay, freshness, and deadline negative tests

Use a disposable test host and a small PowerShell-generated request. The implementation must reject missing/old/duplicate security fields once the contract is implemented:

```powershell
$body = '{"command":"daemon.shutdown","payload":{}}'
$body | python -c "import sys; print(sys.stdin.read())"
```

For a real named-pipe test, use a Python harness that calls `CreateFileW('\\\\.\\pipe\\aegis_control', ...)`, sends the same privileged envelope twice, sends an envelope with an old `issued_at_ms`, and holds a connected pipe without sending a complete request. Record response codes and elapsed time. The expected acceptance criteria are: duplicate nonce rejected, stale deadline rejected, malformed envelope rejected, and the held connection cannot prevent bounded daemon shutdown. The current implementation has no active nonce/deadline/replay enforcement, so this proof is expected to expose a defect rather than pass.

### 12.5 Blocking shutdown and worker join proof

Start the daemon, then run a dedicated Windows harness that:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
$before = Get-Date
python tools\probe_control_pipe.py
python tools\aegisctl.py stop --all
Start-Sleep -Milliseconds 500
Get-Process -Name aegis_nids -ErrorAction SilentlyContinue | Select-Object Id,StartTime
Get-Date
```

The real harness must additionally keep one control client connected with no request and one Go Nose client connected after sending only a partial frame. Send the SCM stop control or `daemon.shutdown`, measure the bounded join time, verify every worker has exited, and verify both `\\.\pipe\aegis_control` and `\\.\pipe\aegis_nose` can be recreated by the next generation. A timeout, stale pipe, or surviving old PID is a failed lifecycle proof.

### 12.6 Recovery and stale-PID negative test

After a clean stop, deliberately place a stale PID file or a PID for an unrelated process in the configured PID location. Then run:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
python tools\aegisctl.py health --json
python tools\aegisctl.py status --json
```

Expected behavior is `runtime_available=false` and an explicit diagnostic-only result, never operational `RUNNING`. Repeat with a new daemon generation and confirm that the health PID, process creation time, control-pipe owner, and generation all match.

### 12.7 Degraded PEP/provider proof

On a host where PEP can initialize but WFP/provider is deliberately unavailable, run:

```powershell
Set-Location -Path 'D:\NIDs_Windows'
python tools\aegisctl.py health --json
python tools\aegisctl.py metrics --json
python tools\aegisctl.py forensics verify --json
```

Expected behavior is `pep_ready=true` only if the live PEP is loaded and attested, `provider_ready=false`, `host_effect_capable=false`, `overall_gate=false`, and no command or UI state says `BLOCKED_CONFIRMED`. A present `aegis_pep.dll`, `sec_monitor.dll`, or import library is not sufficient.

### 12.8 Isolated VMware host-effect proof — only after all P0/P1 gates

This is an elevated, destructive-to-network-state test and is **UNVERIFIED** here. Use only the isolated VMnet1 topology and a disposable Windows target confirmed by the operator:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Sort-Object InterfaceAlias,IPAddress
Get-NetIPConfiguration
Get-NetAdapter | Format-Table Name,Status,MacAddress,InterfaceDescription
```

The proof must record reachability before action, authenticated PEP request, provider filter identity, validated `EnforcementReceipt`, host-side blocked reachability, forensic linkage, cleanup, post-cleanup reachability, and absence of stale filters. Do not use Wi-Fi, NAT/VMnet8, a production gateway, localhost, or an unconfirmed private address. No result from this source review or from a unit test authorizes enabling prevention.

## 13. Final disposition

At current HEAD, the runtime spine is identifiable and contains meaningful lifecycle containment, but the security and lifecycle contracts are incomplete. The named pipe is not a proven authenticated privileged boundary; shutdown is not proven bounded; health is not fully heartbeat-driven; PID/artifact fallbacks remain diagnostically dangerous; and several handlers return mocked success. The correct release disposition is:

> **STOP: do not claim production readiness or host blocking. Keep prevention disabled and operate only in detection-only/degraded mode until the P0 and P1 fixes are implemented and the Windows evidence sequence passes.**

## References

[1]: README.md "AEGIS Windows repository README and source-of-truth hierarchy"
[2]: build.zig "Current Zig build graph and Windows executable root"
[3]: src/main.zig "Active executable entrypoint"
[4]: src/daemon.zig "Zig daemon startup, supervisor, readiness, and joins"
[5]: src/platform/win32_pipe.zig "Windows control named-pipe implementation"
[6]: src/control/protocol.zig "Control protocol roles and envelope declaration"
[7]: src/control/handler_registry.zig "Control dispatch, lifecycle handlers, health, metrics, and mocked responses"
[8]: src/control/state_machine.zig "Runtime state, subsystem state, heartbeat, and health serialization"
[9]: src/pipeline/runtime_state.zig "Worker readiness and runtime counter globals"
[10]: src/pipeline/event_queue.zig "Bounded queue and drop accounting"
[11]: src/pipeline/event_processor.zig "Pipeline readiness, watchdog beat, and event processing loop"
[12]: src/capture/nose_pipe_reader.zig "Go Nose named-pipe reader, cancellation, and event identity checks"
[13]: tools/aegisctl.py "Canonical operator CLI and lifecycle boundary"
[14]: tools/aegisctl/api/control_api.py "Control API client, health reducer, and diagnostic fallback"
[15]: scripts/aegis_daemon.py "Legacy process supervisor and watchdog"
[16]: scripts/aegis_console.py "Legacy console process-management path"
[17]: tests/runtime/test_lifecycle_authority.py "Lifecycle authority tests"
[18]: tests/runtime/test_health.py "Health schema and state tests"
[19]: tests/runtime/test_restart.py "Restart policy model tests"
