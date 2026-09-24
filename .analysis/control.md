# AEGIS NIDS Windows — CLI control contracts and operator paths

**Scope.** This report covers the Python `aegisctl` entrypoint and package, the JSON control path, Zig pipe/handler dispatch, policy/rules/enforcement/forensics/simulation operator paths, and duplicate legacy paths. It deliberately does not assess unrelated detection or ABI areas except where they are reached from an operator command.

**Source baseline.** Findings are based on source at the requested current HEAD `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`. `AI_CONTEXT.md`, `AUTHORITY_MAP.json`, `CONTRACT_MAP.json`, and related generated maps identify `688ab566d477105df5f868cee1571fbec77eedfd`; that SHA is stale for this review and is treated as documentation evidence only, not as source truth.

**Evidence notation.** `[S]` means a source/documentation fact inferred from the inspected files; `[R]` means a command executed in this Linux sandbox. No Windows daemon, named pipe, service, or WFP/PEP runtime was available, so `[R]` evidence does not prove Windows runtime behavior.

## Executive summary

The repository contains two materially different control-plane designs. The active daemon path is a JSON named-pipe server: `src/main.zig` → `src/daemon.zig` → `src/platform/win32_pipe.zig` → `src/control/handler_registry.zig` → `src/control/protocol.zig` handlers. The frozen documentation and generated contract map instead point to `src/policy/control_ipc.zig`, a fixed-header binary authorization design with freshness, caller identity, nonce replay protection, and commands such as `block_request`. That older module is not the path initialized by the active Windows daemon. `[S]`

The top-level `tools/aegisctl.py` is the actual executable entrypoint, but it is not consistently a thin control client. Read-only rules/policy/events/forensic operations and most list/show/validate actions read local files; only selected actions call the pipe. Enforcement mutations are intentionally marked unavailable in the top-level CLI, but the Python Brain still invokes a non-existent CLI syntax (`aegisctl block <ip> ...`). A direct runtime probe confirmed that syntax is rejected by argparse. Consequently, the advertised Brain → aegisctl → PEP block path is currently unreachable through the active entrypoint. `[S][R]`

The package under `tools/aegisctl/commands/` is a second, largely dead command surface. Its `register_commands()` functions are all no-ops, while `tools/aegisctl.py` manually constructs its own parser. If these package modules are imported or wired by another caller, they create divergent behavior: local process start/kill, local rules/policy state, UDP simulation, and control commands named `block_request`/`enforce_push` that are not accepted by the active Zig JSON protocol. `[S]`

The active JSON protocol has additional contract gaps: the client sends only `{command,payload}` and does not send the documented caller role, caller identity, request id, issued time, timeout, or nonce; the pipe server assigns a local `operate` role and a daemon-local audit counter. The active response envelope is `{ok,code,state,data,audit_id}`, not the documented `{ok,data,error}`. The error serializer appears to emit an invalid JSON shape because it closes the outer object before appending `audit_id`. Several handlers return hard-coded success or “not implemented” payloads while their command contracts declare mutation/postcondition behavior. `[S]`

## Files and ownership that matter

| Area | File(s) | Finding |
|---|---|---|
| Canonical Python entrypoint | `tools/aegisctl.py` | Manually builds the reachable parser and dispatches `cmd_<top-level>`; this is the path used by `python tools/aegisctl.py`. |
| Python transport | `tools/aegisctl/client.py`, `tools/aegisctl/api/control_api.py`, `tools/aegisctl/utils.py`, `tools/aegisctl/config.py` | Named pipe is the default; TCP is an explicit client-only option; local file/PID fallbacks and audit side files coexist with pipe calls. |
| Package duplicate surface | `tools/aegisctl/commands/*.py`, `tools/aegisctl/commands/__init__.py` | Auto-discovery finds modules, but every inspected `register_commands()` is `pass`; `setup_subcommands()` is not called by the top-level script. |
| Active daemon entry | `src/main.zig`, `src/platform/win32_service.zig`, `src/daemon.zig` | Service/foreground entry starts one runtime owner and eventually serves the control pipe. |
| Active transport | `src/platform/win32_pipe.zig` | Creates `\\.\pipe\aegis_control`, message-mode, one pipe instance, and dispatches JSON to the new handler registry. |
| Active command contract | `src/control/protocol.zig` | 30 enum commands, dotted names, aliases only for `status`, `health`, `health.check`, `version`; role/contract metadata. |
| Active dispatch/handlers | `src/control/handler_registry.zig` | Parses `command` or `op`, authorizes using daemon-local role, finds handler, wraps success, audits, and signals shutdown. |
| Legacy documented protocol | `src/policy/control_ipc.zig` | Fixed binary `CTRL` header, ACL/caller identity/freshness/replay/audit model, different command enum; not connected to `src/platform/win32_pipe.zig`. |
| Rules runtime | `src/pipeline/rule_loader.zig`, `configs/Rules.json` | `rules.reload` reads `configs/Rules.json`; it requires `nids_rules` and `match_pattern`. |
| CLI rules/policy files | `tools/aegisctl.py`, `tools/aegisctl/config.py`, `tools/aegisctl/utils.py` | Several mutations write `config/Rules.json` or `config/disabled_rules.json`, not the daemon's reload path. |
| Legacy operators | `scripts/aegis_daemon.py`, `scripts/aegis_block.py`, `scripts/aegis_api.py`, `scripts/aegis_event_gen.py` | Deprecated or alternate process/UDP/REST/file paths remain executable and diverge from the active pipe contract. |

## Actual call graph

### 1. Active Windows daemon and control request

```text
Windows SCM/foreground process
  -> src/main.zig:main()
  -> platform/win32_service.mainEntry()
  -> daemon.runDaemon()
       -> initialize rules, PEP, bridges, supervisor and workers
       -> start pipeline / legacy sensor / Go Nose reader / ETW / FIM / Registry
       -> control.serveWindowsPipe(&caps, start_ns)
            -> handler_registry.initHandlers()
            -> CreateNamedPipeW("\\\\.\\pipe\\aegis_control", MESSAGE, max_instances=1)
            -> ReadFile(one request per connection)
            -> handleControlRequest()
                 -> Authorizer{}; local role = getLocalRole() = operate
                 -> HandlerContext(request_id = g_pipeline_audit_id, caller_pid, caps)
                 -> handler_registry.dispatch()
                      -> parse JSON object
                      -> command = root.command or root.op
                      -> protocol.Command.fromString()
                      -> auth.authorize(command, caller_role)
                      -> findHandler(command)
                      -> handler(payload, ctx)
                      -> audit.g_audit.record()
                      -> successEnvelope() or errorEnvelope()
                 -> FlushFileBuffers / DisconnectNamedPipe
       -> after serve returns, supervisor.requestStop()
```

`daemon.shutdown` is special: its handler changes the runtime state to `stopped`, sets `g_stop_requested`, calls `bridge_init.requestShutdown()`, and the dispatch result marks `shutdown=true`; only after the pipe loop returns does `runDaemon()` ask the supervisor to stop/join workers. Thus a successful response means “shutdown requested,” not “all workers joined.” `[S]`

### 2. Top-level CLI status/health/readiness

```text
python tools/aegisctl.py status|health|readiness
  -> tools/aegisctl.py main()
  -> import aegisctl.api.control_api
  -> control_api.get_health_payload() / get_all_status()
       -> _query_daemon_retry("system.health" or "system.status")
            -> on Windows: ctypes CreateFileW/WriteFile/ReadFile on \\.\pipe\aegis_control
            -> require response dict with ok=true
       -> if unavailable: _diagnostic_health_payload()
            -> PID/process inspection only for diagnostic subsystem context
  -> CLI renders payload and selects exit code
```

The active daemon recognizes `system.status` and `system.health`; aliases `status`, `health`, and `health.check` are accepted by Zig. The CLI's health fallback is explicit and marked `degraded`, `source=diagnostic`, and `runtime_available=false`, which is safer than treating PID files as runtime health. `[S]`

### 3. Rules path

```text
rules list/show/validate
  -> top-level cmd_rules()
  -> control_api.load_rules()
  -> configs/Rules.json first, then config/Rules.json
  -> local filtering/validation/output

rules add/update/delete
  -> top-level cmd_rules() -> _mutate_rules()
  -> _save_rules() -> config/Rules.json
  -> no daemon request and no reload/postcondition

rules reload
  -> top-level cmd_rules() -> query_control("rules.reload")
  -> active pipe -> handler_registry -> handlers.rulesReload()
  -> pipeline/rule_loader.reloadRules()
  -> reads configs/Rules.json and swaps the active Aho-Corasick pointer
```

The package duplicate `tools/aegisctl/commands/rules.py` has a different local implementation, including `toggle`, and falls back to reporting successful disk reload when the daemon is unreachable. It is not registered by the active entrypoint. `[S]`

### 4. Policy path

```text
policy list/show
  -> top-level cmd_policy()
  -> local rules + config/disabled_rules.json

policy enable/disable/reload
  -> top-level cmd_policy()
  -> _unavailable("policy", "policy_runtime_postcondition_not_connected")

active protocol policy commands (if called directly)
  -> policy.list / policy.validate / policy.verify / policy.simulate
  -> active Zig handlers
  -> mostly counters or constant payloads; no top-level CLI mapping for them
```

The package `commands/policy.py` also provides local enable/disable and a `rules.reload` client call. This creates two policy meanings: local disabled-rule presentation and runtime policy commands. `[S]`

### 5. Enforcement/block/quarantine path

```text
Brain detection
  -> brain/windows_brain.py:request_enforcement_via_pep()
  -> subprocess [python, tools/aegisctl.py, "block", target_ip, "--rule-id", ..., "--reason", ...]
  -> active parser expects block {add,remove,list,clear}; positional IP is rejected
  -> no PEP request reaches Zig
```

The active top-level `cmd_block` intentionally returns `EXIT_RUNTIME_UNAVAILABLE` for every operation except local `block list`. `cmd_quarantine` behaves analogously; `cmd_enforce` allows only local-state `status` and marks mutations unavailable. The package `commands/network.py` is a different path: `block add` calls `control_request("block_request", ...)`, ignores the returned failure, and then writes `logs/blocked_ips.json`; `enforce push` uses `enforce_push`, a name not recognized by the active dotted command enum. `[S]`

### 6. Forensics/events/alerts/simulation

```text
forensics list/verify (top-level plural)
  -> query_control("forensics.list" or "forensics.verify")
  -> active handler registry

forensic show/search/export (top-level singular)
  -> local logs/aegis_core.ndjson read/search/write
  -> no control request

events count/tail/stats
  -> local logs/aegis_core.ndjson read/follow
  -> active events.* handlers are not queried

simulate ...
  -> top-level cmd_simulate()
  -> always _unavailable(... use scripts/aegis_event_gen.py ...)

package simulate attack
  -> UDP JSON to 127.0.0.1:9999 (Brain)

scripts/aegis_event_gen.py
  -> explicit --pipe / --udp / --tcp synthetic-event transports
```

The active Zig handler registry does contain `events.count`, `events.stats`, `events.tail`, `forensics.list/show/verify/export/replay`, and `enforcement.simulate/verify`, but the top-level command surface maps only a subset and often uses local files instead. Several handlers are placeholders or constant success responses. `[S]`

## Contract mismatches and risks

### A. Protocol/version and transport mismatches

1. **Two incompatible control protocols coexist.** `shared/protocol/control_protocol.md` and `CONTRACT_MAP.json` describe the `src/policy/control_ipc.zig` fixed header (`magic`, version, caller hash, role, issued time, timeout, nonce) and commands such as `block.request`, while the active server calls `src/control/handler_registry.zig` and parses a JSON object containing `command`/`op` and `payload`. The active protocol source labels itself “Control Protocol v2,” but the documentation says frozen version 1.0. `[S]` **Risk:** security and interoperability claims can be validated against the wrong implementation.

2. **Documented command names are not the active command names.** The document lists `federation.status`, `block.request`, `unblock.request`, and `quarantine.request`; `src/control/protocol.zig` has no such enum entries. It has `enforcement.*`, `policy.*`, `forensics.*`, and `runtime.*`, plus a few legacy aliases. `federation.status` is even listed in comments in `src/main.zig` tests although no active command maps it. `[S]` **Risk:** runbooks and automation receive `UNKNOWN_COMMAND` or silently follow a local fallback.

3. **TCP is a client-only optional transport.** `AegisClient` supports explicit TCP port 5117, but the active daemon source inspected creates only the named pipe. No active TCP listener is connected in the main call graph. `[S]` **Risk:** `--transport=tcp` is an operator-visible path with no demonstrated server counterpart; it must be removed or implemented and authenticated explicitly.

4. **The named-pipe security contract is incomplete.** The active `CreateNamedPipeW` call supplies `SECURITY_ATTRIBUTES` with a null security descriptor, while the code comment says to replace the OS-default descriptor with tested SDDL/ACL before exposing the pipe outside a local service boundary. The active `Authorizer` defaults every local pipe caller to `operate`; it does not authenticate an identity or validate a caller-supplied role. `[S]` **Risk:** this does not satisfy the documented explicit caller-to-role ACL/no-catch-all/freshness/replay model.

5. **Wire request fields are omitted.** Both Python clients send only `command` and `payload`; `utils.control_request` writes `request_id`/`nonce` only to a local `logs/control_audit.ndjson` record and does not put them in the wire request. The daemon generates a sequential audit request id. `[S]` **Risk:** the documented replay/freshness/caller attribution guarantees are not provided by the active path.

6. **Response schemas disagree, and the error serializer is suspect.** The docs promise `{ok,data,error}`; active success is `{ok:true,code:"OK",state:"OK",data:...,audit_id:...}`. In `handler_registry.errorEnvelope`, the format string appears to write `"}},"audit_id":...` before the final `}`, closing the root object before appending `audit_id`; this would produce invalid JSON for normal handler/authorization errors. `[S]` **Risk:** clients may convert malformed/error responses into generic transport failures or `None`, obscuring authorization and handler failures.

### B. CLI/operator contract mismatches

7. **Brain block invocation is unreachable.** `brain/windows_brain.py` and `tools/aegisctl/api/control_api.py` invoke `block <ip> --rule-id ... --reason ...`, but `tools/aegisctl.py` requires `block add --ip <ip>` and then rejects add as unavailable. A sandbox probe of the exact Brain-style syntax returned argparse exit code 2; `block add --ip 127.0.0.1` returned JSON unavailable with exit code 4. `[S][R]` **Risk:** automatic/manual enforcement is not merely unverified; this call path cannot reach PEP through the active CLI.

8. **No active CLI command reaches a block/quarantine PEP handler.** The active Zig handler registry does not register `block.request`, `unblock.request`, `quarantine.request`, or any `block` command. The top-level CLI intentionally refuses mutation without a verified PEP/WFP postcondition. This is a safe fail-closed state, but it conflicts with docs, Brain comments, and RB-001, which describe an executable manual block flow. `[S]` **Risk:** operators may believe an action was issued because legacy/package paths print success while only local files changed.

9. **Lifecycle semantics are mixed.** Top-level `start` sends `runtime.start`; the Zig handler is an idempotent assertion that succeeds only when the daemon is already `running`/`ready`, and returns `RUNTIME_NOT_READY` otherwise. It does not create workers. Top-level `stop` sends `daemon.shutdown` and correctly says “requested,” but its parser accepts `--component core` while the handler ignores payload and shuts down the daemon owner as a whole. `[S]` **Risk:** component-scoped operator intent is not honored; “start” is named like a process action but is not a process starter.

10. **Stop postcondition is declared but not proven at response time.** `protocol.contract(.daemon_shutdown)` marks mutation and postcondition; the handler only signals state/stop and returns success before supervisor joining occurs. `[S]` **Risk:** automation may treat `ok=true` as fully stopped and race the still-unwinding workers.

11. **Rules path splits between `configs/` and `config/`.** The daemon reload reads `configs/Rules.json`, while CLI mutations use `config/Rules.json` (`_rules_path`, `RULES_FILE`), and package utilities also use `config/Rules.json`. `control_api.load_rules` prefers `configs/Rules.json`. `[S]` **Risk:** an operator can add/update/delete a rule and receive success while the running engine reloads a different file.

12. **Rules/policy list/validation are local approximations.** Top-level list/show/validate read disk and perform Python checks; active Zig handlers provide `rules.list/show/validate` but are not queried for those operations. The Python validator allows `fast_pattern`; the Zig loader reloads only non-empty `match_pattern`. `[S]` **Risk:** CLI “valid” and runtime “loaded” can disagree.

13. **Forensics has two namespaces and inconsistent authority.** `forensics list/verify` queries the control plane, but `forensic show/search/export` reads/writes `logs/aegis_core.ndjson`. The active `forensics.show` handler returns `{"record":null,"status":"not_implemented"}` with a successful handler result; export/replay return constant success-like payloads. `[S]` **Risk:** operator evidence may be local/stale, and success does not imply a record was exported or replayed.

14. **Events/alerts are local-file paths despite active control commands.** `events count/tail/stats` and package `alerts` read/ack local NDJSON. The active Zig handlers use runtime counters/ring state. `[S]` **Risk:** local files can lag, be absent, or represent another process generation; operator displays are not necessarily runtime truth.

15. **Simulation surfaces disagree.** The active top-level `simulate` command always returns unavailable and points operators to `scripts/aegis_event_gen.py`; the package module sends UDP directly to Brain and reports success; the legacy generator can send pipe/UDP/TCP. `[S]` **Risk:** the command name does not identify which ingress, schema, or runtime boundary is exercised.

16. **Constant/placeholder handlers violate postcondition meaning.** `policy.verify` always returns verified, `policy.simulate` always returns no_match, enforcement verify/simulate are constants, `forensics.export` returns a path without performing export, and `forensics.replay` returns zero events. `forensics.show` explicitly says not implemented but still returns a normal handler result. `[S]` **Risk:** `ok=true` and `code=OK` are not proof of the advertised operation.

### C. Duplicate/legacy path risks

17. **Package modules are dead under the current entrypoint but not safe to ignore.** `commands/__init__.py` discovers modules only to call `register_commands()`, and the inspected modules implement that function as `pass`; the top-level script manually defines all parsers. This leaves a second API that looks official but is not wired, and future wiring could suddenly activate divergent behavior. `[S]`

18. **`scripts/aegis_daemon.py` is a second runtime owner.** It starts five independent subprocesses, writes PID files, watchdogs, terminates/kills by pattern, and offers start/stop/restart. The active daemon has a single Zig supervisor and named-pipe lifecycle. The script's deprecated header is not a technical prevention mechanism. `[S]` **Risk:** two owners can race for the same binaries, logs, pipe, or worker state.

19. **`scripts/aegis_block.py` is an old UDP-to-Brain/WFP path.** It sends `{"cmd":"block_ip"}` to UDP 9999 and its documentation still says Brain/core calls `wfp_ioctl.block_ip()`. This directly conflicts with the current PEP-only safety statement and the active top-level CLI fail-closed behavior. `[S]` **Risk:** users can bypass the intended control contract or obtain a false “request sent” acknowledgement.

20. **`scripts/aegis_api.py` is a REST aggregator path.** It reads port 9200 alerts/stats and has a purge mutation, while the active control API uses the Zig pipe for runtime commands and treats the Go aggregator as a diagnostic subsystem. `[S]` **Risk:** REST data and control-plane data can be mistaken for the same authority.

21. **Console/dashboard contain stale API calls.** `commands/console.py` calls `start_all_subsystems`, `stop_all_subsystems`, and `tail_logs` from `control_api`, but the inspected API exposes neither those exact functions nor a connected TUI registration. It also falls back to PID/process and bridge data. `[S]` **Risk:** an alternate UI can fail at runtime or present non-authoritative status.

## Static evidence versus runtime proof

### Static evidence established

- The active Windows source call graph reaches `src/control/handler_registry.zig`, not `src/policy/control_ipc.zig`.
- The active command set, aliases, roles, handlers, response construction, and lifecycle state mutations are visible in `src/control/protocol.zig`, `src/control/authorization.zig`, `src/control/handler_registry.zig`, and `src/platform/win32_pipe.zig`.
- The top-level Python parser and dispatch are visible in `tools/aegisctl.py` lines 811–957; package command registration is visibly inert.
- The Brain's enforcement subprocess syntax and the active parser syntax disagree.
- Rules, events, policy, forensic, block, quarantine, simulation, and lifecycle commands have local-file, UDP, subprocess, or unavailable branches that do not all converge on the active pipe.
- The generated maps/documents are stale with respect to the mandated current HEAD and also reference the legacy binary protocol.

### Runtime proof actually obtained

The following commands were executed on Linux with no Windows daemon:

| Probe | Result | What it proves |
|---|---|---|
| `python3 tools/aegisctl.py health --json` | Exit 0; JSON says `state=DEGRADED`, `source=diagnostic`, `runtime_available=false`, `availability_error=control daemon unavailable...` | The non-Windows fallback is explicit and does not claim runtime health. It does **not** prove Windows pipe behavior. |
| `python3 tools/aegisctl.py rules reload` | Exit 1; `Rules reload failed: daemon control pipe unavailable` | Active top-level reload fails closed when the selected transport is unavailable. |
| `python3 tools/aegisctl.py block add --ip 127.0.0.1` | Exit 4; `pep_wfp_postcondition_not_connected` | Active CLI refuses block mutation without a verified PEP/WFP postcondition. |
| `python3 tools/aegisctl.py block 127.0.0.1 --rule-id TEST --reason probe` | Exit 2; argparse says positional IP is invalid and choices are add/remove/list/clear | The exact Brain/control_api invocation is unreachable through the active parser. |
| `python3 tools/aegisctl.py simulate attack --type SQL_INJECTION` | Exit 4; points to `scripts/aegis_event_gen.py` | Active top-level simulation is intentionally unavailable, not a proof that the package UDP simulator works. |

No probe established successful Windows named-pipe exchange, authorization, handler response, PEP decision, WFP mutation, worker join, or forensic export. Those remain unproven runtime claims.

## Gaps requiring closure

1. There is no one authoritative control protocol artifact regenerated from the active `src/control/protocol.zig`; docs/maps still describe the legacy binary module.
2. There is no Windows-host integration test that sends every advertised CLI command through `\\.\pipe\aegis_control` and validates response schema, role, error codes, and postconditions.
3. The active pipe has no demonstrated explicit SDDL/ACL identity mapping, freshness window, nonce replay protection, or caller-supplied role validation.
4. There is no end-to-end test for Brain detection → CLI invocation → control command → Rust PEP → WFP result. Current source syntax makes the block leg fail before IPC.
5. There is no verified lifecycle test proving `stop` waits for supervisor signal, reverse-order joins, pipe closure, and process exit before success is reported.
6. Rules source ownership is unresolved (`configs/Rules.json` versus `config/Rules.json`), and no test checks that CLI mutation is the exact file the daemon reloads.
7. Forensic export/replay/show and event query handlers lack real postcondition checks and durable evidence assertions.
8. Duplicate package and `scripts/` paths have deprecation headers but no build-time or runtime guard preventing their use.
9. The exact `errorEnvelope` serialization should be tested with invalid JSON, unknown command, authorization denial, and handler failure; static inspection suggests malformed output.
10. No current-HEAD Windows build/runtime evidence was available in this sandbox; all conclusions about named-pipe execution are source-level unless marked `[R]` above.

## Recommended next actions

1. **Choose one protocol owner immediately.** Either retire `src/policy/control_ipc.zig` and regenerate `shared/protocol/control_protocol.md`, `CONTRACT_MAP.json`, and tests from `src/control/protocol.zig`, or make the binary protocol the actual server path. Do not retain two “frozen” contracts.
2. **Generate a machine-readable command matrix from the active enum.** Include exact spelling, aliases, payload schema, required role, mutation flag, postcondition, and CLI mapping. CI should fail on a documented or CLI command absent from the active registry.
3. **Repair the enforcement path before enabling it.** Make Brain and `control_api.request_enforcement_via_pep` invoke the real CLI shape (or expose a real `block.request` handler), pass a structured payload, and require an explicit PEP/WFP result. Keep the current fail-closed behavior until an end-to-end Windows test passes.
4. **Implement one authenticated pipe contract.** Add tested SDDL/ACL and caller identity, define whether roles are transport-derived or request-derived, and implement request id/freshness/nonce replay semantics if those remain contractual. Remove the unauthenticated/dead TCP option or provide a separate authenticated server.
5. **Fix response/error serialization and client handling.** Add cross-language golden tests for success, unknown command, auth denial, handler failure, chunked pipe reads, and `audit_id`; ensure every error is valid JSON and preserves structured `code/state/data`.
6. **Make lifecycle semantics explicit.** `start` should either be a verified supervisor operation or be renamed to an assertion/status operation. `stop` should return a request-accepted state and provide a separate wait/readiness predicate, or wait for joins before returning success. Reject or eliminate misleading component-scoped flags.
7. **Unify rules/policy/forensics/event sources.** Select the daemon-owned paths and route CLI list/show/validate/reload/query/export through control handlers; eliminate local file fallbacks for operations that claim runtime state. Align schema validation with the Zig loader (`nids_rules`, `match_pattern`).
8. **Disable duplicate operator surfaces.** Remove or hard-fail package modules whose registration is inert, and turn deprecated scripts into wrappers that call the canonical CLI with compatible syntax—or remove them after zero-consumer proof. In particular, prevent `aegis_daemon.py` and `aegis_block.py` from creating alternate owners/bypass paths.
9. **Replace constant handlers with real operations or explicit `NOT_IMPLEMENTED`.** A successful envelope must mean the postcondition was checked. Export, replay, verification, policy simulation, and enforcement verification need evidence-backed result schemas.
10. **Add Windows-host proof gates.** Build the current HEAD, launch the service, exercise the full command matrix over the named pipe, test ACL/RBAC and stale/replay requests, prove Brain-to-PEP block/unblock, verify supervisor joins, and archive the raw request/response/audit evidence.

## Bottom line

The safe behavior visible today is the fail-closed behavior of several top-level mutations and the explicit degraded health fallback. The unsafe contract state is the coexistence of a legacy binary protocol, an active JSON protocol, a dead package CLI, local-file mutations, UDP/REST legacy operators, and documentation that names commands not accepted by the active handler registry. Until those paths converge and are proven on Windows, `aegisctl` should be treated as a mixed diagnostic/local-state tool rather than a verified control-plane authority.
