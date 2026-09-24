# LIFECYCLE-001 — Daemon Authority Patch Evidence

**PATCH-ID:** `LIFECYCLE-001-DAEMON-AUTHORITY`  
**FLOW-ID:** `CLI-LIFECYCLE-TO-DAEMON-001`  
**TARGET HEAD:** `46b93dcf9cca17b323ddff7a4c71e33e81c37fb5`  
**FINAL HEAD:** pending repository commit; working-tree patch verified 17 September 2026  
**Evidence level:** E2 for Python control-plane contract; E1/static for Zig source because Zig toolchain is unavailable in the sandbox

## Target files and symbols

The patch changes `tools/aegisctl.py` at `cmd_start`, `cmd_stop`, `cmd_restart`, and the CLI parser. It changes `src/control/handler_registry.zig` at `handlers.runtimeStart`. It adds `tests/runtime/test_lifecycle_authority.py`.

## Scope

The normal CLI lifecycle path no longer creates or kills processes. `start` sends `runtime.start` to the daemon. `stop` sends `daemon.shutdown` and reports that shutdown was requested. `restart` refuses to perform a partial stop/start transaction until one owner can prove stop, worker join, start, and readiness. The Zig start handler is idempotent only when the current daemon owner is already `READY` or `RUNNING`; it never creates a second worker set.

## Out of scope

This patch does not implement worker creation from a control handler. It does not implement restart. It does not add an emergency kill command. It does not claim Windows host lifecycle proof. It does not change PEP/WFP authority.

## Old flow → new flow

```text
OLD start:
  CLI -> executable/PID inspection -> subprocess.Popen -> PID file -> optimistic success

NEW start:
  CLI -> AegisClient -> runtime.start -> Zig state-machine proof -> response

OLD stop:
  CLI -> daemon shutdown when available, otherwise possible process-kill fallback

NEW stop:
  CLI -> AegisClient -> daemon.shutdown -> stop signal/bridge shutdown -> pipe loop exits -> RuntimeSupervisor joins workers

OLD restart:
  CLI -> stop -> sleep -> start, even when stop/start postconditions were not proven

NEW restart:
  CLI -> explicit RUNTIME_RESTART_UNAVAILABLE; no partial mutation
```

## Invariants

The CLI cannot claim `start` success without `ok=true` from the daemon. Normal start and stop do not call `Popen`, `taskkill`, PID-file mutation, or executable-presence inference. A `runtime.start` request cannot create duplicate workers. The daemon remains the only owner of worker handles and join order. Restart cannot mutate runtime state until a complete transaction exists.

## Contract, ABI, authority, and state impact

The control command contract is reused: `runtime.start` and `daemon.shutdown` remain versioned control requests. There is no ABI change. Authority moves normal start/stop mutation from the Python CLI to the Zig daemon. The start handler adds an idempotent proof response for `READY/RUNNING`; other states return `RUNTIME_NOT_READY`. Stop is asynchronous from the CLI perspective and reports request acceptance rather than completed join.

## Test result

The following targeted suite passed:

```text
python3 -m unittest tests.runtime.test_lifecycle_authority tests.runtime.test_health tests.runtime.test_aegisctl -v
Ran 42 tests in 36.298s
OK
```

Python compilation passed for the changed Python files. `git diff --check` passed for all changed files. Static inspection confirms `cmd_start`, `cmd_stop`, and `cmd_restart` contain no `Popen` path. The Zig formatter/build could not run because `zig` is not installed in the sandbox; this is an open verification blocker, not a claimed build pass.

## Windows result

Not run in this sandbox. Windows live proof remains required: core health pipe response, orderly stop, worker join, process exit, and subsequent clean start by the Windows service manager or supported launcher.

## Rollback

Revert the three patch files and remove `tests/runtime/test_lifecycle_authority.py`. Do not restore the old process-mutating normal start path without an explicit replacement authority review.

## Remaining risk and open blockers

The Zig `RuntimeSupervisor` remains local to `runDaemon()`. This is sufficient for shutdown after `daemon.shutdown`, but it is not yet a reusable transaction object for restart. The CLI's `restart` command therefore remains intentionally unavailable. Zig build and formatter verification require the supported Windows/Zig build environment. Machine maps and evidence index must be rebuilt against the eventual committed final HEAD.

## Completion gate

The control-plane portion of `LIFECYCLE-001` is complete at E2/E1. The overall lifecycle phase is not complete until the Zig build passes, Windows lifecycle integration passes, and restart is implemented or delegated to a verified external service manager.

## Post-patch rebaseline actions

After commit on the repository branch, rebuild the affected machine maps, update `EVIDENCE_INDEX.json`, record the final HEAD, and update the current phase status. Do not treat the pre-patch maps as current truth.
