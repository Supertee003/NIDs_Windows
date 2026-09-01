# AEGIS NIDS — Runtime Contract

> Authority file for component runtime behavior. Every component listed in
> `COMPONENT_MATRIX.md` MUST honor this contract before it is allowed to
> progress past Gate A (Runnable).

Document version: 1.0
Last updated: 2026-09-01
Scope: All 7 engines (Nose / Core / Brain / Flow / Policy / PEP / Forensic)
       plus all auxiliary processes (Go Aggregator, Rust Mouth, C++ Bridge).

---

## 1. Purpose

This document defines the **operational contract** every AEGIS component
must satisfy so that `aegisctl` (and any other supervisor) can drive the
system in a uniform way. The contract specifies:

1. The set of lifecycle states a component can be in.
2. The timeouts that bound each transition.
3. The health-check contract a component must expose.
4. The restart policy applied on failure.
5. The wire format for `STATUS`, `HEALTH`, and `ERROR` messages.

Any component that violates this contract is, by definition, **not runnable**
and cannot advance past Gate A.

---

## 2. Lifecycle States

Every component implements the following five-state lifecycle. No other
states are permitted.

| State       | Numeric | Meaning                                                                       |
|-------------|---------|-------------------------------------------------------------------------------|
| `STOPPED`   | 0       | Process not running. Resources released. PID file absent.                     |
| `STARTING`  | 1       | Process spawned, but not yet ready to serve. Inside startup timeout window.    |
| `READY`     | 2       | Process finished initialization. May not yet be processing events. Transient.  |
| `RUNNING`   | 3       | Process is processing events and reporting healthy on every health check.      |
| `DEGRADED`  | 4       | Process is alive but health check failed for at least one cycle. Non-fatal.   |
| `FAILED`    | 5       | Process exited unexpectedly, or exceeded hard failure threshold.              |

> `READY` is intentionally a transient state. A component that lingers in
> `READY` longer than the startup timeout is treated as `FAILED`.

### 2.1 State Transition Rules

```
            start()                         first healthy event
STOPPED  ───────────►  STARTING  ─────────────────────────────►  RUNNING
                          │                                          │
                          │ startup_timeout                          │ health check fail (soft)
                          ▼                                          ▼
                       FAILED                                   DEGRADED
                                                                     │
                                                                     │ degrade_window expires
                                                                     ▼
                                                                  RUNNING  ◄── recover (k consecutive healthy)
                                                                     │
                                                                     │ health check fail (hard)
                                                                     ▼
                                                                  FAILED
                                                                     │
                                                                     │ stop() / restart()
                                                                     ▼
                                                                  STOPPED
```

Valid transitions (everything else is a contract violation):

| From       | To         | Trigger                                   |
|------------|------------|-------------------------------------------|
| STOPPED    | STARTING   | `start()` invoked                         |
| STARTING   | READY      | Process opened IPC / wrote ready beacon   |
| READY      | RUNNING    | First healthy event processed             |
| STARTING   | FAILED     | Startup timeout exceeded                  |
| RUNNING    | DEGRADED   | Soft health-check failure                 |
| RUNNING    | FAILED     | Hard health-check failure or process exit |
| DEGRADED   | RUNNING    | `k` consecutive healthy checks            |
| DEGRADED   | FAILED     | Degrade window elapsed without recovery  |
| FAILED     | STOPPED    | `stop()` or auto-restart backoff elapsed  |
| RUNNING    | STOPPED    | `stop()` invoked                          |
| DEGRADED   | STOPPED    | `stop()` invoked                          |

---

## 3. Timeouts

All timeouts are **upper bounds**, not targets. A healthy component should
complete each transition in a small fraction of its budget.

| Transition                  | Default | Configurable via                | Hard ceiling |
|-----------------------------|---------|---------------------------------|--------------|
| `STOPPED` → `READY`         | 5 s     | `AEGIS_STARTUP_TIMEOUT_MS`      | 30 s         |
| `READY` → `RUNNING`         | 2 s     | `AEGIS_READY_TIMEOUT_MS`        | 10 s         |
| Health-check interval       | 1 s     | `AEGIS_HEALTH_INTERVAL_MS`      | 5 s          |
| Health-check probe timeout  | 500 ms  | `AEGIS_HEALTH_PROBE_MS`         | 2 s          |
| Soft-fail degrade window    | 5 s     | `AEGIS_DEGRADE_WINDOW_MS`        | 30 s         |
| Recovery threshold (k)       | 3       | `AEGIS_RECOVERY_K`              | 10           |
| `RUNNING` → `STOPPED`       | 3 s     | `AEGIS_SHUTDOWN_TIMEOUT_MS`     | 15 s         |
| `FAILED` → `STOPPED` (grim) | 2 s     | `AEGIS_GRIM_REAP_MS`            | 10 s         |

Notes:

- The startup timeout includes binary load, configuration parse, dependency
  handshake, and the first heartbeat. If a component needs longer it must
  emit an explicit `STARTING_PROGRESS` beacon with a remaining-estimate
  field; the supervisor may grant a single extension up to the hard ceiling.
- The shutdown timeout covers drain of in-flight events. After it expires
  the supervisor issues `SIGKILL` (Windows: `TerminateProcess`).
- The degrade window must be at least `k × health-check interval` so a
  component has a fair chance to recover.

---

## 4. Health-Check Contract

Every component MUST expose a health probe reachable **without** spawning
a child process. Acceptable transports (any one is sufficient):

| Transport              | Use case                              | Contract                                              |
|------------------------|---------------------------------------|-------------------------------------------------------|
| Named pipe             | Windows-native, low latency           | `\\.\pipe\aegis-<comp>-health` returns JSON in <500 ms |
| TCP loopback           | Cross-language, easy to test          | `127.0.0.1:<port>/health` returns JSON in <500 ms     |
| File beacon             | Components without IPC (Cython, etc.) | `logs/health/<comp>.json` mtime within `<health_interval × 2>` |
| Stdout JSON line        | Headless collectors (Nose)            | Last line on stdout within `<health_interval × 2>`   |

### 4.1 Health response schema

```json
{
  "component":   "core",
  "state":       "RUNNING",
  "pid":         12345,
  "uptime_ms":   98217,
  "last_event_ms": 412,
  "counters": {
    "in_events":     1024,
    "out_events":    1023,
    "errors":        0,
    "dropped":       0
  },
  "deps": [
    { "name": "bridge",  "state": "RUNNING" },
    { "name": "fabric",  "state": "RUNNING" }
  ]
}
```

Field semantics:

- `state` MUST match one of the values in §2.
- `last_event_ms` is the time since the component processed (or emitted) its
  last event. A stale value (> `5 × health_interval`) is a soft failure.
- `counters.dropped > 0` is a soft failure if it increased since the last
  probe; hard failure if it increased by more than `0.1%` of `in_events`.
- `deps[].state` MUST reflect the component's own view of its dependencies.
  If a dependency is not `RUNNING`, the component MUST report `DEGRADED`.

### 4.2 Probe execution

- The supervisor (`aegisctl` or a parent process) issues the probe every
  `health_interval` ms.
- A probe that does not respond within `health_probe_ms` is a soft failure.
- A probe whose response fails JSON schema validation is a hard failure.

---

## 5. Restart Policy

A component that lands in `FAILED` triggers the restart policy. The policy
is **exponential backoff with cap and jitter**, identical to AWS SDK v2.

| Attempt | Base delay | Jitter (±) | Total wait |
|----------|------------|------------|------------|
| 1        | 250 ms     | 100 ms     | ~250 ms    |
| 2        | 500 ms     | 150 ms     | ~750 ms    |
| 3        | 1 s        | 300 ms     | ~1.75 s    |
| 4        | 2 s        | 500 ms     | ~3.75 s    |
| 5        | 4 s        | 1 s        | ~7.75 s    |
| 6        | 8 s        | 2 s        | ~15.75 s   |
| 7        | 16 s       | 4 s        | ~31.75 s   |
| 8+       | 30 s (cap) | 5 s        | ~30 s      |

Policy details:

- **Max attempts** before the supervisor escalates to a `SYSTEM_FAILED`
  event: 8 (configurable via `AEGIS_MAX_RESTARTS`).
- **Restart window reset**: if the component stays `RUNNING` for 60 s,
  the attempt counter resets to 1.
- **Required dependencies** (see `COMPONENT_MATRIX.md`): if a required
  dependency is `FAILED`, the dependent component is marked `DEGRADED`
  and is not restarted until the dependency recovers.
- **Optional dependencies**: a missing optional dependency MUST NOT block
  startup. The component reports `DEGRADED` and continues.
- **Quarantine**: after `max_restarts` consecutive failures the supervisor
  writes `logs/quarantine/<comp>.json` and stops attempting. Quarantine is
  cleared only by an explicit `aegisctl unquarantine <comp>` command or a
  supervisor restart.

---

## 6. Wire Format — Status, Health, Error

All control-plane messages between a component and its supervisor use a
single NDJSON envelope. Each line is one message.

```json
{
  "v":   1,
  "ts":  1725148800123,
  "src": "core",
  "kind": "STATUS",
  "state": "RUNNING",
  "pid": 12345,
  "data": { /* see per-kind schema below */ }
}
```

| `kind`     | `data` schema                                              |
|------------|------------------------------------------------------------|
| `STATUS`   | same as health response (§4.1)                              |
| `HEALTH`   | same as health response (§4.1) plus `probe_latency_ms`     |
| `ERROR`    | `{ "class": "<error_class>", "msg": "<text>", "recoverable": bool }` |
| `STARTING_PROGRESS` | `{ "phase": "<phase_name>", "remaining_ms": <int> }` |

Error classes (closed set):

| Class                  | Recoverable | Meaning                                                  |
|------------------------|-------------|----------------------------------------------------------|
| `STARTUP_TIMEOUT`      | yes         | Component exceeded startup budget                         |
| `DEP_UNAVAILABLE`      | yes         | A required dependency is `FAILED`                        |
| `DEP_DEGRADED`         | yes         | A required dependency is `DEGRADED`                       |
| `RESOURCE_EXHAUSTED`   | yes         | Memory / fd / queue capacity hit                         |
| `CONFIG_INVALID`       | no          | Configuration parse failed                                |
| `CONTRACT_VIOLATION`   | no          | Component emitted a state/event that violates this doc    |
| `PANIC`                | no          | Native panic / `abort()` / `std.debug.assert` failure    |
| `UNKNOWN`              | maybe       | Catch-all; should be refined before next release           |

---

## 7. Signal Handling

| Signal       | Windows equivalent        | Expected behavior                                  |
|--------------|---------------------------|----------------------------------------------------|
| `SIGINT`     | `CTRL_C_EVENT`            | Begin graceful drain. Stop accepting new events.   |
| `SIGTERM`    | `CTRL_BREAK_EVENT`        | Same as `SIGINT` but skips drain. Flush + exit.    |
| `SIGKILL`     | `TerminateProcess`        | Immediate. Used only after `shutdown_timeout`.     |

A component that does not finish draining within `shutdown_timeout` after
receiving `SIGINT` is force-killed by the supervisor. Components MUST NOT
perform blocking I/O during drain that cannot be interrupted.

---

## 8. Logging Contract

Every component writes:

- A process log at `logs/<comp>.log` (NDJSON, append-only, rotated at
  100 MB with 3 generations).
- A health beacon at the transport chosen in §4.
- A PID file at `logs/pids/<comp>.pid` on startup, removed on clean exit.

Log levels follow RFC 5424 (`DEBUG`, `INFO`, `NOTICE`, `WARNING`, `ERROR`,
`CRITICAL`, `ALERT`, `EMERG`). The supervisor only surfaces `WARNING` and
above to the operator console by default.

---

## 9. Conformance Checklist

A component is "Gate-A runnable" iff it satisfies ALL of the following:

- [ ] Implements all five states in §2 and refuses illegal transitions.
- [ ] Honors every timeout in §3 or declares an explicit override.
- [ ] Exposes one of the four health transports in §4.1.
- [ ] Emits `STATUS`, `HEALTH`, and `ERROR` messages per §6.
- [ ] Handles `SIGINT` / `SIGTERM` per §7.
- [ ] Writes logs and PID file per §8.
- [ ] Passes `tests/runtime/test_contract_<comp>.py` (skeletons in
      `tests/runtime/`).

Failure on any single item blocks promotion past Gate A.

---

## 10. References

- `docs/runtime/COMPONENT_MATRIX.md` — component inventory.
- `docs/runtime/LIFECYCLE.md` — visual state machine and edge cases.
- `docs/runtime/LOCAL_RUNBOOK.md` — operator runbook.
- `docs/architecture/ARCHITECTURE_CANONICAL.md` — architectural truth.
- `docs/architecture/FAILURE_MODEL.md` — fail-soft and stop-the-line rules.
