# AEGIS NIDS — Component Lifecycle

> Visual and normative reference for the lifecycle state machine every
> AEGIS component implements. This document is the **state-machine
> authority**; `RUNTIME_CONTRACT.md` defines the timeouts and message
> formats, this document defines the legal transitions and edge cases.

Document version: 1.0
Last updated: 2026-09-01

---

## 1. State machine at a glance

```
                                  ┌──────────────┐
                  start()         │              │
        ┌────────────────────────►│   STARTING   │
        │                          │              │
        │                          └──────┬──────┘
        │                                 │
        │                          ready beacon │ first healthy event
        │                                 │
        │                                 ▼
        │                          ┌──────────────┐
        │                          │              │
        │                          │    READY     │  (transient)
        │                          │              │
        │                          └──────┬──────┘
        │                                 │
        │                          ready_timeout
        │                                 │
        │                                 ▼
        │                          ┌──────────────┐
        │   stop()                  │              │
        │  ┌───────────────────────►│   STOPPED    │◄───── grim_reap (FAILED)
        │  │                         │              │
        │  │                         └──────────────┘
        │  │                                 ▲
        │  │                                 │ stop()
        │  │                                 │
        │  │                          ┌──────┴──────┐
        │  │                          │              │
        │  └───────────────────────── │   RUNNING    │
        │                            │              │
        │                            └──────┬──────┘
        │                                   │
        │                            soft fail (health)
        │                                   │
        │                                   ▼
        │                            ┌──────────────┐
        │      k consecutive          │              │
        │      healthy                 │   DEGRADED   │
        │      ◄──────────────────────│              │
        │                            └──────┬──────┘
        │                                   │
        │                            degrade_window elapsed
        │                            OR hard fail (panic, schema)
        │                                   │
        │                                   ▼
        │                            ┌──────────────┐
        │                            │              │
        └───────────────────────────►│    FAILED    │
                                     │              │
                                     └──────────────┘
                                              │
                                       restart backoff
                                       (8 attempts, capped)
                                              │
                                              ▼
                                         back to STOPPED
                                         (then STARTING)
```

---

## 2. State table

Numeric IDs match `RUNTIME_CONTRACT.md` §2. The "Sticky?" column indicates
whether the supervisor is allowed to leave the component in that state
without further action.

| ID | State       | Sticky? | Meaning                                                              |
|----|-------------|---------|----------------------------------------------------------------------|
| 0  | `STOPPED`   | yes     | Idle. Resources released.                                            |
| 1  | `STARTING`  | no      | Inside startup window. Must transition within `startup_timeout`.    |
| 2  | `READY`     | no      | Initialization done, awaiting first event. Transient.               |
| 3  | `RUNNING`   | yes     | Steady state.                                                        |
| 4  | `DEGRADED`  | no      | Health-check failing softly. Auto-recovers if `k` healthy in a row. |
| 5  | `FAILED`    | no      | Hard failure or restart budget exhausted.                            |

Non-sticky states MUST transition within their respective timeouts. A
component stuck in a non-sticky state is, by definition, in violation of
the contract and is force-rolled to `STOPPED` (or `FAILED` if it cannot be
stopped cleanly).

---

## 3. Legal transitions (authoritative list)

Only the transitions in this table are valid. Any other transition is a
`CONTRACT_VIOLATION` error (see `RUNTIME_CONTRACT.md` §6 error classes).

| # | From        | To          | Trigger                                                | Side effects |
|---|-------------|-------------|--------------------------------------------------------|--------------|
| 1 | `STOPPED`   | `STARTING`  | Supervisor invokes `start()`                            | Create PID file, allocate pipes/ports |
| 2 | `STARTING`  | `READY`     | Component emits ready beacon                            | Log `STATUS state=READY` |
| 3 | `READY`     | `RUNNING`   | First healthy event processed                          | Log `STATUS state=RUNNING` |
| 4 | `STARTING`  | `FAILED`    | Startup timeout elapsed                                | Log `ERROR class=STARTUP_TIMEOUT` |
| 5 | `RUNNING`   | `DEGRADED`  | Soft health-check failure                              | Log `STATUS state=DEGRADED` |
| 6 | `RUNNING`   | `FAILED`    | Hard failure (panic, schema mismatch, process exit)    | Log `ERROR class=<...>` |
| 7 | `DEGRADED`  | `RUNNING`   | `k` consecutive healthy checks                          | Log `STATUS state=RUNNING` |
| 8 | `DEGRADED`  | `FAILED`    | Degrade window elapsed without recovery                | Log `ERROR class=DEP_DEGRADED` |
| 9 | `RUNNING`   | `STOPPED`   | Supervisor invokes `stop()`                            | Drain → flush → close |
| 10| `DEGRADED`  | `STOPPED`   | Supervisor invokes `stop()`                            | Drain → flush → close |
| 11| `READY`     | `STOPPED`   | Supervisor invokes `stop()` before first event          | Immediate close |
| 12| `FAILED`    | `STOPPED`   | Process reaped by supervisor                           | Quarantine if `attempts >= max_restarts` |
| 13| `FAILED`    | `STARTING`  | Restart backoff elapsed and attempts < max             | Increment attempt counter |

Transitions **explicitly forbidden**:

- `STOPPED` → any state other than `STARTING`
- `RUNNING` → `READY` (a component cannot "un-run")
- `RUNNING` → `STARTING` (a restart must go through `STOPPED`)
- Any → `STOPPED` from a state other than those listed in §3 rows 9–12

---

## 4. Edge cases

### 4.1 Double-start (idempotent start)

If `start()` is called while the component is already in `STARTING`,
`READY`, or `RUNNING`, the supervisor MUST return success without doing
anything. Idempotency is required so that `aegisctl start --all` can be
re-run safely after a partial failure.

### 4.2 Double-stop (idempotent stop)

Same rule for `stop()`. Calling `stop()` on a `STOPPED` component returns
success and does not log an error.

### 4.3 Restart storm protection

If a component transitions `FAILED → STOPPED → STARTING → FAILED` more
than `max_restarts` (default 8) times within a 5-minute window, the
supervisor:

1. Writes `logs/quarantine/<comp>.json` with the failure history.
2. Sets the component state to `STOPPED` and refuses to start it again.
3. Emits a `SYSTEM_FAILED` event if the component is `Required = yes`.
4. Emits a `SYSTEM_DEGRADED` event if the component is `Required = no`.

Quarantine is cleared by `aegisctl unquarantine <comp>`.

### 4.4 Dependency unavailable

When a component's required dependency enters `FAILED`:

- The dependent component transitions `RUNNING → DEGRADED` immediately.
- It does NOT transition to `FAILED` on its own; that would compound the
  failure.
- When the dependency recovers (`RUNNING`), the dependent is allowed up
  to `degrade_window` to return to `RUNNING` itself.

### 4.5 Lost PID file

If the PID file is missing or stale (points to a non-existent or wrong
process), the supervisor:

1. Performs a port/pipe probe.
2. If the probe succeeds, the supervisor adopts the existing process and
   rewrites the PID file.
3. If the probe fails, the supervisor marks the component `FAILED` and
   invokes the restart policy.

### 4.6 Zombie processes (Windows-specific)

On Windows, a process can exit but leave its handle open. The supervisor
detects this via `WaitForSingleObject` on the adopted handle. If the wait
returns `WAIT_OBJECT_0` but the health probe still answers, the supervisor
treats the situation as a `CONTRACT_VIOLATION` (the process answering is
not the one in the PID file) and quarantines the component.

### 4.7 Health-probe latency spike

A probe that takes longer than `health_probe_ms` (default 500 ms) is a
soft failure. Three consecutive slow probes escalate to a hard failure
because they suggest the component is too loaded to answer control-plane
messages.

---

## 5. State persistence

The supervisor persists the current state of every component to
`logs/runtime/states.json` every `health_interval` (default 1 s). This
file is the authoritative source of truth for `aegisctl status` and for
recovery after a supervisor restart.

```json
{
  "v": 1,
  "ts": 1725148800123,
  "components": {
    "bridge":     { "state": "RUNNING", "pid": 1234, "uptime_ms": 18217, "attempts": 1 },
    "core":       { "state": "RUNNING", "pid": 1240, "uptime_ms": 18150, "attempts": 1 },
    "brain":      { "state": "DEGRADED","pid": 1250, "uptime_ms": 17980, "attempts": 2 },
    "nose":       { "state": "RUNNING", "pid": 1260, "uptime_ms": 17890, "attempts": 1 },
    "aggregator": { "state": "RUNNING", "pid": 1270, "uptime_ms": 17800, "attempts": 1 }
  }
}
```

On supervisor startup, the file is read. Components still alive (PID
valid, probe answers) are adopted. Components whose PID is stale are
restarted.

---

## 6. Audit trail

Every state transition emits one entry to `logs/runtime/audit.ndjson`:

```json
{
  "v": 1,
  "ts": 1725148800123,
  "component": "core",
  "from": "RUNNING",
  "to": "DEGRADED",
  "reason": "health_probe_timeout",
  "attempts": 1,
  "supervisor_pid": 1100
}
```

The audit log is append-only and is the source of truth for post-mortem
analysis. Operators SHOULD NOT edit it. Rotation follows the same rules
as the forensic log (100 MB, 3 generations).

---

## 7. Visual: full system view

Below is the system-level view that ties together all components defined in
`COMPONENT_MATRIX.md`. Arrows show data flow, not state transitions.

```
   ┌────────────────────────────────────────────────────────────┐
   │                   KERNEL (Gate D)                          │
   │  ┌──────────────┐                ┌──────────────┐          │
   │  │ wfp-callout  │                │  minifilter  │          │
   │  └──────┬───────┘                └──────┬───────┘          │
   └─────────┼───────────────────────────────┼──────────────────┘
             │ IOCTL                          │ pipe
             ▼                                ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                    USER MODE                                │
   │                                                             │
   │   ┌──────────┐    events    ┌──────────────────────┐        │
   │   │  bridge  │◄─────────────│   core (Zig)         │        │
   │   │  (C++)   │              │  ┌─────────────────┐  │        │
   │   └────┬─────┘              │  │ shield (Rust)  │  │        │
   │        │ ring buffer        │  └─────────────────┘  │        │
   │        │                    └──────┬───────────────┘        │
   │        │                           │ UDP 9999               │
   │        │                           ▼                        │
   │        │                  ┌──────────────────┐               │
   │        │                  │   brain (Py)     │               │
   │        │                  └──────┬───────────┘               │
   │        │                         │ NDJSON                     │
   │        ▼                         ▼                            │
   │   ┌──────────────────────────────────────────┐               │
   │   │   aggregator (Go)  ──► :9200 REST       │               │
   │   └──────┬──────────────────────────────────┘               │
   │          │                                                    │
   │          ├──► nose (Go) ──► stdout JSON                      │
   │          ├──► mouth (Rust) ──► DEFCON TUI                    │
   │          ├──► metrics ──► :9100                               │
   │          ├──► notifier ──► email/webhook                     │
   │          └──► dashboard (Rust) ──► :8080                     │
   └─────────────────────────────────────────────────────────────┘
```

Each box in the diagram maps to a row in `COMPONENT_MATRIX.md` and follows
the state machine in §1.

---

## 8. References

- `docs/runtime/RUNTIME_CONTRACT.md` — states, timeouts, error classes.
- `docs/runtime/COMPONENT_MATRIX.md` — component inventory.
- `docs/runtime/LOCAL_RUNBOOK.md` — operator runbook.
- `docs/architecture/RUNTIME_SPINE.md` — 12-stage pipeline view.
- `docs/architecture/FAILURE_MODEL.md` — fail-soft model.
