# AEGIS NIDS — Component Matrix

> Single source of truth for every runnable component in the AEGIS runtime.
> Each row corresponds to one process (or loadable module) that the
> supervisor (`aegisctl`) must be able to BUILD, START, READY, HEALTH, STOP,
> RESTART, and VERSION per `RUNTIME_CONTRACT.md`.

Document version: 1.0
Last updated: 2026-09-01

---

## 1. How to read this matrix

A component is a unit the supervisor treats as a single managed entity.
Two binaries that always run together (e.g. WFP callout driver + its user-mode
controller) are merged into one row. Two binaries that can run independently
are split into two rows.

The columns are:

| Column          | Meaning                                                                |
|-----------------|------------------------------------------------------------------------|
| `Component`     | Stable identifier used by `aegisctl` (kebab-case).                     |
| `Binary`        | Artifact path relative to repo root, OR `internal` if in-process.     |
| `Language`      | Implementation language(s).                                            |
| `Inputs`        | What the component consumes (files, pipes, ports, queues).            |
| `Outputs`       | What the component produces.                                          |
| `Dependencies`  | Components that MUST be `RUNNING` before this one can `START`.        |
| `Start`         | How the supervisor launches it.                                       |
| `Health`        | Transport used by the supervisor to probe it.                         |
| `Stop`          | How the supervisor stops it (always graceful first, then force).      |
| `Required`      | `yes` = system cannot serve events without it. `no` = degraded mode OK. |
| `Gate`          | First gate (A–F) at which the component must be operational.          |

A dependency marked with `*` is a **soft** dependency: its absence puts the
component into `DEGRADED` instead of blocking startup.

---

## 2. Component inventory

### 2.1 Primary engines (Gate A — Runnable)

| Component        | Binary                       | Language | Inputs                                  | Outputs                                  | Deps                  | Start                              | Health                                | Stop           | Required | Gate |
|------------------|------------------------------|----------|-----------------------------------------|------------------------------------------|-----------------------|------------------------------------|---------------------------------------|----------------|----------|------|
| `bridge`         | `build/Release/aegis_bridge.exe` | C++      | named pipe `aegis-ipc`                  | `aegis_ipc.dll`, ring buffer events     | (none)                | `aegis_bridge.exe`                 | `\\.\pipe\aegis-bridge-health` (JSON) | SIGINT → 3s → kill | yes | A |
| `core`           | `zig-out/bin/aegis-nids.exe`  | Zig      | events from bridge, WFP, minifilter, pipe sensor | NDJSON forensic log, brain UDP alerts   | `bridge`*             | `aegis-nids.exe`                   | `\\.\pipe\aegis-core-health` (JSON)   | SIGINT → 3s → kill | yes | A |
| `brain`          | `brain/windows_brain.py`      | Python + Cython | UDP 9999 alerts, rules.json             | firewall IPS actions, brain log         | `core`*               | `python windows_brain.py`         | `127.0.0.1:9999/health` (JSON)        | SIGINT → 3s → kill | yes | A |
| `nose`           | `nose/aegis-nose.exe`         | Go       | core NDJSON, /proc-style counters       | JSON to stdout, threat map              | `core`*               | `aegis-nose.exe` (background)      | stdout JSON beacon                    | SIGINT → 2s → kill | no  | A |
| `mouth`          | `mouth/windows_sec_monitor.exe` | Rust    | core NDJSON, DEFCON inputs              | DEFCON TUI (single window)             | `core`*               | `windows_sec_monitor.exe`          | `\\.\pipe\aegis-mouth-health` (JSON)  | SIGINT → 3s → kill | no  | A |
| `shield`         | `target/release/sec_monitor.dll` | Rust   | in-process FFI from core                | payload safety verdict                  | (loaded by core)      | (loaded by core)                    | `\\.\pipe\aegis-core-health` (via core) | (unloaded by core) | yes | A |
| `aggregator`     | `go/aggregator/aegis-aggregator.exe` | Go    | `logs/aegis_core.ndjson` (fsnotify)     | dedup + correlation, REST API :9200     | `core`*               | `aegis-aggregator.exe`             | `127.0.0.1:9200/health` (JSON)        | SIGINT → 3s → kill | no  | A |

### 2.2 Kernel drivers (Gate D — Operational, on Windows)

| Component        | Binary                                    | Language | Inputs                              | Outputs                              | Deps                  | Start                          | Health                                | Stop                         | Required | Gate |
|------------------|-------------------------------------------|----------|-------------------------------------|--------------------------------------|-----------------------|--------------------------------|---------------------------------------|------------------------------|----------|------|
| `wfp-callout`    | `drivers/wfp_callout/aegis_wfp.sys`       | C        | WFP layer callbacks                  | IOCTL to core, block actions          | `core`                | `sc start aegis_wfp`           | IOCTL `GET_HEALTH` (via core)         | `sc stop aegis_wfp`           | no* | D |
| `minifilter`     | `drivers/minifilter/aegis_minifilter.sys` | C        | filesystem IRPs                      | pipe events to core                   | `core`                | `sc start aegis_minifilter`    | IOCTL `GET_HEALTH` (via core)         | `sc stop aegis_minifilter`    | no* | D |

> Drivers marked `no*` are optional for the runtime contract — the system
> can run in "sensor-only" mode without them — but they are required for
> Gate D (real enforcement) and Gate E (production IPS canary).

### 2.3 Auxiliary services

| Component        | Binary                       | Language | Inputs                          | Outputs                              | Deps                  | Start                          | Health                                | Stop                          | Required | Gate |
|------------------|------------------------------|----------|---------------------------------|--------------------------------------|-----------------------|--------------------------------|---------------------------------------|-------------------------------|----------|------|
| `metrics`        | `scripts/aegis_metrics.py`    | Python   | core NDJSON, brain log          | Prometheus :9100 /metrics            | `core`*               | `python aegis_metrics.py`      | `127.0.0.1:9100/-/healthy`           | SIGINT → 2s → kill            | no  | C |
| `notifier`       | `scripts/aegis_notifier.py`   | Python   | aggregator REST                 | email / webhook / syslog             | `aggregator`*         | `python aegis_notifier.py`      | `\\.\pipe\aegis-notifier-health`     | SIGINT → 2s → kill            | no  | C |
| `dashboard`      | `aegis_dashboard/aegis_dashboard.exe` | Rust | core NDJSON, aggregator API     | egui window + axum :8080             | `core`*, `aggregator`* | `aegis_dashboard.exe`          | `127.0.0.1:8080/health`              | SIGINT → 2s → kill            | no  | C |

---

## 3. Port and pipe allocation

To prevent collisions, every fixed transport endpoint is registered here.
**Never reuse an endpoint.** Add new components to the bottom of the table.

| Endpoint                                   | Transport | Owner        | Purpose                          |
|--------------------------------------------|-----------|--------------|----------------------------------|
| `\\.\pipe\aegis-ipc`                       | pipe      | bridge       | Event ring buffer (Zig ↔ C++)    |
| `\\.\pipe\aegis-bridge-health`             | pipe      | bridge       | Health probe                     |
| `\\.\pipe\aegis-core-health`               | pipe      | core         | Health probe                     |
| `\\.\pipe\aegis-mouth-health`              | pipe      | mouth        | Health probe                     |
| `\\.\pipe\aegis-notifier-health`           | pipe      | notifier     | Health probe                     |
| `127.0.0.1:9999`                           | UDP       | brain        | Alerts from core                 |
| `127.0.0.1:9999/health`                    | UDP       | brain        | Health probe (single-packet JSON) |
| `127.0.0.1:9100`                           | HTTP      | metrics      | Prometheus /metrics              |
| `127.0.0.1:9200`                           | HTTP      | aggregator   | REST API                         |
| `127.0.0.1:8080`                           | HTTP      | dashboard    | Web UI + axum API                |
| `127.0.0.1:10001`                          | UDP       | dashboard    | Brain forward listener           |
| `127.0.0.1:12345`                          | TCP       | core         | Admin pipe listener (debug)     |

---

## 4. Startup order (verified sequence)

For the **first full start** of the system, the supervisor MUST launch
components in the following order. Each step waits for the previous step's
health probe to return `RUNNING` before proceeding.

1. `bridge` (C++ IPC hub)
2. `core` (Zig engine; loads `shield` DLL during init)
3. `brain` (Python detection engine)
4. `aggregator` (Go NDJSON watcher)
5. `nose` (Go headless collector)
6. `mouth` (Rust DEFCON TUI; only if interactive session)
7. `metrics` (Prometheus exporter)
8. `notifier` (alert routing)
9. `dashboard` (UI; only if `--with-ui` flag set)
10. `wfp-callout` (kernel driver; only on Windows with admin)
11. `minifilter` (kernel driver; only on Windows with admin)

Optional components (steps 5, 6, 8, 9, 10, 11) may be skipped; the system
MUST still reach `RUNNING` state on the required components.

## 5. Shutdown order (reverse of startup)

1. `dashboard`, `notifier`, `metrics` (UI first, then exporters)
2. `nose`, `mouth` (collectors before engine)
3. `aggregator`
4. `brain` (stop detection before traffic stops)
5. `core` (drain in-flight events)
6. `bridge` (last — it is the IPC hub)
7. Drivers (`wfp-callout`, `minifilter`) — only if they were started

If any component fails to stop within its `shutdown_timeout`, the supervisor
force-kills it and writes a `STOP_FORCED` event to the audit log.

---

## 6. Failure-mode matrix

This matrix lists, for each component, what happens to the rest of the
system if that component fails. "Required = yes" rows have stricter
consequences.

| Failed component | Required? | System impact                                              | Action                                   |
|------------------|-----------|------------------------------------------------------------|------------------------------------------|
| `bridge`         | yes       | Cross-language event flow stops. Core cannot emit events.   | Auto-restart; system → DEGRADED          |
| `core`          | yes       | No detection. Sensors still capture but cannot analyze.    | Auto-restart; system → FAILED after 3 tries |
| `brain`          | yes       | No IPS actions, no rule-based detection.                   | Auto-restart; system → DEGRADED          |
| `nose`           | no        | No threat map / perf counters. DEFCON still works.         | Auto-restart; system → DEGRADED          |
| `mouth`          | no        | No DEFCON display. Logic still computed in core.           | Auto-restart; system → DEGRADED          |
| `shield`        | yes       | No payload safety check. PEP cannot validate.              | Cannot fail independently — loaded by core |
| `aggregator`     | no        | No dedup/correlation. Dashboard still reads NDJSON directly. | Auto-restart; system → DEGRADED         |
| `metrics`        | no        | No Prometheus endpoint.                                    | Auto-restart; system → DEGRADED          |
| `notifier`       | no        | No external alert delivery.                                | Auto-restart; system → DEGRADED          |
| `dashboard`      | no        | No UI. Operator falls back to CLI.                          | Auto-restart; system → DEGRADED          |
| `wfp-callout`    | no*       | No kernel network filtering. Brain IPS still works.        | No auto-restart (needs admin); DEGRADED  |
| `minifilter`     | no*       | No filesystem events.                                      | No auto-restart (needs admin); DEGRADED  |

---

## 7. Versioning

Each component exposes a `VERSION` subcommand (or equivalent). The
supervisor collects these and writes them to `logs/runtime/versions.json`
on startup. The versions file is the authoritative input to the build
manifest (`aegis.manifest.json`).

| Component    | How to query version                                |
|--------------|-----------------------------------------------------|
| `bridge`     | `aegis_bridge.exe --version`                        |
| `core`       | `aegis-nids.exe --version`                          |
| `brain`      | `python windows_brain.py --version`                 |
| `nose`       | `aegis-nose.exe --version`                          |
| `mouth`      | `windows_sec_monitor.exe --version`                 |
| `shield`     | Embedded in core's version string (`shield=<semver>`) |
| `aggregator` | `aegis-aggregator.exe --version`                    |
| `metrics`    | `python aegis_metrics.py --version`                 |
| `notifier`   | `python aegis_notifier.py --version`                |
| `dashboard`  | `aegis_dashboard.exe --version`                     |

If a component does not yet implement `--version`, it is **not** Gate-A
conformant. See `tests/runtime/test_version.py` for the contract test.

---

## 8. References

- `docs/runtime/RUNTIME_CONTRACT.md` — states, timeouts, health probe schema.
- `docs/runtime/LIFECYCLE.md` — visual state machine.
- `docs/runtime/LOCAL_RUNBOOK.md` — operator-facing runbook.
- `docs/architecture/ARCHITECTURE_CANONICAL.md` — architectural truth.
- `docs/architecture/FILE_REGISTRY.csv` — per-file inventory.
