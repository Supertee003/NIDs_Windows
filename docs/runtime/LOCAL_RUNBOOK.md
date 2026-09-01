# AEGIS NIDS — Local Runbook

> Operator-facing runbook for running AEGIS on a single developer machine.
> Use this document to bring the system up from a clean clone, verify it is
> healthy, generate synthetic traffic, observe events, and shut it down
> cleanly. Every step here is reproducible and scriptable.

Document version: 1.0
Last updated: 2026-09-01
Audience: developers, QA, on-call engineers.
Prerequisites: Windows 10/11 with admin rights, Zig 0.13.0, Rust stable,
Go 1.22+, Python 3.11+, CMake, MSVC.

---

## 1. Pre-flight checklist

Before starting any component, verify the environment. Skipping this step
is the most common cause of mysterious failures.

### 1.1 Toolchain versions

```bat
zig version
rustc --version
go version
python --version
cmake --version
```

Expected minimums:

| Tool     | Minimum  | Recommended |
|----------|----------|-------------|
| Zig      | 0.13.0   | 0.13.0      |
| Rust     | 1.75     | stable      |
| Go       | 1.22     | 1.22+       |
| Python   | 3.11     | 3.12        |
| CMake    | 3.27     | 3.28+       |

If any tool is missing, stop and install it. Do not try to "work around" a
missing toolchain.

### 1.2 Ports and pipes

Verify the endpoints listed in `COMPONENT_MATRIX.md` §3 are free:

```bat
netstat -ano | findstr ":9999 :9100 :9200 :8080 :12345"
```

If any of those ports are bound by a non-AEGIS process, free them before
continuing.

### 1.3 Directory layout

```bat
dir logs\pids 2>nul || mkdir logs\pids
dir logs\runtime 2>nul || mkdir logs\runtime
dir logs\health 2>nul || mkdir logs\health
```

These directories MUST exist before any component starts; otherwise the
first start attempt will fail.

---

## 2. Build all components

A single script builds every Gate-A component. Run it from the repo root.

```bat
scripts\build_all.bat
```

The script executes, in order:

1. `cmake -B build -DCMAKE_BUILD_TYPE=Release`
2. `cmake --build build --config Release`
3. `zig build`
4. `cargo build --release` (for `shield` and `dashboard`)
5. `go build -o nose\aegis-nose.exe nose\` (and aggregator)
6. `python -m brain.cython.setup build_ext --inplace`

Each step prints `OK` or `FAIL`. If any step fails, do not proceed — read
the corresponding build log under `logs/build/` and fix the issue first.

### 2.1 Verify build outputs

```bat
dir /b build\Release\aegis_bridge.exe
dir /b build\Release\aegis_ipc.dll
dir /b zig-out\bin\aegis-nids.exe
dir /b target\release\sec_monitor.dll
dir /b nose\aegis-nose.exe
dir /b go\aggregator\aegis-aggregator.exe
dir /b brain\aegis_brain_cython\fast_scan.*.pyd
```

Every line above MUST return a file. If any is missing, that component
will fail at startup with `STARTUP_TIMEOUT`.

---

## 3. Start the bridge (C++ IPC hub)

The bridge must always be the first AEGIS process to start. It owns the
shared ring buffer that every other component talks through.

### 3.1 Start

```bat
start "aegis-bridge" /MIN build\Release\aegis_bridge.exe
```

### 3.2 Wait for READY (≤ 5 s)

```bat
powershell -Command "for ($i=0; $i -lt 50; $i++) { if (Test-Path \\.\pipe\aegis-bridge-health) { break }; Start-Sleep -Milliseconds 100 }"
```

### 3.3 Probe health

```bat
echo { "op": "HEALTH" } > \\.\pipe\aegis-bridge-health
```

Expected response (single line, NDJSON):

```json
{"component":"bridge","state":"RUNNING","pid":1234,"uptime_ms":120,"counters":{"in_events":0,"out_events":0,"errors":0,"dropped":0}}
```

If the response shows `state=STARTING` after 5 seconds, the bridge did not
finish initialization. Read `logs/bridge.log` for the cause.

---

## 4. Start the core (Zig engine)

The core loads `sec_monitor.dll` (the Rust shield) during its own
initialization, so the shield DLL MUST be present before this step.

### 4.1 Start

```bat
start "aegis-core" /MIN zig-out\bin\aegis-nids.exe
```

### 4.2 Wait for READY (≤ 5 s)

The core writes a `READY` beacon to `logs/health/core.json` when it has
finished loading the shield DLL and opened its IPC pipes.

```bat
powershell -Command "for ($i=0; $i -lt 50; $i++) { if (Test-Path logs\health\core.json) { break }; Start-Sleep -Milliseconds 100 }"
```

### 4.3 Probe health

```bat
type \\.\pipe\aegis-core-health
```

The output schema is identical to the bridge. Verify that:

- `state` is `RUNNING`.
- `deps[].state` for `bridge` is `RUNNING`.
- `counters.errors` is `0`.

---

## 5. Start the nose (Go headless collector)

The nose is optional, but it provides the threat map and the perf counters
that the rest of the system relies on for DEFCON calculation. Start it
unless you are running in `--minimal` mode.

### 5.1 Start (background, no window)

```bat
start /B nose\aegis-nose.exe > logs\nose.log 2>&1
```

### 5.2 Wait for first JSON line

```bat
powershell -Command "for ($i=0; $i -lt 30; $i++) { if ((Get-Content logs\nose.log -Tail 1 -ErrorAction SilentlyContinue) -match '\"component\":\"nose\"') { break }; Start-Sleep -Milliseconds 100 }"
```

### 5.3 Verify

The last line of `logs\nose.log` MUST be a JSON object with
`state=RUNNING`. The nose does not expose a separate health pipe — its
stdout JSON is the canonical health beacon.

---

## 6. Start the brain (Python detection engine)

The brain listens on UDP 9999 for alerts from the core, then applies
regex rules and IPS actions. It also loads the Cython `fast_scan` module
if available.

### 6.1 Start

```bat
start "aegis-brain" /MIN python brain\windows_brain.py
```

### 6.2 Wait for READY

The brain binds UDP 9999 and writes a `READY` line to `logs/brain.log`.

```bat
powershell -Command "for ($i=0; $i -lt 50; $i++) { if (Test-NetConnection -ComputerName 127.0.0.1 -Port 9999 -InformationLevel Quiet) { break }; Start-Sleep -Milliseconds 100 }"
```

### 6.3 Probe health

Send a single UDP packet and read the response:

```bat
python -c "import socket, json; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b'{\"op\":\"HEALTH\"}', ('127.0.0.1', 9999)); print(s.recvfrom(4096)[0].decode())"
```

Expected: a JSON object with `state=RUNNING` and `counters.in_events >= 0`.
If you see `ImportError: fast_scan`, the Cython module was not built — go
back to §2 and re-run `python -m brain.cython.setup build_ext --inplace`.

---

## 7. Full health check

Once all four primary components are up (bridge, core, nose, brain), run
the consolidated health check.

### 7.1 Manual check

```bat
python scripts\aegis_status.py --json
```

Expected output:

```json
{
  "ts": 1725148800123,
  "system_state": "RUNNING",
  "components": {
    "bridge":     { "state": "RUNNING", "uptime_ms": 18217 },
    "core":       { "state": "RUNNING", "uptime_ms": 18150 },
    "brain":      { "state": "RUNNING", "uptime_ms": 17980 },
    "nose":       { "state": "RUNNING", "uptime_ms": 17890 }
  }
}
```

### 7.2 Continuous monitor

```bat
python scripts\aegis_status.py --watch --interval 1
```

This re-runs the health check every second and prints a single-line
status. Press `Ctrl+C` to stop the watcher without stopping any
component.

---

## 8. Generate synthetic events

To verify the system actually processes traffic (not just stays healthy),
generate synthetic events.

### 8.1 Synthetic pipe event (Python sensor)

```bat
python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(('127.0.0.1', 12345)); s.sendall(b'SYN-FLOOD-TEST 1.2.3.4 5.6.7.8 80 12345\n'); s.close()"
```

The core should log one event to `logs/aegis_core.ndjson` and forward a
copy to the brain. Verify:

```bat
type logs\aegis_core.ndjson | findstr "SYN-FLOOD-TEST"
```

### 8.2 Synthetic brain alert (UDP)

```bat
python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'{\"type\":\"alert\",\"severity\":7,\"src_ip\":\"1.2.3.4\"}', ('127.0.0.1', 9999))"
```

Verify the brain received it:

```bat
type logs\brain.log | findstr "1.2.3.4"
```

### 8.3 Synthetic threat-map event (Nose)

The nose reads from core's NDJSON, so an event generated in §8.1 should
appear in the threat map within 1 second.

```bat
type logs\nose.log | findstr "1.2.3.4"
```

---

## 9. Observe events

### 9.1 Tail the forensic log

```bat
powershell -Command "Get-Content logs\aegis_core.ndjson -Wait -Tail 10"
```

Each line is one NDJSON event. Press `Ctrl+C` to stop tailing.

### 9.2 Tail the brain log

```bat
powershell -Command "Get-Content logs\brain.log -Wait -Tail 10"
```

### 9.3 Watch the dashboard (optional)

If you started the dashboard in §2, open a browser to
`http://127.0.0.1:8080`. The dashboard polls the aggregator REST API
every 1 s and renders the live event stream.

### 9.4 Use the CLI console

```bat
python scripts\aegis_console.py
```

The console exposes 10 menus: status, alerts, rules, block/unblock,
metrics, notifier, defcon, api, dashboard, exit. Type `help` inside any
menu for available commands.

---

## 10. Stop the system

### 10.1 Graceful stop (recommended)

Use the stop script, which shuts components down in the reverse order
of startup.

```bat
scripts\stop_aegis.bat
```

The script:

1. Sends `SIGINT` (Windows: `CTRL_C_EVENT`) to each component.
2. Waits up to `shutdown_timeout` (default 3 s).
3. Force-kills (`TerminateProcess`) any that did not exit.
4. Removes PID files.
5. Writes a final `SYSTEM_STOPPED` event to `logs/runtime/audit.ndjson`.

### 10.2 Stop one component

To stop only one component (e.g. to restart it after a config change):

```bat
python scripts\aegis_daemon.py stop core
```

This honours the same graceful-then-force sequence but only for the
named component.

### 10.3 Emergency stop (kill everything)

Only use this if the supervisor itself is wedged.

```bat
taskkill /F /IM aegis_bridge.exe
taskkill /F /IM aegis-nids.exe
taskkill /F /IM python.exe /FI "WINDOWTITLE eq aegis-brain*"
taskkill /F /IM aegis-nose.exe
```

After an emergency stop, you MUST delete the PID files manually:

```bat
del /q logs\pids\*.pid
```

---

## 11. Restart

### 11.1 Restart one component

```bat
python scripts\aegis_daemon.py restart brain
```

The supervisor:

1. Records the current state.
2. Stops the component (§10.2).
3. Waits for the port/pipe to be released (1 s).
4. Starts the component again (§6).

### 11.2 Restart the whole system

```bat
scripts\stop_aegis.bat
scripts\run_aegis.bat
```

`run_aegis.bat` is the canonical multi-phase launcher that runs the
startup order from `COMPONENT_MATRIX.md` §4.

### 11.3 Restart after a crash

If a component crashed (not stopped cleanly), the supervisor's restart
policy (exponential backoff, 8 attempts) is already in effect. You
usually do not need to do anything — the supervisor restarts the
component automatically. If it has been quarantined:

```bat
python scripts\aegis_daemon.py unquarantine core
python scripts\aegis_daemon.py start core
```

---

## 12. Troubleshooting quick reference

| Symptom                                                | Likely cause                              | Fix                                        |
|--------------------------------------------------------|-------------------------------------------|--------------------------------------------|
| `aegis_bridge.exe` exits immediately                  | Pipe `aegis-ipc` already in use            | Stop other AEGIS instance; restart          |
| `aegis-nids.exe` reports `FLOW_ENGINE_ERROR`           | Old API reference in `nids_main.zig`       | Verify `core/nids_main.zig` matches repo    |
| Brain logs `ImportError: fast_scan`                    | Cython module not built                    | Re-run §2 build step                        |
| Nose hangs at startup                                  | `core` is not `RUNNING`                    | Start core first                            |
| Health probe returns `state=DEGRADED`                  | A dependency failed                        | Read `deps[].state` in the probe response   |
| Health probe times out                                 | Component is wedged                        | Restart per §11.1                           |
| `aegis_status.py --json` returns `system_state=FAILED` | One required component is `FAILED`        | Read `logs/runtime/audit.ndjson` for `from`/`to` |
| Aggregator shows no events                             | Core NDJSON path mismatch                  | Verify `logs/aegis_core.ndjson` is being written |
| Dashboard shows "no data"                              | Aggregator not running                     | Start aggregator (§2 build, then start)     |

For deeper diagnostics, run:

```bat
scripts\diag_deep.bat
```

This collects: process list, port bindings, pipe list, last 200 lines of
every log, and dumps them to `logs/diag-<timestamp>.zip`.

---

## 13. Reference: command summary

| Action                       | Command                                                |
|------------------------------|--------------------------------------------------------|
| Build all                    | `scripts\build_all.bat`                                |
| Start all                    | `scripts\run_aegis.bat`                                 |
| Stop all                     | `scripts\stop_aegis.bat`                                |
| Status (one-shot, JSON)      | `python scripts\aegis_status.py --json`                |
| Status (watch)               | `python scripts\aegis_status.py --watch --interval 1`  |
| Start one component          | `python scripts\aegis_daemon.py start <comp>`           |
| Stop one component           | `python scripts\aegis_daemon.py stop <comp>`            |
| Restart one component        | `python scripts\aegis_daemon.py restart <comp>`         |
| Unquarantine                 | `python scripts\aegis_daemon.py unquarantine <comp>`    |
| Console                      | `python scripts\aegis_console.py`                       |
| Deep diagnostics             | `scripts\diag_deep.bat`                                 |

---

## 14. References

- `docs/runtime/RUNTIME_CONTRACT.md` — states, timeouts, error classes.
- `docs/runtime/COMPONENT_MATRIX.md` — full component inventory.
- `docs/runtime/LIFECYCLE.md` — state machine.
- `docs/architecture/DEPLOYMENT.md` — production deployment guide.
- `docs/runbooks/RB-001-incident-response.md` — incident response runbook.
- `docs/runbooks/RB-005-recovery.md` — recovery runbook.
- `docs/runbooks/RB-010-troubleshooting.md` — extended troubleshooting.
