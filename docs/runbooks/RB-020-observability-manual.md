# RB-020: Full-System Observability Manual

## Objective

One document that maps every inspectable surface of the running system
to the exact command that shows it: the five components, the three
tiers, the kernel touchpoints (WFP/ETW/npcap), traffic flow, enforcement
truth, rules, and displays. All commands are read-only unless marked;
read-only steps never mutate host state.

## Prerequisites

- System running (service + nose + brain). Operator shell in repo root.
- Elevation: not needed for any read below. Anything needing admin is
  marked [ADMIN] and lives in its own runbook.

## Steps

### 1. Open and check the system

```
scripts\run_aegis.bat --status    # check everything, starts nothing
scripts\run_aegis.bat             # open missing parts + 4 displays
python scripts/aegis_open.py keep # watchdog converge, no displays
```

SKIP rows mean already-running idempotency, not failure. `displays`
exit code 2 means skipped surfaces, never failure.

Layer rule (three different things): the opener owns OS processes;
`aegisctl start/stop` ask the DAEMON over the pipe; `restart` honestly
refuses (needs an external manager) — stop, then start. A second
daemon copy exits 3 fast (owned elsewhere), never fights the service.
In PowerShell always spell `sc.exe` (bare `sc` is Set-Content).

Watchdog (no displays, converges the dead):
```
python scripts/aegis_open.py keep          # converge service+nose+brain
python scripts/aegis_open.py close         # stop nose+brain, service stays
python scripts/aegis_open.py close --with-service   # [ADMIN] also stops it
```
The keeper runs as scheduled task AegisKeeper every 5 minutes, using
liveness only (never pipe counters). One watchdog only: the retired
AegisWatchdog task was deleted (EVT-183).

### 2. The five components as concepts

```
python tools/aegisctl.py components   # Core/Brain/Nose/Mouth/Bridge + roles
python tools/aegisctl.py status       # subsystems, workers, posture lines
python tools/aegisctl.py status --component brain   # one component, deep probe
python tools/aegisctl.py diagnose     # structured snapshot when wrong
python tools/aegisctl.py readiness    # gate verdict
python tools/aegisctl.py version      # static versions incl pep/aggregator
```

Four depths of the same truth, escalate inward: `status` (rows),
`health` (single shot), `diagnose` (structured doc), `readiness`
(gate verdict). `snapshot` emits one JSON doc for dashboards;
`components` answers identity (the five) while `version` answers
static builds (the seven) — different questions, keep both.
One-shot `dashboard` probes deep like `components`; `dashboard
--watch` stays shallow for cheap polling.

### 3. The three tiers (where each decides)

- Tier-1 (Zig core, fast signatures):
  `python tools/aegisctl.py events tail --follow`
  `python tools/aegisctl.py rules list`
- Tier-2 (Python brain, deep inspection, advisory only):
  `python tools/aegisctl.py bridge`
  `python tools/aegisctl.py brain` (counters + inbox tail, labeled)
  `python tools/aegisctl.py metrics` (detections vs anomalies)
- Tier-3 (Rust PEP, enforcement; gate closed = detection-only):
  `python tools/aegisctl.py enforce status`
  `python tools/aegisctl.py block list`
  `python tools/aegisctl.py enforce simulate` (projection, never touches PEP)

### 4. Kernel touchpoints (what the kernel gives us)

- WFP callout driver (flows + block primitive):
  `python tools/aegisctl.py enforce status` (tier3/provider_ready)
  `sc.exe query AegisWfp` (driver service state)
- WFP flow rows (submit-only kernel telemetry; source ordinal 21):
  `python tools/aegisctl.py queue` shows a `capture_wfp` row once traffic
  crosses the callout. Reads run through the Rust PEP adapter, which holds
  the long-lived `\\.\AegisWfpDevice` handle and is the only ROUTINE
  reader; the Zig side never opens the device. The create handler accepts
  every open and the SDDL admits SYSTEM + Administrators (EVT-211), so an
  elevated one-shot probe CAN co-open while the daemon runs (observed
  2026-10-16: probe open rc 0 with the daemon mid-drain) -- concurrent
  readers split ring drains, so stop `AegisNids` for a clean full-drain
  probe. These rows are 5-tuple flow visibility
  (payload_length 0 by driver construction), never payload; L7 stays with
  npcap/host paths.
- WFP telemetry health (labeled absence, never a silent zero):
  `python tools/aegisctl.py queue` prints a `wfp state=... reads=... rows=...
  last_bytes=...` row. `state=ok` = the provider answered the poll (rows>0
  = kernel flows flowing; a drained ring reads 0 bytes and stays ok --
  idle is not a failure, EVT-213); `state=unavailable` names the absence
  (driver stopped, old provider DLL, or IOCTL failure); `state=unknown` = the
  telemetry loop has not reported yet. A daemon binary that predates this
  row renders nothing -- itself the honest signal of an older build.
- WFP device ownership and start order (EVT-211/EVT-212, corrected by the
  2026-10-16 deploy round): the Rust PEP adapter holds the one long-lived
  `\\.\AegisWfpDevice` handle (adopted at provider attestation, shared by
  enforcement and telemetry) and is the sole routine reader. The device is
  not hard-exclusive: a fresh elevated probe opens it fine even while the
  daemon drains (observed open rc 0), but two live readers split ring
  drains -- probe only with the daemon stopped, and read kernel flows via
  `aegisctl queue`/`aegisctl events`. The `AegisWfp` driver service is
  DEMAND_START: after a host reboot start the DRIVER FIRST, then the
  daemon. Start order matters for boot-state DISPLAY, not for data:
  `status` state and `health` capabilities.wfp / provider_ready reflect
  the provider attestation taken once at daemon startup -- a daemon
  booted while the driver is down stays DEGRADED for that session even
  after the driver returns, while its `queue` wfp row and
  `enforce status` provider_ready are live and tell the truth (observed
  2026-10-16: 27,029 rows flowing under a boot DEGRADED; a daemon restart
  with the driver up flips state RUNNING and capabilities.wfp true).
- ETW (kernel trace telemetry):
  `python tools/aegisctl.py status` (etw_ready in workers)
  `python tools/aegisctl.py queue` (capture_etw row)
- npcap (kernel packet capture into nose):
  `python tools/aegisctl.py queue` (capture_npcap row, frames)
- Minifilter (file): present in tree under drivers/minifilter; no
  read path exists from an operator shell, so nothing is claimed here.

### 5. Traffic flow and evidence

```
python tools/aegisctl.py queue                        # pipeline stages + p50/p95
python tools/aegisctl.py metrics                      # totals: detections, anomalies, blocks (0 here)
python tools/aegisctl.py events count                 # how many
python tools/aegisctl.py events tail --count 20       # recent records
python tools/aegisctl.py events stats                 # per-shape summary
python tools/aegisctl.py alerts                       # alert-level only (quiet hosts: empty is normal)
python tools/aegisctl.py incidents list              # counters + open-incident detail (highest score first)
python tools/aegisctl.py incidents top               # top firing rules, ring-derived grouping
python tools/aegisctl.py forensic show --id 11411052  # one record by seq
python tools/aegisctl.py forensic search --field rule --value R1004
python tools/aegisctl.py forensic export --output out.json   # export matches
python tools/aegisctl.py forensics list --limit 100   # ring pages (bulk)
python tools/aegisctl.py forensics verify             # ring integrity (~5s, never during measurements)
python tools/aegisctl.py graph --limit 50             # threat graph HTML
python tools/aegisctl.py graph --json                 # machine-readable graph
```

`--field rule` takes a catalog id (R1004) or integer, hashed
client-side; `--field source` takes a numeric origin ordinal only
(9 npcap, 10 host), never an IP.

### 6. Rules and policy

```
python tools/aegisctl.py rules list                   # all 23 with severity
python tools/aegisctl.py rules show --id R1004        # one rule
python tools/aegisctl.py rules validate               # always first
python tools/aegisctl.py rules reload                 # daemon picks it up
python tools/aegisctl.py rules add --help             # add/update/delete shapes
python tools/aegisctl.py policy list
python tools/aegisctl.py policy show --id 3
python tools/aegisctl.py policy verify                # trust posture
python tools/aegisctl.py policy validate
python tools/aegisctl.py enforce two-person --help    # Project-3 approval gate
python tools/aegisctl.py enforce approve --help       # second-human approval
```

Rule catalog: configs/Rules.json (23 rules). Unsigned policy default
is normal. Rule add/update/delete are live-tested flows (byte-stable
writes); validate-before-reload is mandatory.

### 7. Displays (the four visible surfaces)

```
python scripts/aegis_open.py displays              # open missing, verify all
python scripts/aegis_open.py displays --web        # web only (opens browser tab)
python scripts/aegis_open.py displays --no-browser # no browser tab
python scripts/aegis_open.py displays --stop       # close windows, core keeps running
python tools/aegisctl.py dashboard                 # terminal dashboard, one shot
python tools/aegisctl.py dashboard --watch         # terminal dashboard, polling
python tools/aegisctl.py console                   # interactive Thai menu over all of the above
```

Web UI: http://127.0.0.1:5000/ (loopback-only, GET-only).

### 8. Recovery and audit gates (read these before touching prod)

```
python tools/upgrade_rollback.py snapshot --json      # capture restore point
python tools/upgrade_rollback.py report --json        # what would roll back
python tools/upgrade_rollback.py rollback --snapshot ID --json   # [MUTATES] restore
python tools/truth.py verify                          # maps carry HEAD (seconds)
python tools/release_engineering.py --verify          # 611 digests (seconds)
python tools/fresh_deploy.py --plan                   # deploy dry-run, writes nothing
```

### 9. Where the logs live

- Forensic NDJSON: `C:\Windows\System32\logs\aegis_core.ndjson`
  (service view) and `logs\aegis_core.ndjson` (repo view) — `events`
  reads whichever is live, never a stale default.
- Web server log: `C:\Temp\aegis_web.log` (last line is the honest
  hint when the console does not answer).
- Watchdog log: `C:\Temp\aegis_watchdog.log` (legacy, task deleted).
- Keeper lock: `C:\Temp\aegis_keep.lock` (anti-pile-up, 10-min TTL).

### 10. Lab-only surfaces (never prod)

`simulate`, `canary`, `quarantine`, `federation`, `enforce simulate`
projections, full pytest, per-toolchain rebuilds, `kali_*.py`,
generators. See docs/OPERATOR_COMMAND_MAP.md for the role map.

### 11. Troubleshooting (earned the hard way)

- Non-elevated `close`/`stop` cannot stop keeper-spawned nose/brain:
  expect honest `cannot stop ... (elevate?)`, then use Admin.
- Watch window frozen? Look for a `Select ` title prefix: QuickEdit
  selection pauses output. Enter/Esc resumes.
- `displays` exit 2 with OK rows = skipped surfaces, never failure.
- GUI missing but process runs? It now needs a visible window;
  windowless zombies are cleared and re-reported, never SKIP-hid.
- Second daemon exits 3 fast = owned elsewhere, not a crash.

## Verification

Walk Steps 1-11 top to bottom on a running host: every read exits
0, `status` shows 7/7 subsystems, `components` shows five running,
`enforce status` shows detection-only with a closed gate, `metrics`
flows climb. Anything else is either a failure to investigate or an
item under Honest limits below.

## Rollback

This manual is read-only: there is nothing to roll back. The only
mutating adjacents (`rules reload`, `displays --stop`) are covered by
their own runbooks (RB-009) or re-runnable open commands.

## Honest limits

- `enforce enable/disable/push` print Unavailable (Project 2 design).
- The WFP proof filter is single-slot by driver construction; the E5
  proof is the T11 run, not concurrent blocks.
- Minifilter state cannot be read from here (needs a privileged host
  query); it is documented, not displayed.
- A quiet host shows empty alerts: generate lab traffic (RB-019) to
  see the detection path fire end to end.
