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

### 2. The five components as concepts

```
python tools/aegisctl.py components   # Core/Brain/Nose/Mouth/Bridge + roles
python tools/aegisctl.py status       # subsystems, workers, posture lines
python tools/aegisctl.py status --component brain   # one component, deep probe
python tools/aegisctl.py diagnose     # structured snapshot when wrong
python tools/aegisctl.py readiness    # gate verdict
python tools/aegisctl.py version      # static versions incl pep/aggregator
```

### 3. The three tiers (where each decides)

- Tier-1 (Zig core, fast signatures):
  `python tools/aegisctl.py events tail --follow`
  `python tools/aegisctl.py rules list`
- Tier-2 (Python brain, deep inspection, advisory only):
  `python tools/aegisctl.py bridge`
  `python tools/aegisctl.py metrics` (detections vs anomalies)
- Tier-3 (Rust PEP, enforcement; gate closed = detection-only):
  `python tools/aegisctl.py enforce status`
  `python tools/aegisctl.py block list`
  `python tools/aegisctl.py enforce simulate` (projection, never touches PEP)

### 4. Kernel touchpoints (what the kernel gives us)

- WFP callout driver (flows + block primitive):
  `python tools/aegisctl.py enforce status` (tier3/provider_ready)
  `sc.exe query AegisWfp` (driver service state)
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
python tools/aegisctl.py events count                 # how many
python tools/aegisctl.py events tail --count 20       # recent records
python tools/aegisctl.py alerts                       # alert-level only (quiet hosts: empty is normal)
python tools/aegisctl.py forensic search --field rule --value R1004
python tools/aegisctl.py forensics verify             # ring integrity (~5s, never during measurements)
python tools/aegisctl.py graph --limit 50             # threat graph HTML
```

`--field rule` takes a catalog id (R1004) or integer, hashed
client-side; `--field source` takes a numeric origin ordinal only
(9 npcap, 10 host), never an IP.

### 6. Rules and policy

```
python tools/aegisctl.py rules validate && python tools/aegisctl.py rules reload
python tools/aegisctl.py rules list
python tools/aegisctl.py policy verify
```

Rule catalog: configs/Rules.json (23 rules). Unsigned policy default
is normal.

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

### 8. Lab-only surfaces (never prod)

`simulate`, `canary`, `quarantine`, `federation`, `enforce simulate`
projections, full pytest, per-toolchain rebuilds, `kali_*.py`,
generators. See docs/OPERATOR_COMMAND_MAP.md for the role map.

## Verification

Walk Steps 1-7 top to bottom on a running host: every command exits
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
