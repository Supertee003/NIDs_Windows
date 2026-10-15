# AEGIS Operator Command Map (EVT-170)

Deep analysis showed the confusion is NAMING, not redundancy: almost
nothing is truly duplicated. This map says who uses what, and why the
look-alikes both exist. Anything not listed here is lab tooling, retired
with a pointer, or a support script -- ask before running it on prod.

## Roles

### Daily operator (double-click level)

| Command | When |
|---|---|
| `run_aegis.bat` | Open everything (service+nose+brain+4 displays) |
| `run_aegis.bat --status` | Check anytime, starts nothing |
| `aegisctl dashboard [--watch]` | Live terminal view |
| `aegisctl bridge` | Brain-channel honesty (RB-017 step 3) |
| `aegisctl brain` | Tier-2 counters + inbox tail (labeled, not verdicts) |
| `aegisctl components` | The five as concepts (Core/Brain/Nose/Mouth/Bridge) |
| `aegisctl console` | Menu over all of the below (Thai, role-gated) |
| web `http://127.0.0.1:5000` | Cards, feed, rules, components |
| `aegis_open.py displays --stop` | Close the windows (core keeps running) |

### Incident responder

| Command | When, and how it differs from its twin |
|---|---|
| `events count/tail/stats` | Raw evidence firehose (193K records live) |
| `alerts` | Filtered alert-level view only (quiet hosts: empty is normal) |
| `incidents list` | Threat-tracker counters (open/total/detections) |
| `incidents top` | Top firing rules, ring-derived grouping |
| `forensic show/search/verify/export` | Targeted: one record / one field / chain / export |
| `forensics list/verify` | Bulk: ring pages + chain (different granularity, keep both) |
| `enforce status` | PEP truth: mode, gate, receipts (detection-only here) |
| `block list` | Block candidates (mutations PEP-gated, refused on prod) |
| `diagnose` | Structured snapshot when something looks wrong |
| `authority` | Invariant check (HELD/VIOLATED; auditor + incident) |
| `help` | This map's source of truth for names (topics below) |
| RB-001/002/003 | Copy-paste procedures for the above |

### Maintainer (admin shell)

| Command | When |
|---|---|
| `aegis_open.py keep` + `keep --install-task` | Watchdog converge + task (GAP-016 backstop) |
| `aegis_open.py close [--with-service]` | Stop supervised (service stays unless asked) |
| `rules validate/reload/list` | Ruleset changes (validate first, always) |
| `policy verify/validate` | Trust posture (unsigned default is normal) |
| `forensic verify` | Ring integrity (~5s, never during measurements) |
| `upgrade_rollback.py snapshot/report/rollback` | Recovery (RB-004) |
| `truth.py verify` + `release_engineering.py --verify` | Gates (seconds, read-only) |
| `sc.exe ...` | Service control -- always with `.exe` (bare `sc` is Set-Content) |

### Lab / developer (lab host only, never prod)

`simulate` (traffic), `canary` (tests), `graph` (triage HTML),
`federation` (standalone here), `quarantine` (add/remove/list),
`enforce simulate` (posture projection), full pytest, per-toolchain
rebuilds (`build_truth.json`), `scripts/run_*` kit/canary runners,
`kali_*.py`, generators (`generate_*`, `create_test_vectors.py`).

### Auditor

`truth.py verify`, `release --verify`, `fresh_deploy.py --plan`,
`check_summary.py`, `check_evidence.py`, EVIDENCE_INDEX.json,
`metrics` + `events stats` as numbers.

## Look-alike pairs (why both exist)

- `status` / `health` / `diagnose` / `readiness`: four depths of the
  same truth (process rows / single shot / structured doc / gate
  verdict). Start with `status`; escalate inward.
- `metrics` / `queue`: disjoint keys (totals vs depth/sources/stages).
- `snapshot` (daemon doc, now carries `components`) vs web snapshot
  (adds feed/incidents/threat/forensic-cache) vs `components` (identity).
- `version` (static 7 incl pep/shield/aggregator) vs `components`
  (live 5). Both, different questions.
- `dashboard` one-shot probes deep (same answer as `components`);
  `dashboard --watch` stays shallow for cheap polling (EVT-180).
- `block` (candidates) / `enforce` (PEP state) / `quarantine` (lab
  path) / `policy` (signed lifecycle) / `rules` (detection content).
- `aegisctl start/stop` ask the DAEMON over the pipe; the opener owns
  OS processes. Different layers, not duplicates. `restart` honestly
  refuses (needs an external manager): stop, then start.
- `iptest` is a bounded latency sample (cap 100), never a flood.

## Scripts (49 files): which hat

- Daily: `aegis_open.py`, `aegisctl.py` entry points only.
- Lab runners: `run_*observe_only*`, `run_22rules_kit.py`,
  `run_phase8_lab_scenarios.py`, `*_canary_scan.py`, `kali_*.py`,
  `gen_kali_22.py`, `ml_train.py`, `create_test_vectors.py`.
- Analysis (repaired, pinned): `analyze_vectors.py`,
  `check_evidence.py`, `read_vectors.py`, `check_summary.py`.
- Retired with true pointers (do not run): `aegis_console*.py`,
  `aegis_graph.py`, `aegis_status.py`, `aegis_api.py`,
  `aegis_notifier.py`, `aegis_block.py`, `aegis_unblock.py`,
  `analyze_existing.py`, `Dashboard.py`.
- Honest opt-ins: `aegis_metrics.py` (:9100), `aegis_alerts.py`
  (viewer+ack in logs/), `aegis_event_gen.py` (lab traffic).
- Quarantined (never run on prod): direct-UDP block/unblock flows.

## Entry points (one engine)

`run_aegis.bat` (double-click) -> `scripts/aegis_open.py` (owns all
logic) -> service/nose/brain/displays. `aegisctl console` is the
interactive menu over the same engine. `scripts/aegis.ps1` wraps the
same commands (`tui`/`console`/`web`/`gui`/`graph` route live; `test
golden-path` is the sanctioned canary). Do not reimplement startup
anywhere else.

## Security boundaries (read before hardening)

Audited adversarially (EVT-174). All listeners are loopback-only
(:5000 web, :9999 brain, control/sensor pipes); the web surface is
GET-only; the service DACL is query-only for non-admins; control
mutations are role-gated by impersonated token (unit-tested), with
blocks/quarantine/shutdown privileged-only; the tree carries no secrets
(gitleaks green). Three accepted costs to know:
- The repo tree and `configs/Rules.json` are writable by Authenticated
  Users, while the keeper task executes repo scripts as SYSTEM and any
  authenticated user may trigger `rules.reload` (.operate role). Until
  hardened, ANY local user can reach SYSTEM (via the task path) and
  mute detection (via rules+reload). Harden with the ADMIN icacls block
  in EVT-174 (root RX + logs/ M, backup first), then non-admin pytest
  needs `-o cache_dir` outside the tree.
- `AEGIS_BRAIN_SECRET` lives in machine env: world-readable by design
  (loopback model trusts local). Local malware voids it like any local
  secret; rotation = setx + restart both ends (RB-016).
- The WFP driver is test-signed (expires 2029): WHQL is the proper fix;
  review testsigning state before calling the host hardened.

## Troubleshooting (earned the hard way)

- **Non-elevated `close`/`stop` cannot stop keeper-spawned parts**
  (nose/brain run elevated under the SYSTEM task): expect honest
  `[FAIL] ... (elevate?)`, then use an elevated shell. Never silent.
- **Watch window frozen?** Look for a `Select ` prefix in its title:
  QuickEdit selection pauses console output. Press Enter/Esc to resume.
- **`displays` exit 2 with OK rows** means skipped surfaces, never
  failure (pinned exit-code contract, EVT-147).
- **In PowerShell, always `sc.exe`** (with the extension): bare `sc`
  is the Set-Content alias and writes junk files (EVT-163).
- **Second daemon exits 3, fast.** A second `aegis_nids.exe` while the
  pipe is owned refuses in <1s (GAP-020 preflight, before workers arm)
  instead of lingering. Exit 3 = owned elsewhere, not a crash; check
  `status` for the live owner pid.
