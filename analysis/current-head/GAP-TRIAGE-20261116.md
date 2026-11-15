# GAP-TRIAGE-20261116 — what is actually left, and what each item costs

**Created:** 2026-11-16
**Build source:** unchanged (`7c604d5`). This is a records pass; nothing here is
in `RUNTIME_PATHS`, so `SOAK2-20261115` stays valid.
**Window state at writing:** `16:50:31` start, `7.19 h / 24 h`, closes
`2026-11-16T16:50:31`. `dropped_total` 1387 (budget 3500), `shed_overload` 0,
`depth` 0 — static since the one burst.

---

## 1. The release gate is time, and only time

`docs/gates/T20_100pct_audit.json` at this HEAD:

| Gate | Owner | State |
|---|---|---|
| `truth_artifacts` | none | PASS |
| `component_audit` | none | PASS (66/66 modules) |
| `release_signature` | owner | PASS (`release/T20-final/9ebee9b`, contains `7c604d5`) |
| `clean_host_e5` | owner | PASS |
| `evidence_debt` | none | PASS (0 unnamed) |
| **`soak_24h`** | **time** | **IN_PROGRESS** |

So the honest position is: **no code work is outstanding for the release.** Any
`src/` edit from here reopens the window and costs another 24 h. The remaining
work splits into two piles — "must wait for the clock" and "must wait for a
runtime change that the next release will carry".

Live host facts measured in this session, so the claim is not inherited:

```
$ aegisctl.py readiness
{"ready": true, "degraded": false, "overall_gate": true, "state": "RUNNING",
 "rules_loaded": 23, "policies_loaded": 6, "worker_gate": true, ...}

$ aegisctl.py enforce status
{"enforcement_mode": "detection-only", "prevention_gate": "closed",
 "tier3_enforcing": false, "host_effect_capable": false, ...}
```

`readiness` was reported as degraded-by-QLOSS in earlier records; in this window
it is clean. The detection-only invariant holds on the live daemon.

## 2. The nine open gaps, triaged

None of them is a release gate. Each entry states what it would cost to close,
because "OPEN" without a price is how a backlog becomes permanent.

| # | Gap | Level | What remains | Price | Release impact |
|---|---|---|---|---|---|
| 1 | `EVI-G2-PEP-CACHE-001-LAB-20261023` | E5 | PEP cache swap, direction verify, duplicate canary, unblock, base restore | enforcement lab: second host + PEP DLL swap + proof filter | none — enforcement is out of product scope |
| 2 | `IDS-L7-003-20261031` | E2→E5 | one live L7 protocol anomaly (HTTP/DNS/TLS/SMB) | **one RB-022 window**, no restart | none |
| 3 | `KIDS-002-20261101` | E2 | loopback tests separated; supervised host evidence; RB-017; XDR; E7 | test rewrite + full suite (heavy) | none |
| 4 | `E5-RECHECK-STALE-IMAGE-20261101` | E1 | current-source Kali canary on the installed image | RB-022 window (no restart) or RB-021 (restart) | none |
| 5 | `GAP-QLOSS-ISOLATION-002` | E2/E5 | FIM/ETW ingress reduction + re-measure | `src/` change + **new 24 h soak** | none |
| 6 | `ADR-0012-DUP-RATIO-E5-20261108` | E5 | duplicate identity resolved, then coalescing measure | probe deploy + 20k-file churn | none |
| 7 | `DETECT-L4-001` | P1/E4 | prove a real scan tags an L4 rule | **one RB-022 window** | none, but highest-value proof |
| 8 | `CAPTURE-LOOPBACK-001` | P2/E4 | decide: scope statement or a loopback-pinned daemon | tests-only (scope) or restart (pin) | none |
| 9 | `SOAK-SHED-001` | P1/E4 | the window passing | **time** | blocking (it *is* the gate) |

### 2.1 Two of them are cheaper now than their records say

**#7 `DETECT-L4-001`.** The record says the scan result is "intermittent" and
cannot be pinned with a loopback stimulus. Both halves are now explained:

* loopback is a different Npcap device from the one nose opens, so a loopback
  stimulus can never reach the L4 matcher on this install (`CAPTURE-LOOPBACK-001`);
* the L4 gate requires `ev.source == .capture_npcap`, and the canonical nose path
  satisfies it via `legacySourceFor(.npcap_sensor)` (`event_queue.zig:480`), with
  TCP flags on the `ContextFlags` lane.

So the missing stimulus is an external scan across the sensor's own link — which
is exactly what `tools/lab_attack_window.py` measures in four minutes. This is
the first thing to run after the window closes.

**#2 `IDS-L7-003`.** Its blocker is "live L7 hit never observed", and its premise
("direct Npcap is the only ingress with full Ethernet payload") stopped being
true at wire v3: `nose/capture.go:captureAttachment` attaches up to 1,024 bytes
and `event_processor.zig:341` runs the anomaly checks for any `.capture_npcap`
event with a payload. A malformed HTTP request from a bridged Kali to a listener
on this host is therefore enough — no lab interface, no restart.

The stale comment at `event_processor.zig:335` still asserts the old premise.
Fixing a comment is a `src/` edit and would reopen the soak, so it is queued for
the v1.1 patch set, not for this release.

### 2.2 Three of them are structurally out of this release

**#1** is enforcement-lab evidence, and the product ships detection-only
(`prevention_gate: closed`, `tier3_enforcing: false`, `host_effect_capable:
false`). It is retained as a lab artifact, not as a shipping defect.

**#5** and **#6** both require a `src/` change plus a new 24 h window. They are
the v1.1 backlog. `#5`'s isolation half is already closed at E5; what remains is
total loss under a storming FIM source, which this window shows is not happening
at current load (`shed_overload` 0, `dropped` 1387 of 3,500 all from
`source_quota_shed` in a single burst).

**#3** is a roll-up entry whose listed blockers have partly closed since it was
written (XDR-005 E5, `clean_host_e5` PASS, `readiness` clean). Its remaining
teeth are the loopback test split, which is the same item as `#8`.

## 3. What was verified tonight (soak-safe)

Every check below leaves the window untouched — no restart, no `src/` edit, no
VM, no port scan.

| Check | Result |
|---|---|
| `truth.py verify` | `TRUTH_VALID`, artifacts carry `7c604d5`, source clean |
| `pytest tests/release tests/tools/{test_lab_attack_window,test_runbooks,test_sign_release}.py` | **225 passed** |
| `aegisctl.py readiness` | `ready: true`, `degraded: false` |
| `aegisctl.py enforce status` | detection-only, gate closed, no host effect |
| `queue.stats` | `dropped_total` 1387 (static), `shed_overload` 0, `depth` 0 |
| capture path | Wi-Fi `\Device\NPF_{5FD31C6E-…}` → `192.168.1.39`, `+5219` frames / 5 s |
| CI triggers | delivery branch now runs CI (`00455ba`) |
| soak gate rehearsal (`--hours 7`, no artifact written) | verdict `PASS`, `elapsed 7.21 h`, `daemon_uptime 7.77 h`, `problems []`, `scm_restarts []`, health `RUNNING` |

The rehearsal is the important one: every criterion in `evaluate()` — services
RUNNING, daemon uptime covering the window, no `DEGRADED`, all loss counters
within 3,500, `shed_overload` 0, no SCM 7031/7034 — already passes at 7 h. The
only thing the closeout adds is the 24 h clock. It is a rehearsal with a 7 h
requirement, **not** a 24 h result, and no artifact was written for it.


## 4. The post-soak sequence, in order

Nothing here may start before `2026-11-16T16:50:31`. Recommend `16:51` or later.

```powershell
# 1. close the window (writes the authoritative artifact)
python tools/host_soak_check.py --start 2026-11-15T16:50:31 `
  --baseline admin-evidence\e5-clean-host-20261115-soak2\soak-24h.baseline.json `
  --hours 24 --loss-budget 3500 --shed-budget 20000 `
  --json admin-evidence\e5-clean-host-20261115-soak2\soak-24h-delta-latest.json

# 2. the board must flip to 6/6
python tools/final_audit.py --release-check        # expect exit 0
```

Then, in this order (each step's failure stops the next):

1. `analysis/current-head/SOAK2-CLOSEOUT-20261116.md` — must include a section on
   what did not go as predicted: `SOAK2-20261115.md` predicted `dropped` stays 0,
   and 1387 was shed.
2. Evidence entry + `docs/gates/T20_100pct_audit.*` regeneration.
3. Commit → patch `head_sha` → `python tools/rebuild_truth.py` → `truth.py verify`
   → `python tools/release_engineering.py --refresh-digests` → push.
4. Full battery on the frozen artifact: `zig build test`, `cargo test`,
   `python -m pytest -q`, `release_engineering.py --verify`, `truth.py verify`,
   plus the `host_live` gates.
5. Release tag.

**Only after step 2** (artifact frozen, immutable) is it safe to run the attack
proofs for `#7` and `#2`, because a VM boot and a scan add load that must not
land inside the window being measured.

## 5. What must not happen before the window closes

| Forbidden | Why |
|---|---|
| Any `src/`, `nose/`, `brain/`, `shared/`, `drivers/` edit | runtime commit → new build → window invalid |
| `sc.exe stop/start AegisNids` (or any service restart) | uptime gap → `evaluate()` fails |
| Kali boot + flood | burns the 2,113-drop headroom the closeout needs |
| Port scans, `zig build test`, full `pytest` | same headroom |
| Editing `admin-evidence/**` by hand | evidence is producer-owned; a hand-edit is a fabrication |
