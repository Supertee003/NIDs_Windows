# SOAK2-CLOSEOUT-20261116 - the 24 h window, closed against the host gate

> **DRAFT - NOT EVIDENCE YET.** Every `PENDING-GATE` value below must be copied
> from the gate artifact written by the command in §1 after the window closes at
> `2026-11-16T16:50:31`. Do not cite this file as proof until the banner says
> CLOSED. The intermediate samples are observations, not the verdict.

**Created:** 2026-11-16T00:41+07:00
**Window:** `2026-11-15T16:50:31` -> `2026-11-16T16:50:31` (24 h)
**Build under test:** `aegis_nids.exe` sha256
`7955a6e3c9bb8ac4e5872114b33316aada74f09e39f48c0513ba6ffa58d71a18`,
build source `7c604d5` (verified by hash, not filename)
**Window record:** `analysis/current-head/SOAK2-20261115.md`
**Baseline:** `admin-evidence/e5-clean-host-20261115-soak2/soak-24h.baseline.json`

## 1. Gate command and verdict

```powershell
python tools/host_soak_check.py `
  --start 2026-11-15T16:50:31 `
  --baseline admin-evidence\e5-clean-host-20261115-soak2\soak-24h.baseline.json `
  --hours 24 --loss-budget 3500 --shed-budget 20000 `
  --json admin-evidence\e5-clean-host-20261115-soak2\soak-24h-delta-latest.json
```

| Fact | Value |
|---|---|
| Verdict | `PENDING-GATE` |
| Elapsed | `PENDING-GATE` h |
| `problems` | `PENDING-GATE` |
| SCM restarts (7031/7034) | `PENDING-GATE` |
| Services | `PENDING-GATE` |
| Gate artifact | `PENDING-GATE` |

`PASS` requires: both required services RUNNING, daemon reachable with uptime at
least the window, `state` not DEGRADED, every loss counter within 3,500, policy
shed within 20,000, and no SCM restart inside the window. A check that did not
execute must not print PASS; if the gate cannot run, this file stays DRAFT.

## 2. Counter ledger

Baseline at `2026-11-15T16:50:31` (tool-captured): every loss counter 0,
`shed_overload` 0, loss budget 3,500, shed budget 20,000.

| Counter | At 23:09 (6.32 h) | Live at 00:42 (7.85 h) | At gate |
|---|---:|---:|---:|
| `queue_dropped_total` | 1,387 | 1,387 | `PENDING-GATE` |
| `source_quota_shed` | 1,387 | 1,387 | `PENDING-GATE` |
| `shed_overload` | 0 | 1,094 | `PENDING-GATE` |
| `reserved_tail_shed` | - | 0 | `PENDING-GATE` |
| `depth_peak` | - | 7,168 | `PENDING-GATE` |
| nose rejected/dropped/pipe errors | 0/0/0 | 0/0/0 | `PENDING-GATE` |
| minifilter ring/pipeline dropped | 0/0 | 0/0 | `PENDING-GATE` |

Intermediate sources are recorded so the gate verdict cannot be rewritten from
memory: the 23:09 sample is `admin-evidence/.../soak-24h-delta-latest.json`
(`IN_PROGRESS`), the 00:42 sample is `aegisctl.py queue --json`.

The 1,387 dropped rows are all `capture_etw` / kind `reg_change`, counted as
`source_quota_shed` - the bounded ETW source share rejected them before the
pipeline. They are not network rows and they are not overload shed.

## 3. What did not go as predicted

The window record stated two predictions that measurement falsified. Both are
recorded here because a closeout that only lists wins is not a closeout.

1. **"`dropped` stays at 0."** Actual: 1,387 ETW `reg_change` rows were
   quota-shed, first visible by `2026-11-15T17:07` and flat at every sample
   since. The build did what the quota is designed to do; the prediction was
   wrong, not the code.
2. **"Nothing in this session will run live gates before 16:50."** Actual: the
   40-port proof and its 10-port control ran at `17:07`/`17:10` (see §4). The
   measured cost was 0 dropped, 0 overload shed, 0 quota growth, so the window
   survived - but the deviation is disclosed, not hidden.
3. **Overload shed was not zero after all.** The 23:09 gate sample read 0; by
   00:42 `shed_overload` was 1,094 and `depth_peak` had reached the 7,168 ETW
   occupancy cap. By construction (`telemetry_threads.zig:359-371`) this shed
   only covers ETW Kernel-File Write / NameDelete rows under storm pressure, so
   no network frame was discarded and no detection row was lost. It is inside
   the 20,000 owner-approved budget; the trigger window (23:09-00:42) has not
   been root-caused beyond "ETW share pressure".

## 4. Deviation record - the L4 proof inside the no-gate window

`DETECT-L4-001` needed a real `>= 20` distinct-port SYN burst from one source.
It was run against the same Wi-Fi link the canonical Go Nose watches:

- positive: 40 SYNs to `192.0.2.1:1-40` in 2.30 s, +26,727 captured frames,
  exactly one R9006 row (`rule 1745456278`, `2026-11-15T17:07:45.820Z`);
- negative control: 10 SYNs in 0.58 s, R9006 = 0;
- cost: `dropped` +0, `shed_overload` +0, `source_quota_shed` +0.

Artifacts and the full argument are in
`analysis/current-head/DETECT-L4-001-20261116.md` and
`admin-evidence/lab-l4-testnet-20261116/`,
`admin-evidence/lab-l4-testnet-negative-20261116/`. The owner decision was to
keep the window and disclose the deviation rather than restart for a third 24 h
window; that decision is recorded in `GAP-TRIAGE-20261116.md` §6.

## 5. Adjacent findings carried out of this window

- `RULE-LAYER-SCOPE-001`: the AC at `event_processor.zig:280` applies
  `KERNEL_PROCESS`-layer rules to wire bytes, so R2003 matches TLS records
  (366 rows, 291 with `src_port 443`). All rows are `observed`; no host effect.
  P3/v1.1 because the fix is a `src/` change that would reopen a soak.
- `DETECT-L4-001` is closed at E5 for one rule, one interface, one stimulus
  class. It is not a remote-attacker or L7 claim.
- Protocol-anomaly IDs (`10000 + kind`) are observe-only evidence and absent
  from `Rules.json`; the runbook now documents how to exercise and read them
  (`docs/runbooks/RB-022-wifi-bridged-lab.md`).

## 6. Closeout checklist

- [ ] Gate command above returns `PASS`, elapsed >= 24 h, `problems []`, no restarts
- [ ] `python tools/final_audit.py --release-check` exits 0 (6/6)
- [ ] Evidence entry added and `EVIDENCE_INDEX.json` count updated
- [ ] `docs/gates/T20_100pct_audit.*` regenerated at this HEAD
- [ ] `rebuild_truth.py` then `truth.py verify` = `TRUTH_VALID`
- [ ] `release_engineering.py --refresh-digests` then `--verify`
- [ ] Commit, patch `head_sha`, push `codex/o2-etw-context`

## 7. Limits

1. One host, one build, one 24 h window. It says this daemon did not regress on
   this machine; it says nothing about a second host or a different workload.
2. The window has no *authorized* gate activity except the disclosed L4 proof.
   It does not prove detection under sustained load; that is the E4/E6 battery,
   run after the window on the frozen artifact.
3. The 20,000 shed budget remains an owner-level policy decision, not a claim
   that 20,000 discarded rows are free. The observed 1,094 are ETW-only.
