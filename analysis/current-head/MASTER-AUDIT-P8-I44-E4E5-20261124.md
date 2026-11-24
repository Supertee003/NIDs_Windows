# MASTER AUDIT — P8 / issue #44 E4/E5 elevated Windows-host `-inject` proof (2026-11-24)

**RECORDS HEAD AT READ:** `8cfecc02e34d82bca503ee15fd04c02f258b1145` (clean `main`, synced with `origin/main`)
**BUILD SOURCE (UNCHANGED):** `03bb86d98ea5925170157b6d0f9b63ed12f4c858` (no source/build-tree commit in this slice; ADR-0008)
**STATUS:** PASS_E4 / PASS_E5 — real `-inject` on the canonical Windows named pipe with an elevated stop → inject → restore lifecycle, host restored.

---

## PATCH DECLARATION

```
PATCH-ID:             P8-I44-E4E5-HOST-INJECT (records-only; no source delta)
FLOW-ID:              host lifecycle -> canonical pipe -> real reader loop -> decoder/queue -> authoritative counters -> host restore
TARGET HEAD:          8cfecc0 (build source 03bb86d)
TARGET FILES:         NONE in the source/build tree
                      analysis/current-head/MASTER-AUDIT-P8-I44-E4E5-20261124.md (new)
                      EVIDENCE_INDEX.json (new E5 entry + recomputed level counts)
                      AI_CONTEXT.md, docs/ai-context/10-current-phase.md (current-phase pointer)
IN-SCOPE:             elevated Windows-host execution of the already-built harness on \\.\pipe\aegis_nose;
                      pre-state capture, failure-action disable/restore, service stop/start, Nose stop/restart, post-state check
OUT-OF-SCOPE:         source/code change, wire layout, golden vectors, rules, authority, host-effect/WFP mutation,
                      soak/loss-rate, install, signing, release/tag/key, E6/E7
CONTRACT IMPACT:      NONE
ABI IMPACT:           NONE
AUTHORITY IMPACT:     NONE — no new effect; the service was stopped and restored with its original configuration
STATE IMPACT:         TRANSIENT host lifecycle only: service STOPPED during the window, then RUNNING again with
                      the original failure actions; Nose restarted with the captured command line
TEST IMPACT:          none (records-only; prior E3 source slice remains the build source)
EVIDENCE IMPACT:      one E5 entry; E5_count 122->123 with resolvable-artifact counts +1; build source unchanged
```

## WHY THIS SLICE EXISTS

The E3 slice (`03bb86d`) executed the exact-delta harness on a **private** pipe
(`\\.\pipe\aegis_nose_i44d`) because this agent session is not administrator and
the LocalSystem service ACL grants stop (`WP`) only to SYSTEM/Administrators.
That left two honest limits: the canonical production pipe name was not
exercised, and no elevated host stop/restore lifecycle was demonstrated.

For this slice the user ran the prepared elevated script in their own Admin
PowerShell. The agent did **not** elevate, bypass UAC, or stop any process
itself; all host actions below were performed by that elevated user session and
are recorded verbatim from its transcript.

## SYSTEM FLOW AND INVARIANT

```
pre-state capture (failure config + service state + process command lines)
  -> disable SCM failure actions (no re-arm during the window)
  -> sc stop AegisNids -> STATE 1 STOPPED
  -> stop aegis-nose (twice; watcher re-arm guard) -> canonical pipe free
  -> i44_e3_check.exe -inject -seconds 2 on \\.\pipe\aegis_nose
       -> close-before-payload -> +1 midframe, +1 pipe error
       -> absurd-length       -> +1 framing,  +1 pipe error
       -> drain-then-valid    -> +1 framing,  +1 submitted, no pipe error
  -> restore failure actions -> sc start AegisNids -> STATE 4 RUNNING
  -> restart Nose via WMI with the captured command line
  -> verify single canonical pipe and final failure config
```

**INVARIANT:** the host ends with `AegisNids` RUNNING, the original
`RESET_PERIOD 86400` / `RESTART 5000,15000,60000` failure actions, a single
`\\.\pipe\aegis_nose`, and a live Nose capture process. No build source commit,
wire format, rule, authority or release identity changed.

## REAL HOST EXECUTION (E4/E5)

**Harness provenance:** `D:\aegis-tmp\i44_e3_check.exe`, compiled from build
source `03bb86d`; SHA256
`CAF30D474E734C277BCB66DAAE57E398799B409CA04C9E76EC3882A5A68A87F3`.
Launcher `D:\aegis-tmp\run_i44_e45_as_admin.cmd` (UAC → Admin PowerShell),
script `D:\aegis-tmp\i44_e45_elevated_run.ps1` (PowerShell parser: `PARSE_OK`).

**Lifecycle transcript** (`D:\aegis-tmp\i44_e45_elevated_run.txt`, verbatim times):

| Time (+07:00) | Event |
|---|---|
| 22:39:30.7228727 | pre-state saved to `D:\aegis-tmp\i44_e45_prestate.txt` |
| 22:39:30.8025791 | Nose command line captured: `D:\NIDs_Windows\nose\aegis-nose.exe -capture -iface \Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}` |
| 22:39:30.8046496 | `sc failure AegisNids ... actions= none` → SUCCESS |
| 22:39:30.8341388 | `sc stop AegisNids` → `STATE : 3 STOP_PENDING` |
| 22:39:38.8114969 | `STATE : 1 STOPPED` |
| 22:39:38.8136893 | stop `aegis-nose` (and again after 2 s) |
| 22:39:40.8825147 | pipe owners cleared; run `-inject` on canonical pipe |
| 22:39:44.3830323 | `harness exit=0` |
| 22:39:44.3840450 | restore failure actions → SUCCESS |
| 22:39:44.4059761 | `sc start AegisNids` → `STATE : 2 START_PENDING`, PID 77256 |
| 22:39:49.8374370 | `STATE : 4 RUNNING` |
| 22:39:50.2480513 | Nose restart `ReturnValue=0 ProcessId=65040` |
| 22:39:53.3006566 | final processes `aegis_nids:77256 aegis-nose:65040` |
| 22:39:53.3182132 | final failure config matches pre-state |
| 22:39:53.3192380 | `DONE inject_exit=0` |

**Inject transcript** (`D:\aegis-tmp\i44_e45_inject.txt`, UTF-16LE):

```
[E2E] pipe=\\.\pipe\aegis_nose
info: [NOSE PIPE] pipe server created, waiting for client...
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
error: [NOSE PIPE] absurd frame length 65537: dropping connection to resync (nose will reconnect)
[INJECT] absurd-length OK: +1 framing, +1 pipe error
warning: [NOSE PIPE] rejected frame length: 108, expected 109/133 or v3 165..1189
debug: [NOSE PIPE] canonical event submitted: event_id=62541
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
info: [NOSE PIPE] reader loop exiting (read=1 drop=3 submitted=1)
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
```

`harness exit=0`; `DONE inject_exit=0`. The transcript contains one PowerShell
`NativeCommandError` record at the top because `2>&1 | Tee-Object` promotes the
harness's stderr diagnostics (info/warning/error lines) to error records; that
is a PowerShell rendering artifact, **not** a failed assertion — all three
`[INJECT] ... OK` lines and exit code 0 are recorded in the same transcript.

**Post-run verification by the non-elevated agent session:** `admin=False`;
`sc query AegisNids` → `STATE : 4 RUNNING`, PID 77256; `sc qfailure AegisNids` →
`RESET_PERIOD 86400` and the three original `RESTART` delays 5000/15000/60000;
`\\.\pipe\` contains exactly one AEGIS pipe, `\\.\pipe\aegis_nose`; processes
`aegis_nids 77256` and `aegis-nose 65040`. The pre-run PIDs were 82112/58924 —
they changed because the service and Nose were deliberately restarted, not
because of a crash.

## VERIFICATION OF RECORDS SIDE

```
zig build test                          -> exit 0 (unchanged source at 03bb86d)
zig build                               -> exit 0
python -m pytest -q -m "not host_live"  -> 1486 passed, 1 skipped, 18 deselected, 27 subtests passed
python tools/truth.py verify            -> TRUTH_VALID @ 03bb86d
python tools/release_engineering.py --verify -> 674/674 digests
python scripts/doc_checker.py           -> 0 FAIL, 0 WARN
python scripts/check_summary.py         -> SUMMARY_VALID
bad-link check                          -> none
CI at 8cfecc0 (previous E3 records)     -> AEGIS CI success 45405664748, Host Regression success 45405664473
```

## EVIDENCE LEVEL AND LIMITS

**E4 (system integration) + E5 (Windows host verification), narrow scope:**
the exact-delta counter path on the **canonical** `\\.\pipe\aegis_nose`, under a
real elevated Windows host stop/inject/restore lifecycle, with the host returned
to its original configuration.

Limits, stated explicitly:
- The harness is still the pipe **server** with a fabric sink. It does not exercise the `AegisNids` service as consumer or the Go Nose producer as client; the real Nose was stopped before injection and restarted afterwards. No end-to-end service-consumer claim is made.
- No rule/detection-matrix measurement: the 23-rule matrix and FP/FN register remain un-re-measured at this build source. E5 here is host lifecycle + pipe/counter verification only.
- No E6/E7, no soak, no install, no signing, no production simulation, no loss-rate measurement and no "zero loss ever" claim. The recorded 36.52 h soak remains HISTORICAL at `a53eda8`.
- No WFP/host-effect, wire-layout, golden-vector, rule, authority, re-key, tag or signature change. Release identity remains `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS (0 open).

## ROLLBACK

No source rollback is needed: this slice changes no build source. To retract the
claim, revert the records commits that add this document and its
`EVIDENCE_INDEX` entry/counts; the E3 evidence at `03bb86d` remains intact. The
host-side service/Nose were already restored by the elevated script; no further
host rollback is required.

## COMPLETION GATE

PASS_E4 / PASS_E5 — canonical-pipe `-inject` exact deltas green on a Windows
host, exit 0, failure actions/service/Nose/pipe restored and verified, records
gates green at unchanged build source `03bb86d`.
