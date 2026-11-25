# MASTER AUDIT — issue #44 E4/E5 elevated canonical-pipe run at build source `7822f4c` (2026-11-25)

**BUILD SOURCE:** `7822f4c162f7867555754b7f3677ade33c9548dd` (C6 capture visibility /
shutdown / monotonic source slice)
**STATUS:** PASS_E4_E5 — narrow canonical-pipe `-inject` proof executed by the
owner in an elevated Admin session, with a verified stop/inject/restore lifecycle.
No source, wire, rule, authority, host-effect or release change.

## PATCH DECLARATION

```
PATCH-ID:             C6-E4E5-7822F4C-ELEVATED
FLOW-ID:              elevated host lifecycle -> canonical pipe -> reader loop -> decoder/queue -> authoritative counters -> host restore
TARGET FILES:         records only; no src/nose/build.zig change
IN-SCOPE:             owner-run elevated lifecycle, canonical-pipe -inject, pre-state capture and restore
OUT-OF-SCOPE:         detection-rule matrix, C6 VLAN/QinQ or IPv6 host measurement, soak, loss rate,
                      install, signing, production simulation, E6/E7, AegisNids-consumer or
                      Go-Nose-producer verification, full Windows E5/kernel IDS qualification, release identity
CONTRACT / ABI / AUTHORITY / STATE IMPACT: none (service config and capture path restored)
TEST IMPACT:          none (same harness and exact-delta assertions as the 43a8bcc run)
EVIDENCE IMPACT:      one narrow E4/E5 entry at 7822f4c; 43a8bcc E3/E4/E5 entries remain
                      HISTORICAL at their recorded source
```

## Execution

The agent session is non-elevated (`admin=False`). The owner approved the UAC
prompt launched by `D:\aegis-tmp\run_i44_e45_7822f4c_as_admin.cmd`; the elevated
PowerShell ran:

```
powershell -NoProfile -ExecutionPolicy Bypass -File D:\aegis-tmp\i44_e45_7822f4c_elevated_run.ps1
```

The script's `#Requires -RunAsAdministrator` gate did not abort, and the harness
SHA256 check passed at the start of the run:

```
harness=D:\aegis-tmp\i44_e3_check_7822f4c.exe
sha256=3CAB8A36C289AE18319071600D8D8412DD97CF299F980914D252F9CAE6F88C67
```

Raw transcripts (unmodified):
- `D:\aegis-tmp\i44_e45_7822f4c_prestate.txt`
- `D:\aegis-tmp\i44_e45_7822f4c_inject.txt`
- `D:\aegis-tmp\i44_e45_7822f4c_elevated_run.txt`

## Lifecycle and exact deltas

From `i44_e45_7822f4c_elevated_run.txt` (timestamps +07:00):

```
19:02:28 pre-state saved; Nose CommandLine captured:
         D:\NIDs_Windows\nose\aegis-nose.exe -capture -iface \Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}
19:02:28 [SC] ChangeServiceConfig2 SUCCESS  (failure actions disabled for the window)
19:02:33 sc stop AegisNids -> STATE 1 STOPPED; aegis-nose stopped; pipe owners cleared
19:02:39 harness -inject -seconds 2 on \\.\pipe\aegis_nose -> exit 0
19:02:39 [SC] ChangeServiceConfig2 SUCCESS  (failure actions restored)
19:02:44 sc start AegisNids -> STATE 4 RUNNING PID 10080
19:02:45 Nose restart via WMI ReturnValue=0 ProcessId=19212
19:02:48 final processes: aegis_nids:10080 aegis-nose:19212
19:02:48 final failure config: reset 86400; RESTART 5000 / 15000 / 60000
19:02:48 final named pipes: aegis_nose
         DONE inject_exit=0
```

From `i44_e45_7822f4c_inject.txt`:

```
[E2E] pipe=\\.\pipe\aegis_nose
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
[INJECT] absurd-length OK: +1 framing, +1 pipe error
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
```

`waitForDelta` in `src/tests/cli/nose_pipe_e2e_cli.zig` returns
`error.CounterDeltaTimeout` when an expected delta is not observed, and `main`
returns exit 1 when `frames_submitted == 0`. All three cases printed `OK` and the
harness exited 0, so these are gated assertions, not decorative text.

## Host restore verification

An independent read-only re-check from the (non-elevated) agent session after the
run matched the captured pre-state: `sc qfailure` shows reset 86400 and the same
three RESTART delays (5000/15000/60000) as the pre-run value, `sc query` shows
STATE 4 RUNNING, and exactly one `aegis_nose` pipe is present with both
`aegis_nids.exe` and `aegis-nose.exe` live. Process IDs differ from the pre-state
(22576/16952 -> 10080/19212) because the service and Nose were deliberately
stopped and restarted; service configuration, running state, Nose command line
and the single canonical pipe are restored.

## Transcript artifact — not a failure

The raw inject transcript begins with a PowerShell `NativeCommandError` record
wrapping the first harness line. This is a Windows PowerShell 5.1 stream
artifact: harness messages are emitted with Zig `std.debug.print` (stderr), and
`2>&1 | Tee-Object` wraps the first stderr line in an `ErrorRecord`. It is not a
harness error — the run's `DONE inject_exit=0` line, all exact-delta assertions,
and the restored host are the verdict. The `error: [NOSE PIPE] absurd frame
length 65537: dropping connection to resync` and `warning:` lines inside the
transcript are the **expected log output of the injected failure frames**, not
unexpected faults. The raw transcript is deliberately left unmodified; no
cleaned or re-labeled copy is presented as evidence.

## Limits

- Narrow E4/E5 scope: canonical pipe plus elevated host lifecycle. The harness
  is the pipe server with a fabric sink, not AegisNids-consumer or Go-Nose-producer
  verification.
- This does **not** establish full current-head Windows E5 / kernel IDS
  qualification or detection efficacy. The C6 visibility changes (VLAN/QinQ BPF
  and IPv6 extension-header walk) still have no host measurement.
- No detection-rule or 23-rule matrix measurement; no soak, loss-rate, install,
  signing, production simulation, E6/E7 or "zero loss ever" claim.
- Release identity unchanged: `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS.
  The 36.52 h soak remains HISTORICAL at `a53eda8`.

## Completion gate

**PASS_E4_E5** at build source `7822f4c`. Combined with the E3 record at the
same source, the issue #44 exact-delta counter proof is current again. No new
E6/E7, detection-efficacy or production claim is made.
