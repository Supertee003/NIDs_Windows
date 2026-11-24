# MASTER AUDIT — issue #44 E4/E5 elevated canonical-pipe run at build source `43a8bcc` (2026-11-25)

**BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5`
**STATUS:** PASS_E4_E5 — narrow canonical-pipe `-inject` proof executed by the
owner in an elevated Admin session, with a verified stop/inject/restore lifecycle.
No source, wire, rule, authority, host-effect or release change.

## PATCH DECLARATION

```
PATCH-ID:             P8-I44-43A8BCC-E4E5-ELEVATED
FLOW-ID:              elevated host lifecycle -> canonical pipe -> reader loop -> decoder/queue -> authoritative counters -> host restore
TARGET FILES:         records only; no src/nose/build.zig change
IN-SCOPE:             owner-run elevated lifecycle, canonical-pipe -inject, pre-state capture and restore
OUT-OF-SCOPE:         detection-rule matrix, soak, loss rate, install, signing, production simulation,
                      E6/E7, AegisNids-consumer or Go-Nose-producer verification, release identity
CONTRACT / ABI / AUTHORITY / STATE IMPACT: none (service config and capture path restored)
TEST IMPACT:          none (same harness and exact-delta assertions as the a26c573 run)
EVIDENCE IMPACT:      one E4/E5 entry at 43a8bcc; a26c573 entries remain HISTORICAL
```

## Execution

The agent session is non-elevated (`admin=False`). The owner ran the prepared
script from an elevated PowerShell:

```
powershell -NoProfile -ExecutionPolicy Bypass -File D:\aegis-tmp\i44_e45_43a8bcc_elevated_run.ps1
```

The script's `#Requires -RunAsAdministrator` gate did not abort, and the harness
SHA256 check passed at the start of the run:

```
harness=D:\aegis-tmp\i44_e3_check_43a8bcc.exe
sha256=09EAEAB79800446C926B0FCD7AAB4C04AA655D15770BBB61F033BAF9952302E9
```

Raw transcripts (unmodified):
- `D:\aegis-tmp\i44_e45_43a8bcc_prestate.txt`
- `D:\aegis-tmp\i44_e45_43a8bcc_inject.txt`
- `D:\aegis-tmp\i44_e45_43a8bcc_elevated_run.txt`

## Lifecycle and exact deltas

From `i44_e45_43a8bcc_elevated_run.txt`:

```
03:58:47 pre-state saved; Nose CommandLine captured:
         D:\NIDs_Windows\nose\aegis-nose.exe -capture -iface \Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}
03:58:47 [SC] ChangeServiceConfig2 SUCCESS  (failure actions disabled for the window)
03:58:54 sc stop AegisNids -> STATE 1 STOPPED; aegis-nose stopped; pipe owners cleared
03:58:59 harness -inject -seconds 2 on \\.\pipe\aegis_nose -> exit 0
03:59:00 [SC] ChangeServiceConfig2 SUCCESS  (failure actions restored)
03:59:05 sc start AegisNids -> STATE 4 RUNNING PID 78728
03:59:05 Nose restart via WMI ReturnValue=0 ProcessId=41440
03:59:08 final processes: aegis_nids:78728 aegis-nose:41440
03:59:08 final failure config: reset 86400; RESTART 5000 / 15000 / 60000
03:59:08 final named pipes: aegis_nose
         DONE inject_exit=0
```

From `i44_e45_43a8bcc_inject.txt`:

```
[E2E] pipe=\\.\pipe\aegis_nose
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
[INJECT] absurd-length OK: +1 framing, +1 pipe error
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
```

`waitForDelta` in `src/tests/cli/nose_pipe_e2e_cli.zig:151-170` returns
`error.CounterDeltaTimeout` when an expected delta is not observed, and `main`
returns exit 1 when `frames_submitted == 0` (`:297-299`). All three cases printed
`OK` and the harness exited 0, so these are gated assertions, not decorative text.

## Host restore verification

An independent read-only re-check from the (non-elevated) agent session after the
run matched the captured pre-state: `sc qfailure` shows reset 86400 and the same
three RESTART delays (5000/15000/60000), `sc queryex AegisNids` shows STATE 4
RUNNING PID 78728, and exactly one `aegis_nose` pipe is present. Process IDs
differ from the pre-state (2272/30636 -> 78728/41440) because the service and
Nose were deliberately stopped and restarted; service configuration, running
state, Nose command line and the single canonical pipe are restored.

## Transcript artifact — not a failure

The raw `i44_e45_43a8bcc_inject.txt` begins with a PowerShell
`NativeCommandError` record wrapping the first harness line:

```
i44_e3_check_43a8bcc.exe : [E2E] pipe=\\.\pipe\aegis_nose
At D:\aegis-tmp\i44_e45_43a8bcc_elevated_run.ps1:97 char:5
+     & $harness -inject -seconds 2 2>&1 | Tee-Object -FilePath $outInj ...
    + CategoryInfo          : NotSpecified: ([E2E] pipe=\\.\pipe\aegis_nose:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
```

This is a Windows PowerShell 5.1 stream artifact: every harness message is
emitted with Zig `std.debug.print` (stderr), and `2>&1 | Tee-Object` wraps the
first stderr line in an `ErrorRecord`. It is not a harness error — the run's
`DONE inject_exit=0` line, all exact-delta assertions, and the restored host are
the verdict. The `error: [NOSE PIPE] absurd frame length 65537: dropping
connection to resync` and `warning:` lines inside the transcript are the
**expected log output of the injected failure frames**, not unexpected faults.

The raw transcript is deliberately left unmodified. No cleaned or re-labeled
copy is presented as evidence.

## Limits

- Narrow E4/E5 scope: canonical pipe plus elevated host lifecycle. The harness
  is the pipe server with a fabric sink, not AegisNids-consumer or Go-Nose-producer
  verification.
- No detection-rule or 23-rule matrix measurement; no soak, loss-rate, install,
  signing, production simulation, E6/E7 or "zero loss ever" claim.
- Release identity unchanged: `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS.
  The 36.52 h soak remains HISTORICAL at `a53eda8`.

## Completion gate

**PASS_E4_E5** at build source `43a8bcc`. Combined with the E3 record at the
same source, the issue #44 exact-delta counter proof is current again. No new
E6/E7 or production claim is made.
