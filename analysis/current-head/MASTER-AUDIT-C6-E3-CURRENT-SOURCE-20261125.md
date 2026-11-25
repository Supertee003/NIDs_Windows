# MASTER AUDIT — issue #44 E3 re-executed at current build source `7822f4c` (2026-11-25)

**BUILD SOURCE:** `7822f4c162f7867555754b7f3677ade33c9548dd` (C6 capture visibility /
shutdown / monotonic source slice)
**PREVIOUS BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5`
**STATUS:** PASS_E3 — narrow private-pipe `-inject` exact-delta proof at the current
source. No E4/E5 claim is made here.

## PATCH DECLARATION

```
PATCH-ID:             C6-E3-7822F4C-REPROOF
FLOW-ID:              nose ingress -> pipe reader -> canonical decoder -> queue -> authoritative counters
TARGET FILES:         records only; no src/nose/build.zig change
IN-SCOPE:             recompile the unmodified harness from current source and re-run the
                      non-elevated private-pipe E3 exact-delta proof; prepare the owner-run
                      elevated E4/E5 runbook for this source (not executed by the agent)
OUT-OF-SCOPE:         E4/E5 canonical-pipe elevated run, wire layout, golden vectors, rules,
                      authority, host effects, WFP, soak, install, signing, E6/E7, release identity
CONTRACT / ABI / AUTHORITY / STATE IMPACT: none
TEST IMPACT:          none (same harness assertions as the 43a8bcc proof)
EVIDENCE IMPACT:      one E3 entry at 7822f4c; 43a8bcc E3/E4/E5 entries remain HISTORICAL
                      at their recorded source
```

## Harness rebuild

The harness was recompiled from unmodified current source. A temporary
`src/i44_e3_wrapper.zig` supplied the `src/` module root required by
`src/tests/cli/nose_pipe_e2e_cli.zig`; it was deleted immediately after
compilation and `git status --short` was empty afterward.

```
zig build-exe src/i44_e3_wrapper.zig -femit-bin=D:\aegis-tmp\i44_e3_check_7822f4c.exe \
  --cache-dir D:\aegis-tmp\zig-local --global-cache-dir D:\aegis-tmp\zig-global -> exit 0
D:\aegis-tmp\i44_e3_check_7822f4c.exe
SHA256 3CAB8A36C289AE18319071600D8D8412DD97CF299F980914D252F9CAE6F88C67
```

Prior harness SHAs: `43a8bcc` = `09EAEAB7…02E9`; `a26c573` = `3027F320…A431E`.
The binary differs at `7822f4c`; the harness assertions are unchanged.

## E3 — private pipe, non-elevated agent session

Command: `i44_e3_check_7822f4c.exe -inject -pipe aegis_nose_i44f -seconds 2`
Transcript: `D:\aegis-tmp\c6_e3_inject.txt`. Exit `0`.

```
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
[INJECT] absurd-length OK: +1 framing, +1 pipe error
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
```

The private `aegis_nose_i44f` pipe is a test seam only; the canonical
`\\.\pipe\aegis_nose` and the live service were not touched by this run. The
PowerShell `NativeCommandError` wrapper at the head of the raw transcript is a
stderr-stream artifact, not a harness failure (exit 0, all gated exact deltas
passed); the raw transcript is unmodified.

## Limits and pending work

- This entry claims E3 only. E4/E5 at `7822f4c` remain **NOT_PROVEN** until an
  owner-run elevated canonical-pipe re-proof. The `43a8bcc` E4/E5 record is
  HISTORICAL with respect to this source.
- The prepared owner-run script is
  `D:\aegis-tmp\i44_e45_7822f4c_elevated_run.ps1` (launched by
  `D:\aegis-tmp\run_i44_e45_7822f4c_as_admin.cmd`). It re-verifies the harness
  SHA256 and restores SCM failure actions, service state, Nose command line and
  the single canonical pipe in a `finally` block. It has **not** been run by the
  agent (non-elevated session).
- C6 visibility changes (BPF VLAN/QinQ, IPv6 extension walk) are still source /
  unit-level only; no Npcap host measurement is claimed here.
- No rule matrix re-measurement, soak, loss-rate, install, signing, production
  simulation, E6/E7 or zero-loss claim. The 36.52 h soak remains HISTORICAL at
  `a53eda8`.
- Release identity unchanged: `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS.

## Completion gate

**PASS_E3** for build source `7822f4c`. Full current-source qualification gate
remains **OPEN / NOT_PROVEN** for E4/E5 and all detection-efficacy / host
qualification claims.
