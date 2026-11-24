# MASTER AUDIT — issue #44 E3 re-executed at current build source `43a8bcc` (2026-11-25)

**BUILD SOURCE:** `43a8bcc02358076380fa938b0e5632870643d3c5`
**PREVIOUS BUILD SOURCE:** `a26c5731afe154890e4f3d205d9736a5e1ead78a`
**STATUS:** PASS_E3 — narrow private-pipe `-inject` exact-delta proof at the
current source. No E4/E5 claim is made here.

## PATCH DECLARATION

```
PATCH-ID:             P8-I44-43A8BCC-E3-REPROOF
FLOW-ID:              nose ingress -> pipe reader -> canonical decoder -> queue -> authoritative counters
TARGET FILES:         records only; no src/nose/build.zig change
IN-SCOPE:             recompile the unmodified harness from current source and re-run E3
OUT-OF-SCOPE:         E4/E5 canonical-pipe elevated run, wire layout, golden vectors, rules,
                      authority, host effects, WFP, soak, install, signing, E6/E7, release identity
CONTRACT / ABI / AUTHORITY / STATE IMPACT: none
TEST IMPACT:          none (same harness assertions as the a26c573 proof)
EVIDENCE IMPACT:      one E3 entry at 43a8bcc; a26c573 entries remain HISTORICAL
```

## Harness rebuild

The harness was recompiled from unmodified current source. A temporary
`src/i44_e3_wrapper.zig` supplied the `src/` module root required by
`src/tests/cli/nose_pipe_e2e_cli.zig`; it was deleted immediately after
compilation and `git status --short` was empty afterward.

```
zig build-exe src/i44_e3_wrapper.zig -femit-bin=D:\aegis-tmp\i44_e3_check_43a8bcc.exe \
  --cache-dir D:\aegis-tmp\zig-local --global-cache-dir D:\aegis-tmp\zig-global -> exit 0
D:\aegis-tmp\i44_e3_check_43a8bcc.exe
SHA256 09EAEAB79800446C926B0FCD7AAB4C04AA655D15770BBB61F033BAF9952302E9
```

The previous harness at `a26c573` was
`3027F3205B1A81DFCA795059AAE7AFC13E593328FB962BB2A6172D913E1A431E`.

## E3 — private pipe, non-elevated agent session

Command: `i44_e3_check_43a8bcc.exe -inject -pipe aegis_nose_i44e -seconds 2`
Transcript: `D:\aegis-tmp\i44_e3_43a8bcc_inject.txt`. Exit `0`.

```
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
[INJECT] absurd-length OK: +1 framing, +1 pipe error
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
```

The private `aegis_nose_i44e` pipe is a test seam only; the canonical
`\\.\pipe\aegis_nose` and the live service were not touched by this run.

## Limits and pending work

- This entry claims E3 only. The `a26c573` E4/E5 record is HISTORICAL with
  respect to build source `43a8bcc`; the elevated canonical-pipe re-run at this
  source was subsequently executed by the owner and is recorded in
  `MASTER-AUDIT-P8-I44-SOURCE-43A8BCC-E4E5-20261125.md`.
- No rule matrix, soak, loss-rate, install, signing, production simulation,
  E6/E7 or zero-loss claim. The 36.52 h soak remains HISTORICAL at `a53eda8`.
- Release identity unchanged: `v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS.

## Completion gate

**PASS_E3** for build source `43a8bcc`; E4/E5 at the same source is recorded
separately in `MASTER-AUDIT-P8-I44-SOURCE-43A8BCC-E4E5-20261125.md`.
