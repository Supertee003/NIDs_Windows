# MASTER AUDIT — issue #44 E3 + E4/E5 re-executed at current build source `a26c573` (2026-11-25)

**BUILD SOURCE (unchanged):** `a26c5731afe154890e4f3d205d9736a5e1ead78a` (no source/build-tree commit in this slice; ADR-0008)
**RECORDS HEAD AT READ:** `f9173a2b5bb68ea99fd22553c3deb8ed86dac058`
**STATUS:** PASS_E3 + PASS_E4_E5 — narrow canonical-pipe `-inject` proof at the current source; no wire/rule/authority/host-effect/release change.

## PATCH DECLARATION

```
PATCH-ID:             P8-I44-CURRENT-SOURCE-REPROOF
FLOW-ID:              nose ingress -> pipe reader -> canonical decoder -> queue -> authoritative counters
TARGET FILES:         records only (analysis + EVIDENCE_INDEX + docs); no src/nose/build.zig change
IN-SCOPE:             recompile the unmodified harness from current source; real E3 private-pipe run;
                      real E4/E5 canonical-pipe run under an elevated operator session; host restore
OUT-OF-SCOPE:         wire layout, golden vectors, rules, authority, host effects, WFP, soak, install,
                      signing, production simulation, E6/E7, release identity
CONTRACT IMPACT:      NONE
ABI IMPACT:           NONE
AUTHORITY IMPACT:     NONE
STATE IMPACT:         NONE (service and Nose returned to their captured pre-state)
TEST IMPACT:          none (same harness/exact-delta assertions as the 03bb86d proof)
EVIDENCE IMPACT:      one E3 entry + one E5 entry at a26c573; prior entries at 03bb86d stay HISTORICAL
```

## WHY THIS SLICE EXISTS

The prior E3 (`03bb86d`) and E4/E5 (`03bb86d`) entries are valid **at their recorded
source** (`CLOSED_AT_RECORDED_HEAD`), but the subsequent P1/P8 source-hygiene
commit `a26c573` moved the build source. To make the issue #44 exact-delta
proof a **current-source** claim rather than a historical one, the same
unmodified harness source was recompiled from `a26c573` and both runs were
re-executed. No source file was edited: the temporary `src/i44_e3_wrapper.zig`
was created only to give Zig a `src/` module root and deleted immediately
after compilation (`git status` clean).

Harness: `D:\aegis-tmp\i44_e3_check_a26c573.exe`
SHA256 `3027F3205B1A81DFCA795059AAE7AFC13E593328FB962BB2A6172D913E1A431E`
(previous harness at `03bb86d`: `CAF30D47…A87F3`).

## E3 — private pipe, non-elevated agent session (2026-11-25 00:34 +07:00)

Command: `i44_e3_check_a26c573.exe -inject -pipe aegis_nose_i44e -seconds 2`
Transcript: `D:\aegis-tmp\i44_e3_a26_inject.txt`. Exit `0`.

```
[INJECT] close-before-payload OK: +1 midframe, +1 pipe error
[INJECT] absurd-length OK: +1 framing, +1 pipe error
[INJECT] drain-then-valid OK: +1 framing, +1 submitted, no pipe error
[E2E] reader frames_read=1 submitted=1 rejected=0 dropped=3 pipe_errors=2
[E2E] fabric pending=0 accepted=0 rejected=0 dropped=0
```

The live service was untouched: `AegisNids STATE : 4 RUNNING`, `aegis-nose` PID
82796, and a single `\\.\pipe\aegis_nose` before and after; the private
`aegis_nose_i44e` was a test seam only.

## E4/E5 — canonical pipe, elevated operator session (2026-11-25 00:42 +07:00)

The agent session is non-elevated (`admin=False`); it triggered the UAC launcher
and the **user's Admin session** performed all host actions. Script:
`D:\aegis-tmp\i44_e45_a26_elevated_run.ps1`. Transcripts:
`D:\aegis-tmp\i44_e45_a26_prestate.txt`, `D:\aegis-tmp\i44_e45_a26_inject.txt`,
`D:\aegis-tmp\i44_e45_a26_elevated_run.txt`.

- pre-state: failure actions `RESET 86400` + `RESTART 5000/15000/60000`;
  `AegisNids STATE 4 RUNNING` PID 77256; Nose PID 82796 with captured command
  line `D:\NIDs_Windows\nose\aegis-nose.exe -capture -iface \Device\NPF_{5FD31C6E-…}`.
- window: failure actions disabled, service `STATE 1 STOPPED`, Nose stopped,
  canonical pipe free; harness `-inject -seconds 2` on `\\.\pipe\aegis_nose`
  returned `exit 0` with the same three exact deltas and
  `read=1 drop=3 submitted=1 pipe_errors=2` / fabric all-zero.
- restore: failure actions re-applied identically; `AegisNids STATE 4 RUNNING`
  PID 2272; Nose restarted via WMI `ReturnValue=0 ProcessId=29484` with the
  captured command line; exactly one `\\.\pipe\aegis_nose`; final line
  `DONE inject_exit=0` (elevated script exit `0`).

PowerShell `NativeCommandError` lines in the inject transcript are stderr
diagnostics promoted by `2>&1 | Tee-Object`, not failed assertions.

## VERIFICATION

```
harness recompiled from a26c573 (wrapper removed)          -> exit 0
E3 private-pipe -inject                                    -> exit 0, exact deltas
E4/E5 canonical-pipe -inject (elevated operator session)   -> exit 0, exact deltas, host restored
zig build test / zig build                                 -> exit 0 (verified at a26c573 before this records slice)
cd nose && go test ./...                                   -> exit 0 (verified at a26c573 before this records slice)
python -m pytest -q -m "not host_live"                     -> 1486 passed, 1 skipped, 18 deselected, 27 subtests passed (verified at a26c573 before this records slice)
pytest tests/docs tests/release (this records slice)       -> 262 passed
pytest evidence-index integrity/release valid (this slice) -> 12 passed
python tools/truth.py verify                               -> TRUTH_VALID @ a26c573
python tools/release_engineering.py --verify               -> 674/674 digests
python scripts/check_summary.py                            -> SUMMARY_VALID
python scripts/doc_checker.py                              -> 0 FAIL, 0 WARN
```

Local `C:` hit ENOSPC during a full post-records pytest re-run; npm/Go temp
caches were redirected to `D:` and all TypeScript checks then passed, but the
canary-report and `_nose_probe.exe` tests (both write into the repo tree)
could not be re-run locally. Their fresh-runner result is the CI gate; no
source/test defect was indicated by the failures (`WinError 112` / `ENOSPC`).

## EVIDENCE LEVEL AND LIMITS

**E3** (component integration, private pipe) and **E4/E5** (system integration +
Windows host verification for the **canonical pipe + elevated stop/inject/restore
lifecycle only**). The harness is still the pipe server with a fabric sink:
this is **not** AegisNids-consumer or Go-Nose-producer verification, no
detection-rule or 23-rule-matrix measurement, no soak, loss-rate, install,
signing, production simulation, E6/E7 or "zero loss ever" claim. The 36.52 h
soak remains HISTORICAL at `a53eda8`. Release identity remains
`v1.1` / `466a226` / `a53eda8`, 6/6 gates PASS (0 open).

No wire-layout, golden-vector, rule, authority, host-effect, re-key, tag or
signature change. No new release tag or build-source commit.

## ROLLBACK / GATE

Revert the records commits; the host state is already restored and no source
change exists to roll back. **Completion gate: PASS_E3 + PASS_E4_E5** at
unchanged build source `a26c573` when truth/digest/summary/doc/link gates are
green and CI is success.
