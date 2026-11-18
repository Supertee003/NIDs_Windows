# SUITE-FLAKE-001 — resolution at build source `4169839`

## Claim

The historical `XdrEngine prune` process death is an environmental/interaction
flake, not an open product defect at the recorded build source. It is closed
**at this recorded source only**; if it recurs, reopen it with a crash dump and
the full runner log. No source was changed to make this determination, so the
signed candidate `release/T20-final/bece8f1` and its runtime `4169839` are
unchanged.

## What was observed earlier

Three consecutive full-suite `zig build test` runs on 2026-11-18 ended with:

```text
while executing test 'xdr.xdr_engine.test.XdrEngine prune', the following test command failed
```

Those runs reported 2103/2114 passed, 1 failed, 10 skipped. The same 11 XDR
tests passed in isolation, and the only changes between the failing and passing
periods were records/tooling, not XDR or the test runner. The wording is the
build runner reporting a dead test process, not an assertion failure, so
attribution to `XdrEngine` was always provisional.

## What was run at the recorded source

Source commit: `4169839bff11937060ed4471b3a74717f11a50c3` (unchanged across all
runs below).

CI on `codex/v1.1-release`:

| Run | Records tip | `Zig Build & Test` | Overall |
|---|---|---|---|
| 44323795191 | `6b1b664` | success | success |
| 44325060322 | `1ab2109` | success (4m11s) | success |

Local runs with a fresh Zig cache each time, so the test binaries were rebuilt
and re-executed rather than replayed from cache:

```powershell
$zig=(Get-Command zig).Source
$base='C:\Users\User\AppData\Local\Temp\opencode\zig-fresh-cache'
for ($i=1; $i -le 2; $i++) {
  $c="$base-$i"
  Remove-Item -Recurse -Force $c -ErrorAction SilentlyContinue
  & $zig build test --summary all --cache-dir $c
}
```

Result, both runs:

```text
Build Summary: 8/8 steps succeeded; 3337/3347 tests passed; 10 skipped
exit 0
```

The 10 skipped tests are the declared skips, not unreported failures. Two
additional cached local runs also exited 0, but they are not used as evidence
because they did not re-execute the suite.

## Disposition

- `SUITE-FLAKE-001` → `CLOSED_AT_RECORDED_HEAD`, recorded against `4169839`.
- Root cause is **not claimed**. The evidence is that two CI runs and two
  fresh-cache local runs on the recorded source exited 0, while the earlier
  failure never reproduced after the source settled. Concurrent host load is a
  plausible contributor but is not proven and is not written as a finding.
- No source, build-file, test-runner or candidate change is made. Re-signing the
  release would require a real product fix, which this evidence does not show.
- Recurrence rule: capture the full runner log, the build summary, host memory
  pressure and the exact source SHA before reopening. A cached-green run is not
  evidence; a fresh-cache run or CI run is.
