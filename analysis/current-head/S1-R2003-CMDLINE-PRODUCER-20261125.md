# S1 evidence — R2003 CommandLine producer (FN-1 source gap closed at E2)

**DATE:** 2026-11-25
**TARGET SOURCE HEAD:** `7822f4c162f7867555754b7f3677ade33c9548dd`
**PATCH:** `S1-R2003-CMDLINE-PRODUCER`
**EVIDENCE LEVEL:** E2 (unit/contract) + E1 (source pin). **NOT E5.**

## Claim

A read-only producer now recovers the command line of a Kernel-Process `ProcessStart` event
and carries it on the existing AEGT TLV kind 2 channel. The Zig consumer path
`decodeTdhPayload -> commandLine() -> kernel_process AhoCorasick -> R2003` is proven end to end
at E2. No CanonicalEvent wire field, rule, golden vector, authority or host-effect change.

## What changed

| File | Change |
|---|---|
| `src/windows/etw_native.c` | `append_process_command_line()` resolves `NtQueryInformationProcess` dynamically, opens the started PID with `PROCESS_QUERY_LIMITED_INFORMATION`, queries `ProcessCommandLineInformation` (class 60), validates the returned `UNICODE_STRING` pointer/length, converts UTF-16LE to UTF-8, appends AEGT TLV kind 2. `decode_tdh_properties()` calls it only for Kernel-Process ProcessStart (Id 1) and only when the provider did not publish `CommandLine` itself. |
| `src/windows/etw_realtime.zig` | New test `PROCESS-CMDLINE-002` builds the exact AEGT TLV bytes the helper emits, decodes them, asserts `imagePath()`/`commandLine()`, feeds `commandLine()` to the kernel_process automaton, and asserts the R2003 hit (hash `2485705370`). Negative control: image-only rows still produce an empty command line and no hit. |
| `tests/security/test_etw_session_name.py` | New E1 pin asserts the producer uses `NtQueryInformationProcess`/`PROCESS_QUERY_LIMITED_INFORMATION`, the allow-listed TLV, bounded checks, and contains no hardcoded `IEX`/`powershell.exe` literal. |

## Verification (real commands, real output)

| Command | Result |
|---|---|
| `python -m pytest tests/security/test_etw_session_name.py -q` | `6 passed in 0.08s` |
| `zig build test` with fresh `--cache-dir`/`--global-cache-dir` | exit `0`; direct test-binary run: `2143 passed; 10 skipped; 0 failed`; line `1965/2153 windows.etw_realtime.test.PROCESS-CMDLINE-002: decoded CommandLine fires R2003 end to end in the kernel_process lane...OK` |
| `cmake -S . -B D:\aegis-tmp\s1-build -G "Visual Studio 17 2022" -A x64` + `cmake --build ... --target aegis_etw_helper` | `etw_native.c` compiled clean; `aegis_etw_helper.dll` produced |
| `zig build` with rebuilt helper in `build/Release/` | exit `0` |

Raw logs: `D:\aegis-tmp\s1_zig_fresh.log`, `D:\aegis-tmp\s1_zig_build.log`,
`D:\aegis-tmp\s1-build\Release\aegis_etw_helper.dll`.

## Boundary

- This closes the **source** half of FN-1: the producer exists and the consumer path is proven
  at E2. It does **not** claim a real PowerShell cradle was detected on the installed daemon.
- Host E5 re-measurement (launch a long-lived PowerShell containing `IEX`, prove one R2003 row,
  prove benign/wire-only negative controls stay at zero) remains **owner action** with the
  elevated canonical-pipe runbook.
- `docs/DETECTION_VALIDATION.md` and `docs/portfolio/DETECTION_MATRIX_CURRENT.md` retain the
  "NOT RE-MEASURED at current source" marker for matrix performance until that host run occurs.
- No rule file, `CanonicalEvent` schema, `event_v*` vector, authority map or release identity
  was changed by this patch.

## Rollback

Revert `src/windows/etw_native.c`, `src/windows/etw_realtime.zig` and the test pin to the
parent source commit; rebuild the helper and daemon. No persisted state to migrate.
