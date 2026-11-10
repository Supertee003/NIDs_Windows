# ISSUE-30-ATTRIBUTION-20261110 — heap crash in `aegis_fim_stop`: root cause, provenance, and the deployment gap that kept it alive

**Date:** 2026-11-10
**HEAD at analysis:** `9e0d8626c647e6362244e64064ed9ebd195471b7` (branch `codex/o2-etw-context`)
**Build source commit:** `a8f3abfdfd577c38618f1342200a10545c41fd5c`
**Subject:** AEGIS issue #30 — SCM `7031` terminations of `AegisNids`
**Evidence level:** E1 (static + binary inspection) + E2 (new gate + unit tests). **No E5 claim.** No new host run was made; every host fact below is a read of the existing event log, existing dumps, and existing installed files.

---

## 1. Answer in one paragraph

The crash is a **use-after-free of the native FIM session** in the pre-fix
`aegis_fim_stop()`. The fix exists in source (commit `9766525`, 2026-11-01
16:58 +07) and was even built on 2026-11-01 16:56 into
`build/Release/aegis_fim_helper.dll` (`5275ED8B…`, 14,848 B), but **the packaging
input `zig-out/bin/aegis_fim_helper.dll` was never refreshed**: it is still the
2026-10-16 build (`1291A73E…`, 14,336 B). Every bundle and every installed
runtime therefore ships the crashing helper. The service keeps dying because it
is still running the October binary — not because the fix failed.

This is the same failure class as **S1-01** (WFP driver in `System32` ≠
`build/x64/wfp`): a build output and a packaging input that no step couples,
with no deploy-time hash assertion.

---

## 2. Crash evidence

### 2.1 SCM and WER

```
SCM 7031 (AegisNids terminated unexpectedly), last 8 days
2026-11-10 02:17:57   2026-11-10 02:14:43   2026-11-09 00:33:22
2026-11-06 21:24:41   2026-11-05 17:35:01   2026-11-05 16:23:37
2026-11-04 14:21:20   2026-11-03 22:22:52   2026-11-03 16:41:59
```

Only two of them produced `Application Error 1000`, and both exist as full
dumps (`DumpType 2`, LocalDumps `HKLM\…\Windows Error Reporting\LocalDumps\aegis_nids.exe`
→ `admin-evidence\e5-host-proof-20261026\wer-localdumps`):

| Dump | Crash time | Size | Faulting image |
|---|---|---|---|
| `aegis_nids.exe.16144.dmp` | 2026-11-04 14:21:20 | 289,324,215 B | `aegis_nids.exe` ts `0x6AE98F4A` |
| `aegis_nids.exe.16408.dmp` | 2026-11-05 16:23:37 | 289,315,496 B | `aegis_nids.exe` ts `0x6AE98F4A` |

Both: exception **`0x80000003`** (`STATUS_BREAKPOINT`), fault offset `0x9346a`.
A `0x80000003` here is not a deliberate debugger breakpoint — it is the NT heap's
**corruption check firing `int 3`** inside `RtlpCollectFreeBlocks` while servicing
a `free()`.

### 2.2 Stack (cdb 10.0.28000.2526, `!analyze -v`)

```
RtlpCollectFreeBlocks
RtlpDeCommitFreeBlock
RtlpFreeHeap
RtlFreeHeap
ucrtbase!free_base
aegis_fim_helper!aegis_fim_stop+0x77      <- 16408.dmp (11-05)
aegis_nids+0x3e135 / 0x10a423 / 0xb6bdd

RtlpCallVectoredHandlers
aegis_fim_helper!aegis_fim_stop+0x15a     <- 16144.dmp (11-04)
```

Two different offsets inside the same function, same exception, same faulting
image: the heap is already corrupt when `stop()` frees the session, and the
detection point moves with allocator state. That is the signature of a
**lifetime bug (free-while-referenced)**, not of a bad pointer at one site.

### 2.3 What the pre-fix code did

`src/windows/fim_native.c` pre-fix `fim_thread()` looped on
`InterlockedCompareExchange(&s->running, 1, 1)` and submitted a read **with no
lock**, while `aegis_fim_stop()` called `CancelIoEx()` and then freed `s`
unconditionally. Two races follow:

1. stop's `CancelIoEx` can run **before** the worker submits its next read, so
   that read is never cancelled and the worker keeps touching `s` after `free()`.
2. Nothing waits for the worker before `free()`, so even a cancelled read can
   still be unwinding inside the helper when the memory is released.

Fix (`9766525`, in HEAD at `src/windows/fim_native.c:192-223`): serialize
submission and cancellation on `s->lock`, stop the loop under that lock, wait
with `WaitForSingleObject(s->thread, INFINITE)`, and **retain** the session
(`return -2`) rather than free it if the worker does not signal.

---

## 3. The decisive provenance check

The dumps were taken on 11-04 and 11-05, i.e. *after* the 11-01 fix commit. So
"the dump predates the fix" cannot be argued from dates alone. It was proven
from the loaded module inside the dump:

```
0:002> lm m aegis_fim_helper
00007ffe`770f0000 00007ffe`770f9000   aegis_fim_helper   (deferred)

0:002> !dh 7ffe770f0000 -f
6AD19661 time date stamp Fri Oct 16 10:13:37 2026

0:002> s -a 7ffe770f0000 L?0x9000 "session retained"
0:002> s -a 7ffe770f0000 L?0x9000 "did not signal termination"
0:002> s -a 7ffe770f0000 L?0x9000 "CancelIoEx"
00007ffe`770f3e04  43 61 6e 63 65 6c 49 6f-45 78 ...
```

- The loaded helper's PE timestamp is **2026-10-16 10:13:37** — 16 days before
  the fix commit.
- The post-fix diagnostic strings (`session retained`, `did not signal
  termination`) are **absent** from the loaded image; the pre-existing
  `CancelIoEx` import name is present, so the search reached real module memory.

Conclusion: the crash was produced by the **pre-fix** helper. The fix was not
in the binary that crashed, so the crash says nothing about whether the fix
works — and the recurrence on 11-06/11-09/11-10 is expected, not anomalous.

---

## 4. Why the fix never reached the host

| Artifact | SHA-256 (first 16) | Size | Built | Post-fix strings |
|---|---|---|---|---|
| `build/Release/aegis_fim_helper.dll` | `5275ED8B004E4BEC` | 14,848 | 2026-11-01 16:56 | **yes** |
| `build/Debug/aegis_fim_helper.dll` | `3934AB13B37AE9D4` | 60,928 | 2026-11-09 21:36 | **yes** |
| `zig-out/bin/aegis_fim_helper.dll` *(packaging input)* | `1291A73ED2CC08DB` | 14,336 | **2026-10-16 10:13** | no |
| `C:\Program Files\AEGIS NIDS\runtime\aegis_fim_helper.dll` | `1291A73ED2CC08DB` | 14,336 | 2026-10-16 10:13 | no |
| module loaded in both crash dumps | PE ts `6AD19661` | — | **2026-10-16 10:13:37** | no |

Every consumer reads `zig-out/bin`, never `build/Release`:

```
installer/aegis.nsi:69        File "zig-out\bin\aegis_fim_helper.dll"
tools/installer.py:244        File "zig-out\bin\aegis_fim_helper.dll"
tools/release_candidate.py:43 zig-out/bin/aegis_fim_helper.dll
tools/golden_path_evidence.py:185 zig-out/bin/aegis_fim_helper.dll
```

`CMakeLists.txt` builds the helpers into `build/Release`; `zig build` installs
into `zig-out/bin`. No step connected them, and no gate compared them. So from
2026-10-16 onward **every** package shipped the pre-fix helper — including the
bundles produced for the 11-06 … 11-10 host windows (each `rollback-installed/`
and `package-extract/` directory under `admin-evidence/` still holds
`1291A73E…`).

---

## 5. Repair in this slice

### 5.1 New gate — `tools/stage_helpers.py`

- `--stage` copies `build/Release/{aegis_wfp_user,aegis_etw_helper,aegis_fim_helper}.dll`
  into `zig-out/bin`, and **refuses** when the build output is older than its
  `.c` source, or when the build is missing.
- `--check` is the packaging gate: staged copy must exist, match the build
  byte-for-byte (SHA-256), and not predate the source. Debug output is never
  accepted as a substitute for Release.

Verified on this host (before → after):

```
$ python tools/stage_helpers.py --check
FAIL aegis_wfp_user.dll: staged copy differs from build\Release\aegis_wfp_user.dll
FAIL aegis_etw_helper.dll: staged copy zig-out/bin/aegis_etw_helper.dll predates its source
FAIL aegis_fim_helper.dll: staged copy zig-out/bin/aegis_fim_helper.dll predates its source
exit 1

$ python tools/stage_helpers.py --stage
STAGED aegis_wfp_user.dll 76b46cd6073c <- build\Release\aegis_wfp_user.dll
STAGED aegis_etw_helper.dll ad6d7f1ffd80 <- build\Release\aegis_etw_helper.dll
STAGED aegis_fim_helper.dll 5275ed8b004e <- build\Release\aegis_fim_helper.dll
exit 0
```

`5275ed8b004e` is the fixed 2026-11-01 build (§4).

### 5.2 Wiring

- `scripts/build_all.bat` — after the CMake helper build, runs
  `python tools\stage_helpers.py --stage` and fails the pipeline if it refuses.
- `tools/installer.py` — `generate_nsi()` now runs the same check **before**
  emitting the NSIS script and exits 1 on any problem: a bundle whose helper is
  stale can no longer be generated (verified: generation still passes after
  staging).
- `tools/installer.py` driver copy (S1-01) — replaced
  `cmd /c copy /y …` + "print the signature of whatever is on disk" with
  `copy /y … && fc /b …`, `Pop $0`, and `Abort` on any non-zero code. A silent
  no-op replacement (image still mapped) or a content mismatch now stops setup
  instead of reporting success.

### 5.3 Tests (E2)

`tests/security/test_helper_staging.py` (4 tests): stage copies Release into the
packaging dir; a stale staged helper fails `--check` (the exact #30 shape);
`--stage` refuses a build older than its source; a missing build is reported,
not ignored.

```
python -m pytest tests/security/test_helper_staging.py -q  →  4 passed
```

---

## 6. Status of #30

| Question | Answer | Basis |
|---|---|---|
| Is the crash understood? | **Yes** — free-while-referenced in pre-fix `aegis_fim_stop` | dump stack + source diff |
| Does the committed fix address it? | **Yes in source** (lock + INFINITE wait + retain-on-failure) | `9766525`, `fim_native.c:192-223` |
| Is the fix what crashed? | **No** — crashed helper is the 2026-10-16 build | dump module PE ts + string scan |
| Why did it keep happening? | The fixed DLL was never staged into `zig-out/bin`; every bundle shipped the old one | §4 table + bundle inventory |
| Is the recurrence explained? | **Yes** — 11-06/11-09/11-10 ran the same pre-fix helper | same image hash across bundles |
| Is #30 closed? | **No** — closure requires the fixed helper to be deployed and a clean run observed | needs a host window |

**Not closed by this record.** What this record does close is the *diagnosis*
and the *deployment gap in the build path*. Two things remain and both need the
host:

1. Deploy the staged helper (`5275ED8B…`) into
   `C:\Program Files\AEGIS NIDS\runtime\` and restart the daemon — this is the
   same host window S1-01 needs for the WFP driver.
2. Observe a clean interval with no `7031` for `AegisNids` under the fixed
   helper, and record the deployed hash + uptime as the E5 artifact that closes
   #30.

Because the host-window evidence does not exist yet, the two 11-10 terminations
**(02:14:43, 02:17:57)** are disclosed here explicitly: they have no dump and no
`Application Error 1000`, so they are **unattributed**, but they are consistent
with the same pre-fix helper and are *not* evidence of a surviving bug in the
fixed code.

---

## 7. Reproducible commands

```powershell
# crash pairing
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7031; StartTime=(Get-Date).AddDays(-8)} |
  Where-Object { $_.Message -match 'AegisNids' }
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000; StartTime=(Get-Date).AddDays(-8)} |
  Where-Object { $_.Message -match 'aegis_nids' }

# dump: faulting module provenance
$cdb='C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
& $cdb -z admin-evidence\e5-host-proof-20261026\wer-localdumps\aegis_nids.exe.16408.dmp `
      -c "!analyze -v; lm m aegis_fim_helper; !dh 7ffe770f0000 -f; q"

# which helper is packaged vs built
python tools\stage_helpers.py --check
Get-FileHash build\Release\aegis_fim_helper.dll, zig-out\bin\aegis_fim_helper.dll -Algorithm SHA256
```
