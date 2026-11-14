# DRIVER-SYNTAX-001 — the quarantined WFP dispatch did not parse

**Created:** 2026-11-14
**Build source:** `drivers/wfp_callout/quarantined/aegis_wfp_comm.c` changed
(comment only, and the file is compiled by nothing), so the source commit moves
with a build that still exits 0.
**Level:** E2 for the three minifilter sources (real `cl -Zs` parse), E1 for the
INFs, and an explicit "not verified" for the callout sources.

---

## 1. What was found

The six files under `drivers/` were the last product files named by no evidence
entry. Putting them through a syntax-only compile against the installed WDK
headers found one real defect:

```
drivers/wfp_callout/quarantined/aegis_wfp_comm.c(18): error C2143: syntax error: missing '{' before ':'
drivers/wfp_callout/quarantined/aegis_wfp_comm.c(18): error C2059: syntax error: ':'
drivers/wfp_callout/quarantined/aegis_wfp_comm.c(23): warning C4138: '*/' found outside of comment
```

The quarantine header closed its comment block after the `(HISTORICAL)` line and
left three bullet lines of prose outside any comment, which the compiler read as
code. The file has said "QUARANTINED — DO NOT COMPILE" since it was quarantined,
so nothing was broken in production; but a quarantined file that cannot be
parsed is also a file nobody can ever audit. It parses now.

The three minifilter sources (`aegis_minifilter.c`, `_comm.c`, `_proc.c`) parsed
with **zero** diagnostics against `fltKernel.h` on the first attempt.

## 2. What changed

- `drivers/wfp_callout/quarantined/aegis_wfp_comm.c`: one comment block, closed
  once, with a note explaining the break.
- `tests/release/test_driver_sources.py`, 7 pins:
  - `cl -Zs` parse of the three minifilter sources against the WDK headers
    (skipped when MSVC or the WDK is absent);
  - the quarantine header contains exactly one close before `#include`, starts
    with `/**`, and still says QUARANTINED;
  - no driver build script *uses* the quarantined copy (a `REM` that forbids it
    is allowed — that comment is the guard);
  - both INFs keep `[Version]`, an NT signature line and a `CatalogFile`;
    `[Manufacturer]` is required only for the package that installs a
    root-enumerated device (`Root\AEGIS_WFP`).

## 3. Verification

| Check | Result |
|---|---|
| `pytest -q tests/release/test_driver_sources.py` | 7 passed |
| `cl -Zs` on the three minifilter sources | 0 errors, 0 diagnostics |
| mutation: close the quarantine comment early again | 1 failed (`test_the_quarantined_header_closes_exactly_once`) |
| restored | 7 passed |

## 4. Limitations — what this slice does **not** establish

1. **The WFP callout sources were not compiled.** `drivers/wfp_callout/aegis_wfp.c`
   and `aegis_wfp_callout.c` need the WDK build environment
   (`scripts/wdk_build_*.ps1`); an ad-hoc `cl -Zs` invocation dies inside the
   WDK's own `fwpsk.h` with `UINT32` redefinition errors, which reflects the
   harness, not the file.
2. **Kernel-mode behaviour is unverified.** No driver was loaded, no minifilter
   attached, no WFP filter installed or removed, and no unload path exercised.
   That requires test signing plus an elevated boot, i.e. the same blocker as the
   `clean_host_e5` gate.
3. **The INFs are checked structurally only** (sections present), not with
   `infverif`, which the WDK ships but which needs a driver package build.
4. **The catalog files** referenced by the INFs (`.cat`) are produced by signing,
   which the owner holds.
