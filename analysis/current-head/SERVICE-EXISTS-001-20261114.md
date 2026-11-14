# SERVICE-EXISTS-001 — the installer's existence guard was always false

**Created:** 2026-11-14
**Build source:** `5dfe10c` (touches `scripts/`, `tests/`)
**Level:** E2 (premise measured on the host, structure pinned) + E1 finding
**Found while:** repairing the stale `start= auto` pin in `test_release_tooling.py`

---

## 1. The bug

`scripts/install_aegis.ps1` decided whether to create a service by testing the
*output* of `sc.exe query`:

```powershell
$driverSvc = sc.exe query AegisWfp 2>$null
if (-not $driverSvc) { sc.exe create AegisWfp ... }

if (-not (sc.exe query AegisNids 2>$null)) { sc.exe create AegisNids ... }
```

`sc.exe` writes its failure text to **stdout**, not stderr. Measured on this host
against a name that does not exist:

```
exit=1060
stdout_len=122
truthy=True
WOULD_SKIP
```

So on a machine without the service, `$driverSvc` is a 122-character string,
`-not` of it is `false`, and **neither `sc.exe create` line ever runs**. The
guard did not make the install idempotent; it made the install a no-op for
exactly the case it existed to handle.

The consequence is the clean-host path: `install_aegis.ps1` would copy the
bundle into `Program Files\AEGIS NIDS`, find no services, skip both creates,
install the boot task, run `sc.exe start AegisNids` (warning only, exit code not
checked), and report `Installed AEGIS NIDS`. A fresh machine would then boot
with no `AegisNids` service and no `AegisWfp` driver, while the installer said it
succeeded. The packaged NSIS installer was **not** affected — `tools/installer.py`
issues `sc create` unconditionally at line 272 — which is why the hand-run
deployment on this host worked and the bundle path would not have.

Second, smaller defect in the same lines: both creates were piped to `Out-Null`,
so even a genuine failure (insufficient privileges, WFP policy) would print
nothing and change no exit status.

## 2. Fix

Existence is the exit code, never the output:

```powershell
sc.exe query AegisWfp *> $null
$driverRegistered = ($LASTEXITCODE -eq 0)
if (-not $driverRegistered) {
    sc.exe create AegisWfp type= kernel start= demand error= normal binPath= "\??\$driver" *> $null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create AegisWfp failed (exit $LASTEXITCODE)" }
}

sc.exe query AegisNids *> $null
if ($LASTEXITCODE -ne 0) {
    sc.exe create AegisNids binPath= $svcBin start= demand *> $null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create AegisNids failed (exit $LASTEXITCODE)" }
    ...
}
```

`*> $null` discards both streams (the `2>$null` form left the stdout noise in
place, which is what made the old test look reasonable), and a failed create now
aborts the install instead of being swallowed. The uninstall branch had the same
inverted test — it is now `sc.exe query … *> $null; if ($LASTEXITCODE -eq 0)`.

`scripts/wfp_service.ps1` was already correct (`sc.exe query $svcName 2>$null`
followed by `if ($LASTEXITCODE -eq 0)`), and a pin now keeps it that way.

## 3. Why no test caught it

`tests/release/test_release_tooling.py` asserted that the file contained the
string `sc.exe create AegisNids binPath= $svcBin start= auto` — and that assertion
itself was stale: `INSTALLER-BOOT-MODEL-001` had changed the line to
`start= demand` when the boot model moved to `AegisBootSequence`, so the pin was
failing for an unrelated reason and nobody had a green run to read. A string
presence test cannot see a guard that is always false, and the failing pin was
hiding the file rather than describing it.

## 4. Pins

`tests/release/test_installer_service_guards.py` (5) plus the repaired
`test_release_tooling.py` pin:

| Pin | Prevents |
|---|---|
| `sc.exe query <absent>` exits non-zero **and writes to stdout** | the rule becoming folklore; if the premise changes, the test says so instead of a comment going stale |
| no `if (sc.exe query …)` truthiness test may exist | the exact regression, in any spelling |
| every `sc.exe query` must be followed within four lines by `$LASTEXITCODE` | a future guard that is "obviously fine" again |
| every `sc.exe create` must be followed by `$LASTEXITCODE -ne 0` + `throw`, and may not be piped to `Out-Null` | silent install failure |
| `wfp_service.ps1` keeps its exit-code test | fixing one file must not normalise the other |
| the created service is `start= demand`, `AUTO_START` is refused, `install-boot-task.ps1` is called | the 2026-11-11 boot-order failure returning through the bundle installer |

Comment lines are stripped before the structural analysis — prose that explains
the bug must not be readable as the bug.

## 5. Verification

| Check | Result |
|---|---|
| `pytest tests/release/test_installer_service_guards.py tests/release/test_release_tooling.py` | 16 passed |
| premise measurement | `exit=1060`, `stdout_len=122`, `truthy=True`, `WOULD_SKIP` |
| `pytest tests/release` | 145 passed (previously 1 failing: the stale `start= auto` pin) |

## 6. Residual

- **Not E5.** This machine cannot run the installer elevated from this session,
  so the guard's *consequence* (services registered on a clean host) is proven by
  structure and premise, not by an install. The clean-host run in
  `scripts/e5-clean-host.ps1 -Stage Install` is still the gate that will show it.
- The NSIS path creates the service unconditionally, so a *stale* service from an
  older install is reconfigured rather than skipped — that is deliberate, but it
  means the two installers still differ in idempotency strategy (non-idempotent
  create vs. query-then-create). Unifying them is a separate decision.
- `sc.exe query` on a *driver* service (`type= kernel`) behaves the same way, but
  only the two services in this file were measured.
