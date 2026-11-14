# INSTALLER-BOOT-MODEL-001 — the installer now ships the boot model and budget

**Created:** 2026-11-14
**Build source:** `cc3518d` (unchanged; this patch touches `tools/`, `scripts/`,
`tests/`)
**Finding:** `RC-FINAL` limitation 5. The lab host was fixed by hand, but a
fresh install still created `AegisNids` as `AUTO_START`, never registered
`AegisBootSequence`, and never wrote `AEGIS_LOSS_BUDGET`.
**Level:** E2 (packaging tests + generated NSIS inspection). A clean-host
install/reboot is the E5 gate.

---

## 1. The gap

Both installers had the old contract:

| Installer | Old behaviour |
|---|---|
| `tools/installer.py` (NSIS) | `sc create AegisNids ... start= auto`; no task; no env |
| `scripts/install_aegis.ps1` (bundle) | `sc create AegisNids ... start= auto`; no task; no env |

On a fresh machine that reproduces the 2026-11-11 boot failure: SCM starts the
daemon before the demand-start drivers, the ring fills with no reader, and the
daemon is DEGRADED from the first second. The hand-fixed lab host hid this.

## 2. What changed

New tracked scripts:

- `scripts/boot-sequence.ps1` — the production loader:
  1. start `AegisWfp`, let the device settle;
  2. start `AegisNids` and wait `RUNNING`;
  3. start `AegisMinifilter` last, with the reader already retrying (1 s
     cadence), so the ring starts empty;
  4. write a probe under `%ProgramData%\AEGIS\`.
  Its `State()` joins `sc.exe` output before `-match` (the array defect that
  caused the 448/4,012 losses is not repeated).
- `scripts/install-boot-task.ps1` — called by the installer:
  - writes `AEGIS_LOSS_BUDGET=3500` into the service `Environment`, preserving
    other values;
  - enforces `AegisNids` `DEMAND_START`;
  - registers `AegisBootSequence` (AtStartup, SYSTEM, 20 s delay) pointing at
    the installed `boot-sequence.ps1`;
  - exits non-zero on failure so the installer can abort.

Installer changes:

- `tools/installer.py`:
  - ships both scripts under `$INSTDIR\scripts`;
  - `sc create ... start= demand`;
  - calls `install-boot-task.ps1` after driver registration and **aborts setup**
    if it fails;
  - uninstall deletes `AegisBootSequence` and `$INSTDIR\scripts`.
- `scripts/install_aegis.ps1` (bundle installer):
  - `start= demand`;
  - calls the installed `scripts\install-boot-task.ps1 -LossBudget 3500` and
    throws on failure;
  - uninstall deletes the task.

## 3. Verification

```
python -m pytest -q tests/release/test_boot_model_packaging.py  -> 4 passed
python tools/installer.py --generate --nsi .work/installer-test.nsi -> ok
```

Generated NSIS contains:

```
File "scripts\boot-sequence.ps1"
File "scripts\install-boot-task.ps1"
sc create AegisNids ... start= demand
powershell ... -File "$INSTDIR\scripts\install-boot-task.ps1"
MessageBox MB_ICONSTOP "AEGIS: boot task / loss budget setup failed ..."
schtasks /delete /tn AegisBootSequence /f
```

Tests pin: both installers use `demand` and not `auto`; both ship/call the task
installer; the task installer writes the budget and registers the task; the
boot sequence starts the daemon before the minifilter.

## 4. What this does not prove

- **E2, not E5.** No clean Windows VM has run this installer and rebooted. The
  E5 gate is: fresh install on a clean host, reboot, `AegisBootSequence` runs,
  all services RUNNING, `loss_budget=3500`, `minifilter_ring_dropped=0`.
- **The NSIS binary was not built here.** `makensis` is present on this host but
  the generated script was not compiled into an `.exe`; the syntax is inspected,
  not executed. `tools/installer.py --package` is the next check.
- **Upgrade path.** The installer sets demand on an existing service, but an
  in-place upgrade from the old AUTO_START install was not exercised.
- **Uninstall ordering** is pinned by text, not by a run: the task is deleted
  before the service, and `$INSTDIR\scripts` is removed after the drivers.
