# DRIVER-SIGN-PAYLOAD-001 — install the signed driver bytes, not the WDK build output

**PATCH-ID:** `DRIVER-SIGN-PAYLOAD-001`
**FLOW-ID:** release packaging → host driver deployment → daemon health → E5 preflight
**TARGET HEAD:** `7bc9ee7`
**Build source:** `a53eda8` (unchanged — `tools/` and `tests/` are outside `SOURCE_PATHS`)

## Symptom that triggered this patch

After the corrected installer deployed runtime `FBD9BDB3...`, `host_preflight.py`
still returned `verdict: FAIL` with:

```
failed = ['driver_AegisWfp', 'driver_AegisMinifilter', 'daemon_health']
AegisWfp         STATE STOPPED  WIN32_EXIT_CODE 577 (0x241)
AegisMinifilter  STATE STOPPED  WIN32_EXIT_CODE 577 (0x241)
```

`0x241` is `ERROR_INVALID_IMAGE_HASH`: the images in
`C:\Windows\System32\drivers\` were the raw, **NotSigned** WDK outputs
`593A1299...` (WFP) and `E25A3DA0...` (minifilter), while the test-signed images
`B26AC754...` and `C836A981...` (both `Valid`, signer certs present in
`LocalMachine\Root`) were sitting unused in `release\T20-final\466a226\drivers\`.

## Root cause

`tools/installer.py` hardcoded:

```
File "/nonfatal" "/oname=aegis_wfp.sys"        "build\x64\wfp\aegis_wfp.sys"
File "/nonfatal" "/oname=aegis_minifilter.sys" "build\x64\minifilter\aegis_minifilter.sys"
```

The NSIS then byte-copies `$INSTDIR\drivers\*.sys` into `System32\drivers`.
So a clean install always replaced good signed images with unsigned ones and
guaranteed a DEGRADED daemon / FAIL preflight. Earlier E5 windows only passed
because a manual `scripts/e5_driver_swap.ps1` step re-signed/replaced the images
*after* setup; the installer path itself was broken.

## Patch declaration

| Field | Value |
|---|---|
| TARGET FILES | `tools/installer.py`, `tests/release/test_installer_template.py`, `tests/release/test_driver_packaging_sources.py`, `analysis/current-head/SOAK-WINDOW-466A226-20261120.md` |
| TARGET SYMBOLS | `signed_driver_sources`, `_owner_signed_tree`, `signed_drivers_available`, `driver_presence`, `generate_nsi`, `main`, NSIS `@WFP_DRIVER_SOURCE@`/`@FIM_DRIVER_SOURCE@` |
| IN-SCOPE | resolve NSIS driver payload from newest owner-signed candidate; Ed25519 verify + SHA256SUMS byte match; fail closed before makensis; test pins and soak guide |
| OUT-OF-SCOPE | runtime source, wire/codecs, signed candidate tree (no re-sign), host install, services, soak |
| CONTRACT IMPACT | NSIS `File` sources now point at `release\T20-final\<candidate>\drivers\*.sys`; service registration/copy path unchanged |
| ABI IMPACT | none |
| AUTHORITY IMPACT | none — drivers remain detection-only; no WFP policy/host effect change |
| STATE IMPACT | none — build-time selection only |
| TEST IMPACT | 40 targeted tests pass; full suite below |
| EVIDENCE IMPACT | this record + regenerated installer hash; no E5/E6 claim |
| OLD FLOW | unsigned WDK output → System32 → image hash 577 → services STOPPED → daemon DEGRADED → preflight FAIL |
| NEW FLOW | owner-signed candidate bytes (hash-verified) → System32 → services start → daemon RUNNING → preflight can PASS |
| INVARIANT | the installer never packages a `.sys` that is not byte-for-byte listed in an owner-signed `SHA256SUMS` |

## Verification (real, this head)

- `signed_driver_sources()` resolves the only matching candidate `466a226` and
  both payload hashes match `SHA256SUMS`; generated NSI contains:
  `File "/nonfatal" "/oname=aegis_wfp.sys" "release\T20-final\466a226\drivers\aegis_wfp.sys"`
  (and the minifilter equivalent).
- Packaging gate exercised: with `RELEASE_ROOT` pointed at an empty dir,
  `signed_drivers_available()` is `False` and the source falls back to a
  **non-existent** `release\signed-drivers\` path (never to `build\x64\`).
- Targeted suites: **40 passed** (`test_installer_template`,
  `test_driver_packaging_sources`, `test_ci_gates`).
- `python tools\installer.py --package --output dist/aegis_setup_6.0.0_trial.exe`
  succeeded; new installer SHA-256 `D2267E720266807D6CB0EDBF5B83F6C6648FF75B4448D433117CDEA6031C3B83` (6,150,809 B).
- `python tools\truth.py verify` → `TRUTH_VALID` at build source `a53eda8`.
- Two additional live-host-state test issues surfaced during full-suite rerun
  and were fixed records-only: `READINESS-CAUSE-003` names `capabilities.wfp=false`
  (and treats `state_degraded` as an attributable cause) so readiness never
  emits `degraded_without_named_component` on a driver-down host; and
  `test_api_snapshot_carries_additive_alerts_key` now points `ALERT_LOG` at a
  tmp path so a running daemon's real `logs/alerts.ndjson` cannot invalidate it.
- Final full suite: **1456 passed, 14 skipped, 1 xfailed, 1 xpassed,
  26 subtests passed, 0 failed** in 347.41 s (`FULL_EXIT=0`).
- `python tools\sign_release.py --verify --dir release\T20-final\466a226` →
  PASS, digest `A053C048...` unchanged (candidate tree untouched).
- `final_audit --release-check`: `clean_host_e5` and `soak_24h` remain OPEN;
  all other four gates PASS.

## Why the release is still NOT SHIPPABLE

This closes the packaging defect that made preflight FAIL, but the corrected
installer has **not yet been run by the owner**. `clean_host_e5` and `soak_24h`
remain OPEN until the elevated RB-024 window in
`SOAK-WINDOW-466A226-20261120.md` produces genuine artifacts. No tag, push, or
publish before a real 24 h PASS.
