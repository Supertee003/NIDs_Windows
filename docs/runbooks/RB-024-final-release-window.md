# RB-024 — Final release window (install → prove → soak)

**Type:** Deployment / Release proof
**Module:** `release_closeout`
**Status:** OPERATOR ACTION (needs an elevated session; the soak needs 24 h of wall clock)

This is the one window that turns `release: 5/6 gates` into a shippable release.
Everything in it changes the host, so it is done once, in order, and nothing
else touches the machine until the soak closes.

Commands are PowerShell, from `D:\NIDs_Windows`, in an **elevated** session.

```powershell
# elevation check — must print True
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

## Objective

Install the signed `bece8f1` candidate over the existing service, prove the
installed runtime answers a preflight, confirm both capture topologies still
resolve, re-measure the Wi-Fi duplicate sighting on this build, exercise
upgrade/rollback, and run 24 h of wall clock with no loss — then close the
release board.

What this window does **not** prove: driver signing/HLK, a true clean-machine
boot model, or WFP enforcement. Drivers stay test-signed; prevention stays
closed by design.

## Steps

### 1. Verify the artifact before touching the host

```powershell
python tools\sign_release.py --verify --dir release\T20-final\bece8f1
$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = 'txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='
python tools\final_audit.py --release-check
```

Expect `PASS: signatures.json signs SHA256SUMS (B008EA1C...)` and a board where
`soak_24h` is the only `OPEN` gate. If any other gate is open, stop — do not
install a candidate whose chain does not verify.

### 2. Install the bundle

```powershell
$W = "admin-evidence\e5-clean-host-20261118-final"
New-Item -ItemType Directory -Force $W | Out-Null
Start-Process -FilePath "dist\aegis_setup_6.0.0_trial.exe" -ArgumentList "/S" -Wait
Get-Service AegisNids, AegisAggregator, AegisWfp, AegisMinifilter |
    Select-Object Name, Status, StartType
```

All four must be `RUNNING`. The installer refuses to overwrite a service whose
image path is not `<install>\runtime\aegis_nids.exe`; that refusal is a stop
condition, not something to work around.

Product version stays `5.0.0` (`aegisctl version`) while the bundle line is
`6.0.0`. That split is deliberate (`D2-BUNDLE-VERSION-001`) — do not "fix" it.

### 3. Preflight — the current-source `clean_host_e5` artifact

Wait until the daemon uptime is at least 5 minutes, then:

```powershell
python tools\host_preflight.py --min-uptime-min 5 --json "$W\preflight-20261118.json"
```

PASS here means `clean_host_e5` finally describes *this* build instead of the
2026-11-14 image.

### 4. Capture topology on the installed build

```powershell
python tools\capture_select.py --show
python tools\capture_select.py --verify --seconds 10
```

`--show` must say `direct capture: enabled` only when the two pins resolve to
two different devices, and `--verify` must report `PREFLIGHT OK` with ingress
advancing. To switch topologies (Wi-Fi bridged ↔ host-only VMnet1) follow
RB-023; every switch costs a service restart, so it happens **before** the soak
starts, never inside it.

### 5. Re-measure the Wi-Fi duplicate sighting on this build

The 2026-11-18 02:39 capture had 5 byte-identical `host_tx` pairs in 14 frames
and has never reproduced (`CURRENT-STATUS-20261118.md`). Close it only on a
measured zero from this build:

```powershell
python admin-evidence\g2-single-host-20261117\lab-kit-v3\g3_dup_ratio.py `
  --device "\Device\NPF_{5FD31C6E-DE48-44CB-838E-14667A04DA4B}" `
  --seconds 60 --traffic 20 --out "D:\NIDs_Windows\admin-evidence\capture-dup-20261118"
```

Read the JSON it writes. `pairs == 0` closes the item for this build; any pair
keeps it open and files the pcap, not a conclusion.

### 6. Upgrade / rollback drill

```powershell
python tools\upgrade_rollback.py snapshot
python tools\upgrade_rollback.py report
python tools\upgrade_rollback.py rollback --snapshot <id-from-snapshot>
python tools\upgrade_rollback.py report
Get-Service AegisNids
```

The service must return to `RUNNING` after the rollback, and the second report
must show the runtime image the snapshot recorded. (Procedure context: RB-005,
RB-004.)

### 7. Start the soak — only when nothing else will touch the host

```powershell
python tools\host_soak_check.py --start auto --hours 24 `
  --loss-budget 3500 --shed-budget 20000 `
  --baseline-out "$W\soak-24h.baseline.json" `
  --json "$W\soak-24h-delta-$(Get-Date -Format yyyyMMdd-HHmm).json"
```

Re-check about once an hour with the same baseline (it is what makes counters
deltas rather than lifetime totals), and a final time after 24 h:

```powershell
python tools\host_soak_check.py --start auto --hours 24 `
  --loss-budget 3500 --shed-budget 20000 `
  --baseline "$W\soak-24h.baseline.json" `
  --json "$W\soak-24h-delta-latest.json"
```

During the window: no installs, no service restarts, no adversarial load. An
adversarial run inside the window is how the 2026-11-14 window failed at
16.95 h on `shed_overload`.

### 8. Close the board

```powershell
$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = 'txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='
python tools\final_audit.py --release-check
```

## Verification

6/6 PASS is the release condition. Record the final delta path, the preflight
path and the duplicate-measurement verdict in `EVIDENCE_INDEX.json` in the same
commit that flips the board. A window that ends `IN_PROGRESS`, or whose newest
artifact is a FAIL, is not verification — the board stays at 5/6.

## Rollback

- **Before the soak:** `python tools\upgrade_rollback.py rollback --snapshot <id>`
  restores the previous runtime; the signed trees under `release/T20-final/`
  are immutable, so a rejected candidate is re-selected by rebuilding and
  re-signing, never by editing a tree.
- **After the soak:** the window measured a build; rolling back voids it. Start
  a new window rather than rescoring the old one.
- **Host-level backout:** uninstall the bundle and reinstall the previous
  signed candidate; `release/T20-final/ad7948c` still verifies.

## Failure handling

| Symptom | Meaning | Action |
|---|---|---|
| Installer refuses the service path | a foreign `aegis_nids.exe` owns the service | stop; do not rename files to satisfy the installer |
| `AegisWfp` / `AegisMinifilter` not RUNNING | driver load failed (test-signing?) | record `sc query` + setupapi log; do not claim kernel coverage |
| Preflight loss counters non-zero at start | the baseline is already dirty | restart the window with a clean baseline; never score it |
| Soak FAIL at `daemon uptime shorter than the soak` | the daemon restarted mid-window | the window is void; start a new one |
| Duplicate pairs > 0 | the sighting reproduced | keep the item open, attach the pcap and ratio JSON |
