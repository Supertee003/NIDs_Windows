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

Install the current signed `b597e71` candidate for build source `f4cde3c`
(`bece8f1` was rejected for unsigned kernel telemetry drivers; `7d91e30` was
superseded when the fail-closed rule-layer slice moved the build source) over
the existing service, prove the installed runtime answers a preflight, confirm
both capture topologies still resolve, re-measure the Wi-Fi duplicate sighting
on this build, exercise upgrade/rollback, and run 24 h of wall clock with no
loss — then close the release board.

What this window does **not** prove: driver signing/HLK, a true clean-machine
boot model, or WFP enforcement. Drivers stay test-signed; prevention stays
closed by design.

## Steps

### 1. Verify the artifact before touching the host

```powershell
python tools\sign_release.py --verify --dir release\T20-final\b597e71
Get-AuthenticodeSignature release\T20-final\b597e71\drivers\*.sys |
    Select-Object Path, Status, @{n='Signer';e={$_.SignerCertificate.Thumbprint}}
$env:AEGIS_RELEASE_TRUSTED_PUBLIC_KEY = 'txigrGWzVRf/zJ3OGdrctW2eBqqy18LOJv6dY5keJ6o='
python tools\final_audit.py --release-check
```

Expect `PASS: signatures.json signs SHA256SUMS (02562BC958AE4516...)` and a board
where `soak_24h` is the only `OPEN` gate. Both driver images must report
`Status = Valid` (WFP `00E92849867308596564D134BB981EF726798E97`, minifilter
`60B05537FEB7A40D6F6624FF5C005C09DC245A63`). If any other gate is open, or a
driver is unsigned, stop — do not install a candidate whose chain does not
verify. `bece8f1` is rejected and `7d91e30` is superseded; see
`analysis/current-head/RC-7D91E30-20261118.md` and
`analysis/current-head/RULE-LAYER-FAILCLOSED-001-20261119.md`.

### 2. Install the bundle

```powershell
$W = "admin-evidence\e5-clean-host-20261119-final"
New-Item -ItemType Directory -Force $W | Out-Null
Start-Process -FilePath "dist\aegis_setup_6.0.0_trial.exe" -ArgumentList "/S" -Wait
Get-Service AegisNids, AegisAggregator, AegisWfp, AegisMinifilter |
    Select-Object Name, Status, StartType
```

All four must be `RUNNING`. The installer at this step is the rebuilt
`dist\aegis_setup_6.0.0_trial.exe`, sha256
`360B9C0666959AFB2064D1CD815565073A61051ACBBF1F4887C9C0A9D05ECDB9`, carrying
runtime `0CB573EC6CF3B77BE5CBB477BA7803F4C63361F325AB22A561343092A4C0DF1F`. If
`AegisWfp` or `AegisMinifilter` is `STOPPED` with `WIN32_EXIT_CODE 577`, the
installed image is unsigned — check `Get-AuthenticodeSignature
C:\Windows\System32\drivers\aegis_*.sys` and stop; do not start the service by
hand to make the board green. The installer refuses to overwrite a service
whose image path is not `<install>\runtime\aegis_nids.exe`; that refusal is a
stop condition, not something to work around.

Product version stays `5.0.0` (`aegisctl version`) while the bundle line is
`6.0.0`. That split is deliberate (`D2-BUNDLE-VERSION-001`) — do not "fix" it.

### 3. Preflight — the current-source `clean_host_e5` artifact

Wait until the daemon uptime is at least 5 minutes, then:

```powershell
python tools\host_preflight.py --min-uptime-min 5 --json "$W\preflight-20261119.json"
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
  --seconds 60 --traffic 20 --out "D:\NIDs_Windows\admin-evidence\capture-dup-20261119"
```

Read the JSON it writes. `pairs == 0` closes the item for this build; any pair
keeps it open and files the pcap, not a conclusion. The 5-tuple counter also
matches TCP Dup ACKs, so interpret a non-zero result with the byte-level probe
on the same pcap rather than calling it frame duplication:

```powershell
python admin-evidence\g2-single-host-20261117\lab-kit-v3\g3_dup_bytes.py `
  --pcap "<pcap path from dup-ratio.json>"
```

`identical_byte_pairs == 0` means the ratio pairs are protocol repeats; keep
the item open and attach both JSON files, but do not claim a capture-path
defect. Non-zero byte-identical pairs are a real finding: attach the pcap and
stop before the soak.

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
  --baseline auto --baseline-out "$W\soak-24h.baseline.json" `
  --json "$W\soak-24h-delta-$(Get-Date -Format yyyyMMdd-HHmm).json"
```

`--baseline auto` is required: it snapshots the counters into
`soak-24h.baseline.json`; `--baseline-out` alone only names where to write it.
The same baseline file is passed back on every later check.

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

## Result — 2026-11-19 (steps 1-6, current build source)

`admin-evidence/e5-clean-host-20261119-final/RB-024-result.json` records the
clean rerun against `release/T20-final/b597e71` on build source `f4cde3c`:
installer `360B9C06…` exit 0, installed runtime `0CB573EC…`, 2/2 driver images
`Valid`, 4/4 services RUNNING, preflight PASS with 0 failed checks, both capture
pins resolving to disjoint devices with ingress advancing, 18,774/20,191 ratio
pairs but byte-level 0/20,191 identical pairs, and rollback drill PASS with
`AegisNids` RUNNING. The Wi-Fi item stays open under the runbook's literal rule.

No soak currently passes. The `2026-11-19T00:20:11` window is
**VOIDED BY SUPERSEDED BUILD**; the `2026-11-19T01:44:10` and
`2026-11-19T02:23:21` windows were stopped by owner decision at 0.2 h and 0.01 h
respectively (`VOIDED_BY_OWNER_DECISION_PENDING_HANDOFF_AUDIT` and
`VOIDED_BY_OWNER_DECISION_PENDING_REMAINING_WORK`) with 0 loss, 0 shed and no
problems. They are retained only for provenance and are not release proof. One
fresh 24 h window with `--baseline auto` is still required after all remaining
work is closed. Details: `analysis/current-head/RB-024-F4CDE3C-20261119.md`,
`analysis/current-head/AI-HANDOFF-AUDIT-20261119.md`.

## Result — 2026-11-18 (steps 1-6, historical)

`admin-evidence/e5-clean-host-20261118-final/RB-024-result.json` records a clean
run against `release/T20-final/7d91e30`: installer exit 0, 2/2 driver images
`Valid`, 4/4 services RUNNING, preflight PASS with 0 failed checks, both capture
pins resolving to disjoint devices with ingress advancing, ratio 66/1084 pairs
but byte-level 0/1084 identical pairs, and rollback drill PASS with `AegisNids`
RUNNING. `soak_started` is `false`. The two earlier aborted attempts in the same
transcript directory were an expected-stderr handling bug and the unsigned
`bece8f1` driver defect; neither is the final result.

The Wi-Fi item stays open under this runbook's literal rule (ratio > 0), with
`admin-evidence/capture-dup-20261118/dup-ratio-20261118T153405Z/capture.pcapng`
and both JSON measurements retained.

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
| `AegisWfp` / `AegisMinifilter` not RUNNING | driver load failed (unsigned image or test-signing?) | record `sc query` + `Get-AuthenticodeSignature` + setupapi log; re-sign and rebuild the candidate, do not start the service by hand or claim kernel coverage |
| Preflight loss counters non-zero at start | the baseline is already dirty | restart the window with a clean baseline; never score it |
| Soak FAIL at `daemon uptime shorter than the soak` | the daemon restarted mid-window | the window is void; start a new one |
| Duplicate pairs > 0 | the sighting reproduced | keep the item open, attach the pcap and ratio JSON |
