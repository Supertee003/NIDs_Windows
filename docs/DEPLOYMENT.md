# AEGIS NIDS Deployment Guide (updated 2026-10-19)

## Prerequisites

### Build Tools
- **Zig 0.13** - runtime spine (`aegis_nids.exe`)
- **Rust (stable) / Cargo** - PEP (`aegis_pep.dll`); optional Shield
  payload-screening support DLL and dashboard
- **CMake + MSVC** - native adapters (WFP user / ETW / FIM DLLs)
- **Go 1.22+** - acquisition (nose); optional aggregator
- **Python 3.11+** - brain (Tier-2) + operator CLI
- **Node.js** - policy authoring (TypeScript; advisory only)
- **NSIS (makensis)** - installer packaging (`tools\installer.py --package`);
  fail-closed when absent

### Runtime
- Windows 10/11 x64
- Administrator privileges (drivers, services, named pipes)

## Build Order

Canonical commands per `build_truth.json` (run from the repo root):

```bat
:: 1. Runtime spine (Zig)
zig build
::    -> zig-out\bin\aegis_nids.exe

:: 2. Enforcement (Rust PEP)
cargo build --release
::    -> target\release\aegis_pep.dll

:: 3. Native adapters (root CMake)
cmake -B build && cmake --build build
::    -> build\Release\aegis_wfp_user.dll, aegis_etw_helper.dll, aegis_fim_helper.dll

:: 4. C++ bridge (IPC / adapter / DEFCON)
cd bridge && cmake -B build && cmake --build build
::    -> dist\aegis_ipc.dll, dist\aegis_adapter.dll, dist\aegis_bridge.exe

:: 5. Acquisition (Go)
cd nose && go build -o aegis-nose.exe .

:: 6. Shield payload screening (optional SUPPORT DLL)
cd shield && cargo build --release
::    -> shield\target\release\sec_monitor.dll

:: 7. Brain (Tier-2) - interpreted; optional Cython acceleration
python brain\windows_brain.py
::    (optional: cd brain\aegis_brain_cython && python setup.py build_ext --inplace)

:: 8. Aggregator (optional)
cd go\aggregator && go build -o aegis-aggregator.exe .

:: 9. Dashboard (optional, egui local viewer)
cd aegis_dashboard && cargo build --release

:: 10. Kernel telemetry drivers (lab / test-signed; see next section)
powershell -ExecutionPolicy Bypass -File scripts/wdk_build_production.ps1
::    -> build\x64\wfp\aegis_wfp.sys
powershell -ExecutionPolicy Bypass -File scripts/wfp_sign.ps1
::    test sign (cert + signature)
powershell -ExecutionPolicy Bypass -File scripts/wdk_build_minifilter.ps1
::    -> build\x64\minifilter\aegis_minifilter.sys
powershell -ExecutionPolicy Bypass -File scripts/minifilter_sign.ps1
::    test sign (cert + signature)

:: 11. Policy authoring (advisory only, no build output)
cd ts_policy && npm run typecheck && npm run test:all
```

## Install Order (packaged release)

A packaged release (`aegis-nids-windows-*`) ships `runtime\` with
`aegis_nids.exe`, `aegis_pep.dll`, `aegis_wfp_user.dll`,
`aegis_etw_helper.dll`, `aegis_fim_helper.dll`, `aegis_ipc.dll`,
plus `configs\`, `drivers\aegis_wfp.sys` and `scripts\install_aegis.ps1`.
`aegis-nose.exe` and `aegis_minifilter.sys` ride the NSIS installer path
(`tools\installer.py`), not the bundle zip.

The bundle-path installer (`scripts\install_aegis.ps1`) hash-verifies
every manifest artifact, reports Authenticode status (unsigned builds
warn; a broken signature fails closed), registers and starts the
`AegisNids` service, and supports rollback (`-Rollback`) and uninstall
(`-Uninstall`, operator configs preserved). `scripts\verify_release.ps1`
re-verifies a bundle read-only before any install.

`python tools\installer.py --package` generates `installer.generated.nsi`
and builds `aegis-installer-*.exe` with NSIS (fail-closed without
makensis). Setup installs the runtime under `<install>\runtime\`, stops
a running service before replacing binaries, and registers the daemon
service:

```bat
sc create AegisNids binPath= "<install>\runtime\aegis_nids.exe" start= auto
sc failure AegisNids reset= 86400 actions= restart/5000/restart/15000/restart/60000
```

Uninstall unloads the driver services, deletes them, and removes the
System32 driver copies.

## Kernel Telemetry Drivers (DEPLOY-120)

The installer (`python tools/installer.py --package`) ships both kernel
telemetry drivers and registers their services - detection-only
(observe/copy; nothing blocks):

- `aegis_wfp.sys` (WFP payload callout) -> service `AegisWfp`, type kernel,
  demand start
- `aegis_minifilter.sys` (file/process events) -> service `AegisMinifilter`,
  type filesys, demand start, altitude 370000

Packaged sources are the canonical WDK build outputs
`build\x64\wfp\aegis_wfp.sys` and `build\x64\minifilter\aegis_minifilter.sys`
- the same binaries `scripts\wfp_service.ps1` / `scripts\minifilter_service.ps1`
deploy during development (and that EVT-231/EVT-232 proved live). If those
outputs are absent at packaging time the installer still builds (`/nonfatal`)
and setup skips the matching service with an honest log line - build + sign
the drivers first (Build Order step 10).

Prerequisite - test signing: the drivers are signed with the local
`CN=AEGIS NIDS Test Signing` certificate. Loading them requires:

1. test signing enabled on the target (`bcdedit /set testsigning on` + reboot)
2. the signing certificate trusted (Root + TrustedPublisher) on the target

Both are handled by `scripts\wfp_sign.ps1` / `scripts\minifilter_sign.ps1`
when run elevated on the machine that will load the drivers. Setup logs each
driver's Authenticode status at install time (`AEGIS_DRIVER_SIG_WFP` /
`AEGIS_DRIVER_SIG_FIM` lines). Production signing (EV certificate / HLK) is
still pending; until then this is a test-signed lab/kernel-telemetry
deployment.

Setup copies each driver to `%SystemRoot%\System32\drivers\`, creates its
service (parameters identical to the lifecycle scripts), and starts the
drivers before the daemon. Reinstalling unloads/stops and recreates the
services first; uninstall unloads, deletes the services and removes the
System32 copies.

Verify after install (elevated shell for `fltmc`):

```powershell
sc.exe query AegisWfp
sc.exe query AegisMinifilter
fltmc filters | Select-String Aegis
python tools\aegisctl.py queue --json     # capture_wfp / capture_fim counters move
```

The drivers are demand-start by contract: they run from install time until
next reboot; after a reboot start them with `scripts\wfp_service.ps1 start`
and `scripts\minifilter_service.ps1 start` (boot persistence is a product
decision still open).

## Post-Install Verification

```bat
:: 1. Check all subsystems
python scripts\aegis_status.py

:: 2. Verify Go aggregator
python scripts\aegis_api.py

:: 3. Check Prometheus metrics
python scripts\aegis_metrics.py --print

:: 4. Verify Rules.json integrity
python scripts\aegis_rules.py --sign
python scripts\aegis_rules.py --verify

:: 5. Check DEFCON level
python scripts\aegis_defcon.py
```

## Service Configuration

The setup registers the daemon service `AegisNids` (binPath
`<install>\runtime\aegis_nids.exe`, start= auto, restart-on-failure; see
Install Order). Day-to-day control goes through the operator CLI:

```powershell
python tools\aegisctl.py status
python tools\aegisctl.py start      # asks the daemon; the opener owns OS processes
python tools\aegisctl.py stop
```

## Log Management

- `logs\aegis_core.ndjson` - NDJSON evidence projection written by the
  daemon (forensic pipeline + SIEM forwarder source)
- `logs\payloads\` - payload samples saved by the forensic logger
  (`src/forensic/forensic_log.zig`)
- `logs\control_audit.ndjson` - control-plane audit ring export
- `logs\blocked_ips.json` - legacy script stack bookkeeping
  (`scripts\aegis_block.py`), not the daemon

## Rollback Procedure

1. Stop the service: `sc.exe stop AegisNids`
2. Snapshot / inspect / revert configuration state:

```bat
python tools\upgrade_rollback.py snapshot
python tools\upgrade_rollback.py report --json
python tools\upgrade_rollback.py rollback --snapshot <id>
```

   (Runbook: `docs/runbooks/RB-005-config-rollback.md`)
3. Start the service: `sc.exe start AegisNids`

## Troubleshooting

| Issue | Fix |
|-------|-----|
| BUILD FAILED | Check Zig version: `zig version` (must be 0.13) |
| SDDL error | Run as Administrator |
| UDP send failed | Brain not listening: check `127.0.0.1:9999` (UDP health probe) |
| Web dashboard empty | Start `python -m tools.aegisctl.web_dashboard.app` (port 5000, `DASHBOARD_PORT` overrides) and confirm `logs\aegis_core.ndjson` exists; terminal view: `python tools\aegisctl.py dashboard --watch` |
| HMAC mismatch | Regenerate: `python scripts\aegis_rules.py --sign` |
| AegisWfp / AegisMinifilter missing after setup | Driver build outputs were absent at packaging time: run Build Order step 10, repackage, reinstall |
| Driver service fails to start (577/0x8007041F, 1275) | Test-signed driver not trusted: enable testsigning (`bcdedit /set testsigning on` + reboot) and install the signing cert (`scripts\wfp_sign.ps1` / `scripts\minifilter_sign.ps1`) |
