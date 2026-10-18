# AEGIS NIDS Deployment Guide (Phase 20, DOC-2)

## Prerequisites

### Build Tools
- **Zig 0.13** — Core engine
- **Visual Studio 2022** (C++ Build Tools) — C++ Bridge + Cython
- **Rust/Cargo** — Dashboard + Shield
- **Go 1.21+** — Aggregator
- **Python 3.10+** — Brain + CLI tools + Cython

### Runtime
- Windows 10/11 x64
- Administrator privileges (for WFP driver + named pipes)

## Build Order

```bash
# 1. Build Zig Core (produces aegis.exe)
cd core
zig build

# 2. Build C++ Bridge (produces aegis_ipc.dll)
cd ../bridge
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# 3. Build Rust Shield (produces sec_monitor.dll)
cd ../shield
cargo build --release
rem The crate's lib name is "sec_monitor", so cargo emits
rem shield\target\release\sec_monitor.dll directly (loaded by the Zig core).

# 4. Build Dashboard (produces aegis_dashboard.exe)
cd ../aegis_dashboard
cargo build --release

# 5. Build Go Aggregator (produces aegis-aggregator.exe)
cd ../go/aggregator
go mod tidy
go build -o aegis-aggregator.exe .

# 6. Compile Cython (produces fast_scan.pyd)
cd ../../brain/aegis_brain_cython
python setup.py build_ext --inplace

# 7. Install Python dependencies
pip install cython

# 8. Build + sign the kernel telemetry drivers (kernel sensors need these;
#    the installer packages build\x64\... outputs and registers services)
powershell -ExecutionPolicy Bypass -File scripts/wdk_build_production.ps1   # -> build\x64\wfp\aegis_wfp.sys
powershell -ExecutionPolicy Bypass -File scripts/wfp_sign.ps1              # test sign (cert + signature)
powershell -ExecutionPolicy Bypass -File scripts/wdk_build_minifilter.ps1  # -> build\x64\minifilter\aegis_minifilter.sys
powershell -ExecutionPolicy Bypass -File scripts/minifilter_sign.ps1       # test sign (cert + signature)
```

## Install Order

1. **Zig Core** — `aegis.exe` (main NIDS process)
2. **C++ Bridge** — `aegis_ipc.dll` (in `bridge/` directory)
3. **Rust Shield** — `sec_monitor.dll` (in `shield/target/release/`)
4. **Python Brain** — `python brain/windows_brain.py`
5. **Go Aggregator** — `go/aggregator/aegis-aggregator.exe`
6. **Dashboard** — `aegis_dashboard.exe` (optional, for monitoring)

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
the drivers first (Build Order steps 8-9).

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

```bash
# 1. Check all subsystems
python scripts/aegis_status.py

# 2. Verify Go aggregator
python scripts/aegis_api.py

# 3. Check Prometheus metrics
python scripts/aegis_metrics.py --print

# 4. Verify Rules.json integrity
python scripts/aegis_rules.py --sign
python scripts/aegis_rules.py --verify

# 5. Check DEFCON level
python scripts/aegis_defcon.py
```

## Service Configuration

### Zig Core (as Windows Service)
```powershell
sc.exe create AEGIS_NIDS binPath= "C:\AEGIS\aegis.exe" start= auto
sc.exe description AEGIS_NIDS "AEGIS NIDS Core - 3-Tier Detection Engine"
sc.exe start AEGIS_NIDS
```

### Go Aggregator (background)
```powershell
Start-Process -NoNewWindow -FilePath "aegis-aggregator.exe"
```

### Prometheus Metrics
```powershell
Start-Process -NoNewWindow -FilePath "python" -ArgumentList "scripts/aegis_metrics.py"
```

## Log Management

- **Log rotation**: Automatic at 100MB, keeps 7 files
- **Payload capture**: Block-event payloads saved to `logs/payloads/`
- **Blocked IPs**: Persisted to `logs/blocked_ips.json`

## Rollback Procedure

1. Stop AEGIS service: `sc.exe stop AEGIS_NIDS`
2. Restore from `.phase*_backup` files
3. Restart service: `sc.exe start AEGIS_NIDS`

## Troubleshooting

| Issue | Fix |
|-------|-----|
| BUILD FAILED | Check Zig version: `zig version` (must be 0.13) |
| SDDL error | Run as Administrator |
| UDP send failed | Check Brain is running on port 9999 |
| Dashboard empty | Check `logs/aegis_core.ndjson` exists |
| HMAC mismatch | Regenerate: `python aegis_rules.py --sign` |
| AegisWfp / AegisMinifilter missing after setup | Driver build outputs were absent at packaging time: run Build Order steps 8-9, repackage, reinstall |
| Driver service fails to start (577/0x8007041F, 1275) | Test-signed driver not trusted: enable testsigning (`bcdedit /set testsigning on` + reboot) and install the signing cert (`scripts\wfp_sign.ps1` / `scripts\minifilter_sign.ps1`) |
