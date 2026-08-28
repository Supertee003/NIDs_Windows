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
copy target\release\aegis_shield.dll ..\sec_monitor.dll

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
```

## Install Order

1. **Zig Core** — `aegis.exe` (main NIDS process)
2. **C++ Bridge** — `aegis_ipc.dll` (in `bridge/` directory)
3. **Rust Shield** — `sec_monitor.dll` (in `shield/target/release/`)
4. **Python Brain** — `python brain/windows_brain.py`
5. **Go Aggregator** — `go/aggregator/aegis-aggregator.exe`
6. **Dashboard** — `aegis_dashboard.exe` (optional, for monitoring)

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
sc create AEGIS_NIDS binPath= "C:\AEGIS\aegis.exe" start= auto
sc description AEGIS_NIDS "AEGIS NIDS Core - 3-Tier Detection Engine"
sc start AEGIS_NIDS
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

1. Stop AEGIS service: `sc stop AEGIS_NIDS`
2. Restore from `.phase*_backup` files
3. Restart service: `sc start AEGIS_NIDS`

## Troubleshooting

| Issue | Fix |
|-------|-----|
| BUILD FAILED | Check Zig version: `zig version` (must be 0.13) |
| SDDL error | Run as Administrator |
| UDP send failed | Check Brain is running on port 9999 |
| Dashboard empty | Check `logs/aegis_core.ndjson` exists |
| HMAC mismatch | Regenerate: `python aegis_rules.py --sign` |
