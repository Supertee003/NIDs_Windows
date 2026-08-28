# AEGIS NIDS — Deployment Runbook (v3.0)

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Build from Source](#build-from-source)
3. [First-Time Deployment](#first-time-deployment)
4. [Driver Installation (Optional)](#driver-installation-optional)
5. [Starting AEGIS NIDS](#starting-aegis-nids)
6. [Stopping AEGIS NIDS](#stopping-aegis-nids)
7. [Configuration](#configuration)
8. [Monitoring](#monitoring)
9. [Troubleshooting](#troubleshooting)
10. [Upgrade Procedure](#upgrade-procedure)
11. [Rollback Procedure](#rollback-procedure)
12. [Health Checks](#health-checks)

---

## Prerequisites

### Software Requirements
- **Zig 0.13.0** — https://ziglang.org/download/
- **Windows 10/11 x64** or **Windows Server 2019+**
- **PowerShell 5.1+**
- **Git** (for cloning/updating)

### Optional (for full IPS functionality)
- **WDK (Windows Driver Kit)** — for building WFP/minifilter drivers
- **Visual Studio Build Tools 2022** — for C++ bridge compilation
- **Rust toolchain** — for shield module compilation
- **Go 1.21+** — for aggregator service
- **Python 3.12+** — for brain module + Cython acceleration

### Hardware Requirements
- **CPU:** 4+ cores (6-thread architecture)
- **RAM:** 2GB minimum (4GB recommended for production)
- **Disk:** 500MB for binary + logs (1GB recommended)
- **Network:** Ethernet/WiFi adapter for packet capture

---

## Build from Source

### Step 1: Clone Repository
```powershell
git clone https://github.com/Supertee003/NIds_Windows.git
cd NIds_Windows
```

### Step 2: Build Debug Binary
```powershell
zig build
```
**Output:** `zig-out\bin\aegis-nids.exe`

### Step 3: Run Tests
```powershell
zig build test
```
**Expected:** ~558 tests pass across 43 test files

### Step 4: Build Release Binary (Optional)
```powershell
zig build release
```
**Output:** `zig-out\bin\aegis-nids.exe` (ReleaseFast optimized)

---

## First-Time Deployment

### Step 1: Create Directory Structure
```powershell
mkdir C:\AEGIS
mkdir C:\AEGIS\bin
mkdir C:\AEGIS\config
mkdir C:\AEGIS\logs
mkdir C:\AEGIS\drivers
```

### Step 2: Copy Binary
```powershell
copy zig-out\bin\aegis-nids.exe C:\AEGIS\bin\
```

### Step 3: Copy Configuration
```powershell
copy config\Rules.json C:\AEGIS\config\
```

### Step 4: Verify Binary
```powershell
C:\AEGIS\bin\aegis-nids.exe --version
```
**Expected output:**
```
AEGIS NIDS v2.0.0 (Golden Path) [Debug, 2026-08-28]
```

---

## Driver Installation (Optional)

### WFP Callout Driver (for IPS blocking)
```powershell
cd C:\AEGIS\drivers
# Build driver (requires WDK)
build_drivers.bat
# Install driver
install_drivers.bat
```

### Verify Driver
```powershell
# Check if device is open
sc query aegis_wfp
```

### Minifilter Driver (for file system monitoring)
```powershell
cd C:\AEGIS\drivers\minifilter
# Install
fltmc load aegis_minifilter
```

---

## Starting AEGIS NIDS

### Option A: Command Line
```powershell
cd C:\AEGIS\bin
.\aegis-nids.exe
```

### Option B: As Windows Service (Recommended for Production)
```powershell
# Create service
sc create AEGIS_NIDS binPath= "C:\AEGIS\bin\aegis-nids.exe" start= auto
# Start service
sc start AEGIS_NIDS
```

### Option C: Using run_aegis.bat
```powershell
cd C:\AEGIS
.\run_aegis.bat
```

### Verify Startup
```powershell
# Check process is running
Get-Process aegis-nids
# Check logs directory
dir C:\AEGIS\logs\
```

**Expected log files:**
- `logs\aegis_core.ndjson` — main forensic log
- `logs\blocked_ips.json` — blocked IP table
- `logs\pids\*.pid` — thread PID files

---

## Stopping AEGIS NIDS

### Graceful Shutdown (Recommended)
```powershell
# Send CTRL+C to the process
Stop-Process -Name aegis-nids -Force
```

### As Windows Service
```powershell
sc stop AEGIS_NIDS
```

### Verify Clean Shutdown
```powershell
# Check process exited
Get-Process aegis-nids -ErrorAction SilentlyContinue
# Verify forensic log flushed
Get-Content C:\AEGIS\logs\aegis_core.ndjson -Tail 5
```

---

## Configuration

### Rules.json
Location: `config\Rules.json`

```json
{
  "rules": [
    {
      "name": "Block Malware",
      "pattern": "malware",
      "severity": "critical",
      "action": "block"
    }
  ]
}
```

### Environment Variables
| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_LOG_PATH` | `logs/aegis_core.ndjson` | Forensic log file path |
| `AEGIS_API_PORT` | `9200` | Go aggregator REST API port |
| `AEGIS_MAX_ALERTS` | `10000` | Max alerts in aggregator |
| `AEGIS_BRAIN_HOST` | `127.0.0.1` | Python brain UDP host |
| `AEGIS_BRAIN_PORT` | `9999` | Python brain UDP port |

### Runtime Configuration
```powershell
# Set log path
$env:AEGIS_LOG_PATH = "D:\logs\aegis.ndjson"

# Set API port
$env:AEGIS_API_PORT = 9300

# Start with custom config
.\aegis-nids.exe
```

---

## Monitoring

### Prometheus Metrics
```powershell
# Collect metrics (from Zig pipeline)
# In application code:
# metrics_export.collectAllMetrics()
# metrics_export.exportPrometheus(buf)
```

### Go Aggregator REST API
```powershell
# Health check
curl http://127.0.0.1:9200/api/health

# List alerts
curl http://127.0.0.1:9200/api/alerts

# Critical alerts
curl http://127.0.0.1:9200/api/alerts/critical

# Stats
curl http://127.0.0.1:9200/api/stats
```

### Log Monitoring
```powershell
# Tail forensic log
Get-Content C:\AEGIS\logs\aegis_core.ndjson -Wait -Tail 10

# Count BLOCK events
Select-String -Path C:\AEGIS\logs\aegis_core.ndjson -Pattern "BLOCK" | Measure-Object

# Check blocked IPs
Get-Content C:\AEGIS\logs\blocked_ips.json
```

---

## Troubleshooting

### Binary Won't Start
```powershell
# Check Zig version
zig version
# Should be 0.13.0

# Check binary exists
Test-Path C:\AEGIS\bin\aegis-nids.exe

# Check Rules.json exists
Test-Path C:\AEGIS\config\Rules.json

# Run with debug output
.\aegis-nids.exe 2>&1 | Tee-Object -FilePath debug.log
```

### WFP Device Not Open
```
[WFP IOCTL] block_ip: device not open
```
**Cause:** WFP driver not installed or not running
**Fix:**
```powershell
# Install driver
cd C:\AEGIS\drivers
.\install_drivers.bat
# Verify
sc query aegis_wfp
```

### High Memory Usage
```powershell
# Check process memory
Get-Process aegis-nids | Select-Object WorkingSet, PrivateMemorySize

# If > 500MB, restart
Stop-Process -Name aegis-nids -Force
Start-Process -FilePath "C:\AEGIS\bin\aegis-nids.exe" -WorkingDirectory "C:\AEGIS"
```

### Queue Overflow (Events Dropped)
```
[NOSE] Event dropped at source (pressure sampling)
```
**Cause:** Pipeline overloaded
**Fix:** Increase queue capacity or add more detection threads

---

## Upgrade Procedure

### Step 1: Backup Current Version
```powershell
Copy-Item -Path C:\AEGIS\bin -Destination C:\AEGIS\bin_backup -Recurse
Copy-Item -Path C:\AEGIS\config -Destination C:\AEGIS\config_backup -Recurse
```

### Step 2: Stop AEGIS
```powershell
Stop-Process -Name aegis-nids -Force
```

### Step 3: Pull Latest Code
```powershell
cd D:\NIds_Windows
git pull origin main
```

### Step 4: Build New Version
```powershell
zig build
```

### Step 5: Deploy New Binary
```powershell
Copy-Item zig-out\bin\aegis-nids.exe C:\AEGIS\bin\ -Force
```

### Step 6: Run Tests
```powershell
zig build test
```

### Step 7: Start AEGIS
```powershell
Start-Process -FilePath "C:\AEGIS\bin\aegis-nids.exe" -WorkingDirectory "C:\AEGIS"
```

### Step 8: Verify
```powershell
C:\AEGIS\bin\aegis-nids.exe --version
```

---

## Rollback Procedure

### Step 1: Stop AEGIS
```powershell
Stop-Process -Name aegis-nids -Force
```

### Step 2: Restore Backup
```powershell
Copy-Item -Path C:\AEGIS\bin_backup\* -Destination C:\AEGIS\bin\ -Force
Copy-Item -Path C:\AEGIS\config_backup\* -Destination C:\AEGIS\config\ -Force
```

### Step 3: Start Old Version
```powershell
Start-Process -FilePath "C:\AEGIS\bin\aegis-nids.exe" -WorkingDirectory "C:\AEGIS"
```

### Step 4: Verify
```powershell
C:\AEGIS\bin\aegis-nids.exe --version
# Should show previous version
```

---

## Health Checks

### Quick Health Check Script
```powershell
# health_check.ps1
Write-Host "=== AEGIS NIDS Health Check ==="

# 1. Process running?
$proc = Get-Process aegis-nids -ErrorAction SilentlyContinue
if ($proc) {
    Write-Host "[OK] Process running (PID: $($proc.Id))"
    Write-Host "     Memory: $([math]::Round($proc.WorkingSet / 1MB, 2)) MB"
} else {
    Write-Host "[FAIL] Process not running"
}

# 2. Log file exists?
if (Test-Path "C:\AEGIS\logs\aegis_core.ndjson") {
    $size = (Get-Item "C:\AEGIS\logs\aegis_core.ndjson").Length
    Write-Host "[OK] Forensic log exists ($size bytes)"
} else {
    Write-Host "[WARN] Forensic log not found"
}

# 3. Blocked IPs file?
if (Test-Path "C:\AEGIS\logs\blocked_ips.json") {
    $ips = Get-Content "C:\AEGIS\logs\blocked_ips.json" | ConvertFrom-Json
    Write-Host "[OK] Blocked IPs: $($ips.Count)"
} else {
    Write-Host "[WARN] blocked_ips.json not found"
}

# 4. Go aggregator reachable?
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:9200/api/health" -TimeoutSec 5
    Write-Host "[OK] Go aggregator: $($health.status)"
} catch {
    Write-Host "[WARN] Go aggregator not reachable"
}

Write-Host "=== Health Check Complete ==="
```

### Run Health Check
```powershell
.\health_check.ps1
```
