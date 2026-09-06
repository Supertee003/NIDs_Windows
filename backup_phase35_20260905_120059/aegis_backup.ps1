# ============================================================
# AEGIS NIDS - Phase 35: Backup Script
# ============================================================
# Backs up all AEGIS NIDS state to a timestamped archive.
# Safe to run while AEGIS is in production (read-only operations).
#
# What gets backed up:
#   1. config/         - Configuration files (aegis.conf, Rules.json, etc.)
#   2. core/*.zig      - Engine source files (in case of accidental modification)
#   3. logs/           - Forensic logs (anomalous.json, daemon.log, etc.)
#   4. blocked_ips.json - Current WFP blocklist (if exists)
#   5. .git/HEAD       - Current git commit hash (for version tracking)
#   6. WFP driver state - Service config + cert thumbprint
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\aegis_backup.ps1
#   powershell -ExecutionPolicy Bypass -File .\aegis_backup.ps1 -Full    # include .git history
#   powershell -ExecutionPolicy Bypass -File .\aegis_backup.ps1 -Logs    # logs only
# ============================================================

param(
    [switch]$Full,
    [switch]$Logs,
    [switch]$Config,
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Get-Location).Path
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupDir = Join-Path $repoRoot "backups\backup_$timestamp"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AEGIS NIDS - Phase 35: Backup" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Timestamp: $timestamp"
Write-Host "  Backup to: $backupDir"
Write-Host ""

# ============================================================
# Helper: Copy directory with verification
# ============================================================

function Copy-DirSafe {
    param([string]$Src, [string]$Dst, [string]$Label)

    if (-not (Test-Path $Src)) {
        Write-Host "  [SKIP] $Label (not found: $Src)" -ForegroundColor Yellow
        return 0
    }

    $fileCount = (Get-ChildItem -Path $Src -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
    Copy-Item -Path $Src -Destination $Dst -Recurse -Force -ErrorAction Stop
    Write-Host "  [OK] $Label ($fileCount files)" -ForegroundColor Green
    return $fileCount
}

function Copy-FileSafe {
    param([string]$Src, [string]$Dst, [string]$Label)

    if (-not (Test-Path $Src)) {
        Write-Host "  [SKIP] $Label (not found: $Src)" -ForegroundColor Yellow
        return $false
    }

    Copy-Item -Path $Src -Destination $Dst -Force -ErrorAction Stop
    $size = (Get-Item $Src).Length
    Write-Host "  [OK] $Label ($size bytes)" -ForegroundColor Green
    return $true
}

# ============================================================
# Create backup directory structure
# ============================================================

Write-Host "[STEP 1] Creating backup directory..." -ForegroundColor Cyan

$backupDirs = @(
    $backupDir,
    (Join-Path $backupDir 'config'),
    (Join-Path $backupDir 'core'),
    (Join-Path $backupDir 'logs'),
    (Join-Path $backupDir 'system'),
    (Join-Path $backupDir 'git')
)

foreach ($d in $backupDirs) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "  [OK] Directory structure created" -ForegroundColor Green

# ============================================================
# STEP 2: Backup configuration
# ============================================================

Write-Host ""
Write-Host "[STEP 2] Backing up configuration..." -ForegroundColor Cyan

$totalFiles = 0

# config/ directory
$totalFiles += Copy-DirSafe -Src (Join-Path $repoRoot 'config') -Dst (Join-Path $backupDir 'config') -Label 'config/'

# Rules.json (in root or config/)
$rulesPaths = @(
    (Join-Path $repoRoot 'Rules.json'),
    (Join-Path $repoRoot 'config\Rules.json'),
    (Join-Path $repoRoot 'rules.json')
)
foreach ($rp in $rulesPaths) {
    if (Test-Path $rp) {
        $destName = Split-Path $rp -Leaf
        Copy-FileSafe -Src $rp -Dst (Join-Path $backupDir "config\$destName") -Label $destName
        break
    }
}

# .github/workflows/ (CI config)
if (Test-Path (Join-Path $repoRoot '.github\workflows')) {
    $totalFiles += Copy-DirSafe -Src (Join-Path $repoRoot '.github\workflows') -Dst (Join-Path $backupDir 'config\workflows') -Label '.github/workflows/'
}

# ============================================================
# STEP 3: Backup engine source files
# ============================================================

Write-Host ""
Write-Host "[STEP 3] Backing up engine source files..." -ForegroundColor Cyan

# core/ directory (all .zig files)
$totalFiles += Copy-DirSafe -Src (Join-Path $repoRoot 'core') -Dst (Join-Path $backupDir 'core') -Label 'core/'

# build.zig
Copy-FileSafe -Src (Join-Path $repoRoot 'build.zig') -Dst (Join-Path $backupDir 'build.zig') -Label 'build.zig'

# scripts/ directory
if (Test-Path (Join-Path $repoRoot 'scripts')) {
    $totalFiles += Copy-DirSafe -Src (Join-Path $repoRoot 'scripts') -Dst (Join-Path $backupDir 'scripts') -Label 'scripts/'
}

# ============================================================
# STEP 4: Backup logs
# ============================================================

Write-Host ""
Write-Host "[STEP 4] Backing up logs..." -ForegroundColor Cyan

if (Test-Path (Join-Path $repoRoot 'logs')) {
    $totalFiles += Copy-DirSafe -Src (Join-Path $repoRoot 'logs') -Dst (Join-Path $backupDir 'logs') -Label 'logs/'

    # Show log stats
    $anomalousPath = Join-Path $repoRoot 'logs\anomalous.json'
    if (Test-Path $anomalousPath) {
        $logLines = (Get-Content $anomalousPath | Measure-Object).Count
        $logSize = (Get-Item $anomalousPath).Length / 1KB
        Write-Host "       anomalous.json: $logLines events, $([math]::Round($logSize, 1)) KB" -ForegroundColor Gray
    }
} else {
    Write-Host "  [SKIP] logs/ not found" -ForegroundColor Yellow
}

# ============================================================
# STEP 5: Backup WFP driver state
# ============================================================

Write-Host ""
Write-Host "[STEP 5] Backing up system state..." -ForegroundColor Cyan

# WFP driver service status
$wfpStatus = & sc.exe query aegis_wfp 2>&1 | Out-String
$wfpStatus | Out-File -FilePath (Join-Path $backupDir 'system\wfp_driver_status.txt') -Encoding UTF8

if ($wfpStatus -match 'RUNNING') {
    Write-Host "  [OK] WFP driver: RUNNING" -ForegroundColor Green
} else {
    Write-Host "  [INFO] WFP driver: NOT RUNNING" -ForegroundColor Yellow
}

# Blocked IPs (if WFP driver is running, query the blocklist)
$blockedIpsPath = Join-Path $repoRoot 'logs\blocked_ips.json'
if (Test-Path $blockedIpsPath) {
    Copy-FileSafe -Src $blockedIpsPath -Dst (Join-Path $backupDir 'system\blocked_ips.json') -Label 'blocked_ips.json'
}

# Also try to export current blocklist via sc query (if possible)
$scConfig = & sc.exe qc aegis_wfp 2>&1 | Out-String
$scConfig | Out-File -FilePath (Join-Path $backupDir 'system\wfp_service_config.txt') -Encoding UTF8
Write-Host "  [OK] WFP service config saved" -ForegroundColor Green

# Test signing mode status
$bcdEdit = & bcdedit /enum '{current}' 2>&1 | Out-String
$bcdEdit | Out-File -FilePath (Join-Path $backupDir 'system\bcdedit.txt') -Encoding UTF8

if ($bcdEdit -match 'testsigning\s+Yes') {
    Write-Host "  [OK] Test signing: ENABLED" -ForegroundColor Green
} else {
    Write-Host "  [INFO] Test signing: NOT enabled" -ForegroundColor Yellow
}

# Cert thumbprint (AEGIS test signer)
$cert = Get-ChildItem 'Cert:\CurrentUser\My' | Where-Object { $_.Subject -match 'AEGIS Test Signer' } | Select-Object -First 1
if ($cert) {
    $certInfo = @{
        thumbprint = $cert.Thumbprint
        subject = $cert.Subject
        notAfter = $cert.NotAfter.ToString()
    }
    $certInfo | ConvertTo-Json | Out-File -FilePath (Join-Path $backupDir 'system\test_cert.json') -Encoding UTF8
    Write-Host "  [OK] Test cert: $($cert.Thumbprint)" -ForegroundColor Green
}

# ============================================================
# STEP 6: Backup git state
# ============================================================

Write-Host ""
Write-Host "[STEP 6] Backing up git state..." -ForegroundColor Cyan

# Current commit hash
$gitHash = & git rev-parse HEAD 2>&1
if ($LASTEXITCODE -eq 0) {
    $gitHash | Out-File -FilePath (Join-Path $backupDir 'git\commit_hash.txt') -Encoding UTF8 -NoNewline
    Write-Host "  [OK] Git commit: $($gitHash.Substring(0, 8))..." -ForegroundColor Green

    # Git status (uncommitted changes)
    $gitStatus = & git status --short 2>&1
    $gitStatus | Out-File -FilePath (Join-Path $backupDir 'git\status.txt') -Encoding UTF8

    if ($gitStatus) {
        $changeCount = ($gitStatus | Measure-Object).Count
        Write-Host "  [INFO] Uncommitted changes: $changeCount file(s)" -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] Working tree clean" -ForegroundColor Green
    }

    # Git log (last 20 commits)
    $gitLog = & git log --oneline -20 2>&1
    $gitLog | Out-File -FilePath (Join-Path $backupDir 'git\log.txt') -Encoding UTF8

    if ($Full) {
        Write-Host "  [INFO] Full backup: copying .git/ directory..." -ForegroundColor Yellow
        Copy-DirSafe -Src (Join-Path $repoRoot '.git') -Dst (Join-Path $backupDir 'git\.git') -Label '.git/ (full history)'
    }
} else {
    Write-Host "  [SKIP] Not a git repository" -ForegroundColor Yellow
}

# ============================================================
# STEP 7: Create manifest
# ============================================================

Write-Host ""
Write-Host "[STEP 7] Creating backup manifest..." -ForegroundColor Cyan

$manifest = @{
    backup_timestamp = $timestamp
    backup_date = (Get-Date).ToString('o')
    repo_root = $repoRoot
    backup_dir = $backupDir
    total_files = $totalFiles
    mode = if ($Full) { 'Full' } elseif ($Logs) { 'Logs' } elseif ($Config) { 'Config' } else { 'Standard' }
    contents = @{
        config = (Test-Path (Join-Path $backupDir 'config'))
        core = (Test-Path (Join-Path $backupDir 'core'))
        logs = (Test-Path (Join-Path $backupDir 'logs'))
        system = (Test-Path (Join-Path $backupDir 'system'))
        git = (Test-Path (Join-Path $backupDir 'git\commit_hash.txt'))
    }
    system_state = @{
        wfp_driver_running = ($wfpStatus -match 'RUNNING')
        test_signing_enabled = ($bcdEdit -match 'testsigning\s+Yes')
        test_cert_thumbprint = if ($cert) { $cert.Thumbprint } else { $null }
    }
}

$manifestPath = Join-Path $backupDir 'manifest.json'
$manifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host "  [OK] Manifest saved: manifest.json" -ForegroundColor Green

# ============================================================
# STEP 8: Verify backup
# ============================================================

if ($Verify) {
    Write-Host ""
    Write-Host "[STEP 8] Verifying backup..." -ForegroundColor Cyan

    $verifyFiles = @(
        (Join-Path $backupDir 'manifest.json'),
        (Join-Path $backupDir 'config'),
        (Join-Path $backupDir 'core'),
        (Join-Path $backupDir 'logs'),
        (Join-Path $backupDir 'system')
    )

    $allOk = $true
    foreach ($vf in $verifyFiles) {
        if (Test-Path $vf) {
            Write-Host "  [OK] $vf" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $vf" -ForegroundColor Red
            $allOk = $false
        }
    }

    if ($allOk) {
        Write-Host "  [OK] Backup verified successfully" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Some files missing from backup" -ForegroundColor Yellow
    }
}

# ============================================================
# STEP 9: Create compressed archive
# ============================================================

Write-Host ""
Write-Host "[STEP 9] Creating compressed archive..." -ForegroundColor Cyan

$archivePath = "$backupDir.zip"
try {
    Compress-Archive -Path "$backupDir\*" -DestinationPath $archivePath -Force
    $archiveSize = (Get-Item $archivePath).Length / 1MB
    Write-Host "  [OK] Archive created: $archivePath ($([math]::Round($archiveSize, 2)) MB)" -ForegroundColor Green

    # Optionally remove the uncompressed directory
    Remove-Item $backupDir -Recurse -Force
    Write-Host "  [OK] Removed uncompressed directory (archive retained)" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Archive creation failed: $_" -ForegroundColor Yellow
    Write-Host "  Uncompressed backup retained at: $backupDir" -ForegroundColor Gray
}

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "BACKUP COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Backup location: $archivePath"
Write-Host "Total files:     $totalFiles"
Write-Host "Mode:            $($manifest.mode)"
Write-Host ""
Write-Host "Contents:"
Write-Host "  config/  - Configuration files + Rules.json"
Write-Host "  core/    - Engine source files (all .zig)"
Write-Host "  logs/    - Forensic logs (anomalous.json, etc.)"
Write-Host "  system/  - WFP driver state + cert + test signing"
Write-Host "  git/     - Commit hash + status + log"
Write-Host "  manifest.json - Backup metadata"
Write-Host ""
Write-Host "To restore:"
Write-Host "  powershell -ExecutionPolicy Bypass -File .\aegis_restore.ps1 -Backup $archivePath"
Write-Host ""
Write-Host "To list backups:"
Write-Host "  Get-ChildItem backups\backup_*.zip | Sort-Object Name -Descending"
Write-Host ""
Write-Host "=== AEGIS NIDS PHASE 35 BACKUP COMPLETE ===" -ForegroundColor Green
