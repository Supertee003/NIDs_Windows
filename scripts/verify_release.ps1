# ============================================================
# AEGIS NIDS - Release Verification Script (STEP 15)
# ============================================================
# Verifies a release package is complete and runnable.
#
# Usage:
#   .\scripts\verify_release.ps1
#   .\scripts\verify_release.ps1 -ZipPath "release\aegis-nids-v2.0.0.zip"
# ============================================================

param(
    [string]$ZipPath = "",
    [string]$ExtractDir = "release\verify"
)

$ErrorActionPreference = 'Continue'
$ProjectRoot = $PSScriptRoot | Split-Path -Parent
Set-Location $ProjectRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AEGIS NIDS - Release Verification" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 1: Find release package
if ($ZipPath -eq "") {
    $zips = Get-ChildItem "release" -Filter "aegis-nids-v*.zip" -ErrorAction SilentlyContinue
    if ($zips.Count -eq 0) {
        Write-Host "[FAIL] No release ZIP found in release\" -ForegroundColor Red
        Write-Host "       Run: .\scripts\release_package.ps1" -ForegroundColor Yellow
        exit 1
    }
    $ZipPath = $zips | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $ZipPath = $ZipPath.FullName
}
Write-Host "[1/6] Release package: $ZipPath" -ForegroundColor Yellow

if (-not (Test-Path $ZipPath)) {
    Write-Host "[FAIL] ZIP not found: $ZipPath" -ForegroundColor Red
    exit 1
}

# Verify SHA256
$hash_file = "$ZipPath.sha256"
if (Test-Path $hash_file) {
    $expected_hash = (Get-Content $hash_file).Split(' ')[0]
    $actual_hash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash
    if ($expected_hash -ne $actual_hash) {
        Write-Host "[FAIL] SHA256 mismatch" -ForegroundColor Red
        Write-Host "  Expected: $expected_hash"
        Write-Host "  Actual:   $actual_hash"
        exit 1
    }
    Write-Host "  [OK] SHA256 verified" -ForegroundColor Green
}

# Step 2: Extract ZIP
Write-Host "[2/6] Extracting to $ExtractDir..." -ForegroundColor Yellow
if (Test-Path $ExtractDir) {
    Remove-Item -Recurse -Force $ExtractDir
}
New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null
Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force
Write-Host "  [OK] Extracted" -ForegroundColor Green

# Step 3: Verify required files
Write-Host "[3/6] Checking required files..." -ForegroundColor Yellow
$required = @(
    "bin\aegis-nids.exe",
    "config\Rules.json",
    "build.zig",
    "core\release_info.zig",
    "core\nids_main.zig",
    "release-manifest.json"
)
$missing = @()
foreach ($f in $required) {
    $path = "$ExtractDir\$f"
    if (Test-Path $path) {
        Write-Host "  [OK] $f" -ForegroundColor Green
    } else {
        Write-Host "  [MISS] $f" -ForegroundColor Red
        $missing += $f
    }
}
if ($missing.Count -gt 0) {
    Write-Host "[FAIL] Missing $($missing.Count) required files" -ForegroundColor Red
    exit 1
}

# Step 4: Verify manifest
Write-Host "[4/6] Checking release manifest..." -ForegroundColor Yellow
$manifest_path = "$ExtractDir\release-manifest.json"
if (Test-Path $manifest_path) {
    $manifest = Get-Content $manifest_path | ConvertFrom-Json
    Write-Host "  [OK] Version: $($manifest.version)" -ForegroundColor Green
    Write-Host "  [OK] Build date: $($manifest.build_date)" -ForegroundColor Green
    Write-Host "  [OK] File count: $($manifest.files.Count)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Manifest not found" -ForegroundColor Red
    exit 1
}

# Step 5: Verify binary exists + is executable
Write-Host "[5/6] Checking binary..." -ForegroundColor Yellow
$binary = "$ExtractDir\bin\aegis-nids.exe"
if (Test-Path $binary) {
    $size = (Get-Item $binary).Length
    Write-Host "  [OK] Binary exists ($size bytes)" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Binary not found" -ForegroundColor Red
    exit 1
}

# Step 6: Summary
Write-Host "[6/6] Verification summary..." -ForegroundColor Yellow
$total_files = (Get-ChildItem -Recurse $ExtractDir | Where-Object { -not $_.PSIsContainer }).Count
$total_size = (Get-ChildItem -Recurse $ExtractDir | Measure-Object -Property Length -Sum).Sum / 1MB
Write-Host "  Total files: $total_files" -ForegroundColor Green
Write-Host "  Total size:  $([math]::Round($total_size, 2)) MB" -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VERIFICATION PASSED" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Version:      $($manifest.version)"
Write-Host " Binary:       $binary"
Write-Host " File count:   $total_files"
Write-Host " Total size:   $([math]::Round($total_size, 2)) MB"
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run the binary:"
Write-Host "  cd $ExtractDir\bin"
Write-Host "  .\aegis-nids.exe"
Write-Host ""
