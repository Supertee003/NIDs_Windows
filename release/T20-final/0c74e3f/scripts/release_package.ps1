# ============================================================
# AEGIS NIDS - Release Packaging Script (STEP 15)
# ============================================================
# Builds release binary + collects all deps + creates versioned ZIP
#
# Usage:
#   .\scripts\release_package.ps1
#   .\scripts\release_package.ps1 -Version "2.0.1"
# ============================================================

param(
    [string]$Version = "",
    [string]$OutputDir = "release"
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot | Split-Path -Parent
Set-Location $ProjectRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AEGIS NIDS - Release Packaging" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Step 1: Determine version
if ($Version -eq "") {
    # Extract from release_info.zig
    $release_info = Get-Content "core\release_info.zig" -Raw
    $major = [regex]::Match($release_info, 'VERSION_MAJOR:\s*u32\s*=\s*(\d+)').Groups[1].Value
    $minor = [regex]::Match($release_info, 'VERSION_MINOR:\s*u32\s*=\s*(\d+)').Groups[1].Value
    $patch = [regex]::Match($release_info, 'VERSION_PATCH:\s*u32\s*=\s*(\d+)').Groups[1].Value
    $Version = "$major.$minor.$patch"
}
Write-Host "[1/6] Version: $Version" -ForegroundColor Yellow

# Step 2: Build release binary
Write-Host "[2/6] Building release binary..." -ForegroundColor Yellow
& zig build release 2>&1 | Out-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] Release build failed" -ForegroundColor Red
    exit 1
}
$binary = "zig-out\bin\aegis-nids.exe"
if (-not (Test-Path $binary)) {
    Write-Host "[FAIL] Binary not found: $binary" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] Built: $binary" -ForegroundColor Green

# Step 3: Create output directory
$release_dir = "$OutputDir\aegis-nids-v$Version"
if (Test-Path $release_dir) {
    Remove-Item -Recurse -Force $release_dir
}
New-Item -ItemType Directory -Path $release_dir -Force | Out-Null
New-Item -ItemType Directory -Path "$release_dir\bin" -Force | Out-Null
New-Item -ItemType Directory -Path "$release_dir\config" -Force | Out-Null
New-Item -ItemType Directory -Path "$release_dir\core" -Force | Out-Null
New-Item -ItemType Directory -Path "$release_dir\scripts" -Force | Out-Null
New-Item -ItemType Directory -Path "$release_dir\docs" -Force | Out-Null
Write-Host "[3/6] Created release directory: $release_dir" -ForegroundColor Yellow

# Step 4: Collect files
Write-Host "[4/6] Collecting files..." -ForegroundColor Yellow

# Binary
Copy-Item $binary "$release_dir\bin\" -Force
Write-Host "  [OK] bin\aegis-nids.exe" -ForegroundColor Green

# Config
if (Test-Path "config\Rules.json") {
    Copy-Item "config\Rules.json" "$release_dir\config\" -Force
    Write-Host "  [OK] config\Rules.json" -ForegroundColor Green
}

# Core source (for reproducibility)
$core_files = @(
    "nids_main.zig", "nids_analyze.zig", "nids_capture.zig",
    "canonical_event.zig", "wire_event.zig",
    "event_queue.zig", "priority_queue.zig", "event_fabric.zig",
    "nose_contract.zig", "nose_integration.zig",
    "flow_engine.zig", "flow_integration.zig",
    "detection_interface.zig", "detection_integration.zig",
    "policy_contract.zig", "policy_integration.zig",
    "correlation_integration.zig", "xdr_correlator.zig", "xdr_hardening.zig",
    "rag_intelligence.zig", "rag_integration.zig",
    "forensic_log.zig", "forensics_integration.zig",
    "hids_process_monitor.zig", "wfp_ioctl.zig",
    "bridge_init.zig", "win32_io.zig",
    "release_info.zig",
    "runtime_golden_path_test.zig", "perf_benchmark.zig", "ips_canary_test.zig"
)
foreach ($f in $core_files) {
    $src = "core\$f"
    if (Test-Path $src) {
        Copy-Item $src "$release_dir\core\" -Force
    }
}
Write-Host "  [OK] core\*.zig ($($core_files.Count) files)" -ForegroundColor Green

# build.zig
Copy-Item "build.zig" "$release_dir\" -Force
Write-Host "  [OK] build.zig" -ForegroundColor Green

# Scripts (if scripts dir exists)
if (Test-Path "scripts") {
    Get-ChildItem "scripts" -Filter "*.ps1" | ForEach-Object {
        Copy-Item $_.FullName "$release_dir\scripts\" -Force
    }
    Get-ChildItem "scripts" -Filter "*.py" | ForEach-Object {
        Copy-Item $_.FullName "$release_dir\scripts\" -Force
    }
    Write-Host "  [OK] scripts\* (scripts collected)" -ForegroundColor Green
}

# Docs (if docs dir exists)
if (Test-Path "docs") {
    Get-ChildItem "docs" -Recurse | ForEach-Object {
        $rel = $_.FullName.Substring((Resolve-Path "docs").Path.Length + 1)
        $dest = "$release_dir\docs\$rel"
        $dest_dir = Split-Path -Parent $dest
        if (-not (Test-Path $dest_dir)) {
            New-Item -ItemType Directory -Path $dest_dir -Force | Out-Null
        }
        if (-not $_.PSIsContainer) {
            Copy-Item $_.FullName $dest -Force
        }
    }
    Write-Host "  [OK] docs\* (documentation collected)" -ForegroundColor Green
}

# Step 5: Generate release manifest
Write-Host "[5/6] Generating release manifest..." -ForegroundColor Yellow
$manifest = @{
    version = $Version
    build_date = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    binary = "bin/aegis-nids.exe"
    zig_version = (zig version 2>&1)
    files = (Get-ChildItem -Recurse $release_dir | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName.Substring($release_dir.Length + 1) })
}
$manifest | ConvertTo-Json -Depth 3 | Out-File "$release_dir\release-manifest.json" -Encoding utf8
Write-Host "  [OK] release-manifest.json" -ForegroundColor Green

# Step 6: Create ZIP + checksum
Write-Host "[6/6] Creating ZIP archive..." -ForegroundColor Yellow
$zip_path = "$OutputDir\aegis-nids-v$Version.zip"
if (Test-Path $zip_path) {
    Remove-Item $zip_path -Force
}
Compress-Archive -Path "$release_dir\*" -DestinationPath $zip_path -CompressionLevel Optimal
Write-Host "  [OK] Created: $zip_path" -ForegroundColor Green

# Generate SHA256
$hash = (Get-FileHash $zip_path -Algorithm SHA256).Hash
$hash_path = "$zip_path.sha256"
"$hash  $(Split-Path $zip_path -Leaf)" | Out-File $hash_path -Encoding ascii
Write-Host "  [OK] SHA256: $hash" -ForegroundColor Green

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " RELEASE COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Version: $Version"
Write-Host " Binary:  $release_dir\bin\aegis-nids.exe"
Write-Host " ZIP:     $zip_path"
Write-Host " SHA256:  $hash"
Write-Host "============================================================" -ForegroundColor Cyan
