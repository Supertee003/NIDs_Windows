# ============================================================
# AEGIS NIDS - bundle verification (read-only preflight)
# ============================================================
# Verifies a packaged Windows bundle (release\aegis-nids-windows-*)
# against its manifest.json:
#   1. manifest.json parses (product / version / artifacts)
#   2. every artifact exists with the declared SHA256 + byte length
#   3. the canonical required files are present
#   4. canonical_rules points at a shipped artifact
#
# Read-only: nothing is extracted, created, or modified.
#
# Usage:
#   .\scripts\verify_release.ps1                      # latest bundle under release\
#   .\scripts\verify_release.ps1 -BundleRoot <dir>    # explicit bundle directory
# ============================================================

param(
    [string]$BundleRoot = ""
)

$ErrorActionPreference = 'Stop'

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " AEGIS NIDS - bundle verification (read-only)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$failures = @()
function Add-Failure([string]$message) {
    $script:failures += $message
    Write-Host "  [FAIL] $message" -ForegroundColor Red
}

# Step 1: locate the bundle
if ($BundleRoot -eq "") {
    $bundleCandidate = Join-Path $PSScriptRoot '..'
    if (Test-Path (Join-Path $bundleCandidate 'manifest.json')) {
        # Running from inside a bundle (<bundle>\scripts\verify_release.ps1)
        $BundleRoot = (Resolve-Path $bundleCandidate).Path
    } else {
        $releaseDir = Join-Path $PSScriptRoot '..\release'
        $latest = Get-ChildItem $releaseDir -Directory -Filter 'aegis-nids-windows-*' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $latest) {
            Write-Host "[FAIL] No aegis-nids-windows-* bundle found under $releaseDir" -ForegroundColor Red
            Write-Host "       Pass one explicitly: -BundleRoot <dir>" -ForegroundColor Yellow
            exit 1
        }
        $BundleRoot = $latest.FullName
    }
} else {
    if (-not (Test-Path $BundleRoot)) {
        Write-Host "[FAIL] Bundle not found: $BundleRoot" -ForegroundColor Red
        exit 1
    }
    $BundleRoot = (Resolve-Path $BundleRoot).Path
}
Write-Host "[1/4] Bundle: $BundleRoot" -ForegroundColor Yellow

# Step 2: manifest
$manifestPath = Join-Path $BundleRoot 'manifest.json'
if (-not (Test-Path $manifestPath)) {
    Write-Host "[FAIL] manifest.json not found in bundle" -ForegroundColor Red
    exit 1
}
$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Host "[2/4] manifest: product=$($manifest.product) version=$($manifest.version)" -ForegroundColor Yellow
if ($manifest.product -ne 'AEGIS NIDS') { Add-Failure "unexpected product: $($manifest.product)" }
if (-not $manifest.version) { Add-Failure "manifest.version is empty" }
if (-not $manifest.artifacts -or $manifest.artifacts.Count -eq 0) { Add-Failure "manifest.artifacts is empty" }

# Step 3: required files (canonical layout: runtime\ configs\ drivers\ scripts\)
$requiredFiles = @(
    'runtime/aegis_nids.exe',
    'runtime/aegis_pep.dll',
    'configs/Rules.json',
    'configs/policies.json',
    'drivers/aegis_wfp.sys',
    'scripts/install_aegis.ps1',
    'README.txt'
)
Write-Host "[3/4] Checking required files..." -ForegroundColor Yellow
foreach ($rel in $requiredFiles) {
    $filePath = Join-Path $BundleRoot ($rel -replace '/', '\')
    if (Test-Path $filePath) { Write-Host "  [OK] $rel" -ForegroundColor Green }
    else { Add-Failure "missing required file: $rel" }
}

# Step 4: artifact digests + lengths
Write-Host "[4/4] Verifying manifest artifacts (SHA256 + length)..." -ForegroundColor Yellow
$verified = 0
foreach ($artifact in $manifest.artifacts) {
    $rel = $artifact.path
    $filePath = Join-Path $BundleRoot ($rel -replace '/', '\')
    if (-not (Test-Path $filePath -PathType Leaf)) { Add-Failure "artifact missing: $rel"; continue }
    $actualHash = (Get-FileHash $filePath -Algorithm SHA256).Hash
    $actualLength = (Get-Item $filePath).Length
    if ($actualHash -ne $artifact.sha256) { Add-Failure "SHA256 mismatch: $rel"; continue }
    if ($actualLength -ne $artifact.length) { Add-Failure "length mismatch: $rel"; continue }
    $verified++
    Write-Host "  [OK] $rel" -ForegroundColor Green
}
if ($manifest.canonical_rules) {
    $shipped = @($manifest.artifacts | ForEach-Object { $_.path })
    if ($shipped -notcontains $manifest.canonical_rules) {
        Add-Failure "canonical_rules not shipped: $($manifest.canonical_rules)"
    }
}

# Summary
Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " VERIFICATION FAILED ($($failures.Count) problem(s); $verified artifact(s) verified)" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 1
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " VERIFICATION PASSED" -ForegroundColor Green
Write-Host " Artifacts: $verified hash-verified against manifest.json" -ForegroundColor Green
Write-Host " Layout:    runtime\ configs\ drivers\ scripts\" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
exit 0
