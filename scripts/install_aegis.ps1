#Requires -RunAsAdministrator
# ============================================================
# AEGIS NIDS - bundle installer / rollback / uninstall
# ============================================================
# Installs a packaged bundle (release\aegis-nids-windows-*) under
# $InstallRoot after hash-verifying every manifest artifact, registers
# the AegisNids core service (auto-start + restart-on-failure recovery;
# the same contract as tools/installer.py and docs/DEPLOYMENT.md) and
# starts it.
#
# Usage (elevated):
#   install:   powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot <bundle>
#   rollback:  ... -Rollback                 (restore the pre-install backup)
#   uninstall: ... -Uninstall                (remove runtime/driver/scripts + service; configs preserved)
# ============================================================
[CmdletBinding()]
param(
    [string]$BundleRoot = "",
    [string]$InstallRoot = "C:\Program Files\AEGIS NIDS",
    [switch]$Rollback,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$backupRoot = "$InstallRoot.backup"

function Stop-Aegis {
    Get-Process aegis_nids -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    sc.exe stop AegisNids 2>$null | Out-Null
    Start-Sleep -Seconds 2
}

if ($Rollback) {
    if (-not (Test-Path $backupRoot)) { throw "No rollback backup found: $backupRoot" }
    Stop-Aegis
    if (Test-Path $InstallRoot) { Remove-Item $InstallRoot -Recurse -Force }
    Move-Item $backupRoot $InstallRoot
    Write-Host "Rollback completed: $InstallRoot" -ForegroundColor Green
    exit 0
}

if ($Uninstall) {
    if (-not (Test-Path $InstallRoot)) { throw "Install root not found: $InstallRoot" }
    Stop-Aegis
    if (sc.exe query AegisNids 2>$null) { sc.exe delete AegisNids | Out-Null }
    $driverQc = (sc.exe qc AegisWfp 2>$null) -join ' '
    if ($driverQc -match [regex]::Escape($InstallRoot)) {
        sc.exe stop AegisWfp 2>$null | Out-Null
        sc.exe delete AegisWfp | Out-Null
    } elseif ($driverQc) {
        Write-Host "AegisWfp service points outside this install root; leaving it untouched." -ForegroundColor Yellow
    }
    foreach ($sub in 'runtime', 'drivers', 'scripts') {
        $p = Join-Path $InstallRoot $sub
        if (Test-Path $p) { Remove-Item $p -Recurse -Force }
    }
    foreach ($f in 'manifest.json', 'README.txt') {
        $p = Join-Path $InstallRoot $f
        if (Test-Path $p) { Remove-Item $p -Force }
    }
    Write-Host "Uninstall complete. Configs preserved: $InstallRoot\configs" -ForegroundColor Green
    exit 0
}

if ($BundleRoot -eq "") { throw "-BundleRoot is required for install (or use -Rollback / -Uninstall)." }
$BundleRoot = (Resolve-Path $BundleRoot).Path
$manifestPath = Join-Path $BundleRoot "manifest.json"
if (-not (Test-Path $manifestPath)) { throw "manifest.json not found in $BundleRoot" }
$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $manifest.artifacts -or $manifest.artifacts.Count -eq 0) {
    throw "manifest.artifacts is empty or missing: $manifestPath"
}

foreach ($artifact in $manifest.artifacts) {
    $path = Join-Path $BundleRoot ($artifact.path -replace '/', '\')
    if (-not (Test-Path $path -PathType Leaf)) { throw "Bundle artifact missing: $path" }
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash
    if ($actual -ne $artifact.sha256) { throw "Hash mismatch: $($artifact.path)" }
}

# Authenticode status (provenance): the hash gate above proves the bytes
# match the manifest; signatures prove who shipped them. Unsigned builds
# are expected until the operator signing gate (EV cert / HLK) lands ->
# warn. Lab/test certificates report NotTrusted -> warn. HashMismatch /
# UnknownError fail closed (default arm).
$unsigned = 0
$untrusted = 0
foreach ($artifact in $manifest.artifacts) {
    if ($artifact.path -notmatch '\.(exe|dll)$') { continue }
    $path = Join-Path $BundleRoot ($artifact.path -replace '/', '\')
    $sig = Get-AuthenticodeSignature $path
    switch ($sig.Status.ToString()) {
        'Valid' { }
        'NotSigned' { $unsigned++ }
        'NotTrusted' { $untrusted++ }
        default { throw "Authenticode invalid ($($sig.Status)): $($artifact.path)" }
    }
}
if ($unsigned -gt 0) {
    Write-Warning "Authenticode: $unsigned runtime binaries unsigned (expected until the production signing gate); hashes verified against the manifest."
}
if ($untrusted -gt 0) {
    Write-Warning "Authenticode: $untrusted runtime binaries carry untrusted (lab/test) signatures."
}

Stop-Aegis
if (Test-Path $backupRoot) { Remove-Item $backupRoot -Recurse -Force }
if (Test-Path $InstallRoot) { Move-Item $InstallRoot $backupRoot }
New-Item -ItemType Directory -Force $InstallRoot | Out-Null
Copy-Item (Join-Path $BundleRoot '*') $InstallRoot -Recurse -Force

$runtime = Join-Path $InstallRoot 'runtime'
$driver = Join-Path $InstallRoot 'drivers\aegis_wfp.sys'
$driverSvc = sc.exe query AegisWfp 2>$null
if (-not (Test-Path $driver)) { throw "Installed WFP driver missing: $driver" }

if (-not $driverSvc) {
    sc.exe create AegisWfp type= kernel start= demand error= normal binPath= "\??\$driver" | Out-Null
}

# Core service: identical contract to the NSIS installer (tools/installer.py)
# and docs/DEPLOYMENT.md - auto-start + restart-on-failure recovery.
$svcBin = Join-Path $InstallRoot 'runtime\aegis_nids.exe'
if (-not (sc.exe query AegisNids 2>$null)) {
    sc.exe create AegisNids binPath= $svcBin start= auto | Out-Null
    sc.exe description AegisNids "AEGIS Network Intrusion Detection System" | Out-Null
    sc.exe failure AegisNids reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
    Write-Host "Registered service AegisNids (auto-start + restart-on-failure)" -ForegroundColor Green
}
sc.exe start AegisNids | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "sc.exe start AegisNids returned $LASTEXITCODE; check the service state."
}

Write-Host "Installed AEGIS NIDS to $InstallRoot" -ForegroundColor Green
Write-Host "Start driver: sc.exe start AegisWfp" -ForegroundColor Yellow
Write-Host "Uninstall:    powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -Uninstall" -ForegroundColor Yellow
Write-Host "Rollback:     powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot '$InstallRoot' -Rollback" -ForegroundColor Yellow
