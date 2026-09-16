[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$BundleRoot,
    [string]$InstallRoot = "C:\Program Files\AEGIS NIDS",
    [switch]$Rollback
)

$ErrorActionPreference = "Stop"
$BundleRoot = (Resolve-Path $BundleRoot).Path
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

$manifestPath = Join-Path $BundleRoot "manifest.json"
if (-not (Test-Path $manifestPath)) { throw "manifest.json not found in $BundleRoot" }
$manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json

foreach ($artifact in $manifest.artifacts) {
    $path = Join-Path $BundleRoot ($artifact.path -replace '/', '\\')
    if (-not (Test-Path $path -PathType Leaf)) { throw "Bundle artifact missing: $path" }
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash
    if ($actual -ne $artifact.sha256) { throw "Hash mismatch: $($artifact.path)" }
}

Stop-Aegis
if (Test-Path $backupRoot) { Remove-Item $backupRoot -Recurse -Force }
if (Test-Path $InstallRoot) { Move-Item $InstallRoot $backupRoot }
New-Item -ItemType Directory -Force $InstallRoot | Out-Null
Copy-Item (Join-Path $BundleRoot '*') $InstallRoot -Recurse -Force

$runtime = Join-Path $InstallRoot 'runtime'
$driver = Join-Path $InstallRoot 'drivers\aegis_wfp.sys'
$service = sc.exe query AegisWfp 2>$null
if (-not (Test-Path $driver)) { throw "Installed WFP driver missing: $driver" }

if (-not $service) {
    sc.exe create AegisWfp type= kernel start= demand error= normal binPath= "\??\$driver" | Out-Null
}

Write-Host "Installed AEGIS NIDS to $InstallRoot" -ForegroundColor Green
Write-Host "Start driver: sc.exe start AegisWfp"
Write-Host "Start core:   Start-Process '$runtime\aegis_nids.exe' -WorkingDirectory '$InstallRoot'"
Write-Host "Rollback:     powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot '$InstallRoot' -Rollback"
