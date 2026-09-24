[CmdletBinding()]
param(
    [string]$Version = "6.0.0",
    [string]$OutputRoot = "release"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$bundleName = "aegis-nids-windows-$Version-$stamp"
$bundle = Join-Path $root (Join-Path $OutputRoot $bundleName)
$runtime = Join-Path $bundle "runtime"
$config = Join-Path $bundle "configs"
$drivers = Join-Path $bundle "drivers"
$scripts = Join-Path $bundle "scripts"

New-Item -ItemType Directory -Force $runtime,$config,$drivers,$scripts | Out-Null

$artifacts = @(
    @{ Source = "zig-out\bin\aegis_nids.exe"; Destination = "runtime\aegis_nids.exe" },
    @{ Source = "zig-out\bin\aegis_pep.dll"; Destination = "runtime\aegis_pep.dll" },
    @{ Source = "zig-out\bin\aegis_fim_helper.dll"; Destination = "runtime\aegis_fim_helper.dll" },
    @{ Source = "zig-out\bin\aegis_etw_helper.dll"; Destination = "runtime\aegis_etw_helper.dll" },
    @{ Source = "zig-out\bin\aegis_wfp_user.dll"; Destination = "runtime\aegis_wfp_user.dll" },
    @{ Source = "zig-out\bin\aegis_ipc.dll"; Destination = "runtime\aegis_ipc.dll" },
    @{ Source = "configs\Rules.json"; Destination = "configs\Rules.json" },
    @{ Source = "configs\policies.json"; Destination = "configs\policies.json" },
    @{ Source = "drivers\wfp_callout\aegis_wfp.sys"; Destination = "drivers\aegis_wfp.sys" }
)

$manifest = @()
foreach ($item in $artifacts) {
    $source = Join-Path $root $item.Source
    if (-not (Test-Path $source -PathType Leaf)) {
        throw "Missing release artifact: $source"
    }
    $destination = Join-Path $bundle $item.Destination
    New-Item -ItemType Directory -Force (Split-Path -Parent $destination) | Out-Null
    Copy-Item $source $destination -Force
    $hash = (Get-FileHash $destination -Algorithm SHA256).Hash
    $manifest += [PSCustomObject]@{
        path = $item.Destination.Replace('\','/')
        sha256 = $hash
        length = (Get-Item $destination).Length
    }
}

$metadata = [ordered]@{
    product = "AEGIS NIDS"
    version = $Version
    platform = "windows-x86_64"
    created_utc = (Get-Date).ToUniversalTime().ToString("o")
    canonical_rules = "configs/Rules.json"
    artifacts = $manifest
}
$metadata | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $bundle "manifest.json") -Encoding UTF8

@"
AEGIS NIDS Production Bundle
Version: $Version
Platform: Windows x86_64

Install (elevated PowerShell):
  powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot .

Verify:
  Get-Content .\manifest.json | ConvertFrom-Json

Rollback:
  powershell -ExecutionPolicy Bypass -File .\scripts\install_aegis.ps1 -BundleRoot . -Rollback
"@ | Set-Content (Join-Path $bundle "README.txt") -Encoding UTF8

$installer = Join-Path $root "scripts\install_aegis.ps1"
if (Test-Path $installer) { Copy-Item $installer (Join-Path $scripts "install_aegis.ps1") -Force }

$zip = "$bundle.zip"
Compress-Archive -Path "$bundle\*" -DestinationPath $zip -Force
Write-Host "Release bundle: $bundle" -ForegroundColor Green
Write-Host "Archive: $zip" -ForegroundColor Green
