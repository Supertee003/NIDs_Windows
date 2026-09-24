[CmdletBinding()]
param(
    [string]$Repo = 'D:\NIDs_Windows',
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo
$evidence = Join-Path $Repo 'admin-evidence'
New-Item -ItemType Directory -Force $evidence | Out-Null
$buildDir = Join-Path $Repo 'build\wfp-user'

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name. Install Visual Studio C++/CMake tools first."
    }
}

Require-Command 'cmake'

Write-Host "[1/5] Configuring user-mode WFP bridge"
cmake -S $Repo -B $buildDir -A x64 -DBUILD_KERNEL_DRIVER=OFF
if ($LASTEXITCODE -ne 0) { throw "CMake configure failed: $LASTEXITCODE" }

Write-Host "[2/5] Building aegis_wfp_user ($Configuration)"
cmake --build $buildDir --config $Configuration --target aegis_wfp_user --parallel
if ($LASTEXITCODE -ne 0) { throw "WFP user bridge build failed: $LASTEXITCODE" }

$candidates = @(
    (Join-Path $buildDir "$Configuration\aegis_wfp_user.dll"),
    (Join-Path $buildDir "aegis_wfp_user.dll")
)
$dll = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $dll) { throw "Build succeeded but aegis_wfp_user.dll was not found under $buildDir" }

Write-Host "[3/5] Installing bridge beside runtime executable"
$destinations = @(
    (Join-Path $Repo 'aegis_wfp_user.dll'),
    (Join-Path $Repo "zig-out\bin\aegis_wfp_user.dll")
)
foreach ($destination in $destinations) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $destination) | Out-Null
    Copy-Item $dll $destination -Force
}

Write-Host "[4/5] Recording bridge provenance"
$hash = (Get-FileHash $dll -Algorithm SHA256).Hash
$record = [ordered]@{
    artifact = 'aegis_wfp_user.dll'
    source = $dll
    configuration = $Configuration
    sha256 = $hash
    built_at = (Get-Date).ToUniversalTime().ToString('o')
    exports_required = @(
        'aegis_wfp_ioctl_open',
        'aegis_wfp_ioctl_block_ip',
        'aegis_wfp_ioctl_unblock_ip',
        'aegis_wfp_ioctl_block_flow',
        'aegis_wfp_ioctl_unblock_filter'
    )
}
$record | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidence 'wfp-user-bridge-provenance.json') -Encoding utf8

Write-Host "[5/5] Validating required exports"
$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($dumpbin) {
    & $dumpbin.Source /exports $dll | Tee-Object (Join-Path $evidence 'wfp-user-bridge-exports.txt')
    if ($LASTEXITCODE -ne 0) { throw "dumpbin export inspection failed: $LASTEXITCODE" }
    $exports = Get-Content (Join-Path $evidence 'wfp-user-bridge-exports.txt') -Raw
    foreach ($name in $record.exports_required) {
        if ($exports -notmatch [regex]::Escape($name)) { throw "Required export missing: $name" }
    }
} else {
    Write-Warning 'dumpbin.exe not found; DLL was built and copied, but export validation must be run from a VS Developer PowerShell.'
}

[ordered]@{
    passed = $true
    dll = $dll
    installed = $destinations
    sha256 = $hash
    next_step = 'Start AegisWfp, then run provider attestation and health check; do not claim host effect until controlled proof.'
} | ConvertTo-Json -Depth 5
