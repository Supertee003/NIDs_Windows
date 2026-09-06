# AEGIS WFP Driver - Service Lifecycle (P4 / Phase S toolchain)
# Install / start / stop / status / uninstall for the aegis_wfp.sys
# kernel driver, with rollback of every partial install step.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 install
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 start
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 status
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 stop
#   powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 uninstall
#
# Service contract (matches core/wfp_production.zig + p4 contract doc):
#   Name:     AegisWfp          Type: kernel   Start: demand
#   Binary:   System32\drivers\aegis_wfp.sys
#   Device:   \\.\AegisWfp      (symlink created by DriverEntry)

param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('install', 'start', 'stop', 'status', 'uninstall')]
    [string]$Action,
    [string]$SysPath = ""
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$svcName = 'AegisWfp'
$svcBin = "$env:SystemRoot\System32\drivers\aegis_wfp.sys"

function Info($msg) { Write-Host "[svc] $msg" }
function Warn($msg) { Write-Host "[svc] WARN: $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "[svc] FAIL: $msg" -ForegroundColor Red; exit 1 }

# ----------------------------------------------------------------
# 0. Admin requirement
# ----------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Fail "Administrator required for service operations." }

function Test-DriverPresent {
    param([string]$path)
    if (-not (Test-Path $path)) {
        Warn "Driver file missing: $path"
        return $false
    }
    $sig = Get-AuthenticodeSignature $path
    Info "Driver signature: $($sig.Status) ($($sig.SignerCertificate.Subject))"
    return $true
}

function Install-Driver {
    Info "Install: $svcName"
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    if (-not $SysPath) { $SysPath = Join-Path $repoRoot "build\x64\wfp\aegis_wfp.sys" }
    if (-not (Test-Path $SysPath)) {
        Fail "aegis_wfp.sys not found at $SysPath - run wdk_build_production.ps1 + wfp_sign.ps1 first."
    }
    if (-not (Test-DriverPresent $SysPath)) {
        Warn "Continuing with an unsigned/missing-signature driver will fail to load"
        Warn "unless test signing is enabled (bcdedit /set testsigning on + reboot)."
    }

    # Idempotency: remove an existing copy of the service first.
    $existing = sc.exe query $svcName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Warn "Service already exists - removing for a clean install."
        & Uninstall-Driver -SkipConfirm
    }

    # Step 1: copy binary.
    Copy-Item $SysPath $svcBin -Force
    if (-not (Test-Path $svcBin)) { Fail "Could not copy driver to $svcBin." }
    Info "Binary in place: $svcBin"

    # Step 2: create the kernel service (start = demand: manual).
    $out = sc.exe create $svcName type= kernel start= demand binPath= "$svcBin" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "sc.exe create failed: $out (rolling back binary)."
        Remove-Item $svcBin -Force -ErrorAction SilentlyContinue
    }
    Info "Service created (type=kernel start=demand)."
    Info "Install OK. Start it with: scripts\wfp_service.ps1 start"
}

function Start-Driver {
    Info "Start: $svcName"
    $out = sc.exe start $svcName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "sc.exe start failed: $out"
        Fail "Common causes: unsigned driver (testsigning off), missing WFP callout registration,"
        Fail "or another driver holds the name. Check: wevtutil qe System /c:20 /f:text"
    }
    Start-Sleep -Seconds 1
    & Show-Status
}

function Stop-Driver {
    Info "Stop: $svcName"
    $out = sc.exe stop $svcName 2>&1
    if ($LASTEXITCODE -ne 0) { Warn "sc.exe stop: $out (may already be stopped)." }
    Start-Sleep -Seconds 1
    & Show-Status
}

function Uninstall-Driver {
    param([switch]$SkipConfirm)
    Info "Uninstall: $svcName"
    if (-not $SkipConfirm) {
        $confirm = Read-Host "Stop + remove the $svcName driver service? (y/N)"
        if ($confirm -ne 'y') { Info "Aborted by user."; return }
    }
    $null = sc.exe stop $svcName 2>&1
    Start-Sleep -Seconds 1
    $out = sc.exe delete $svcName 2>&1
    if ($LASTEXITCODE -ne 0) { Warn "sc.exe delete: $out" }
    if (Test-Path $svcBin) {
        Remove-Item $svcBin -Force -ErrorAction SilentlyContinue
        Info "Binary removed: $svcBin"
    }
    Info "Uninstall OK."
}

function Show-Status {
    $out = sc.exe query $svcName 2>&1
    if ($LASTEXITCODE -ne 0) {
        Info "Status: NOT INSTALLED"
        return
    }
    $running = ($out -match 'RUNNING').Count -gt 0
    $out | ForEach-Object { Write-Host "  $_" }
    if ($running) {
        Info "Status: RUNNING - device \\\\.\\AegisWfp should be openable."
        Info "Verify from userspace: open \\\\.\\AegisWfp and issue IOCTL_AEGIS_GET_STATS (0x801)."
    } else {
        Info "Status: INSTALLED (not running)."
    }
    if (Test-Path $svcBin) {
        $h = (Get-FileHash $svcBin -Algorithm SHA256).Hash
        Info "Binary SHA-256: $h"
    }
}

switch ($Action) {
    'install'   { Install-Driver }
    'start'     { Start-Driver }
    'stop'      { Stop-Driver }
    'status'    { Show-Status }
    'uninstall' { Uninstall-Driver }
}
exit 0
