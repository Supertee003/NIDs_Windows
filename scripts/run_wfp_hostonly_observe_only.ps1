[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpectedKaliIp,
    [string]$ExpectedVictimIp = '192.168.126.20',
    [string]$ExpectedNidsIp = '192.168.126.1',
    [int]$ListenPort = 49152,
    [int]$WaitSeconds = 30,
    [string]$ProofOutput = '',
    [switch]$RequireCurrentSource
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
if (-not $ProofOutput) { $ProofOutput = Join-Path $repo ("analysis\hostonly-wfp-" + (Get-Date -Format 'yyyyMMdd_HHmmss')) }
New-Item -ItemType Directory -Force -Path $ProofOutput | Out-Null
$ready = Join-Path $ProofOutput 'READY.txt'
$console = Join-Path $ProofOutput 'console.log'

if ($RequireCurrentSource) {
    $preflight = Join-Path $repo 'scripts\rb021_current_source_preflight.ps1'
    Write-Host 'Running RB-021 current-source preflight before opening the listener.'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $preflight `
        -ExpectedKaliIp $ExpectedKaliIp `
        -ExpectedVictimIp $ExpectedVictimIp `
        -ExpectedNidsIp $ExpectedNidsIp `
        -ProofOutput (Join-Path $ProofOutput 'preflight')
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'RB-021 stopped before canary: current-source preflight did not pass.'
        Write-Host "Evidence directory: $ProofOutput"
        exit $LASTEXITCODE
    }
}

Write-Host "Starting WFP collector before waiting for Kali probe."
Write-Host "Expected Kali IP: $ExpectedKaliIp"
Write-Host "Listen port: $ListenPort"

$args = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
    (Join-Path $repo 'scripts\run_wfp_l4_observe_only_proof.ps1'),
    '-WaitSeconds', [string]$WaitSeconds,
    '-ExpectedSourceIp', $ExpectedKaliIp,
    '-ExpectedDestPort', [string]$ListenPort,
    '-RequireExpectedFlow',
    '-ExternalListenPort', [string]$ListenPort,
    '-ReadyFile', $ready
)
$raw = & powershell.exe @args 2>&1
$raw | Tee-Object -FilePath $console
if ($LASTEXITCODE -ne 0) {
    Write-Error "WFP host-only observe-only proof failed with exit code $LASTEXITCODE"
    Write-Host "Evidence directory: $ProofOutput"
    exit $LASTEXITCODE
}
Write-Host "Evidence directory: $ProofOutput"
Write-Host "Ready marker: $ready"
