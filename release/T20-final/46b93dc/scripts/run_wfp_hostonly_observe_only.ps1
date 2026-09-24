[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ExpectedKaliIp,
    [int]$ListenPort = 49152,
    [int]$WaitSeconds = 30,
    [string]$ProofOutput = ''
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
if (-not $ProofOutput) { $ProofOutput = Join-Path $repo ("analysis\hostonly-wfp-" + (Get-Date -Format 'yyyyMMdd_HHmmss')) }
New-Item -ItemType Directory -Force -Path $ProofOutput | Out-Null
$ready = Join-Path $ProofOutput 'READY.txt'
$console = Join-Path $ProofOutput 'console.log'

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
