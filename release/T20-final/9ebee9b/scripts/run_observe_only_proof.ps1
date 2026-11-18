[CmdletBinding()]
param(
    [int]$Count = 1,
    [string]$Pipe = '\\.\pipe\aegis_nose',
    [int]$WaitSeconds = 10
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Invoke-AegisJson([string[]]$CliArgs, [bool]$AllowNonZero = $false) {
    $raw = & python tools\aegisctl.py @CliArgs 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0 -and -not $AllowNonZero) {
        throw "aegisctl failed ($LASTEXITCODE): $($raw -join [Environment]::NewLine)"
    }
    $text = ($raw -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'aegisctl returned empty output' }
    try { return $text | ConvertFrom-Json }
    catch { throw "aegisctl returned non-JSON output: $text" }
}

Write-Host '[1/5] Checking observe-only runtime prerequisites'
$health = Invoke-AegisJson @('health', '--json') $true
$readiness = Invoke-AegisJson @('readiness') $true

if ($health.rust_shield.state -ne 'READY' -or
    $health.rust_shield.pep_ready -ne $true -or
    $health.rust_shield.policy_authority -ne $true) {
    throw "FAIL_CLOSED: Rust Shield is not ready/authoritative"
}
# Provider readiness/capability is not an enforcement attempt.  Observe-only
# must be runnable against a fully attested runtime so it can prove that the
# event/forensic path does not mutate the host.  The prevention gate and the
# post-run block delta are the safety boundaries.  In aegisctl, overall_gate
# means runtime readiness (workers/health), not permission to mutate the host;
# observe-only therefore requires it to be true before injecting events.
if ($readiness.overall_gate -ne $true) {
    throw 'FAIL_CLOSED: runtime readiness gate is not ready for observe-only proof'
}
foreach ($name in @('pipeline_ready','sensor_ready','nose_ready','etw_ready','fim_ready','registry_ready')) {
    if ($health.workers.$name -ne $true) { throw "FAIL_CLOSED: worker not ready: $name" }
}

Write-Host '[2/5] Taking pre-injection metrics and forensic snapshot'
$before = Invoke-AegisJson @('metrics')
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain is not verified before injection' }

$nose = Join-Path $repo 'dist\aegis-nose.exe'
if (-not (Test-Path $nose)) { throw "Missing Nose binary: $nose" }

Write-Host "[3/5] Sending $Count canonical observe-only event(s) through $Pipe"
& $nose -inject-observe -inject-count $Count -pipe $Pipe
if ($LASTEXITCODE -ne 0) { throw "FAIL_CLOSED: observe injector exit code $LASTEXITCODE" }

Write-Host "[4/5] Waiting up to $WaitSeconds seconds for Core processing"
$after = $null
$afterForensic = $null
$processedDelta = 0
$forensicDelta = 0
$deadline = (Get-Date).AddSeconds($WaitSeconds)
do {
    Start-Sleep -Milliseconds 250
    $after = Invoke-AegisJson @('metrics')
    $afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
    $processedDelta = [int64]$after.events_processed - [int64]$before.events_processed
    $forensicDelta = [int64]$after.forensic_records - [int64]$before.forensic_records
    if ($processedDelta -ge $Count -and $forensicDelta -ge $Count) { break }
} while ((Get-Date) -lt $deadline)

$blockDelta = [int64]$after.blocks - [int64]$before.blocks
$errorDelta = [int64]$after.errors - [int64]$before.errors

$result = [ordered]@{
    proof = 'canonical_observe_only'
    passed = ($processedDelta -ge $Count -and $forensicDelta -ge $Count -and $afterForensic.verified -eq $true -and $blockDelta -eq 0 -and $errorDelta -eq 0)
    requested = $Count
    health_state = $health.state
    rust_shield_state = $health.rust_shield.state
    runtime_readiness = [bool]$readiness.overall_gate
    host_effect_capable = [bool]$health.rust_shield.host_effect_capable
    deltas = [ordered]@{
        events_processed = $processedDelta
        forensic_records = $forensicDelta
        blocks = $blockDelta
        errors = $errorDelta
    }
    forensic = $afterForensic
}

Write-Host '[5/5] Observe-only proof result'
$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 1 }
