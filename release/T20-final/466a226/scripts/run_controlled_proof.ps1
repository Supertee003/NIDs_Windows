[CmdletBinding()]
param(
    [int]$Count = 1,
    [string]$Pipe = '\\.\pipe\aegis_nose'
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Invoke-AegisJson([string[]]$CliArgs) {
    $raw = & python tools\aegisctl.py @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "aegisctl failed ($LASTEXITCODE): $($raw -join [Environment]::NewLine)"
    }
    $text = ($raw -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'aegisctl returned empty output' }
    try { return $text | ConvertFrom-Json }
    catch { throw "aegisctl returned non-JSON output: $text" }
}

Write-Host '[1/4] Checking runtime health'
$health = Invoke-AegisJson @('health', '--json')
if ($health.state -ne 'RUNNING' -or $health.degraded -ne $false) {
    throw "FAIL_CLOSED: daemon is not healthy (state=$($health.state), degraded=$($health.degraded))"
}
$workers = $health.workers
foreach ($name in @('pipeline_ready','sensor_ready','nose_ready','etw_ready','fim_ready','registry_ready')) {
    if ($workers.$name -ne $true) { throw "FAIL_CLOSED: worker not ready: $name" }
}

Write-Host '[2/4] Taking pre-injection metrics and forensic snapshot'
$before = Invoke-AegisJson @('metrics')
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain is not verified before injection' }

$nose = Join-Path $repo 'dist\aegis-nose.exe'
if (-not (Test-Path $nose)) { throw "Missing Nose binary: $nose" }

Write-Host "[3/4] Sending $Count canonical observe-only event(s) through $Pipe"
& $nose -inject-observe -inject-count $Count -pipe $Pipe
if ($LASTEXITCODE -ne 0) { throw "FAIL_CLOSED: observe injector exit code $LASTEXITCODE" }

Write-Host '[4/4] Taking post-injection metrics and forensic snapshot'
$after = Invoke-AegisJson @('metrics')
$afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')

$processedDelta = [int64]$after.events_processed - [int64]$before.events_processed
$forensicDelta = [int64]$after.forensic_records - [int64]$before.forensic_records
$packetDelta = [int64]$after.packets_captured - [int64]$before.packets_captured
$blockDelta = [int64]$after.blocks - [int64]$before.blocks
$errorDelta = [int64]$after.errors - [int64]$before.errors

$result = [ordered]@{
    proof = 'canonical_observe_only'
    passed = ($processedDelta -ge $Count -and $forensicDelta -ge $Count -and $afterForensic.verified -eq $true -and $blockDelta -eq 0 -and $errorDelta -eq 0)
    requested = $Count
    deltas = [ordered]@{
        packets_captured = $packetDelta
        events_processed = $processedDelta
        forensic_records = $forensicDelta
        blocks = $blockDelta
        errors = $errorDelta
    }
    forensic = $afterForensic
}
$result | ConvertTo-Json -Depth 6
if (-not $result.passed) { exit 1 }
