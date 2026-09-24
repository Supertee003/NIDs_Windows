[CmdletBinding()]
param(
    [int]$Count = 3,
    [int]$WaitSeconds = 5
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Invoke-AegisJson([string[]]$CliArgs) {
    $raw = & python tools\aegisctl.py @CliArgs 2>&1
    if ($LASTEXITCODE -ne 0) { throw "aegisctl failed ($LASTEXITCODE): $($raw -join [Environment]::NewLine)" }
    $text = ($raw -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'aegisctl returned empty output' }
    return $text | ConvertFrom-Json
}

function Get-Number($Object, [string]$Name) {
    $value = $Object.$Name
    if ($null -eq $value) { return [int64]0 }
    return [int64]$value
}

Write-Host '[1/5] Checking runtime and Nose/pipe readiness'
$health = Invoke-AegisJson @('health', '--json')
if ($health.runtime_state -ne 'RUNNING' -or $health.degraded -ne $false) {
    throw "FAIL_CLOSED: runtime not healthy (state=$($health.runtime_state), degraded=$($health.degraded))"
}
if ($health.workers.nose_ready -ne $true) { throw 'FAIL_CLOSED: nose_ready is not true' }

$before = Invoke-AegisJson @('metrics')
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid before pipe probe' }

Write-Host "[2/5] Sending $Count benign canonical event(s) through \\.\pipe\aegis_sensor_pipe"
$generator = Join-Path $repo 'scripts\aegis_event_gen.py'
if (-not (Test-Path $generator)) { throw "missing event generator: $generator" }
& python $generator --pipe --count $Count --wait 0.2 --attack 'AEGIS_PIPE_OBSERVE_ONLY' --rule-id 'PIPE-OBSERVE-001' --severity Low --policy Alert --src-ip '192.0.2.10'
if ($LASTEXITCODE -ne 0) { throw "pipe event generator failed with exit code $LASTEXITCODE" }

Write-Host "[3/5] Waiting $WaitSeconds second(s) for pipe reader and pipeline"
Start-Sleep -Seconds $WaitSeconds
$after = Invoke-AegisJson @('metrics')
$afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')

$eventDelta = (Get-Number $after 'events_processed') - (Get-Number $before 'events_processed')
$forensicDelta = (Get-Number $after 'forensic_records') - (Get-Number $before 'forensic_records')
$blockDelta = (Get-Number $after 'blocks') - (Get-Number $before 'blocks')
$errorDelta = (Get-Number $after 'errors') - (Get-Number $before 'errors')

Write-Host '[4/5] No enforcement operations requested'
$result = [ordered]@{
    proof = 'pipe_runtime_observe_only'
    passed = ($eventDelta -gt 0 -and $forensicDelta -gt 0 -and $afterForensic.verified -eq $true -and $blockDelta -eq 0 -and $errorDelta -eq 0)
    sensor = 'canonical named pipe \\.\pipe\aegis_sensor_pipe'
    requested_events = $Count
    deltas = [ordered]@{
        events_processed = $eventDelta
        forensic_records = $forensicDelta
        blocks = $blockDelta
        errors = $errorDelta
    }
    forensic_verified = $afterForensic.verified
    host_effect = 'none'
    prevention_gate = 'closed'
    wfp_block_called = $false
    pep_called = $false
    rule_match_status = 'not_asserted_by_this_runner'
    note = 'This proves benign named-pipe ingress and pipeline processing. It does not execute named-pipe attack behavior or claim a Rule-22 match.'
}

Write-Host '[5/5] Proof result'
$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 2 }
