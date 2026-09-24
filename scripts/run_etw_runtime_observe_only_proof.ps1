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

Write-Host '[1/5] Checking runtime and ETW readiness'
$health = Invoke-AegisJson @('health', '--json')
if ($health.state -ne 'RUNNING') {
    throw "FAIL_CLOSED: runtime state=$($health.state), degraded=$($health.degraded)"
}
if ($health.workers.etw_ready -ne $true) { throw 'FAIL_CLOSED: etw_ready is not true' }

$before = Invoke-AegisJson @('metrics')
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid before ETW probe' }

Write-Host "[2/5] Starting $Count harmless child process event(s)"
for ($i = 0; $i -lt $Count; $i++) {
    $p = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'exit', '0') -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) { throw "harmless child process returned $($p.ExitCode)" }
}

Write-Host "[3/5] Waiting $WaitSeconds second(s) for ETW callback and pipeline"
Start-Sleep -Seconds $WaitSeconds
$after = Invoke-AegisJson @('metrics')
$afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')

$eventDelta = (Get-Number $after 'events_processed') - (Get-Number $before 'events_processed')
$forensicDelta = (Get-Number $after 'forensic_records') - (Get-Number $before 'forensic_records')
$blockDelta = (Get-Number $after 'blocks') - (Get-Number $before 'blocks')
$errorDelta = (Get-Number $after 'errors') - (Get-Number $before 'errors')

Write-Host '[4/5] No enforcement operations requested'
$result = [ordered]@{
    proof = 'etw_runtime_observe_only'
    passed = ($eventDelta -gt 0 -and $forensicDelta -gt 0 -and $afterForensic.verified -eq $true -and $blockDelta -eq 0 -and $errorDelta -eq 0)
    sensor = 'Windows ETW kernel process provider'
    requested_process_events = $Count
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
    note = 'This uses only harmless cmd.exe child processes. Rule-specific process qualification requires matched_rule_id and canonical ETW provenance.'
}

Write-Host '[5/5] Proof result'
$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 2 }
