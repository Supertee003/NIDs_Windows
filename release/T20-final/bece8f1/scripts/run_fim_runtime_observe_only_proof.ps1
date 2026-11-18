[CmdletBinding()]
param(
    [string]$ProofRoot = "$env:TEMP\aegis-fim-runtime-proof-$PID",
    [int]$WaitSeconds = 5,
    [switch]$KeepFixture
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

New-Item -ItemType Directory -Force -Path $ProofRoot | Out-Null
$marker = Join-Path $ProofRoot 'AEGIS_FIM_RUNTIME_OBSERVE_ONLY.marker.txt'
$renamed = Join-Path $ProofRoot 'AEGIS_FIM_RUNTIME_OBSERVE_ONLY.renamed.txt'

Write-Host '[1/6] Checking FIM proof-root contract'
if ($env:AEGIS_FIM_PROOF_ROOT -ne $ProofRoot) {
    throw "FAIL_CLOSED: daemon must be started with AEGIS_FIM_PROOF_ROOT=$ProofRoot"
}

Write-Host '[2/6] Checking runtime health and FIM readiness'
$health = Invoke-AegisJson @('health', '--json')
if ($health.state -ne 'RUNNING') { throw "FAIL_CLOSED: runtime state=$($health.state)" }
if ($health.workers.fim_ready -ne $true) { throw 'FAIL_CLOSED: fim_ready is not true' }

$before = Invoke-AegisJson @('metrics')
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid before fixture' }

Write-Host '[3/6] Creating benign disposable FIM fixture'
[IO.File]::WriteAllText($marker, "AEGIS FIM runtime observe-only $(Get-Date -Format o)", [Text.Encoding]::UTF8)
Start-Sleep -Milliseconds 700
[IO.File]::AppendAllText($marker, "`nmodified observe-only", [Text.Encoding]::UTF8)
Start-Sleep -Milliseconds 700
Move-Item -Force $marker $renamed
Start-Sleep -Seconds $WaitSeconds

Write-Host '[4/6] Checking fixture and runtime deltas'
if (-not (Test-Path $renamed)) { throw 'fixture rename did not complete' }
$hash = (Get-FileHash -Algorithm SHA256 $renamed).Hash
$after = Invoke-AegisJson @('metrics')
$afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')

$eventDelta = (Get-Number $after 'events_processed') - (Get-Number $before 'events_processed')
$forensicDelta = (Get-Number $after 'forensic_records') - (Get-Number $before 'forensic_records')
$blockDelta = (Get-Number $after 'blocks') - (Get-Number $before 'blocks')
$errorDelta = (Get-Number $after 'errors') - (Get-Number $before 'errors')

Write-Host '[5/6] No enforcement operations requested'
$result = [ordered]@{
    proof = 'fim_runtime_observe_only'
    # This proof requires real FIM processing and forensic progress, but does
    # not claim a rule match unless a canonical record exposes matched_rule_id.
    passed = ($eventDelta -gt 0 -and $forensicDelta -gt 0 -and $afterForensic.verified -eq $true -and $blockDelta -eq 0 -and $errorDelta -eq 0)
    sensor = 'ReadDirectoryChangesW via aegis_fim_helper'
    proof_root = $ProofRoot
    fixture = $renamed
    fixture_sha256 = $hash
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
    note = 'Real FIM pipeline progress is proven only when metrics and forensic deltas are positive. Rule-specific qualification requires matched_rule_id in a canonical event.'
}

Write-Host '[6/6] Proof result'
$result | ConvertTo-Json -Depth 8
if (-not $KeepFixture) { Remove-Item -Force $renamed -ErrorAction SilentlyContinue }
if (-not $result.passed) { exit 2 }
