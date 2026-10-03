[CmdletBinding()]
param(
    [string]$EvidenceDir = ""
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
    $EvidenceDir = Join-Path $repo ("admin-evidence\project2-runtime-gate-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Invoke-AegisJson {
    param([string[]]$Arguments, [string]$Name)
    $raw = (& python (Join-Path $repo "tools\aegisctl.py") @Arguments 2>&1 | Out-String).Trim()
    $exitCode = $LASTEXITCODE
    $path = Join-Path $EvidenceDir "$Name.raw.txt"
    Set-Content -Path $path -Value $raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "$Name returned empty output (exit=$exitCode)"
    }
    try {
        $json = $raw | ConvertFrom-Json
    } catch {
        throw "$Name returned non-JSON output (exit=$exitCode): $raw"
    }
    $json | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $EvidenceDir "$Name.json") -Encoding UTF8
    return [pscustomobject]@{ Json = $json; ExitCode = $exitCode }
}

$healthResult = Invoke-AegisJson @("health", "--json") "health"
$readinessResult = Invoke-AegisJson @("readiness", "--pretty") "readiness"
$snapshotResult = Invoke-AegisJson @("snapshot") "snapshot"
$enforceResult = Invoke-AegisJson @("enforce", "status") "enforce-status"

$health = $healthResult.Json
$readiness = $readinessResult.Json
$snapshot = $snapshotResult.Json
$enforce = $enforceResult.Json
$failures = [System.Collections.Generic.List[string]]::new()
$missingReadiness = @($readiness.missing | Where-Object { $null -ne $_ -and "$($_)".Length -gt 0 })
$contractErrors = @($snapshot.presentation.contract_errors | Where-Object { $null -ne $_ -and "$($_)".Length -gt 0 })

if ($health.state -ne "RUNNING") { $failures.Add("health.state=$($health.state)") }
if ($health.degraded -ne $false) { $failures.Add("health.degraded=$($health.degraded)") }
if ([int]$health.rules_loaded -ne 22) { $failures.Add("health.rules_loaded=$($health.rules_loaded), expected 22") }
if ($readiness.ready -ne $true) { $failures.Add("readiness.ready=$($readiness.ready)") }
if ($readiness.overall_gate -ne $true) { $failures.Add("readiness.overall_gate=$($readiness.overall_gate)") }
if ($missingReadiness.Count -ne 0) { $failures.Add("readiness.missing=$($missingReadiness -join ',')") }
if ($snapshot.enforcement.enforcement_mode -ne "detection-only") { $failures.Add("enforcement_mode=$($snapshot.enforcement.enforcement_mode)") }
if ($snapshot.enforcement.prevention_gate -ne "closed") { $failures.Add("prevention_gate=$($snapshot.enforcement.prevention_gate)") }
if ($snapshot.enforcement.tier3_enforcing -eq $true) { $failures.Add("tier3_enforcing=true") }
if ($contractErrors.Count -ne 0) { $failures.Add("presentation.contract_errors=$($contractErrors -join ',')") }
if ($snapshot.presentation.host_effect -eq "CONFIRMED") { $failures.Add("host_effect incorrectly CONFIRMED in Project 2") }
if ($snapshot.forensic.verified -ne $true) { $failures.Add("forensic.verified=$($snapshot.forensic.verified)") }
if ($health.workers.nose_ready -ne $true) { $failures.Add("workers.nose_ready=$($health.workers.nose_ready)") }
if ($health.data_plane.nose_connected -ne $true) { $failures.Add("data_plane.nose_connected=$($health.data_plane.nose_connected)") }
if ($enforce.prevention_gate -ne "closed") { $failures.Add("enforce.status prevention_gate=$($enforce.prevention_gate)") }

$result = [ordered]@{
    proof = "project2_runtime_gate"
    passed = ($failures.Count -eq 0)
    evidence_dir = $EvidenceDir
    runtime_state = $health.state
    rules_loaded = [int]$health.rules_loaded
    policies_loaded = [int]$health.policies_loaded
    readiness = [bool]$readiness.ready
    forensic_verified = [bool]$snapshot.forensic.verified
    nose_ready = [bool]$health.workers.nose_ready
    nose_connected = [bool]$health.data_plane.nose_connected
    prevention_gate = $snapshot.enforcement.prevention_gate
    enforcement_mode = $snapshot.enforcement.enforcement_mode
    failures = @($failures)
}
$result | ConvertTo-Json -Depth 10 | Tee-Object -FilePath (Join-Path $EvidenceDir "result.json")

if ($failures.Count -gt 0) {
    throw ("PROJECT2_RUNTIME_GATE_FAIL: " + ($failures -join "; "))
}
Write-Host "PROJECT2_RUNTIME_GATE=PASS"
