[CmdletBinding()]
param(
    [int]$HealthRetries = 3,
    [int]$RetryDelaySeconds = 1
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Get-Health {
    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath 'python' -ArgumentList @('tools\aegisctl.py', 'health', '--json') -WorkingDirectory $repo -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
        if (-not $process.WaitForExit(5000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw 'health query timed out after 5 seconds'
        }
        $exitCode = $process.ExitCode
        $text = ((Get-Content $stdout -Raw -ErrorAction SilentlyContinue) + (Get-Content $stderr -Raw -ErrorAction SilentlyContinue)).Trim()
    } finally {
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
    }
    if ([string]::IsNullOrWhiteSpace($text)) { throw 'health returned empty output' }
    try { $health = $text | ConvertFrom-Json }
    catch { throw "health returned non-JSON output: $text" }
    if ($exitCode -ne 0 -and $health.runtime_available -ne $false) {
        throw "health failed ($exitCode): $text"
    }
    return $health
}

function Test-RequiredPath([string]$RelativePath) {
    return Test-Path (Join-Path $repo $RelativePath)
}

$health = $null
$healthError = $null
for ($i = 0; $i -lt [Math]::Max(1, $HealthRetries); $i++) {
    try {
        $health = Get-Health
        if ($null -ne $health) { break }
    } catch {
        $healthError = $_.Exception.Message
        if ($i + 1 -lt $HealthRetries) { Start-Sleep -Seconds $RetryDelaySeconds }
    }
}

$requiredWorkers = @('pipeline_ready','sensor_ready','nose_ready','etw_ready','fim_ready','registry_ready')
$workerResults = [ordered]@{}
foreach ($name in $requiredWorkers) {
    $workerResults[$name] = $null -ne $health -and $null -ne $health.workers -and $health.workers.$name -eq $true
}
$workersReady = $workerResults.Values -notcontains $false

$requiredPaths = @(
    'configs\policies.json',
    'runtime_manifest.json',
    'inventory.json',
    'reference_map.json',
    'scripts\run_lifecycle_recovery_proof.ps1',
    'scripts\run_wfp_phase10_preflight.ps1'
)
$pathResults = [ordered]@{}
foreach ($path in $requiredPaths) { $pathResults[$path] = Test-RequiredPath $path }
$pathsReady = $pathResults.Values -notcontains $false

$forensic = $null
$forensicError = $null
try {
    $stdout = [IO.Path]::GetTempFileName()
    $stderr = [IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath 'python' -ArgumentList @('tools\aegisctl.py', 'forensics', 'verify', '--json') -WorkingDirectory $repo -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    if (-not $process.WaitForExit(5000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'forensic verification timed out after 5 seconds'
    }
    $text = ((Get-Content $stdout -Raw -ErrorAction SilentlyContinue) + (Get-Content $stderr -Raw -ErrorAction SilentlyContinue)).Trim()
    $forensic = $text | ConvertFrom-Json
} catch { $forensicError = $_.Exception.Message }
finally { Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue }

$gateClosed = $null -ne $health -and [bool]$health.rust_shield.host_effect_capable -eq $false -and [bool]$health.tier3.provider_ready -eq $false
$runtimeReady = $null -ne $health -and $health.runtime_state -eq 'RUNNING'
$pepReady = $null -ne $health -and [bool]$health.rust_shield.pep_ready
$tier3Ready = $null -ne $health -and [bool]$health.tier3.ready

$result = [ordered]@{
    proof = 'host_production_preflight_read_only'
    passed = $runtimeReady -and $pepReady -and $tier3Ready -and $workersReady -and $pathsReady -and $gateClosed -and $null -ne $forensic -and $forensic.verified -eq $true
    runtime_available = $null -ne $health
    runtime_state = if ($null -ne $health) { $health.runtime_state } else { $null }
    health_state = if ($null -ne $health) { $health.state } else { $null }
    health_error = $healthError
    pep_ready = $pepReady
    tier3_ready = $tier3Ready
    workers = $workerResults
    workers_ready = $workersReady
    required_paths = $pathResults
    paths_ready = $pathsReady
    forensic_verified = $null -ne $forensic -and $forensic.verified -eq $true
    forensic_integrity = if ($null -ne $forensic) { $forensic.integrity } else { $null }
    forensic_error = $forensicError
    provider_ready = if ($null -ne $health) { [bool]$health.rust_shield.provider_ready } else { $false }
    host_effect_capable = if ($null -ne $health) { [bool]$health.rust_shield.host_effect_capable } else { $false }
    overall_gate = if ($null -ne $health) { [bool]$health.rust_shield.host_effect_capable -and [bool]$health.tier3.provider_ready } else { $false }
    production_attested = $false
    attack_attempted = $false
    enforcement_attempted = $false
    next_step = 'Run Windows build/tests and lifecycle proof. Production attestation remains false until isolated WFP host-effect and cleanup proofs pass.'
}

$result | ConvertTo-Json -Depth 10
if (-not $result.passed) { exit 1 }
