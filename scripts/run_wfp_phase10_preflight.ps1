[CmdletBinding()]
param(
    [int]$HealthRetries = 3,
    [int]$RetryDelaySeconds = 1
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Get-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw 'health returned empty output'
    }
    try { $health = $text | ConvertFrom-Json }
    catch { throw "health returned non-JSON output: $text" }
    if ($exitCode -ne 0 -and $health.runtime_available -ne $false) {
        throw "health failed ($exitCode): $text"
    }
    return $health
}

$isAdmin = Get-IsAdministrator
$serviceText = @(sc.exe query AegisWfp 2>&1)
$serviceExit = $LASTEXITCODE
$serviceInstalled = $serviceExit -eq 0
$serviceRunning = $serviceInstalled -and (($serviceText -join "`n") -match 'STATE\s+:\s+\d+\s+RUNNING')

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

$result = [ordered]@{
    proof = 'phase10_wfp_preflight_read_only'
    passed = $false
    administrator = $isAdmin
    service_name = 'AegisWfp'
    service_installed = $serviceInstalled
    service_running = $serviceRunning
    device_contract = '\\.\AegisWfpDevice'
    device_attested = $false
    health_available = $null -ne $health
    health_error = $healthError
    tier3_ready = $false
    pep_ready = $false
    provider_ready = $false
    host_effect_capable = $false
    overall_gate = $false
    enforcement_attempted = $false
    next_step = 'No host effect attempted; inspect service/device contract and build an isolated reversible proof only after provider readiness is attested.'
}

if ($null -ne $health) {
    $result.tier3_ready = [bool]$health.tier3.ready
    $result.pep_ready = [bool]$health.rust_shield.pep_ready
    $result.provider_ready = [bool]$health.rust_shield.provider_ready
    $result.host_effect_capable = [bool]$health.rust_shield.host_effect_capable
    $result.overall_gate = [bool]$health.rust_shield.host_effect_capable -and [bool]$health.tier3.provider_ready
    $result.passed = $isAdmin -and $health.runtime_state -eq 'RUNNING' -and $result.tier3_ready -and $result.pep_ready -and -not $result.overall_gate
}

$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 1 }
