[CmdletBinding()]
param(
    [int]$WaitSeconds = 15
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

function Invoke-AegisJson([string[]]$CliArgs, [bool]$AllowNonZero = $false, [bool]$AllowText = $false) {
    $raw = & python tools\aegisctl.py @CliArgs 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($raw -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "aegisctl returned empty output for: $($CliArgs -join ' ')"
    }
    try { $parsed = $text | ConvertFrom-Json }
    catch {
        if ($AllowText) { return $text }
        throw "aegisctl returned non-JSON output: $text"
    }
    if ($exitCode -ne 0 -and -not $AllowNonZero) {
        throw "aegisctl failed ($exitCode): $text"
    }
    return $parsed
}

function Wait-ForState([string]$Expected, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 500
        $health = Invoke-AegisJson @('health', '--json') $true
        if ($health.runtime_state -eq $Expected -or $health.state -eq $Expected) { return $health }
    } while ((Get-Date) -lt $deadline)
    return $health
}

function Wait-ForControlPipeRelease([int]$Seconds) {
    # A STOPPED diagnostic response is not sufficient: the old owner may still
    # be draining and still own \\.\pipe\aegis_control. Starting a second
    # owner in that window causes ERROR_PIPE_BUSY (231) and a false recovery
    # failure in nose_ready.
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 500
        $health = $null
        try { $health = Invoke-AegisJson @('health', '--json') $true } catch { $health = $null }
        if ($null -eq $health -or $health.runtime_available -eq $false) { return $true }
    } while ((Get-Date) -lt $deadline)
    return $false
}

Write-Host '[1/7] Checking pre-stop runtime and forensic state'
$beforeHealth = Invoke-AegisJson @('health', '--json') $true
if ($beforeHealth.runtime_state -ne 'RUNNING' -or
    $beforeHealth.state -notin @('RUNNING', 'READY', 'DEGRADED')) {
    throw "FAIL_CLOSED: daemon is not serving before lifecycle proof (runtime_state=$($beforeHealth.runtime_state), state=$($beforeHealth.state)); start 'zig build run' first"
}
if ($beforeHealth.rust_shield.state -ne 'READY' -or $beforeHealth.rust_shield.pep_ready -ne $true) {
    throw 'FAIL_CLOSED: Rust Shield/control runtime is not ready before forensic query; start zig build run and retry'
}
$beforePid = [int]$beforeHealth.pid
$beforeForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
if ($beforeForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid before lifecycle proof' }
$beforeRecords = [int64]$beforeForensic.records

Write-Host '[2/7] Requesting orderly daemon shutdown'
$stop = Invoke-AegisJson @('stop', '--all') $true $true

Write-Host '[3/7] Verifying stopped/degraded state'
$stopped = Wait-ForState 'STOPPED' $WaitSeconds
$stoppedReadiness = Invoke-AegisJson @('readiness') $true
if ($stoppedReadiness.overall_gate -eq $true) { throw 'FAIL_CLOSED: gate remained ready after shutdown' }
Write-Host "[3/7] Waiting for previous runtime process to exit (pid=$beforePid)"
$processDeadline = (Get-Date).AddSeconds($WaitSeconds)
do {
    Start-Sleep -Milliseconds 500
    $oldProcess = Get-Process -Id $beforePid -ErrorAction SilentlyContinue
    if ($null -eq $oldProcess) { break }
} while ((Get-Date) -lt $processDeadline)
if ($null -ne (Get-Process -Id $beforePid -ErrorAction SilentlyContinue)) {
    throw "FAIL_CLOSED: previous runtime process is still alive after shutdown (pid=$beforePid)"
}
if (-not (Wait-ForControlPipeRelease $WaitSeconds)) {
    throw 'FAIL_CLOSED: previous runtime owner still holds the control pipe; refusing to start a second owner'
}

Write-Host '[4/7] Starting runtime owner externally'
# daemonShutdown intentionally closes the control pipe and exits the runtime
# owner. Therefore runtime.start cannot be used after stop: there is no server
# left to receive that request. Recreate the owner process, then wait for its
# control pipe and health endpoint to become authoritative again.
$runtimeLog = Join-Path $repo '.analysis\lifecycle-restart-runtime.log'
$runtimeErr = Join-Path $repo '.analysis\lifecycle-restart-runtime.err.log'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $runtimeLog) | Out-Null
Remove-Item $runtimeLog -Force -ErrorAction SilentlyContinue
Remove-Item $runtimeErr -Force -ErrorAction SilentlyContinue
$runtimeProcess = Start-Process -FilePath 'zig' -ArgumentList @('build', 'run') -WorkingDirectory $repo -WindowStyle Hidden -RedirectStandardOutput $runtimeLog -RedirectStandardError $runtimeErr -PassThru
if ($null -eq $runtimeProcess) { throw 'FAIL_CLOSED: unable to start external runtime owner with zig build run' }

Write-Host '[5/7] Waiting for Rust Shield and workers after restart'
$afterHealth = $null
$lastCandidate = $null
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$requiredWorkers = @('pipeline_ready','sensor_ready','nose_ready','etw_ready','fim_ready','registry_ready')
do {
    Start-Sleep -Milliseconds 500
    try { $candidate = Invoke-AegisJson @('health', '--json') $true } catch { $candidate = $null }
    if ($null -ne $candidate) { $lastCandidate = $candidate }
    $workersReady = $false
    if ($null -ne $candidate -and $null -ne $candidate.workers) {
        $missingWorkers = @(
            $requiredWorkers | Where-Object {
                $property = $candidate.workers.PSObject.Properties[$_]
                $null -eq $property -or $property.Value -ne $true
            }
        )
        $workersReady = $missingWorkers.Count -eq 0
    }
    if ($null -ne $candidate -and
        $candidate.runtime_state -eq 'RUNNING' -and
        [int]$candidate.pid -ne $beforePid -and
        $candidate.rust_shield.state -eq 'READY' -and
        $workersReady) {
        $afterHealth = $candidate
        break
    }
} while ((Get-Date) -lt $deadline)
if ($null -eq $afterHealth) {
    $runtimeOutTail = if (Test-Path $runtimeLog) { (Get-Content $runtimeLog -Tail 60) -join [Environment]::NewLine } else { '<runtime stdout unavailable>' }
    $runtimeErrTail = if (Test-Path $runtimeErr) { (Get-Content $runtimeErr -Tail 40) -join [Environment]::NewLine } else { '<runtime stderr unavailable>' }
    $candidateJson = if ($null -ne $lastCandidate) { $lastCandidate | ConvertTo-Json -Depth 10 -Compress } else { '<no health candidate>' }
    throw "FAIL_CLOSED: external runtime owner did not recover within $WaitSeconds seconds`nLAST_HEALTH:`n$candidateJson`nSTDOUT:`n$runtimeOutTail`nSTDERR:`n$runtimeErrTail"
}
$afterHealth = Invoke-AegisJson @('health', '--json') $true
if ($afterHealth.rust_shield.state -ne 'READY' -or
    $afterHealth.rust_shield.pep_ready -ne $true -or
    $afterHealth.rust_shield.policy_authority -ne $true) {
    throw 'FAIL_CLOSED: Rust Shield did not recover after restart'
}
foreach ($name in @('pipeline_ready','sensor_ready','nose_ready','etw_ready','fim_ready','registry_ready')) {
    if ($afterHealth.workers.$name -ne $true) { throw "FAIL_CLOSED: worker not recovered: $name" }
}

Write-Host '[6/7] Verifying forensic chain and gate after restart'
$afterForensic = Invoke-AegisJson @('forensics', 'verify', '--json')
$afterReadiness = Invoke-AegisJson @('readiness') $true
if ($afterForensic.verified -ne $true) { throw 'FAIL_CLOSED: forensic chain invalid after restart' }
if ($afterReadiness.overall_gate -eq $true -and $afterHealth.rust_shield.host_effect_capable -ne $true) {
    throw 'FAIL_CLOSED: enforcement gate inconsistent with host-effect capability'
}

$afterRecords = [int64]$afterForensic.records
# The current forensic ring is process-local volatile state. A clean owner
# restart is therefore allowed to reset its record count; integrity and
# verification of the new generation are the acceptance properties here.
$forensicGenerationValid = ($afterForensic.verified -eq $true -and $afterForensic.integrity -eq 'ok')
$result = [ordered]@{
    proof = 'lifecycle_recovery_observe_only'
    passed = ($afterHealth.rust_shield.state -eq 'READY' -and $afterHealth.rust_shield.pep_ready -eq $true -and $forensicGenerationValid -and $afterReadiness.overall_gate -eq $false)
    before_records = $beforeRecords
    after_records = $afterRecords
    stopped_state = $stopped.state
    restarted_state = $afterHealth.state
    rust_shield_state = $afterHealth.rust_shield.state
    overall_gate = [bool]$afterReadiness.overall_gate
    host_effect_capable = [bool]$afterHealth.rust_shield.host_effect_capable
    forensic_generation_valid = $forensicGenerationValid
    forensic_record_count_reset_allowed = ($afterRecords -lt $beforeRecords)
    forensic = $afterForensic
}

Write-Host '[7/7] Lifecycle proof result'
$result | ConvertTo-Json -Depth 8
if (-not $result.passed) { exit 1 }
