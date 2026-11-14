# One-command O2 E5 functional proof with unconditional candidate rollback.
# Run from elevated PowerShell. The child scripts preserve their own raw logs.
param(
    [string]$RemoteAddress,

    [int]$RemotePort
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

$runtime = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$candidateHash = '8B3128640C0E6F5EACB85E751471441646A350290A569ED2608757DBD84EAE4F'
$baseHash = '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61'
$evidenceDir = Join-Path $repo 'admin-evidence\e5-host-proof-20261026'
$scriptsDir = Join-Path $repo 'scripts'
$deployScript = Join-Path $scriptsDir 'e5_o2_deploy_candidate.ps1'
$directionScript = Join-Path $scriptsDir 'e5_o2_direction_verified.ps1'
$rollbackScript = Join-Path $scriptsDir 'e5_o2_rollback_candidate.ps1'
$childPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $evidenceDir "e5d-o2-functional-$stamp.log"
$resultPath = Join-Path $evidenceDir "e5d-o2-functional-$stamp.json"
$startAt = Get-Date
$directionFilesBefore = @(
    Get-ChildItem -LiteralPath $evidenceDir -Filter 'e5d-o2-direction-*.json' -File -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
)

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function Invoke-ChildScript([string]$Path, [string[]]$ExtraArguments = @()) {
    $child = Start-Process -FilePath $childPowerShell `
        -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $Path)) + $ExtraArguments) `
        -PassThru -NoNewWindow
    # Process.WaitForExit waits only for this PowerShell child. Start-Process
    # -Wait also waits for descendant processes such as the intentionally
    # persistent Nose process that the direction proof restarts.
    $child.WaitForExit()
    $child.Refresh()
    return [int]$child.ExitCode
}
function Invoke-JsonCommand([string[]]$Command) {
    $raw = & python @Command 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    if ($start -lt 0) { throw "No JSON response from $($Command -join ' '):`n$raw" }
    return ($raw.Substring($start) | ConvertFrom-Json)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this orchestration from elevated PowerShell.'
}
if ((Get-Sha256 (Join-Path $repo 'zig-out\bin\aegis_nids.exe')) -ne $candidateHash) {
    throw 'Workspace candidate hash does not match the E5-pinned candidate.'
}
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
Start-Transcript -Path $transcript -Force | Out-Null

$deployExit = $null
$directionExit = $null
$rollbackExit = $null
$directionJson = $null
$directionPath = $null
$errorText = $null
$rollbackVerified = $false
$gateAfter = $null
$forensicAfter = $null

try {
    $deployExit = Invoke-ChildScript $deployScript
    if ($deployExit -ne 0) { throw "Candidate deployment helper exited $deployExit." }

    $directionArgs = @()
    if ($RemoteAddress) {
        if ($RemotePort -lt 1) { throw 'Remote mode requires a valid -RemotePort.' }
        $directionArgs = @('-RemoteAddress', $RemoteAddress, '-RemotePort', [string]$RemotePort)
    }
    $directionExit = Invoke-ChildScript $directionScript $directionArgs
    $directionFiles = @(
        Get-ChildItem -LiteralPath $evidenceDir -Filter 'e5d-o2-direction-*.json' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notin $directionFilesBefore -and $_.LastWriteTime -ge $startAt } |
            Sort-Object LastWriteTime -Descending
    )
    if ($directionFiles.Count -gt 0) {
        $directionPath = $directionFiles[0].FullName
        $directionJson = Get-Content -LiteralPath $directionPath -Raw | ConvertFrom-Json
    }
    if ($directionExit -ne 0) { throw "Outbound direction proof exited $directionExit." }
    if (-not $directionJson -or $directionJson.gate -ne $true) { throw 'Outbound direction proof did not report gate=true.' }
} catch {
    $errorText = $_.Exception.Message
    Write-Warning $errorText
} finally {
    try {
        $currentHash = Get-Sha256 $runtime
        if ($currentHash -eq $candidateHash) {
            $rollbackExit = Invoke-ChildScript $rollbackScript
            if ($rollbackExit -ne 0) { throw "Rollback helper exited $rollbackExit." }
        } elseif ($currentHash -ne $baseHash) {
            throw "Unexpected runtime hash $currentHash; refusing to overwrite it during rollback."
        }
        $gateAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
        $forensicAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify')
        $rollbackVerified = (Get-Sha256 $runtime) -eq $baseHash -and
            (Get-Service AegisNids).Status.ToString() -eq 'Running' -and
            (Get-Service AegisWfp).Status.ToString() -eq 'Running' -and
            $gateAfter.prevention_gate -eq 'closed' -and -not $gateAfter.host_effect_capable -and
            $forensicAfter.verified -eq $true
        if (-not $rollbackVerified) { throw 'Post-proof rollback/service/gate/forensic verification failed.' }
    } catch {
        $rollbackError = $_.Exception.Message
        $errorText = if ($errorText) { "$errorText; rollback verification: $rollbackError" } else { "rollback verification: $rollbackError" }
        Write-Warning $errorText
    }

    $result = [ordered]@{
        started_at = $startAt.ToString('o')
        candidate_sha256 = $candidateHash
        base_sha256 = $baseHash
        deploy_exit_code = $deployExit
        direction_exit_code = $directionExit
        direction_result_json = $directionPath
        direction_gate = if ($directionJson) { $directionJson.gate } else { $false }
        direction_error = if ($directionJson) { $directionJson.error } else { $errorText }
        rollback_exit_code = $rollbackExit
        rollback_verified = $rollbackVerified
        prevention_gate_after = if ($gateAfter) { $gateAfter.prevention_gate } else { $null }
        forensic_verified_after = if ($forensicAfter) { $forensicAfter.verified } else { $false }
        diagnostic_error = $errorText
        transcript = $transcript
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Host "RESULT direction_gate=$($result.direction_gate) rollback=$rollbackVerified result=$resultPath"
    Stop-Transcript | Out-Null
}

if (-not $rollbackVerified -or -not $directionJson -or $directionJson.gate -ne $true) { exit 1 }
