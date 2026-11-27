# Deploy a pinned, signed AEGIS WFP driver on this lab host.
#
# The operator must supply the exact signed candidate hash (from
# scripts/sign_wfp_driver_20261024.ps1) and the exact hash of the currently
# loaded driver. Both are checked before anything is stopped. A fresh,
# uniquely named backup is created and hash-verified; every failure path
# restores that backup and verifies the restored hash before restarting.
#
# Requires Administrator and a running AegisNids + AegisWfp stack.
#
# Usage (elevated):
#   powershell -NoProfile -ExecutionPolicy Bypass -File `
#     scripts/deploy_wfp_driver_20261024.ps1 `
#     -ExpectedCandidateSha256 <signed-sha256> `
#     -ExpectedBackupSha256 <loaded-sha256>

param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedCandidateSha256,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedBackupSha256,

    [string]$ExpectedSignerThumbprint = "00E92849867308596564D134BB981EF726798E97",

    [string]$OutDir = "admin-evidence\g2-dupfilter-20261024"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

$src = Join-Path $repo "build\x64\wfp\aegis_wfp.sys"
$dst = Join-Path $env:SystemRoot "System32\drivers\aegis_wfp.sys"
$out = if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $OutDir
} else {
    Join-Path $repo $OutDir
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "deploy requires an elevated Administrator shell"
}

function Wait-ServiceState {
    param([string]$Name, [string]$Desired, [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq $Desired) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Record-Service {
    param([string]$Name, [string]$Path)
    & sc.exe qc $Name 2>&1 | Out-File -FilePath $Path -Encoding utf8
    & sc.exe query $Name 2>&1 |
        Out-File -FilePath $Path -Encoding utf8 -Append
}

function Assert-Running {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { throw "service not found: $Name" }
    if ($svc.Status -ne "Running") {
        throw "service $Name is $($svc.Status), expected Running"
    }
}

# ── Preflight: nothing is stopped until every pin matches. ─────────────
if (-not (Test-Path $src)) { throw "candidate driver not found: $src" }
if (-not (Test-Path $dst)) { throw "installed driver not found: $dst" }

$srcHash = Get-Sha256 $src
$dstHash = Get-Sha256 $dst
if ($srcHash -ne $ExpectedCandidateSha256.ToUpperInvariant()) {
    throw "candidate hash mismatch: $srcHash != $ExpectedCandidateSha256"
}
if ($dstHash -ne $ExpectedBackupSha256.ToUpperInvariant()) {
    throw "installed driver hash mismatch: $dstHash != $ExpectedBackupSha256"
}

$srcSig = Get-AuthenticodeSignature $src
if ($srcSig.Status -ne "Valid") {
    throw "candidate driver signature is $($srcSig.Status), not Valid"
}
if ($null -eq $srcSig.SignerCertificate -or
    $srcSig.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint) {
    throw "candidate signed by unexpected certificate: $($srcSig.SignerCertificate.Thumbprint)"
}

Assert-Running "AegisNids"
Assert-Running "AegisWfp"

New-Item -ItemType Directory -Force -Path $out | Out-Null
$backup = Join-Path $out (
    "aegis_wfp.sys.before-{0}-{1}" -f
        (Get-Date -Format "yyyyMMdd-HHmmss"),
        ([guid]::NewGuid().ToString("N").Substring(0, 8))
)
Copy-Item $dst $backup -Force
$backupHash = Get-Sha256 $backup
if ($backupHash -ne $ExpectedBackupSha256.ToUpperInvariant()) {
    throw "backup hash mismatch: $backupHash != $ExpectedBackupSha256"
}

Record-Service "AegisNids" (Join-Path $out "service-before.txt")
Record-Service "AegisWfp" (Join-Path $out "driver-before.txt")

$result = [ordered]@{
    started_at = (Get-Date).ToString("o")
    candidate_path = $src
    candidate_sha256 = $srcHash
    candidate_signature = [string]$srcSig.Status
    candidate_signer = $srcSig.SignerCertificate.Thumbprint
    previous_sha256 = $dstHash
    backup_path = $backup
    backup_sha256 = $backupHash
    daemon_stop_requested = $false
    driver_stopped = $false
    driver_touched = $false
    driver_replaced = $false
    driver_started = $false
    daemon_started = $false
    readiness = $null
    rollback = $false
    rollback_verified = $false
    error = $null
}

try {
    $stopOut = Join-Path $out "daemon-stop.out"
    $stopErr = Join-Path $out "daemon-stop.err"
    $proc = Start-Process -FilePath "python" `
        -ArgumentList @("tools/aegisctl.py", "stop", "--all") `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $stopOut -RedirectStandardError $stopErr
    if (-not $proc.WaitForExit(20000)) {
        $proc.Kill()
        throw "aegisctl stop timed out; driver left untouched"
    }
    $result.daemon_stop_requested = $true
    if (-not (Wait-ServiceState "AegisNids" "Stopped" 30)) {
        throw "AegisNids did not reach Stopped; driver left untouched"
    }

    & sc.exe stop AegisWfp 2>&1 |
        Out-File (Join-Path $out "driver-stop.txt") -Encoding utf8
    if (-not (Wait-ServiceState "AegisWfp" "Stopped" 20)) {
        throw "AegisWfp did not reach Stopped; driver binary not replaced"
    }
    $result.driver_stopped = $true

    # From here on a failed copy still requires restoring the verified backup.
    $result.driver_touched = $true
    Copy-Item $src $dst -Force
    $afterHash = Get-Sha256 $dst
    if ($afterHash -ne $srcHash) {
        throw "copied driver hash mismatch: $afterHash != $srcHash"
    }
    $result.driver_replaced = $true

    & sc.exe start AegisWfp 2>&1 |
        Out-File (Join-Path $out "driver-start.txt") -Encoding utf8
    if (-not (Wait-ServiceState "AegisWfp" "Running" 20)) {
        throw "AegisWfp did not reach Running after the swap"
    }
    $result.driver_started = $true
    Assert-Running "AegisWfp"

    & sc.exe start AegisNids 2>&1 |
        Out-File (Join-Path $out "daemon-start.txt") -Encoding utf8
    if (-not (Wait-ServiceState "AegisNids" "Running" 30)) {
        throw "AegisNids did not reach Running after the swap"
    }
    $result.daemon_started = $true

    Start-Sleep -Seconds 4
    $readiness = & python tools/aegisctl.py readiness 2>&1 | Out-String
    $readinessRc = $LASTEXITCODE
    $result.readiness = $readiness.Trim()
    $readiness | Out-File (Join-Path $out "readiness-after.txt") -Encoding utf8
    if ($readinessRc -ne 0) {
        throw "aegisctl readiness failed with exit $readinessRc"
    }

    $runningHash = Get-Sha256 $dst
    if ($runningHash -ne $srcHash) {
        throw "running driver file hash mismatch: $runningHash != $srcHash"
    }

    Record-Service "AegisNids" (Join-Path $out "service-after.txt")
    Record-Service "AegisWfp" (Join-Path $out "driver-after.txt")
    (Get-FileHash $dst -Algorithm SHA256) |
        Format-List |
        Out-File (Join-Path $out "driver-hash-after.txt") -Encoding utf8
    $result.finished_at = (Get-Date).ToString("o")
    $result |
        ConvertTo-Json -Depth 6 |
        Out-File (Join-Path $out "driver-swap-result.json") -Encoding utf8
    Write-Host "[swap] OK: $dstHash -> $srcHash"
}
catch {
    $result.error = $_.Exception.Message
    $result.rollback = $true
    Write-Host "[swap] FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "[swap] restoring the hash-verified previous driver" -ForegroundColor Yellow

    $restoreErrors = @()

    # The daemon owns a PEP/bridge handle to the driver. Stop it before
    # swapping the binary back; otherwise the old image can remain mapped.
    # If aegisctl cannot stop it, fall back to the service control manager so
    # the restore is still attempted. Any failure is recorded, never hidden.
    $daemonStopped = $false
    try {
        $daemonSvc = Get-Service -Name "AegisNids" -ErrorAction SilentlyContinue
        if (-not $daemonSvc -or $daemonSvc.Status -eq "Stopped") {
            $daemonStopped = $true
        } else {
            $rbStopOut = Join-Path $out "daemon-rollback-stop.out"
            $rbStopErr = Join-Path $out "daemon-rollback-stop.err"
            $rbProc = Start-Process -FilePath "python" `
                -ArgumentList @("tools/aegisctl.py", "stop", "--all") `
                -NoNewWindow -PassThru `
                -RedirectStandardOutput $rbStopOut `
                -RedirectStandardError $rbStopErr
            if (-not $rbProc.WaitForExit(20000)) {
                $rbProc.Kill()
                throw "aegisctl rollback stop timed out"
            }
            if (-not (Wait-ServiceState "AegisNids" "Stopped" 30)) {
                throw "AegisNids did not reach Stopped for rollback"
            }
            $daemonStopped = $true
        }
    } catch {
        $restoreErrors += "daemon-stop: $($_.Exception.Message)"
        Write-Host "[swap] daemon rollback stop error: $($_.Exception.Message)" -ForegroundColor Red
    }
    if (-not $daemonStopped) {
        try {
            & sc.exe stop AegisNids 2>&1 |
                Out-File (Join-Path $out "daemon-rollback-stop-scm.txt") -Encoding utf8
            if (-not (Wait-ServiceState "AegisNids" "Stopped" 30)) {
                throw "AegisNids did not stop via SCM"
            }
            $daemonStopped = $true
        } catch {
            $restoreErrors += "daemon-stop-scm: $($_.Exception.Message)"
            Write-Host "[swap] SCM daemon stop error: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    try {
        if ($result.driver_touched) {
            & sc.exe stop AegisWfp 2>&1 | Out-Null
            if (-not (Wait-ServiceState "AegisWfp" "Stopped" 20)) {
                throw "AegisWfp did not reach Stopped for rollback"
            }
            Copy-Item $backup $dst -Force
            $restoredHash = Get-Sha256 $dst
            if ($restoredHash -ne $ExpectedBackupSha256.ToUpperInvariant()) {
                throw "restored driver hash mismatch: $restoredHash"
            }
            $result.rollback_verified = $true
        }
        if ($result.driver_touched -or $result.driver_stopped) {
            & sc.exe start AegisWfp 2>&1 | Out-Null
            if (-not (Wait-ServiceState "AegisWfp" "Running" 20)) {
                throw "AegisWfp did not reach Running after rollback"
            }
        }
    } catch {
        $restoreErrors += "driver: $($_.Exception.Message)"
        Write-Host "[swap] driver rollback error: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        & sc.exe start AegisNids 2>&1 | Out-Null
        if (-not (Wait-ServiceState "AegisNids" "Running" 30)) {
            throw "AegisNids did not reach Running after rollback"
        }
    } catch {
        $restoreErrors += "daemon: $($_.Exception.Message)"
        Write-Host "[swap] daemon rollback error: $($_.Exception.Message)" -ForegroundColor Red
    }

    if ($restoreErrors.Count -gt 0) {
        $result.error = "$($result.error); rollback errors: $($restoreErrors -join '; ')"
    }
    $result.finished_at = (Get-Date).ToString("o")
    $result |
        ConvertTo-Json -Depth 6 |
        Out-File (Join-Path $out "driver-swap-result.json") -Encoding utf8
    throw
}

Write-Host "[swap] driver swap complete; run scripts/run_g2_dupfilter_proof.ps1 with the pinned hashes"
