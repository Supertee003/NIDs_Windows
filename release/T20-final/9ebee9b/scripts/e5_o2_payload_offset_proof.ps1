# Build-sign-deploy-test-rollback the O2 payload-offset driver slice.
# Run elevated. Default probe sink is loopback (see e5_o2_direction_verified.ps1);
# pass -RemoteAddress/-RemotePort when an operator-controlled remote TCP sink is listening.
param(
    [string]$RemoteAddress,

    [int]$RemotePort
)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

# Current candidate = O1 build at source 24d8d81 (includes the O2 payload-offset
# fix AND the O1 v6 sidecar); rebuilt with /Brepro so this pin is reproducible.
$expectedUnsigned = 'A583B630BCE55C7FBDE6B29B59657BABD0BD00910151F9257147F20DDE96732C'
$expectedInstalledDriver = '49E65BB12B4FC164F0B0C255AC75CDFA096F17AC77B056586BF16891FCDABE8C'
$expectedSigner = '00E92849867308596564D134BB981EF726798E97'
$baseDaemon = '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61'
$source = Join-Path $repo 'build\x64\wfp\aegis_wfp.sys'
$signScript = Join-Path $repo 'scripts\wfp_sign.ps1'
$functionalScript = Join-Path $repo 'scripts\e5_o2_functional_proof.ps1'
$driverPath = Join-Path $env:SystemRoot 'System32\drivers\aegis_wfp.sys'
$runtimePath = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$evidenceDir = Join-Path $repo 'admin-evidence\e5-host-proof-20261026'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcriptPath = Join-Path $evidenceDir "e5d-o2-offset-proof-$stamp.log"
$resultPath = Join-Path $evidenceDir "e5d-o2-offset-proof-$stamp.json"
$backupPath = Join-Path $evidenceDir 'aegis_wfp_pre_payload_offset_49e65bb1.sys'
$unsignedStage = Join-Path $evidenceDir "aegis_wfp_payload_offset_unsigned_$stamp.sys"
$proofStarted = Get-Date
$proofJson = $null
$proofJsonPath = $null
$proofExit = $null
$signedHash = $null
$driverDeployed = $false
$driverRestored = $false
$gateAfter = $null
$forensicAfter = $null
$errorText = $null

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}
function Wait-Service([string]$Name, [string]$Desired, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status.ToString() -eq $Desired) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}
function Stop-DriverStack {
    if ((Get-Service AegisNids).Status.ToString() -ne 'Stopped') {
        sc.exe stop AegisNids | Out-Host
        if (-not (Wait-Service 'AegisNids' 'Stopped' 45)) { throw 'AegisNids did not stop.' }
    }
    if ((Get-Service AegisWfp).Status.ToString() -ne 'Stopped') {
        sc.exe stop AegisWfp | Out-Host
        if (-not (Wait-Service 'AegisWfp' 'Stopped' 45)) { throw 'AegisWfp did not stop.' }
    }
}
function Start-DriverStack {
    sc.exe start AegisWfp | Out-Host
    if (-not (Wait-Service 'AegisWfp' 'Running' 30)) { throw 'AegisWfp did not return RUNNING.' }
    sc.exe start AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Running' 45)) { throw 'AegisNids did not return RUNNING.' }
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
    throw 'Run this proof from elevated PowerShell.'
}
if ((Get-Sha256 $source) -ne $expectedUnsigned) {
    throw 'Unsigned WFP candidate hash mismatch; rebuild and rebaseline before deployment.'
}
if ((Get-Sha256 $driverPath) -ne $expectedInstalledDriver) {
    throw 'Installed WFP driver is not the pinned pre-offset O2 image; inspect before replacing it.'
}
if ((Get-Sha256 $runtimePath) -ne $baseDaemon) {
    throw 'Installed daemon is not the verified base image; the functional proof cannot safely roll back.'
}
if ((Get-Service AegisNids).Status.ToString() -ne 'Running' -or
    (Get-Service AegisWfp).Status.ToString() -ne 'Running') {
    throw 'AegisNids and AegisWfp must be RUNNING before the driver swap.'
}

New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
Start-Transcript -Path $transcriptPath -Force | Out-Null
try {
    $gateBefore = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    if ($gateBefore.prevention_gate -ne 'closed' -or $gateBefore.host_effect_capable) {
        throw 'Refusing O2 proof unless prevention_gate=closed and host_effect_capable=false.'
    }
    $forensicBefore = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify')
    if ($forensicBefore.verified -ne $true) { throw 'Forensic hash chain failed before driver swap.' }

    if (Test-Path -LiteralPath $backupPath) {
        if ((Get-Sha256 $backupPath) -ne $expectedInstalledDriver) {
            throw 'Existing pre-offset driver backup has the wrong hash.'
        }
    } else {
        Copy-Item -LiteralPath $driverPath -Destination $backupPath
    }
    if ((Get-Sha256 $backupPath) -ne $expectedInstalledDriver) {
        throw 'Pre-offset driver backup hash verification failed.'
    }

    Copy-Item -LiteralPath $source -Destination $unsignedStage
    if ((Get-Sha256 $unsignedStage) -ne $expectedUnsigned) { throw 'Staged unsigned driver hash mismatch.' }
    $powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
    & $powerShell -NoProfile -ExecutionPolicy Bypass -File $signScript -SysPath $unsignedStage | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Test-sign helper exited $LASTEXITCODE." }
    $signature = Get-AuthenticodeSignature -LiteralPath $unsignedStage
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $expectedSigner) {
        throw "Signed candidate has unexpected signature: $($signature.Status), $($signature.SignerCertificate.Thumbprint)."
    }
    $signedHash = Get-Sha256 $unsignedStage
    $signedCandidate = Join-Path $evidenceDir "aegis_wfp_payload_offset_$($signedHash.Substring(0,12)).sys"
    if (Test-Path -LiteralPath $signedCandidate) {
        if ((Get-Sha256 $signedCandidate) -ne $signedHash) { throw 'Existing signed candidate path has a hash collision.' }
    } else {
        Copy-Item -LiteralPath $unsignedStage -Destination $signedCandidate
    }
    Write-Host "signed candidate=$signedCandidate sha256=$signedHash signer=$expectedSigner"

    $driverDeployed = $true
    Stop-DriverStack
    Copy-Item -LiteralPath $signedCandidate -Destination $driverPath -Force
    if ((Get-Sha256 $driverPath) -ne $signedHash) { throw 'Installed driver hash differs from signed candidate.' }
    Start-DriverStack
    $gateDuring = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    if ($gateDuring.prevention_gate -ne 'closed' -or $gateDuring.host_effect_capable) {
        throw 'Prevention gate changed during driver deployment; stop and investigate.'
    }

    $proofArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $functionalScript))
    if ($RemoteAddress) {
        if ($RemotePort -lt 1) { throw 'Remote mode requires a valid -RemotePort.' }
        Write-Host "Running marker proof to ${RemoteAddress}:$RemotePort; remote sink must already be listening."
        $proofArgs += @('-RemoteAddress', $RemoteAddress, '-RemotePort', [string]$RemotePort)
    } else {
        Write-Host 'Running marker proof to the loopback sink (default mode).'
    }
    $child = Start-Process -FilePath $powerShell -ArgumentList $proofArgs `
        -WorkingDirectory $repo -PassThru -NoNewWindow
    $child.WaitForExit()
    $child.Refresh()
    $proofExit = [int]$child.ExitCode
    $proofFiles = @(Get-ChildItem -LiteralPath $evidenceDir -Filter 'e5d-o2-functional-*.json' -File |
        Where-Object { $_.LastWriteTime -ge $proofStarted } | Sort-Object LastWriteTime -Descending)
    if ($proofFiles.Count -gt 0) {
        $proofJsonPath = $proofFiles[0].FullName
        $proofJson = Get-Content -LiteralPath $proofJsonPath -Raw | ConvertFrom-Json
    }
    if (-not $proofJson) { throw 'Functional proof produced no result JSON.' }
} catch {
    $errorText = $_.Exception.Message
    Write-Warning $errorText
} finally {
    if ($driverDeployed) {
        try {
            Stop-DriverStack
            Copy-Item -LiteralPath $backupPath -Destination $driverPath -Force
            if ((Get-Sha256 $driverPath) -ne $expectedInstalledDriver) {
                throw 'Restored pre-offset driver hash mismatch.'
            }
            Start-DriverStack
            $driverRestored = $true
        } catch {
            $restoreError = $_.Exception.Message
            $errorText = if ($errorText) { "$errorText; driver rollback: $restoreError" } else { "driver rollback: $restoreError" }
            Write-Warning $errorText
        }
    } else {
        $driverRestored = (Get-Sha256 $driverPath) -eq $expectedInstalledDriver
    }

    try {
        $gateAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
        $forensicAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify')
    } catch {
        $postError = $_.Exception.Message
        $errorText = if ($errorText) { "$errorText; post-check: $postError" } else { "post-check: $postError" }
    }
    $rollbackVerified = $driverRestored -and
        (Get-Sha256 $driverPath) -eq $expectedInstalledDriver -and
        (Get-Sha256 $runtimePath) -eq $baseDaemon -and
        (Get-Service AegisNids).Status.ToString() -eq 'Running' -and
        (Get-Service AegisWfp).Status.ToString() -eq 'Running' -and
        $gateAfter.prevention_gate -eq 'closed' -and -not $gateAfter.host_effect_capable -and
        $forensicAfter.verified -eq $true
    $result = [ordered]@{
        started_at = $proofStarted.ToString('o')
        source_unsigned_sha256 = $expectedUnsigned
        candidate_signed_sha256 = $signedHash
        original_driver_sha256 = $expectedInstalledDriver
        original_daemon_sha256 = $baseDaemon
        probe_mode = if ($RemoteAddress) { 'remote' } else { 'loopback' }
        remote_address = $RemoteAddress
        remote_port = $RemotePort
        functional_proof_exit_code = $proofExit
        functional_proof_json = $proofJsonPath
        direction_gate = if ($proofJson) { $proofJson.direction_gate } else { $false }
        direction_error = if ($proofJson) { $proofJson.direction_error } else { $errorText }
        driver_rollback_verified = $rollbackVerified
        prevention_gate_after = if ($gateAfter) { $gateAfter.prevention_gate } else { $null }
        forensic_verified_after = if ($forensicAfter) { $forensicAfter.verified } else { $false }
        error = $errorText
        transcript = $transcriptPath
    }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
    Write-Host "RESULT direction_gate=$($result.direction_gate) driver_rollback=$rollbackVerified result=$resultPath"
    Stop-Transcript | Out-Null
}

if (-not $rollbackVerified -or -not $proofJson -or $proofJson.direction_gate -ne $true) { exit 1 }
