# Install the hash-pinned ReleaseSafe O2 daemon candidate for the E5 direction proof.
# Run from elevated PowerShell. This changes only the daemon executable; it does
# not change WFP filters, driver/service configuration, or prevention state.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

$runtime = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$candidate = Join-Path $repo 'zig-out\bin\aegis_nids.exe'
$expected = 'E19370F598507FBC9A1194EA8182059B319DFAF76DFF4D3DE34814C57386B407'
$evidenceDir = Join-Path $repo 'admin-evidence\e5-host-proof-20261026'
$backup = Join-Path $evidenceDir 'aegis_nids_pre_o2_direction_464e765b.exe'
$transcript = Join-Path $evidenceDir ("e5d-o2-deploy-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

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
function Invoke-JsonCommand([string[]]$Command) {
    $raw = & python @Command 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    if ($start -lt 0) { throw "No JSON response from $($Command -join ' '):`n$raw" }
    return ($raw.Substring($start) | ConvertFrom-Json)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this deployment from elevated PowerShell.'
}
if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { throw "Candidate missing: $candidate" }
if ((Get-Sha256 $candidate) -ne $expected) { throw 'ReleaseSafe candidate hash mismatch; rebuild and rebaseline before deployment.' }
if ((Get-Service AegisNids).Status -ne 'Running' -or (Get-Service AegisWfp).Status -ne 'Running') {
    throw 'AegisNids and AegisWfp must both be running before deployment.'
}
$gate = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
if ($gate.prevention_gate -ne 'closed' -or $gate.host_effect_capable) {
    throw 'Refusing daemon deployment unless prevention_gate=closed and host_effect_capable=false.'
}
if ((Get-Sha256 $runtime) -ne '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61') {
    throw 'Installed daemon hash changed from the expected pre-O2 runtime; inspect before replacing it.'
}
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
Start-Transcript -Path $transcript -Force | Out-Null

$stopped = $false
try {
    if (Test-Path -LiteralPath $backup) {
        if ((Get-Sha256 $backup) -ne '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61') {
            throw "Existing rollback backup hash mismatch; refusing to use it: $backup"
        }
        Write-Host "reusing verified rollback backup=$backup"
    } else {
        Copy-Item -LiteralPath $runtime -Destination $backup
    }
    if ((Get-Sha256 $backup) -ne '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61') {
        throw 'Backup hash verification failed.'
    }
    sc.exe stop AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Stopped' 45)) { throw 'AegisNids did not stop.' }
    $stopped = $true

    $staged = "$runtime.o2-staged"
    Copy-Item -LiteralPath $candidate -Destination $staged -Force
    if ((Get-Sha256 $staged) -ne $expected) { throw 'Staged daemon hash verification failed.' }
    Move-Item -LiteralPath $staged -Destination $runtime -Force
    if ((Get-Sha256 $runtime) -ne $expected) { throw 'Installed daemon hash verification failed.' }

    sc.exe start AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Running' 45)) { throw 'AegisNids failed to restart.' }
    $daemonProcess = Get-CimInstance Win32_Process -Filter "Name='aegis_nids.exe'" |
        Select-Object -First 1 ProcessId,ExecutablePath
    Write-Host "started daemon pid=$($daemonProcess.ProcessId) image=$($daemonProcess.ExecutablePath) sha256=$(Get-Sha256 $runtime)"

    # Service state can reach RUNNING before the control pipe accepts requests.
    # The CLI itself retries for <1s; poll for up to 45s while retaining its
    # AEGIS_DEBUG_CONTROL diagnostics to distinguish readiness from a bad reply.
    $oldDebugControl = $env:AEGIS_DEBUG_CONTROL
    $env:AEGIS_DEBUG_CONTROL = '1'
    $probe = $null
    $lastProbeError = 'No response yet.'
    $deadline = (Get-Date).AddSeconds(45)
    try {
        do {
            try {
                $candidateProbe = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'list', '--json', '--limit', '1')
                $records = @($candidateProbe.records)
                if ($records.Count -gt 0 -and $records[0].PSObject.Properties['direction']) {
                    $probe = $candidateProbe
                    break
                }
                if ($records.Count -gt 0) {
                    $lastProbeError = 'Control responded, but records do not expose direction metadata.'
                } else {
                    $lastProbeError = 'Control responded, but the forensic ring has no record to validate the direction field.'
                }
            } catch {
                $lastProbeError = $_.Exception.Message
                Write-Warning "forensics.list readiness retry: $lastProbeError"
            }
            Start-Sleep -Seconds 1
        } while ((Get-Date) -lt $deadline)
    } finally {
        if ($null -eq $oldDebugControl) { Remove-Item Env:AEGIS_DEBUG_CONTROL -ErrorAction SilentlyContinue }
        else { $env:AEGIS_DEBUG_CONTROL = $oldDebugControl }
    }
    if (-not $probe) {
        throw "Installed daemon did not pass forensic direction readiness within 45 seconds. Last result: $lastProbeError"
    }
    $gateAfter = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    if ($gateAfter.prevention_gate -ne 'closed' -or $gateAfter.host_effect_capable) {
        throw 'Post-deploy prevention gate is not closed; stop and investigate.'
    }
    Write-Host "O2 daemon installed. SHA-256=$expected; backup=$backup; prevention_gate=closed. Transcript=$transcript. Next: .\scripts\e5_o2_direction_verified.ps1"
} catch {
    $failure = $_.Exception.Message
    if ($stopped) {
        try {
            $service = Get-Service AegisNids -ErrorAction SilentlyContinue
            if ($service -and $service.Status.ToString() -ne 'Stopped') {
                sc.exe stop AegisNids | Out-Host
                [void](Wait-Service 'AegisNids' 'Stopped' 45)
            }
            if (Test-Path -LiteralPath $backup) {
                Copy-Item -LiteralPath $backup -Destination $runtime -Force
                if ((Get-Sha256 $runtime) -ne '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61') {
                    throw 'Rollback file hash verification failed.'
                }
                sc.exe start AegisNids | Out-Host
                if (-not (Wait-Service 'AegisNids' 'Running' 45)) { throw 'Rollback daemon did not restart.' }
                Write-Warning 'Deployment failed; prior daemon restored and service restarted.'
            }
        } catch { Write-Error "Rollback also failed: $($_.Exception.Message)" }
    }
    throw $failure
} finally {
    Stop-Transcript | Out-Null
}
