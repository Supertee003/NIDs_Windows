# Restore the hash-pinned pre-O2 daemon after candidate service instability.
# Run from elevated PowerShell. Does not change driver, filters, policy, or gate.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo

$runtime = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$backup = Join-Path $repo 'admin-evidence\e5-host-proof-20261026\aegis_nids_pre_o2_direction_464e765b.exe'
$candidateHash = '8B3128640C0E6F5EACB85E751471441646A350290A569ED2608757DBD84EAE4F'
$baseHash = '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61'
$transcript = Join-Path (Split-Path $backup) ("e5d-o2-rollback-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))

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
    throw 'Run this rollback from elevated PowerShell.'
}
if (-not (Test-Path -LiteralPath $backup -PathType Leaf) -or (Get-Sha256 $backup) -ne $baseHash) {
    throw 'Verified pre-O2 rollback backup is missing or has the wrong hash.'
}
if (-not (Test-Path -LiteralPath $runtime -PathType Leaf)) { throw "Installed daemon missing: $runtime" }
$currentHash = Get-Sha256 $runtime
if ($currentHash -notin @($candidateHash, $baseHash)) {
    throw "Installed daemon hash is not the pinned candidate or base: $currentHash"
}

Start-Transcript -Path $transcript -Force | Out-Null
try {
    Write-Host "current_hash=$currentHash backup_hash=$(Get-Sha256 $backup)"
    $service = Get-Service AegisNids
    if ($service.Status.ToString() -ne 'Stopped') {
        sc.exe stop AegisNids | Out-Host
        if (-not (Wait-Service 'AegisNids' 'Stopped' 45)) { throw 'AegisNids did not reach STOPPED.' }
    }

    if ($currentHash -ne $baseHash) {
        $staged = "$runtime.rollback-staged"
        Copy-Item -LiteralPath $backup -Destination $staged -Force
        if ((Get-Sha256 $staged) -ne $baseHash) { throw 'Staged rollback hash verification failed.' }
        Move-Item -LiteralPath $staged -Destination $runtime -Force
    }
    if ((Get-Sha256 $runtime) -ne $baseHash) { throw 'Restored daemon hash verification failed.' }

    sc.exe start AegisNids | Out-Host
    if (-not (Wait-Service 'AegisNids' 'Running' 45)) { throw 'Restored AegisNids did not reach RUNNING.' }
    Start-Sleep -Seconds 2
    $gate = Invoke-JsonCommand @('tools/aegisctl.py', 'enforce', 'status')
    $forensic = Invoke-JsonCommand @('tools/aegisctl.py', 'forensics', 'verify')
    if ($gate.prevention_gate -ne 'closed' -or $gate.host_effect_capable) {
        throw 'Restored runtime is up but prevention status is not closed; stop and investigate.'
    }
    if ($forensic.verified -ne $true) { throw 'Restored runtime forensic chain did not verify.' }
    Write-Host "ROLLBACK_OK sha256=$baseHash service=RUNNING prevention_gate=closed forensic_verified=true transcript=$transcript"
} finally {
    Stop-Transcript | Out-Null
}
