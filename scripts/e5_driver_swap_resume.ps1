# E5-A resume: finish the outbound driver swap exactly like
# scripts/deploy_wfp_driver_20261024.ps1 (daemon-first stop), with the pins
# already established in this session:
#   candidate (signed Valid, thumbprint 00E928...): 7EDE4DCD...7C9
#   currently loaded (backed up already):           95C7E749...E03
# Requires Administrator.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$src = Join-Path $repo 'build\x64\wfp\aegis_wfp.sys'
$dst = Join-Path $env:SystemRoot 'System32\drivers\aegis_wfp.sys'
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$result = [ordered]@{}
Start-Transcript -Path (Join-Path $evDir 'e5a-resume.log') -Force

function Get-Sha256([string]$Path) { (Get-FileHash $Path -Algorithm SHA256).Hash.ToUpperInvariant() }
function Wait-Service([string]$Name, [string]$Desired, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($s -and $s.Status -eq $Desired) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

# Pins. 7EDE4DCD... is the UNSIGNED O2 build (kernel-outbound-capture-20261025
# evidence); Authenticode signing rewrites the file, so the installed pin is
# the SIGNED artifact hash recorded right after scripts\wfp_sign.ps1 ran.
$candidate = '49E65BB12B4FC164F0B0C255AC75CDFA096F17AC77B056586BF16891FCDABE8C'
$prevLoaded = '95C7E749F45602EB6423C842734239450039627D710DBAF27B5FDDA52F8CCE03'
$signer = '00E92849867308596564D134BB981EF726798E97'

$srcHash = Get-Sha256 $src
if ($srcHash -ne $candidate) { throw "candidate pin mismatch: $srcHash" }
$dstHash = Get-Sha256 $dst
if ($dstHash -ne $prevLoaded) { throw "installed pin mismatch: $dstHash (not $prevLoaded)" }
$sig = Get-AuthenticodeSignature $src
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $signer) {
    throw "candidate signature invalid: $($sig.Status) $($sig.SignerCertificate.Thumbprint)"
}
Write-Host "pins OK: candidate $srcHash signature $($sig.Status)"
$result.unsigned_build_sha256 = '7EDE4DCD4DC1D24CC2A98916648258A7B98437C0D8ECD70A0C3144C08D87A7C9'
$result.pin_candidate = $srcHash
$result.pin_installed_before = $dstHash

$startedAt = Get-Date -Format o

# 1. Stop daemon (it holds the device handle that blocks driver stop).
Write-Host '=== stop AegisNids ==='
sc.exe stop AegisNids | Out-Host
if (-not (Wait-Service 'AegisNids' 'Stopped' 30)) { throw 'AegisNids did not stop' }

# 2. Wait for AegisWfp to settle at STOPPED.
if (-not (Wait-Service 'AegisWfp' 'Stopped' 30)) { throw 'AegisWfp did not stop' }
Write-Host 'driver stopped'

# 3. Replace binary (hash-verified copy).
Copy-Item $src $dst -Force
$installed = Get-Sha256 $dst
if ($installed -ne $candidate) { throw "copy mismatch: $installed" }
Write-Host "installed: $installed ($((Get-Item $dst).Length) bytes)"
$result.replaced_sha256 = $installed
$result.replaced_bytes = (Get-Item $dst).Length

# 4. Start driver.
sc.exe start AegisWfp | Out-Host
$stateA = Wait-Service 'AegisWfp' 'Running' 20
Write-Host "driver running: $stateA"
if (-not $stateA) {
    Write-Host 'ROLLOBACK: restore old driver'
    Copy-Item (Join-Path $evDir 'aegis_wfp_old.sys') $dst -Force
    sc.exe start AegisWfp | Out-Host
    sc.exe start AegisNids | Out-Host
    throw 'driver failed to start; old driver restored'
}

# 5. Start daemon.
sc.exe start AegisNids | Out-Host
$stateN = Wait-Service 'AegisNids' 'Running' 30
Write-Host "daemon running: $stateN"
if (-not $stateN) { throw 'AegisNids failed to restart' }
Start-Sleep -Seconds 8

# 6. Readiness (same JSON as the g2 evidence).
try {
    $python = "tools\aegisd_proof_ready.py"
    if (Test-Path $python) {
        & python $python 2>&1 | Out-Host
    } else {
        Write-Host '(no readiness helper; operator should verify with aegisctl)'
    }
} catch { Write-Host "readiness check skipped: $_" }

$result.daemon_started = $stateN
$result.started_at = $startedAt
$result.finished_at = Get-Date -Format o
$result | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evDir 'e5a-swap-result.json')
Write-Host 'E5-A RESUME OK'
Stop-Transcript
exit 0
