#Requires -RunAsAdministrator
# Apply signed candidate 466a226 and run the E5 preflight.
# Uses ABSOLUTE paths derived from this script's location, so the caller's
# current directory (D:\NIds_Windows vs the worktree) cannot select the wrong
# installer again. Run from ANYWHERE in an ELEVATED PowerShell:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\User\.local\share\opencode\worktree\a6f58a\rule-coverage-20261119\analysis\current-head\apply-466a226-and-preflight.ps1"

$ErrorActionPreference = 'Stop'

$Repo      = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $Repo
$Installer = Join-Path $Repo 'dist\aegis_setup_6.0.0_trial.exe'
$Evidence  = Join-Path $Repo 'admin-evidence\e5-clean-host-20261120-final'
$Preflight = Join-Path $Evidence 'preflight-20261120.json'

# Pinned by analysis/current-head/SOAK-WINDOW-466A226-20261120.md
$Expected = @{
    installer  = 'D2267E720266807D6CB0EDBF5B83F6C6648FF75B4448D433117CDEA6031C3B83'
    runtime    = 'FBD9BDB3456C9C7DAFCBF1B0C3FBDAD9778F61C3186167856E373CC376185474'
    wfp        = 'B26AC754C92B7BD0616EEBD73EB2A153A25C77C04FD7B5EF00B81FCE8C287877'
    minifilter = 'C836A981AC74074B222CC9456BC7C6AD0960F7FD88B51220353A1D2D62AA3107'
}

$RuntimePath    = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$WfpPath        = 'C:\Windows\System32\drivers\aegis_wfp.sys'
$MiniPath       = 'C:\Windows\System32\drivers\aegis_minifilter.sys'

function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'MISSING' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

Write-Host "== AEGIS 466a226 apply + E5 preflight =="
Write-Host "Repo (absolute): $Repo"

# 0. Refuse to touch the host unless the exact corrected installer is present.
$installerHash = Get-Sha256 $Installer
if ($installerHash -ne $Expected.installer) {
    throw "WRONG INSTALLER at $Installer`nexpected: $($Expected.installer)`nactual:   $installerHash`nDo not continue - the main-tree installer (360B9C06...) embeds the old runtime and unsigned drivers."
}
Write-Host "installer hash OK: $installerHash"

# 1. Install. The fixed NSIS stops services, swaps the runtime and the two
#    owner-signed driver images, then starts everything again.
Write-Host "== Installing (silent) =="
Start-Process -FilePath $Installer -ArgumentList '/S' -Wait

# 2. Verify the three deployed images. These hashes are the gate; a service
#    that merely looks RUNNING is not proof.
$failed = $false
foreach ($check in @(
    @{ name = 'runtime';    path = $RuntimePath; want = $Expected.runtime },
    @{ name = 'wfp';        path = $WfpPath;     want = $Expected.wfp },
    @{ name = 'minifilter'; path = $MiniPath;    want = $Expected.minifilter }
)) {
    $actual = Get-Sha256 $check.path
    $ok = $actual -eq $check.want
    if (-not $ok) { $failed = $true }
    "{0,-12} {1}  {2}" -f $check.name, $(if ($ok) { 'OK  ' } else { 'FAIL' }), $actual
    if (-not $ok) { Write-Host ("             expected: " + $check.want) }
}
Get-Service AegisNids, AegisAggregator, AegisWfp, AegisMinifilter -ErrorAction SilentlyContinue |
    Select-Object Name, Status | Format-Table -AutoSize | Out-Host

if ($failed) {
    throw "Image verification FAILED. Do not start a soak. Most likely a wrong installer was used; re-check the absolute installer path above. No hand-copying."
}

# 3. Wait for a real >=5 minute daemon uptime before preflight.
Write-Host "== Waiting for >=5 min daemon uptime =="
$deadline = (Get-Date).AddMinutes(12)
do {
    $proc = Get-Process -Name aegis_nids -ErrorAction SilentlyContinue | Select-Object -First 1
    $uptime = $null
    if ($proc -and $proc.StartTime) { $uptime = ((Get-Date) - $proc.StartTime).TotalMinutes }
    if ($uptime -ne $null -and $uptime -ge 5) { break }
    Start-Sleep -Seconds 15
} while ((Get-Date) -lt $deadline)
if ($uptime -eq $null) {
    Write-Host "Uptime unreadable; allowing the preflight tool to make the final decision."
} else {
    "daemon uptime: {0:N2} min" -f $uptime
}

# 4. Preflight into the worktree evidence root (that is where final_audit looks).
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
Write-Host "== Preflight =="
python tools\host_preflight.py --min-uptime-min 5 --json $Preflight
$exit = $LASTEXITCODE
if (Test-Path -LiteralPath $Preflight) {
    $result = Get-Content -LiteralPath $Preflight -Raw -Encoding UTF8 | ConvertFrom-Json
    "verdict: $($result.verdict)"
    if ($result.failed) { "failed:  $($result.failed -join ', ')" }
}
if ($exit -ne 0) {
    throw "Preflight did not pass (exit $exit). Paste this output to the agent; do not start the soak."
}

Write-Host "== E5 PREFLIGHT PASS =="
Write-Host "Evidence: $Preflight"
Write-Host "Next: run the 24 h window from analysis/current-head/SOAK-WINDOW-466A226-20261120.md (steps 4-6). Do not install, restart, or run adversarial load after the soak starts."
