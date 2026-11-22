#Requires -RunAsAdministrator
# RESET the AEGIS telemetry stack to a CLEAN, ZERO-LOSS baseline immediately
# before the 24 h soak for candidate 466a226. Run from ANYWHERE elevated.
#
# Why this exists: the pre-soak audit's heavy file reads filled the minifilter
# kernel ring. Loss counters are CUMULATIVE (minifilter_ring_dropped comes from
# the driver's GET_STATS, not from the daemon process), so they do not clear on
# their own. host_soak_check.py:223 fails on a DEGRADED daemon, and RB-024:235
# says a dirty loss baseline must never be scored. This script unloads the
# minifilter driver (resetting the kernel counter), restarts the daemon
# (resetting process counters), enforces no-sleep, waits for a verified quiet
# zero-loss state, then re-runs the E5 preflight into the worktree evidence root.
#
# It does NOT install anything, copy any driver by hand, or change any pinned
# hash. If any image hash is wrong, it stops before touching a service.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\User\.local\share\opencode\worktree\a6f58a\rule-coverage-20261119\analysis\current-head\reset-soak-baseline-466a226.ps1"
#
# After this prints "BASELINE CLEAN", start the clock with soak-466a226.ps1 -Mode start

$ErrorActionPreference = 'Stop'

$Repo     = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location $Repo
$Evidence = Join-Path $Repo 'admin-evidence\e5-clean-host-20261120-final'
$Preflight = Join-Path $Evidence 'preflight-20261120.json'

$Want = @{
    runtime    = 'FBD9BDB3456C9C7DAFCBF1B0C3FBDAD9778F61C3186167856E373CC376185474'
    wfp        = 'B26AC754C92B7BD0616EEBD73EB2A153A25C77C04FD7B5EF00B81FCE8C287877'
    minifilter = 'C836A981AC74074B222CC9456BC7C6AD0960F7FD88B51220353A1D2D62AA3107'
}
$Paths = @(
    @{ name = 'runtime';    path = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe' },
    @{ name = 'wfp';        path = 'C:\Windows\System32\drivers\aegis_wfp.sys' },
    @{ name = 'minifilter'; path = 'C:\Windows\System32\drivers\aegis_minifilter.sys' }
)

function Get-Sha256([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return 'MISSING' }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}
function State([string]$Name) {
    $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $s) { return 'MISSING' }
    return [string]$s.Status
}
function Wait-State([string]$Name, [string]$Desired, [int]$Seconds = 90) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $now = State $Name
        if ($now -eq $Desired) { return $true }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)
    return $false
}

Write-Host "== Pre-soak clean baseline reset | repo=$Repo =="

# 0. Refuse to touch a mis-installed host.
$fail = $false
foreach ($p in $Paths) {
    $actual = Get-Sha256 $p.path
    $ok = $actual -eq $Want[$p.name]
    if (-not $ok) { $fail = $true }
    "{0,-12} {1}  {2}" -f $p.name, $(if ($ok) { 'OK  ' } else { 'FAIL' }), $actual
    if (-not $ok) { Write-Host ("             expected: " + $Want[$p.name]) }
}
if ($fail) {
    throw "Image verification FAILED. Re-run apply-466a226-and-preflight.ps1 with the corrected installer. No hand-copying, no soak."
}

# 1. Enforce no sleep/hibernate for the whole window (AC and DC). AC was already
#    0; DC hibernate was 10800 s (3 h), which would void a 24 h soak on battery.
Write-Host "== Enforcing no sleep/hibernate =="
powercfg /change standby-timeout-ac 0 2>&1 | Out-Null
powercfg /change standby-timeout-dc 0 2>&1 | Out-Null
powercfg /change hibernate-timeout-ac 0 2>&1 | Out-Null
powercfg /change hibernate-timeout-dc 0 2>&1 | Out-Null
$sb = powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 2>&1 | Select-String 'Current AC|Current DC'
$hb = powercfg /query SCHEME_CURRENT SUB_SLEEP HIBERNATEIDLE 2>&1 | Select-String 'Current AC|Current DC'
'  standby: ' + (($sb | ForEach-Object { $_.Line.Trim() }) -join ' ; ')
'  hibernate: ' + (($hb | ForEach-Object { $_.Line.Trim() }) -join ' ; ')

# 2. Stop daemon first, then unload the minifilter driver so the kernel ring
#    counter resets. WFP is left alone (it is not a loss-counter source).
Write-Host "== Restarting telemetry stack in clean order =="
foreach ($s in 'AegisNids', 'AegisMinifilter') {
    if ((State $s) -eq 'RUNNING') {
        & sc.exe stop $s | Out-Null
        if (-not (Wait-State $s 'STOPPED' 90)) { throw "Could not stop $s" }
        "  stopped $s"
    }
}
if ((State 'AegisWfp') -ne 'RUNNING') {
    & sc.exe start AegisWfp | Out-Null
    if (-not (Wait-State 'AegisWfp' 'RUNNING' 90)) { throw 'AegisWfp did not start' }
}
# Boot order: daemon first (its minifilter reader retries the port), driver last.
& sc.exe start AegisNids | Out-Null
if (-not (Wait-State 'AegisNids' 'RUNNING' 120)) { throw 'AegisNids did not start' }
& sc.exe start AegisMinifilter | Out-Null
if (-not (Wait-State 'AegisMinifilter' 'RUNNING' 90)) { throw 'AegisMinifilter did not start' }
foreach ($s in 'AegisNids', 'AegisAggregator', 'AegisWfp', 'AegisMinifilter') {
    "  {0,-18} {1}" -f $s, (State $s)
}

# 3. Wait for a QUIET, zero-loss, RUNNING state that stays stable. Heavy file
#    I/O during this wait would refill the ring; keep this machine idle.
Write-Host "== Waiting for a stable zero-loss baseline (keep this machine idle) =="
$lossKeys = @(
    'queue_dropped_total', 'nose_frames_rejected', 'nose_frames_dropped',
    'nose_pipe_errors', 'minifilter_ring_dropped', 'minifilter_pipeline_dropped'
)
$deadline = (Get-Date).AddMinutes(20)
$streak = 0
$seen = $null
do {
    Start-Sleep -Seconds 15
    $raw = python tools\aegisctl.py health --json 2>$null
    if (-not $raw -or -not ("$raw".Contains('{'))) { continue }
    try { $h = ("$raw".Substring("$raw".IndexOf('{'))) | ConvertFrom-Json } catch { continue }
    $i = $h.data_integrity
    $sum = [int64]0
    foreach ($k in $lossKeys) {
        $v = $i.$k
        if ($null -ne $v) { $sum += [int64]$v }
    }
    $uptimeH = 0.0
    if ($null -ne $h.uptime_ms) { $uptimeH = ([double]$h.uptime_ms) / 3600000.0 }
    $clean = ($h.state -eq 'RUNNING') -and (-not $h.degraded) -and ($sum -eq 0) -and ($uptimeH -ge 0.084)
    if ($clean) { $streak++ } else { $streak = 0 }
    $seen = "state=$($h.state) degraded=$($h.degraded) loss_sum=$sum uptime=$([math]::Round($uptimeH,2))h streak=$streak/4"
    Write-Host "  $seen"
    if ($streak -ge 4) { break }
} while ((Get-Date) -lt $deadline)

if ($streak -lt 4) {
    throw "Baseline never reached a stable zero-loss RUNNING state. Last: $seen`nDo NOT start the soak. Check what is generating FIM/minifilter load; paste this output to the agent."
}

# 4. Re-run the E5 preflight into the exact artifact the board reads.
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
Write-Host "== Re-running E5 preflight =="
python tools\host_preflight.py --min-uptime-min 5 --json $Preflight
$exit = $LASTEXITCODE
if (-not (Test-Path -LiteralPath $Preflight)) { throw "Preflight produced no artifact at $Preflight" }
$r = Get-Content -LiteralPath $Preflight -Raw -Encoding UTF8 | ConvertFrom-Json
"  verdict: $($r.verdict)"
if ($r.failed) { "  failed:  $($r.failed -join ', ')" }
if ($exit -ne 0 -or $r.verdict -ne 'PASS') {
    throw "Preflight did not PASS (exit $exit). Do not start the soak; paste this output to the agent."
}

Write-Host "== BASELINE CLEAN =="
Write-Host "Artifact: $Preflight"
Write-Host "Now start the clock (do not touch the host afterwards):"
Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\User\.local\share\opencode\worktree\a6f58a\rule-coverage-20261119\analysis\current-head\soak-466a226.ps1" -Mode start'
