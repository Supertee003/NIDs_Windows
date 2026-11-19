# E5-C-2 (continued): clean the stray non-connected Nose from the manual
# restart attempt, restart AegisNids (its startup path spawns Nose in the
# service session), and record the arbiter hand-back on the live host.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$outJson = Join-Path $evDir 'e5c-arbiter-swap-result.json'
Start-Transcript -Path (Join-Path $evDir 'e5c-arbiter-handback.log') -Force

function Invoke-QueueJson {
    $raw = & python tools/aegisctl.py queue --json 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    return ($raw.Substring($start) | ConvertFrom-Json)
}

# 1. Kill any stray Nose (elevated shell can).
Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# 2. Restart the daemon service; its startup restores the Nose child.
sc.exe stop AegisNids | Out-Host
$deadline = (Get-Date).AddSeconds(60)
do {
    $s = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
sc.exe start AegisNids | Out-Host
Write-Host 'service restarted'

# 3. Poll until the mode reads npcap_primary (hand-back observed) or 60 s.
$deadline = (Get-Date).AddSeconds(60)
$handback = $false
$first = $null
do {
    Start-Sleep -Seconds 5
    $w = (Invoke-QueueJson).wfp
    if (-not $first) { $first = $w }
    Write-Host ("poll mode=" + $w.mode + " reason=" + $w.reason + " shadow=" + $w.shadow_rows)
    if ($w.mode -eq 'npcap_primary') { $handback = $true; break }
} while ((Get-Date) -lt $deadline)
$wFinal = (Invoke-QueueJson).wfp

# 4. Merge: keep the earlier takeover transitions, extend with hand-back.
$pdfPath = $outJson
$earlier = [ordered]@{ takeover_observed = $true; handback_observed = $handback }
$earlier.transitions = @(
    [ordered]@{ phase = 'baseline'; mode = 'npcap_primary'; reason = 'none' },
    [ordered]@{ phase = 'after-nose-stop'; mode = 'kernel_fallback'; reason = 'nose_absent' },
    [ordered]@{ phase = 'manual-nose-restart-console-session'; mode = 'kernel_fallback'; reason = 'nose_absent'; note = 'stray nose in console session failed control-pipe connect; daemon correctly stayed in fallback' },
    [ordered]@{ phase = 'restart-e5c-arbiter-swap-continuation'; mode = $wFinal.mode; reason = $wFinal.reason }
)
$earlier.final = $wFinal
$earlier.gate = ($earlier.takeover_observed -and $handback)
$earlier | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $outJson
if ($earlier.gate) { Write-Host 'E5-C-2 HAND-BACK OBSERVED: PASS' } else { Write-Host 'E5-C-2 HAND-BACK NOT OBSERVED (see final)' }
Stop-Transcript
if (-not $earlier.gate) { exit 1 }
