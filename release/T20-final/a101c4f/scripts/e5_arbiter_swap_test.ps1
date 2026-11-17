# E5-C-2 arbiter swap test: prove the acquisition arbiter changes hands on
# the live host and hands it back, with every transition recorded.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$outJson = Join-Path $evDir 'e5c-arbiter-swap-result.json'
Start-Transcript -Path (Join-Path $evDir 'e5c-arbiter-swap.log') -Force

function Invoke-QueueJson {
    $raw = & python tools/aegisctl.py queue --json 2>&1 | Out-String
    $start = $raw.IndexOf('{')
    return ($raw.Substring($start) | ConvertFrom-Json)
}
function Get-Wfp { param($doc)  return $doc.wfp }

$transitions = @()
$doc = Invoke-QueueJson
$w0 = Get-Wfp $doc
$transitions += [ordered]@{ t = [DateTime]::Now.ToString('o'); phase = 'baseline'; mode = $w0.mode; reason = $w0.reason; shadow_rows = $w0.shadow_rows }
Write-Host ("baseline mode=" + $w0.mode + " reason=" + $w0.reason)

# 1. Stop Nose and expect kernel_fallback within ~25 s (10 s stall + kernel rows).
Stop-Process -Name 'aegis-nose' -Force -ErrorAction SilentlyContinue
Write-Host 'nose stopped; waiting for takeover...'
$deadline = (Get-Date).AddSeconds(45)
$tookOver = $false
do {
    Start-Sleep -Seconds 5
    $w = Get-Wfp (Invoke-QueueJson)
    if ($w.mode -ne $w0.mode) {
        $transitions += [ordered]@{ t = [DateTime]::Now.ToString('o'); phase = 'after-nose-stop'; mode = $w.mode; reason = $w.reason; shadow_rows = $w.shadow_rows }
        Write-Host ("changed to mode=" + $w.mode + " reason=" + $w.reason)
        if ($w.mode -eq 'kernel_fallback') { $tookOver = $true }
        break
    }
} while ((Get-Date) -lt $deadline)
if (-not $tookOver) { Write-Host 'WARN: no observed takeover before deadline' }

# 2. Restart Nose from the runtime dir and expect the mode back to npcap_primary.
$nose = Join-Path 'C:\Program Files\AEGIS NIDS\runtime' 'aegis-nose.exe'
Start-Process -FilePath $nose -WindowStyle Hidden
Write-Host 'nose restarted; waiting for hand-back...'
$deadline = (Get-Date).AddSeconds(45)
$handBack = $false
do {
    Start-Sleep -Seconds 5
    $w = Get-Wfp (Invoke-QueueJson)
    if ($w.mode -eq 'npcap_primary') { $handBack = $true; break }
} while ((Get-Date) -lt $deadline)
$w2 = Get-Wfp (Invoke-QueueJson)
$transitions += [ordered]@{ t = [DateTime]::Now.ToString('o'); phase = 'after-nose-restart'; mode = $w2.mode; reason = $w2.reason; shadow_rows = $w2.shadow_rows }
Write-Host ("final mode=" + $w2.mode + " reason=" + $w2.reason)

# 3. Persist the evidence.
$out = [ordered]@{
    started_at = [DateTime]::Now.ToString('o')
    takeover_observed = $tookOver
    handback_observed = $handBack
    transitions = $transitions
    gate = ($tookOver -and $handBack)
}
$out | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $outJson
if ($out.gate) { Write-Host 'E5-C-2 ARBITER SWAP: PASS' } else { Write-Host 'E5-C-2 ARBITER SWAP: FAIL (see transitions)' }
Stop-Transcript
if (-not $out.gate) { exit 1 }
