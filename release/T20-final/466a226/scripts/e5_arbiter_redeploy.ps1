# E5-C: redeploy daemon (767cb98 arbiter build) + arbiter switch proof.
# Elevated. Sequence:
#   1. stop AegisNids, hash-pin swap runtime\aegis_nids.exe (old backed up)
#   2. stage1 snapshot -> wfp mode=npacpcap_primary expected
#   3. kill aegis-nose.exe -> wait past the 10 s stall window
#      stage2 snapshot -> mode=kernel_fallback expected (kernel owns ingress)
#   4. restart aegis-nose.exe -> stage3 snapshot -> mode=npacpcap_primary again
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
Start-Transcript -Path (Join-Path $evDir 'e5c-arbiter-redeploy.log') -Force

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
function Snapshot([string]$Stage) {
    $txt = & python (Join-Path $repo 'tools\aegisctl.py') queue 2>&1 | Out-String
    $txt | Out-File -FilePath (Join-Path $evDir "queue-$Stage.txt") -Encoding utf8
    Write-Host "--- queue[$Stage] ---"
    ($txt -split "`r?`n") | Where-Object { $_ -match 'wfp |src=capture_|queue ' } | ForEach-Object { Write-Host "  $_" }
}

$runtime = 'C:\Program Files\AEGIS NIDS\runtime\aegis_nids.exe'
$src = Join-Path (Join-Path $repo 'zig-out\bin') 'aegis_nids.exe'
$oldPin = 'E19C76C3EA493B6FCF4DB840F061DA1563A64791213797C8891C6A7C52B9D770'
$newExpected = '464E765BAED95C47C0ECCABCC4C47EF682D96762A8C44B329B7B536AB656BC61'

# 1. swap
$cur = Get-Sha256 $runtime
if ($cur -ne $oldPin) { throw "before-pin mismatch (already replaced?): $cur" }
if ((Get-Sha256 $src) -ne $newExpected) { throw 'zig-out candidate hash mismatch — rebuild first' }
sc.exe stop AegisNids | Out-Host
if (-not (Wait-Service 'AegisNids' 'Stopped' 40)) { throw 'AegisNids did not stop' }
Copy-Item $runtime (Join-Path $evDir 'aegis_nids_old_e19c76c3.exe') -Force
Copy-Item $src $runtime -Force
if ((Get-Sha256 $runtime) -ne $newExpected) { throw 'installed exe hash mismatch' }
Write-Host 'daemon exe swapped (arbiter build)'
sc.exe start AegisNids | Out-Host
if (-not (Wait-Service 'AegisNids' 'Running' 40)) { throw 'AegisNids failed to restart' }
Start-Sleep -Seconds 20

# 2. stage1: expect npacpcap_primary (nose running)
Snapshot 'stage1-npcap-primary'

# 3. kill nose; expect kernel_fallback after the 10 s stall window
$nose = Get-Process -Name 'aegis-nose' -ErrorAction SilentlyContinue
if ($nose) {
    Write-Host "killing aegis-nose.exe PID $($nose.Id)"
    Stop-Process -Id $nose.Id -Force
} else {
    Write-Warning 'aegis-nose.exe not running at stage2 (already absent)'
}
Start-Sleep -Seconds 18
Snapshot 'stage2-kernel-fallback'

# 4. restart nose
Start-Process -FilePath 'C:\Program Files\AEGIS NIDS\runtime\aegis-nose.exe' -WindowStyle Hidden
Start-Sleep -Seconds 15
Snapshot 'stage3-npcap-primary-again'

Write-Host 'E5-C SEQUENCE DONE — inspect queue-stage*.txt for mode/reason/shadow_rows'
Stop-Transcript
