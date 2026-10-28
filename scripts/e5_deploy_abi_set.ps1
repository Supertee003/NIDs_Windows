# E5-C-2: full staged deploy of the daemon AND its dependency DLLs.
# Preflight: assert every needed export exists in the candidate DLLs before
# anything is touched. All backups recorded for rollback.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$runDir = 'C:\Program Files\AEGIS NIDS\runtime'
$srcDir = Join-Path $repo 'zig-out\bin'
$result = [ordered]@{
    started_at = [DateTime]::Now.ToString('o')
    preflight  = @()
    copied     = @()
    rolled_back = $false
}
Start-Transcript -Path (Join-Path $evDir 'e5c-abi-deploy.log') -Force

function Get-Sha256 { param([string]$Path)
    return (Get-FileHash $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

# 1. Preflight: every export that the deployed set lacks must be filled by
#    a file in THIS deploy's copy list; otherwise refuse.
$copyList = @('aegis_nids.exe', 'aegis_pep.dll', 'aegis_wfp_user.dll',
              'aegis_ipc.dll', 'aegis_etw_helper.dll', 'aegis_fim_helper.dll',
              'sec_monitor.dll')
$diff = & python scripts/e5_pe_export_diff.py @copyList 2>&1 | Out-String
$result.preflight += ($diff.Trim() -split "`r?`n")[-1]
if ($LASTEXITCODE -ne 0) {
    throw "preflight: missing exports are NOT covered by this deploy set"
}
Write-Host 'preflight OK (all missing exports covered by this deploy set)'

# 2. Stop the service and wait fully stopped.
sc.exe stop AegisNids | Out-Host
$deadline = (Get-Date).AddSeconds(60)
do {
    $s = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if (-not ($s -and $s.Status -eq 'Stopped')) { throw 'AegisNids never reached Stopped' }

# 3. Backup + copy the dependency set. Only files that actually change.
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bakDir = Join-Path $evDir "runtime-before-$stamp"
New-Item -ItemType Directory -Force -Path $bakDir | Out-Null
foreach ($f in @('aegis_nids.exe','aegis_pep.dll','aegis_wfp_user.dll',
                 'aegis_ipc.dll','aegis_etw_helper.dll','aegis_fim_helper.dll',
                 'sec_monitor.dll')) {
    $src = Join-Path $srcDir $f
    $dst = Join-Path $runDir $f
    if (-not (Test-Path $src)) { Write-Host "skip missing source: $f"; continue }
    $srcH = Get-Sha256 $src
    $dstH = if (Test-Path $dst) { Get-Sha256 $dst } else { 'ABSENT' }
    if ($srcH -eq $dstH) { Write-Host "unchanged: $f"; continue }
    if (Test-Path $dst) { Copy-Item $dst (Join-Path $bakDir $f) -Force }
    else { 'ABSENT' | Set-Content (Join-Path $bakDir ($f + '.was-absent')) -Encoding utf8 }
    Copy-Item $src $dst -Force
    if ((Get-Sha256 $dst) -ne $srcH) { throw "copy verify failed for $f" }
    $short = { param($h) if ($h) { $h.Substring(0, [Math]::Min(8, $h.Length)) } else { '?' } }
    $result.copied += ("$f ({0} -> {1})" -f (& $short $dstH), (& $short $srcH))
    Write-Host "deployed: $f"
}

# 4. Restart, wait RUNNING, sanity check health.
sc.exe start AegisNids | Out-Host
$deadline = (Get-Date).AddSeconds(90)
do {
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    $ok = $false
    try {
        $o = & python tools/aegisctl.py status 2>&1 | Out-String
        $ok = ($o -match 'State:\s*RUNNING')
    } catch {}
    if ($ok) { break }
} while ((Get-Date) -lt $deadline)
$health = & python tools/aegisctl.py status 2>&1 | Out-String
Write-Host $health
if ($health -notmatch 'State:\s*RUNNING') {
    Write-Host 'ROLLBACK: service failed health check'
    foreach ($f2 in Get-ChildItem $bakDir -File) {
        $t = $f2.Name -replace '\.was-absent$', ''
        if ($f2.Name -like '*.was-absent') {
            Remove-Item (Join-Path $runDir $t) -Force -ErrorAction SilentlyContinue
            Write-Host "rollback (remove new-only file): $t"
        } else {
            Copy-Item $f2.FullName (Join-Path $runDir $t) -Force
            Write-Host "rollback: $t"
        }
    }
    sc.exe start AegisNids | Out-Host
    $result.rolled_back = $true
}

$result.finished_at = [DateTime]::Now.ToString('o')
$result | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $evDir 'e5c-abi-deploy-result.json')
Stop-Transcript
if ($result.rolled_back) { exit 1 }
