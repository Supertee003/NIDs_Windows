# E5-C-1: enable WER LocalDumps (full) for aegis_nids.exe, trigger one
# bare console crash of the new daemon, verify the .dmp lands.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$dumpDir = Join-Path $evDir 'wer-localdumps'
New-Item -ItemType Directory -Force -Path $dumpDir | Out-Null
$runtimeDir = 'C:\Program Files\AEGIS NIDS\runtime'
$exe = Join-Path $runtimeDir 'aegis_nids.exe'
$new = Join-Path $repo 'zig-out\bin\aegis_nids.exe'
$bak = Join-Path $evDir 'aegis_nids_old_e19c76c3.exe'
Start-Transcript -Path (Join-Path $evDir 'e5c-localdumps-run.log') -Force

# 1. Enable LocalDumps for our image (DumpType=2 full).
$ldRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
New-Item -Path $ldRoot -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path $ldRoot -Name 'DumpFolder' -Value $dumpDir -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -Path $ldRoot -Name 'DumpType' -Value 2 -PropertyType DWord -Force | Out-Null
$imgKey = Join-Path $ldRoot 'aegis_nids.exe'
New-Item -Path $imgKey -Force | Out-Null
New-ItemProperty -Path $imgKey -Name 'DumpType' -Value 2 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $imgKey -Name 'DumpFolder' -Value $dumpDir -PropertyType ExpandString -Force | Out-Null
Write-Host 'LocalDumps enabled for aegis_nids.exe'

# 2. Stop service, stage new exe, run bare (mirror service condition) for up
#    to 75 s or until it exits on its own.
sc.exe stop AegisNids | Out-Host
$deadline = (Get-Date).AddSeconds(60)
do {
    $s = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if (-not ($s -and $s.Status -eq 'Stopped')) { throw 'AegisNids never reached Stopped' }
Copy-Item $new $exe -Force
Write-Host 'new exe staged, running bare from runtime dir'
$p = Start-Process -FilePath $exe -WorkingDirectory $runtimeDir -WindowStyle Hidden -PassThru
$deadline = (Get-Date).AddSeconds(75)
while (-not $p.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
if (-not $p.HasExited) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Write-Host 'daemon still alive after 75 s (no crash) — killing'
} else {
    Write-Host ("daemon exited with code " + $p.ExitCode)
}
Get-ChildItem $dumpDir -Filter '*.dmp' -ErrorAction SilentlyContinue | Out-Host

# 3. Restore old exe and restart the service.
Copy-Item $bak $exe -Force
sc.exe start AegisNids | Out-Host
Start-Sleep -Seconds 10
sc.exe query AegisNids | Out-Host
Stop-Transcript
