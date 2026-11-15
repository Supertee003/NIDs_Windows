# E5-C-1 crash repro: run the new daemon console-mode from runtime dir,
# capture output, then restore the old daemon and restart the service.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$runtimeDir = 'C:\Program Files\AEGIS NIDS\runtime'
$exe = Join-Path $runtimeDir 'aegis_nids.exe'
$bak = Join-Path $evDir 'aegis_nids_old_e19c76c3.exe'
$new = Join-Path $repo 'zig-out\bin\aegis_nids.exe'
$log = Join-Path $evDir 'e5c-crash-console.log'
Start-Transcript -Path (Join-Path $evDir 'e5c-repro.log') -Force

# Wait until the service fully stops (STOP_PENDING does not release the exe).
$deadline = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $deadline) {
    $s = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 500
}
if (-not ($s -and $s.Status -eq 'Stopped')) { throw 'AegisNids never reached Stopped' }
Write-Host 'service fully stopped'
Copy-Item $new $exe -Force
Write-Host 'new exe staged in runtime dir'

# Console run with output capture; hard cap 40 s.
$proc = Start-Process -FilePath $exe -WorkingDirectory $runtimeDir -RedirectStandardOutput $log -RedirectStandardError "$env:TEMP\aegis_stderr.log" -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 35
if (-not $proc.HasExited) {
    Write-Host ("still running after 35 s (no crash) - pid " + $proc.Id + ", stopping")
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "exited with code $($proc.ExitCode)"
}
Get-Content $log -ErrorAction SilentlyContinue | Out-Host
Write-Host '--- stderr ---'
if (Test-Path "$env:TEMP\aegis_stderr.log") { Get-Content "$env:TEMP\aegis_stderr.log" | Out-Host }

# Restore + restart service either way.
Copy-Item $bak $exe -Force
sc.exe start AegisNids | Out-Host
Start-Sleep -Seconds 10
sc.exe query AegisNids | Out-Host
Stop-Transcript
