# E5-C-1 final: cdb-backed repro of the daemon startup int3 crash.
# Elevated. Steps: stop AegisNids (poll to Stopped), run zig-out daemon under
# cdb with symbol path pointing at the build dir, sxe on int3 (STATUS_BREAKPOINT),
# print the stack, then restore/restart the service.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
New-Item -ItemType Directory -Force -Path $evDir | Out-Null
$cdbLog = Join-Path $evDir 'e5c-cdb.log'
$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
Start-Transcript -Path (Join-Path $evDir 'e5c-cdb-run.log') -Force

# 1. Stop service and WAIT for Stopped (releases pipe + exe).
sc.exe stop AegisNids | Out-Host
$deadline = (Get-Date).AddSeconds(60)
do {
    $s = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if (-not ($s -and $s.Status -eq 'Stopped')) { throw 'AegisNids never reached Stopped' }
Write-Host 'service fully stopped'

# 2. Run the daemon under cdb (int3 stop, stack print, quit).
$cmds = 'sxe 0x80000003; g; k 50; q'
$argsList = @(
    '-y', (Join-Path (Join-Path $repo 'zig-out') 'bin'),
    '-logo', $cdbLog,
    '-c', ('"' + $cmds + '"'),
    (Join-Path (Join-Path (Join-Path $repo 'zig-out') 'bin') 'aegis_nids.exe')
)
$proc = Start-Process -FilePath $cdb -ArgumentList $argsList -WorkingDirectory $repo -WindowStyle Hidden -PassThru
Write-Host "cdb running pid $($proc.Id)"

# 3. Give it 45 s to reach the crash, then terminate.
Start-Sleep -Seconds 45
if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host 'cdb worker stopped after timeout'
} else {
    Write-Host ("cdb exited with code " + $proc.ExitCode)
}
Get-Content $cdbLog -ErrorAction SilentlyContinue | Select-Object -Last 70 | Out-Host

# 4. Bring the service back only when it is not already running.
$svc = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Running') {
    sc.exe start AegisNids | Out-Host
    Start-Sleep -Seconds 10
}
sc.exe query AegisNids | Out-Host
Stop-Transcript
