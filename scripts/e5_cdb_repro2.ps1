# E5-C-1 stack capture v2: stop on PANIC int3 (0x80000003) AND heap
# corruption (0xc0000374), cwd = runtime dir to mirror the service condition,
# print a symbolized stack at the first hit.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$cdbLog = Join-Path $evDir 'e5c-cdb2.log'
$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$exe = Join-Path (Join-Path (Join-Path $repo 'zig-out') 'bin') 'aegis_nids.exe'
$cwdSvc = 'C:\Program Files\AEGIS NIDS\runtime'
Start-Transcript -Path (Join-Path $evDir 'e5c-cdb2-run.log') -Force

# 1. Stop the service so the pipe/exe are free; wait for Stopped.
sc.exe stop AegisNids | Out-Host
$deadline = (Get-Date).AddSeconds(60)
do {
    $s = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
    if ($s -and $s.Status -eq 'Stopped') { break }
    Start-Sleep -Milliseconds 500
} while ((Get-Date) -lt $deadline)
if (-not ($s -and $s.Status -eq 'Stopped')) { throw 'AegisNids never reached Stopped' }
Write-Host 'service fully stopped'

# 2. Run the daemon under cdb with both breakpoints.
$cmds = 'sxe 0x80000003; sxe 0xc0000374; g; k 50; q'
$argsList = @(
    '-y', (Join-Path (Join-Path $repo 'zig-out') 'bin'),
    '-logo', $cdbLog,
    '-c', ('"' + $cmds + '"'),
    $exe
)
$proc = Start-Process -FilePath $cdb -ArgumentList $argsList -WorkingDirectory $cwdSvc -WindowStyle Hidden -PassThru
Write-Host "cdb running pid $($proc.Id) cwd=$cwdSvc"

# 3. Wait up to 120 s for cdb to finish (crash captured or clean exit).
$deadline = (Get-Date).AddSeconds(120)
do {
    Start-Sleep -Seconds 5
} while (-not $proc.HasExited -and (Get-Date) -lt $deadline)
if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    Write-Host 'cdb worker killed after timeout (no crash captured)'
} else {
    Write-Host ("cdb exited with code " + $proc.ExitCode)
}
Get-Content $cdbLog -ErrorAction SilentlyContinue | Select-Object -Last 90 | Out-Host

# 4. Bring the service back only if not already running.
$svc = Get-Service -Name 'AegisNids' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Running') {
    sc.exe start AegisNids | Out-Host
    Start-Sleep -Seconds 10
}
sc.exe query AegisNids | Out-Host
Stop-Transcript
