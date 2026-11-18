# E5-C-1: harvest WER crash dumps for aegis_nids.exe and symbolize the stacks
# with the build PDB via cdb.
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$repo = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Set-Location $repo
$evDir = Join-Path (Join-Path $repo 'admin-evidence') 'e5-host-proof-20261026'
$werRoot = Join-Path $evDir 'wer'
New-Item -ItemType Directory -Force -Path $werRoot | Out-Null
$cdb = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
$symPath = Join-Path (Join-Path $repo 'zig-out') 'bin'
Start-Transcript -Path (Join-Path $evDir 'e5c-wer-harvest.log') -Force

$dirs = Get-ChildItem 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'AppCrash_aegis_nids*' }
foreach ($d in $dirs) {
    $dest = Join-Path $werRoot $d.Name
    if (Test-Path $dest) { Write-Host "already harvested: $d.Name"; continue }
    Write-Host "--- harvesting $($d.Name) ($($d.LastWriteTime)) ---"
    Copy-Item $d.FullName $dest -Recurse -Force -ErrorAction SilentlyContinue
    $wer = Join-Path $dest 'Report.wer'
    if (Test-Path $wer) {
        Select-String -Path $wer -Pattern '^EventType=|^Sig\[' | Out-Host
    }
    $dump = Get-ChildItem $dest -Filter '*.dmp' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dump) {
        Write-Host "dump: $($dump.FullName)"
        $cdbLog = Join-Path $dest 'cdb-analysis.log'
        $cmds = 'k 60; lm m aegis*; q'
        $argsList = @(
            '-y', $symPath,
            '-logo', ('"' + $cdbLog + '"'),
            '-z', ('"' + $dump.FullName + '"'),
            '-c', ('"' + $cmds + '"')
        )
        $p = Start-Process -FilePath $cdb -ArgumentList $argsList -WorkingDirectory $repo -WindowStyle Hidden -PassThru
        Wait-Process -Id $p.Id -Timeout 120 -ErrorAction SilentlyContinue
        if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        Write-Host '--- cdb stack ---'
        if (Test-Path $cdbLog) {
            Get-Content $cdbLog | Select-Object -Last 80 | Out-Host
        }
    } else {
        Write-Host 'no dump file found in this report'
    }
}
Stop-Transcript
