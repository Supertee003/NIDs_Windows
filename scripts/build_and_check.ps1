[CmdletBinding()]
param(
    [switch]$Start,
    [switch]$SkipNative,
    [switch]$RunFixture
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/5] Stopping stale AEGIS processes" -ForegroundColor Cyan
Get-Process aegis_nids -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
sc.exe stop AegisNids 2>$null | Out-Null
Start-Sleep -Milliseconds 500

if (-not $SkipNative) {
    Write-Host "[2/5] Building native helpers" -ForegroundColor Cyan
    cmake --build build --config Release
}

Write-Host "[3/5] Building Zig core" -ForegroundColor Cyan
$out = Join-Path $root 'zig-out/bin/aegis_nids.exe'
$temp = Join-Path $root 'zig-out/bin/aegis_nids.new.exe'
if (Test-Path $temp) { Remove-Item $temp -Force }

zig build-exe src/main.zig -ODebug -target x86_64-windows -lc `
    -Ltarget/release -laegis_pep `
    -Lbuild/Release -laegis_fim_helper -laegis_etw_helper `
    -L"$env:LOCALAPPDATA/NpcapSDK/Lib/x64" -lwpcap -lPacket `
    -lws2_32 -ladvapi32 -lkernel32 -luser32 -lole32 -lsecur32 -lntdll -ltdh `
    "-femit-bin=$temp"

if (-not (Test-Path $temp)) { throw "Core build produced no output: $temp" }
Move-Item $temp $out -Force
Get-Item $out | Select-Object FullName,Length,LastWriteTime

Write-Host "[4/5] Checking installed native services" -ForegroundColor Cyan
sc.exe query AegisWfp 2>$null
sc.exe query aegis_wfp 2>$null
Get-Service AegisNids -ErrorAction SilentlyContinue

if ($Start) {
    Write-Host "[5/5] Starting daemon" -ForegroundColor Cyan
    Start-Process $out -WorkingDirectory $root
    Start-Sleep -Seconds 3
    if ($RunFixture) {
        python scripts/aegis_event_gen.py --pipe --fixture xss --count 1
    }
    python tools/aegisctl.py health
    python tools/aegisctl.py metrics
    python tools/aegisctl.py events stats
} else {
    Write-Host "[5/5] Build complete. Use -Start for runtime validation." -ForegroundColor Green
}
