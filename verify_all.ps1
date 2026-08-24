<#
verify_all.ps1 - AEGIS NIDS Automated Verification
#
Checks that all files exist, zig build passes, and produces
#a summary of the complete project state.
#
#Usage: powershell -ExecutionPolicy Bypass -File verify_all.ps1
#>

$ErrorActionPreference = 'Continue'
Set-StrictMode -Off

$srcDir = Join-Path $PSScriptRoot 'core'
$failCount = 0
$passCount = 0

Write-Host ''
Write-Host '============================================================'
Write-Host ' AEGIS NIDS - Automated Verification'
Write-Host '============================================================'
Write-Host ''

# ============================================================
# 1. Check Zig source files
# ============================================================
Write-Host '[1/4] Checking Zig source files...'

$zigFiles = @(
    'nids_main.zig',
    'nids_analyze.zig',
    'windows_capture.zig',
    'nids_capture.zig',
    'minifilter_reader.zig',
    'pipe_monitor.zig',
    'wfp_ioctl.zig',
    'bridge_init.zig'
)

foreach ($f in $zigFiles) {
    $path = Join-Path $srcDir $f
    if (Test-Path $path) {
        $lines = (Get-Content $path | Measure-Object -Line).Lines
        Write-Host "  [OK] $f ($lines lines)"
        $passCount++
    } else {
        Write-Host "  [FAIL] $f MISSING" -ForegroundColor Red
        $failCount++
    }
}

# ============================================================
# 2. Check kernel driver files
# ============================================================
Write-Host ''
Write-Host '[2/4] Checking kernel driver sources...'

$wfpDir = Join-Path $PSScriptRoot 'drivers\wfp_callout'
$miniDir = Join-Path $PSScriptRoot 'drivers\minifilter'

$wfpFiles = @('aegis_wfp.h', 'aegis_wfp.c', 'aegis_wfp_callout.c', 'aegis_wfp_comm.c')
$miniFiles = @('aegis_minifilter.h', 'aegis_minifilter.c', 'aegis_minifilter_comm.c', 'aegis_minifilter_file.c', 'aegis_minifilter_proc.c')

foreach ($f in $wfpFiles) {
    $path = Join-Path $wfpDir $f
    if (Test-Path $path) {
        Write-Host "  [OK] wfp_callout\$f"
        $passCount++
    } else {
        Write-Host "  [FAIL] wfp_callout\$f MISSING" -ForegroundColor Red
        $failCount++
    }
}

foreach ($f in $miniFiles) {
    $path = Join-Path $miniDir $f
    if (Test-Path $path) {
        Write-Host "  [OK] minifilter\$f"
        $passCount++
    } else {
        Write-Host "  [FAIL] minifilter\$f MISSING" -ForegroundColor Red
        $failCount++
    }
}

# Check built .sys files
Write-Host ''
$wfpSys = Join-Path $wfpDir 'aegis_wfp.sys'
$miniSys = Join-Path $miniDir 'aegis_minifilter.sys'
if (Test-Path $wfpSys) {
    $size = (Get-Item $wfpSys).Length
    Write-Host "  [OK] aegis_wfp.sys ($size bytes)" -ForegroundColor Green
    $passCount++
} else {
    Write-Host '  [--] aegis_wfp.sys not built (run build_all.bat)'
}
if (Test-Path $miniSys) {
    $size = (Get-Item $miniSys).Length
    Write-Host "  [OK] aegis_minifilter.sys ($size bytes)" -ForegroundColor Green
    $passCount++
} else {
    Write-Host '  [--] aegis_minifilter.sys not built (run build_all.bat)'
}

# ============================================================
# 3. Check build artifacts
# ============================================================
Write-Host ''
Write-Host '[3/4] Checking build artifacts...'

$buildZig = Join-Path $PSScriptRoot 'build.zig'
if (Test-Path $buildZig) {
    Write-Host '  [OK] build.zig'
    $passCount++
} else {
    Write-Host '  [FAIL] build.zig MISSING' -ForegroundColor Red
    $failCount++
}

$exePath = Join-Path $PSScriptRoot 'zig-out\bin\aegis-nids.exe'
if (Test-Path $exePath) {
    $size = (Get-Item $exePath).Length
    Write-Host "  [OK] zig-out\bin\aegis-nids.exe ($size bytes)" -ForegroundColor Green
    $passCount++
} else {
    Write-Host '  [--] aegis-nids.exe not built yet'
}

# Check INF files for driver installation
$wfpInf = Join-Path $wfpDir 'aegis_wfp.inf'
$miniInf = Join-Path $miniDir 'aegis_minifilter.inf'
if (Test-Path $wfpInf) { Write-Host '  [OK] aegis_wfp.inf'; $passCount++ } else { Write-Host '  [--] aegis_wfp.inf (needed for deploy)' }
if (Test-Path $miniInf) { Write-Host '  [OK] aegis_minifilter.inf'; $passCount++ } else { Write-Host '  [--] aegis_minifilter.inf (needed for deploy)' }

# ============================================================
# 4. Zig build test
# ============================================================
Write-Host ''
Write-Host '[4/4] Running zig build...'

$zigExe = Get-Command 'zig' -ErrorAction SilentlyContinue
if (-not $zigExe) {
    Write-Host '  [SKIP] zig not found in PATH'
} else {
    $proc = Start-Process -FilePath 'zig' -ArgumentList 'build' -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput (Join-Path $PSScriptRoot 'verify_build.stdout') `
        -RedirectStandardError (Join-Path $PSScriptRoot 'verify_build.stderr')
    if ($proc.ExitCode -eq 0) {
        $exe = Join-Path $PSScriptRoot 'zig-out\bin\aegis-nids.exe'
        if (Test-Path $exe) {
            $size = (Get-Item $exe).Length
            Write-Host "  [OK] zig build passed -> aegis-nids.exe ($size bytes)" -ForegroundColor Green
            $passCount++
        } else {
            Write-Host '  [OK] zig build passed (no exe in zig-out?)'
            $passCount++
        }
    } else {
        Write-Host '  [FAIL] zig build failed!' -ForegroundColor Red
        $failCount++
        Get-Content (Join-Path $PSScriptRoot 'verify_build.stderr') -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Host "    $_" }
    }
}

# ============================================================
# SUMMARY
# ============================================================
Write-Host ''
Write-Host '============================================================'
Write-Host " RESULTS: $passCount passed, $failCount failed"
Write-Host '============================================================'
Write-Host ''