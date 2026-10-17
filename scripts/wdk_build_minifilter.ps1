# AEGIS Minifilter Driver - Production Build (WDK toolchain)
# Builds the authoritative kernel sources from drivers/minifilter/ into an
# x64 .sys using the Windows Driver Kit, without requiring a .vcxproj.
# Modeled on scripts/wdk_build_production.ps1 (the proven WFP build path).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\wdk_build_minifilter.ps1
#
# Differences from the WFP build (each is deliberate):
#   - NTDDI_VERSION=0x0A000008 (NTDDI_WIN10_VB): the sources use
#     ExAllocatePool2, which wdm.h only declares at
#     "#if (NTDDI_VERSION >= NTDDI_WIN10_VB)". The WFP script's 0x0A000000
#     would leave the declaration hidden and fail the compile.
#   - fltMgr.lib + fltKernel.h are REQUIRED (the filter-manager runtime).
#   - No NDIS defines: the minifilter never touches NDIS/NBL.
#
# Fail-soft: every dependency is probed first; missing tooling prints the
# exact install step instead of half-compiling.

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$failCount = 0
function Info($msg)    { Write-Host "[build] $msg" }
function Warn($msg)    { Write-Host "[build] WARN: $msg" -ForegroundColor Yellow }
function Fail($msg)    { Write-Host "[build] FAIL: $msg" -ForegroundColor Red; $script:failCount++ }

# ----------------------------------------------------------------
# 1. Locate Visual Studio (cl.exe + link.exe) via vswhere
# ----------------------------------------------------------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$vsRoot = $null
if (Test-Path $vswhere) {
    $vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (-not $vsRoot) {
    Fail "Visual Studio C++ build tools not found (needs Microsoft.VisualStudio.Component.VC.Tools.x86.x64)."
} else {
    Info "VS installation: $vsRoot"
    $msvcDirs = Get-ChildItem -Directory (Join-Path $vsRoot "VC\Tools\MSVC") -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending
    if (-not $msvcDirs) {
        Fail "No MSVC toolset under VC\Tools\MSVC."
    } else {
        $msvc = $msvcDirs[0].FullName
        $cl = Join-Path $msvc "bin\Hostx64\x64\cl.exe"
        $link = Join-Path $msvc "bin\Hostx64\x64\link.exe"
        $msvcLib = Join-Path $msvc "lib\x64"
        if ((Test-Path $cl) -and (Test-Path $link) -and (Test-Path $msvcLib)) {
            Info "MSVC: $msvc"
        } else {
            Fail "cl.exe/link.exe or lib\x64 missing under $msvc."
        }
    }
}

# ----------------------------------------------------------------
# 2. Locate WDK km headers/libs, ntoskrnl.lib, fltKernel.h, fltMgr.lib
# ----------------------------------------------------------------
$kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$kmDirs = Get-ChildItem -Directory (Join-Path $kitsRoot "Include") -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^10\.0\.\d+' } |
    Sort-Object Name -Descending
if (-not $kmDirs) {
    Fail "Windows 10/11 SDK+WDK headers not found under $kitsRoot\Include."
} else {
    $wdkVer = $null
    $kmLib = $null
    foreach ($d in $kmDirs) {
        $candidate = Join-Path $kitsRoot "Lib\$($d.Name)\km\x64"
        if ((Test-Path (Join-Path $candidate "ntoskrnl.lib")) -and
            (Test-Path (Join-Path $candidate "fltMgr.lib"))) {
            $wdkVer = $d.Name
            $kmLib = $candidate
            break
        }
    }
    if (-not $wdkVer) {
        Fail "No WDK with BOTH ntoskrnl.lib and fltMgr.lib under $kitsRoot\Lib\*\km\x64."
        Fail "Reinstall the WDK (not just the Windows SDK)."
    } else {
        $umInc = Join-Path $kitsRoot "Include\$wdkVer\um"
        $kmInc = Join-Path $kitsRoot "Include\$wdkVer\km"
        $sharedInc = Join-Path $kitsRoot "Include\$wdkVer\shared"
        $kmCrt = Join-Path $kmInc "crt"
        Info "WDK version: $wdkVer"
        Info "Kernel libs OK: $kmLib (ntoskrnl.lib + fltMgr.lib)"
        foreach ($h in @("fltKernel.h", "wdm.h", "ntddk.h")) {
            $found = (Test-Path (Join-Path $kmInc $h)) -or
                     (Test-Path (Join-Path $sharedInc $h)) -or
                     (Test-Path (Join-Path $umInc $h))
            if (-not $found) {
                Fail "Missing header: $h (looked in km, shared, um under $wdkVer)."
            }
        }
        if ($failCount -eq 0) { Info "Headers OK (fltKernel.h, wdm.h, ntddk.h)" }
    }
}

# ----------------------------------------------------------------
# 3. Validate driver source presence (authoritative sources only)
# ----------------------------------------------------------------
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$srcDir = Join-Path $repoRoot "drivers\minifilter"
$srcFiles = @(
    "aegis_minifilter.c",
    "aegis_minifilter_comm.c",
    "aegis_minifilter_file.c",
    "aegis_minifilter_proc.c"
)
foreach ($f in $srcFiles) {
    $p = Join-Path $srcDir $f
    if (-not (Test-Path $p)) {
        Fail "Driver source not found: $p"
    } else {
        Info "Driver source: $f ($((Get-Item $p).Length) bytes)"
    }
}

if ($failCount -gt 0) {
    Write-Host ""
    Fail "$failCount dependency problem(s) - fix them and re-run. Nothing was compiled."
    exit 1
}

# ----------------------------------------------------------------
# 4. Compile authoritative sources + link (link /DRIVER)
# ----------------------------------------------------------------
$outDir = Join-Path $repoRoot "build\x64\minifilter"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$objFiles = @()
$sysFile = Join-Path $outDir "aegis_minifilter.sys"

# Include order: shared (basetsd.h, ntdef.h) first, then km, then um fallback.
$includeArgs = @("/I$sharedInc", "/I$kmInc", "/I$umInc")
if (Test-Path $kmCrt) { $includeArgs += "/I$kmCrt" }

foreach ($f in $srcFiles) {
    $srcPath = Join-Path $srcDir $f
    $objPath = Join-Path $outDir ([System.IO.Path]::GetFileNameWithoutExtension($f) + ".obj")
    $objFiles += $objPath
    Info "Compiling $f (x64, kernel mode)..."
    # /wd4324 (WDK header padding noise) /wd4100 (unreferenced params) - cosmetic.
    & $cl /nologo /kernel /W4 /GS- /O2 /wd4324 /wd4100 /c `
        /D_AMD64_ /DAMD64 /D_WIN64 `
        /DNTDDI_VERSION=0x0A000008 `
        $includeArgs `
        /Fo"$objPath" `
        "$srcPath" 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { Fail "cl.exe failed on $f (exit $LASTEXITCODE)."; exit 1 }
}

Info "Linking aegis_minifilter.sys..."
# Minifilter link libs:
#   ntoskrnl.lib               - kernel core (Ke*/Ex*/Ps*)
#   hal.lib                    - hardware abstraction
#   bufferoverflowfastfailk.lib- __fastfail (WDK generic)
#   fltMgr.lib                 - FltRegisterFilter / FltStartFiltering /
#                                FltCreateCommunicationPort / FltGetFileNameInformation
#   wdmsec.lib                 - soft-add (only pulled in if referenced)
$umLib = Join-Path $kitsRoot "Lib\$wdkVer\um\x64"
$linkLibs = @("ntoskrnl.lib", "hal.lib", "bufferoverflowfastfailk.lib", "fltMgr.lib")
foreach ($l in @("wdmsec.lib")) {
    if (Test-Path (Join-Path $kmLib $l)) { $linkLibs += $l }
}
$linkArgs = @(
    "/nologo", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:DriverEntry",
    # EVT-230: FORCE_INTEGRITY (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
    # is mandatory for PsSetCreateProcessNotifyRoutineEx - the API returns
    # STATUS_ACCESS_DENIED for images without it (documented WDK return
    # code; observed 2026-10-17 as SCM start error 5 with a register-then-
    # unload FilterManager event pair). Consequence: this .sys MUST be
    # signed before it can load (CI enforces the embedded signature on
    # FORCE_INTEGRITY images; test-signing + machine-trusted cert OK).
    "/INTEGRITYCHECK",
    "/NODEFAULTLIB",
    "/OUT:$sysFile"
) + $objFiles + @(
    "/LIBPATH:$kmLib", "/LIBPATH:$msvcLib", "/LIBPATH:$umLib"
) + $linkLibs
& $link $linkArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { Fail "link.exe failed (exit $LASTEXITCODE)."; exit 1 }

if (-not (Test-Path $sysFile)) { Fail "aegis_minifilter.sys was not produced."; exit 1 }

# ----------------------------------------------------------------
# 5. Summary
# ----------------------------------------------------------------
$hash = (Get-FileHash $sysFile -Algorithm SHA256).Hash
Info "BUILD OK: $sysFile ($((Get-Item $sysFile).Length) bytes)"
Info "SHA-256:  $hash"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. powershell -ExecutionPolicy Bypass -File scripts\minifilter_sign.ps1   (test-sign the .sys)"
Write-Host "  2. powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 install"
Write-Host "  3. powershell -ExecutionPolicy Bypass -File scripts\minifilter_service.ps1 start"
exit 0
