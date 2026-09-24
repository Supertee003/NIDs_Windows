# AEGIS WFP Driver - Production Build (P4 / Phase S toolchain)
# Builds drivers/wfp_callout/{aegis_wfp.c, aegis_wfp_callout.c,
# aegis_wfp_comm.c} into a signed-ready x64 .sys using the Windows
# Driver Kit (WDK) toolchain, without requiring a .vcxproj.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\wdk_build_production.ps1
#
# Fail-soft: every dependency is probed first; missing tooling prints
# the exact install step instead of half-compiling.

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$failCount = 0
$fwpkclntPath = $null
$fwpmkLibPath = $null
$useFwpkclntForFwpm = $false
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
    Fail "Install: https://visualstudio.microsoft.com/downloads/ (Build Tools for Visual Studio)."
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
        $msvcLib = Join-Path $msvc "lib\x64"        # LIBCMT.lib, libcmt.lib, libvcruntime.lib
        if ((Test-Path $cl) -and (Test-Path $link) -and (Test-Path $msvcLib)) {
            Info "MSVC: $msvc"
            Info "MSVC libs: $msvcLib"
        } else {
            Fail "cl.exe/link.exe or lib\x64 missing under $msvc."
        }
    }
}

# ----------------------------------------------------------------
# 2. Locate WDK um + km headers/libs and ntoskrnl.lib
# ----------------------------------------------------------------
# WDK installs versions like "10.0.22621.0" under Include\<ver> and
# Lib\<ver>. Filter to real versioned dirs (skip "wdf", "netfx", etc.)
# and pick the newest one that actually contains ntoskrnl.lib.
$kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10"
$kmDirs = Get-ChildItem -Directory (Join-Path $kitsRoot "Include") -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^10\.0\.\d+' } |
    Sort-Object Name -Descending
if (-not $kmDirs) {
    Fail "Windows 10/11 SDK+WDK headers not found under $kitsRoot\Include."
    Fail "Found these dirs (none match WDK version pattern 10.0.*):"
    Get-ChildItem -Directory (Join-Path $kitsRoot "Include") -ErrorAction SilentlyContinue |
        ForEach-Object { Fail "  - $($_.Name)" }
    Fail "Install the WDK: https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
} else {
    $wdkVer = $null
    $kmLib = $null
    foreach ($d in $kmDirs) {
        $candidate = Join-Path $kitsRoot "Lib\$($d.Name)\km\x64"
        if (Test-Path (Join-Path $candidate "ntoskrnl.lib")) {
            $wdkVer = $d.Name
            $kmLib = $candidate
            break
        }
    }
    if (-not $wdkVer) {
        Fail "ntoskrnl.lib not found under any WDK version at $kitsRoot\Lib\*\km\x64."
        Fail "Detected Include versions:"
        $kmDirs | ForEach-Object { Fail "  - $($_.Name)" }
        Fail "This means WDK headers are installed but WDK libraries are not."
        Fail "Reinstall WDK (not just Windows SDK) from https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
    } else {
        $umInc = Join-Path $kitsRoot "Include\$wdkVer\um"
        $kmInc = Join-Path $kitsRoot "Include\$wdkVer\km"
        $sharedInc = Join-Path $kitsRoot "Include\$wdkVer\shared"
        $kmCrt = Join-Path $kmInc "crt"
        Info "WDK version: $wdkVer"
        Info "ntoskrnl.lib OK at $kmLib"
        # Pre-flight: verify the headers aegis_wfp.c actually needs exist.
        # initguid.h lives in km\ (and historically in shared\); wdm.h in km\;
        # fwpsk.h in km\; ndis.h in km\ (required for NDIS types).
        # Missing any of these means WDK install is partial (SDK-only without WDK).
        foreach ($h in @("initguid.h", "wdm.h", "ntddk.h", "fwpsk.h", "ndis.h", "fwpmk.h")) {
            $found = (Test-Path (Join-Path $kmInc $h)) -or
                     (Test-Path (Join-Path $sharedInc $h)) -or
                     (Test-Path (Join-Path $umInc $h))
            if (-not $found) {
                Fail "Missing header: $h (looked in km, shared, um under $wdkVer)."
                Fail "This means WDK headers are partial. Reinstall WDK from https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
            }
        }
        if ($failCount -eq 0) { Info "Kernel-mode headers OK (initguid.h, wdm.h, ntddk.h, fwpsk.h, ndis.h, fwpmk.h)" }
        # Pre-flight: fwpkclnt.lib is mandatory (FWPS runtime - Fwps*).
        if (-not (Test-Path (Join-Path $kmLib "fwpkclnt.lib"))) {
            Fail "Missing kernel lib: fwpkclnt.lib (expected at $kmLib). WDK install is partial - reinstall the WDK."
        } else {
            $fwpkclntPath = Join-Path $kmLib "fwpkclnt.lib"
        }
    }
}

# ----------------------------------------------------------------
# 2b. Resolve FWPM management lib (Fwpm*) - dynamic, any WDK layout
# ----------------------------------------------------------------
# Fwpm* (FwpmEngineOpen0 / FwpmCalloutAdd0 / FwpmFilterAdd0 ...) used to
# ship as fwpmk.lib. Recent/Insider WDK builds may merge those symbols
# into fwpkclnt.lib or drop the lib entirely. Decide dynamically:
#   1. dumpbin fwpkclnt.lib - does it already export Fwpm*?
#   2. else look for fwpmk*.lib in known Lib\<ver> subfolders
#   3. else search Lib\<ver> recursively, then ALL side-by-side 10.0.* WDKs
if ($failCount -eq 0) {
    $dumpbin = Join-Path $msvc "bin\Hostx64\x64\dumpbin.exe"
    if ((Test-Path $dumpbin) -and ($fwpkclntPath) -and (Test-Path $fwpkclntPath)) {
        $members = & $dumpbin /LINKERMEMBER:1 $fwpkclntPath 2>&1 | Out-String
        if ($members -match 'FwpmEngineOpen0') {
            $useFwpkclntForFwpm = $true
            Info "fwpkclnt.lib also exports Fwpm* (merged lib layout - no fwpmk.lib needed)"
        }
    }
    if (-not $useFwpkclntForFwpm) {
        $hit = $null
        foreach ($cand in @(
            (Join-Path $kitsRoot "Lib\$wdkVer\km\x64\fwpmk.lib"),
            (Join-Path $kitsRoot "Lib\$wdkVer\km\fwpmk.lib"),
            (Join-Path $kitsRoot "Lib\$wdkVer\um\x64\fwpmk.lib"))) {
            if (Test-Path $cand) { $hit = Get-Item $cand; break }
        }
        if (-not $hit) {
            $hit = Get-ChildItem -Path (Join-Path $kitsRoot "Lib\$wdkVer") -Recurse -Filter "fwpmk*.lib" -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        if (-not $hit) {
            foreach ($vdir in (Get-ChildItem -Path (Join-Path $kitsRoot "Lib") -Directory -ErrorAction SilentlyContinue)) {
                if ($vdir.Name -match '^10\.0\.\d+' -and $vdir.Name -ne $wdkVer) {
                    $cand = Get-ChildItem -Path $vdir.FullName -Recurse -Filter "fwpmk*.lib" -ErrorAction SilentlyContinue |
                        Select-Object -First 1
                    if ($cand) { $hit = $cand; break }
                }
            }
            if ($hit) { Info "fwpmk lib borrowed from side-by-side WDK: $($hit.FullName)" }
        }
        if ($hit) {
            $fwpmkLibPath = $hit.FullName
            Info "fwpmk lib found: $($hit.FullName)"
        } else {
            Fail "Cannot resolve Fwpm* symbols: fwpkclnt.lib does not export them and no fwpmk*.lib exists under $kitsRoot\Lib."
            Fail "Fix: install a full (non-Insider) WDK release, e.g. WDK 10.0.26100.0, then re-run."
        }
    }
    if ($failCount -eq 0) {
        $fwpmVia = "fwpmk.lib"
        if ($useFwpkclntForFwpm) { $fwpmVia = "fwpkclnt.lib" }
        Info "WFP kernel libs resolved (Fwps* via fwpkclnt.lib, Fwpm* via $fwpmVia)"
    }
}

# ----------------------------------------------------------------
# 3. Validate driver source presence (3 source files)
# ----------------------------------------------------------------
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$srcDir = Join-Path $repoRoot "drivers\wfp_callout"
$srcFiles = @(
    "aegis_wfp.c",
    "aegis_wfp_callout.c",
    "aegis_wfp_comm.c"
)
foreach ($f in $srcFiles) {
    $p = Join-Path $srcDir $f
    if (-not (Test-Path $p)) {
        Fail "Driver source not found: $p"
    } else {
        Info "Driver source: $p ($((Get-Item $p).Length) bytes)"
    }
}

if ($failCount -gt 0) {
    Write-Host ""
    Fail "$failCount dependency problem(s) - fix them and re-run. Nothing was compiled."
    exit 1
}

# ----------------------------------------------------------------
# 4. Compile (cl) all 3 sources + link (link /DRIVER)
# ----------------------------------------------------------------
$outDir = Join-Path $repoRoot "build\x64\wfp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$objFiles = @()
$sysFile = Join-Path $outDir "aegis_wfp.sys"

# Critical preprocessor defines for WFP callout driver (must match WDK samples):
#   /DNDIS_WDM=1   - tells ndis.h we're WDM-based (NOT a miniport driver);
#                    without this NDIS typedefs (NDIS_HANDLE, UINT32 etc.)
#                    clash with basetsd.h/ntdef.h producing ~100 C2370 errors.
#   /DNDIS630      - NDIS version 6.30 (Windows 8+ baseline).
#   /DNTDDI_VERSION=0x0A000000 - target Windows 10+.
# NOTE: /D_KERNEL_MODE is reserved - the /kernel flag sets it automatically.
# Include order: shared (basetsd.h, ntdef.h) first, then km, then um fallback.
$includeArgs = @("/I$sharedInc", "/I$kmInc", "/I$umInc")
if (Test-Path $kmCrt) { $includeArgs += "/I$kmCrt" }

foreach ($f in $srcFiles) {
    $srcPath = Join-Path $srcDir $f
    $objPath = Join-Path $outDir ([System.IO.Path]::GetFileNameWithoutExtension($f) + ".obj")
    $objFiles += $objPath
    Info "Compiling $f (x64, kernel mode)..."
    # /wd4324 (WDK header padding noise) /wd4100 (unreferenced params) - cosmetic only.
    & $cl /nologo /kernel /W4 /GS- /O2 /wd4324 /wd4100 /c `
        /D_AMD64_ /DAMD64 /D_WIN64 `
        /DNDIS_WDM=1 /DNDIS630 `
        /DNTDDI_VERSION=0x0A000000 /D_OEMNETWORK=25 `
        $includeArgs `
        /Fo"$objPath" `
        "$srcPath" 2>&1 | ForEach-Object { Write-Host "  $_" }
    if ($LASTEXITCODE -ne 0) { Fail "cl.exe failed on $f (exit $LASTEXITCODE)."; exit 1 }
}

Info "Linking aegis_wfp.sys..."
# Driver link: kernel subsystem, NATIVE entry, no CRT.
# /NODEFAULTLIB strips libcmt/libvcruntime (user-mode CRT) - we only want
# kernel libs. WFP callout link libs:
#   fwpkclnt.lib - Fwps* (FwpsCalloutRegister0 etc.); may also carry Fwpm*
#                  on merged-layout WDKs (resolved in section 2b)
#   fwpmk lib    - Fwpm* (FwpmEngineOpen0 / FwpmCalloutAdd0 / FwpmFilterAdd0);
#                  full path resolved dynamically in section 2b (optional)
#   ndis.lib     - NDIS helpers (soft-add: only pulled in if referenced)
#   uuid.lib     - BFE layer/callout GUID definitions (kernel variant, soft-add)
$umLib = Join-Path $kitsRoot "Lib\$wdkVer\um\x64"
$linkLibs = @("ntoskrnl.lib", "hal.lib", "bufferoverflowfastfailk.lib",
    "fwpkclnt.lib")
if ($fwpmkLibPath) { $linkLibs += $fwpmkLibPath }
foreach ($l in @("ndis.lib", "uuid.lib")) {
    if (Test-Path (Join-Path $kmLib $l)) { $linkLibs += $l }
}
$linkArgs = @(
    "/nologo", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:DriverEntry",
    "/NODEFAULTLIB",
    "/OUT:$sysFile"
) + $objFiles + @(
    "/LIBPATH:$kmLib", "/LIBPATH:$msvcLib", "/LIBPATH:$umLib"
) + $linkLibs
& $link $linkArgs 2>&1 | ForEach-Object { Write-Host "  $_" }
if ($LASTEXITCODE -ne 0) { Fail "link.exe failed (exit $LASTEXITCODE)."; exit 1 }

if (-not (Test-Path $sysFile)) { Fail "aegis_wfp.sys was not produced."; exit 1 }

# ----------------------------------------------------------------
# 5. Summary
# ----------------------------------------------------------------
$hash = (Get-FileHash $sysFile -Algorithm SHA256).Hash
Info "BUILD OK: $sysFile ($((Get-Item $sysFile).Length) bytes)"
Info "SHA-256:  $hash"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. powershell -ExecutionPolicy Bypass -File scripts\wfp_sign.ps1   (test-sign the .sys)"
Write-Host "  2. powershell -ExecutionPolicy Bypass -File scripts\wfp_service.ps1 install"
exit 0
