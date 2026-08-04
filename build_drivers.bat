@@ -0,0 +1,238 @@
@echo off
REM =====================================================================
REM build_drivers.bat — AEGIS NIDS Kernel Driver Build Script
REM
REM Builds WFP Callout + Minifilter drivers using Windows Driver Kit (WDK)
REM
REM Prerequisites:
REM   - Windows Driver Kit (WDK) installed
REM   - Visual Studio Build Tools with C++ desktop workload
REM   - Test signing enabled: bcdedit /set testsigning on
REM
REM Usage:
REM   build_drivers.bat          — Build both drivers (Release)
REM   build_drivers.bat debug    — Build both drivers (Debug)
REM   build_drivers.bat wfp      — Build WFP Callout only
REM   build_drivers.bat miniflt  — Build Minifilter only
REM =====================================================================

setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════════════╗
echo ║       AEGIS NIDS — Kernel Driver Build System        ║
echo ║       WFP Callout + Minifilter (WDK)                 ║
echo ╚══════════════════════════════════════════════════════╝
echo.

REM ====== Configuration ======
set AEGIS_ROOT=%~dp0..
set DRIVERS_DIR=%AEGIS_ROOT%\drivers
set BUILD_DIR=%AEGIS_ROOT%\build\drivers
set CONFIG=Release

if "%1"=="debug" set CONFIG=Debug

REM ====== Detect WDK ======
set WDK_PATH=

REM Check WDK 11 first (Windows 11 24H2+)
for /f "delims=" %%p in ('dir /b /ad "C:\Program Files (x86)\Windows Kits\11\bin\wdk" 2^>nul') do (
    set WDK_PATH=C:\Program Files (x86)\Windows Kits\11
    set WDK_BIN=C:\Program Files (x86)\Windows Kits\11\bin\%%p
)

REM Check WDK 10
if not defined WDK_PATH (
    for /f "delims=" %%p in ('dir /b /ad "C:\Program Files (x86)\Windows Kits\10\bin\10*" 2^>nul') do (
        set WDK_PATH=C:\Program Files (x86)\Windows Kits\10
        set WDK_BIN=C:\Program Files (x86)\Windows Kits\10\bin\%%p
    )
)

if not defined WDK_PATH (
    echo [ERROR] Windows Driver Kit (WDK) not found!
    echo         Install WDK from: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    echo.
    echo         Alternatively, build only the user-mode Bridge:
    echo           cmake -B build -S . && cmake --build build --config Release
    exit /b 1
)

echo [OK] WDK found: %WDK_PATH%
echo [OK] WDK bin:   %WDK_BIN%
echo [OK] Config:    %CONFIG%
echo.

REM ====== Create build directories ======
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
if not exist "%BUILD_DIR%\wfp" mkdir "%BUILD_DIR%\wfp"
if not exist "%BUILD_DIR%\minifilter" mkdir "%BUILD_DIR%\minifilter"

set BUILD_WFP=1
set BUILD_MF=1

if "%1"=="wfp" set BUILD_MF=0
if "%1"=="miniflt" set BUILD_WFP=0

REM ====== Build WFP Callout Driver ======
if "%BUILD_WFP%"=="1" (
    echo [1/2] Building WFP Callout Driver (aegis_wfp.sys)...
    echo.

    pushd "%DRIVERS_DIR%\wfp_callout"

    REM Use MSBuild with WDK toolset
    REM The WFP callout is a NDIS/classic WFP driver compiled with WDK
    REM We need to create a vcxproj or use direct compiler invocation

    REM Direct WDK compiler invocation for kernel-mode WFP driver:
    REM cl /Zi /W4 /kernel /Gs /MDd -c aegis_wfp.c aegis_wfp_callout.c aegis_wfp_comm.c
    REM link /kernel /out:aegis_wfp.sys aegis_wfp.obj aegis_wfp_callout.obj aegis_wfp_comm.obj

    REM For WDK 10/11, we can use the build.exe (legacy) or MSBuild
    REM Simplest approach: use the WDK's compiler directly

    set CL_PATH=%WDK_BIN%\x64\cl.exe
    set LINK_PATH=%WDK_BIN%\x64\link.exe

    if not exist "!CL_PATH!" (
        echo [WARN] WDK x64 compiler not found at !CL_PATH!
        echo        Using MSBuild approach instead...

        REM Try MSBuild if vcxproj exists
        if exist "aegis_wfp.vcxproj" (
            msbuild aegis_wfp.vcxproj /p:Configuration=%CONFIG% /p:Platform=x64
        ) else (
            echo [SKIP] No vcxproj found — WFP driver needs manual WDK build
            echo        See: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wfp-version-2-names2
        )
    ) else (
        echo        Compiling with WDK compiler...

        REM Compile C sources
        "!CL_PATH!" /Zi /W4 /kernel /Gs /D_AMD64_ /DWINNT=1 /DNDIS60=1 ^
            /I"%WDK_PATH%\Include\km" ^
            /I"%WDK_PATH%\Include\shared" ^
            /I"%WDK_PATH%\Include\km\crt" ^
            /Fo"%BUILD_DIR%\wfp\\" ^
            /c aegis_wfp.c aegis_wfp_callout.c aegis_wfp_comm.c

        if !errorlevel! neq 0 (
            echo [ERROR] WFP driver compilation failed
            popd
            goto :minifilter_build
        )

        REM Link into .sys
        "!LINK_PATH!" /kernel /out:"%BUILD_DIR%\wfp\aegis_wfp.sys" ^
            /LIBPATH:"%WDK_PATH%\Lib\km\x64" ^
            /ENTRY:GsDriverEntry ^
            /SUBSYSTEM:NATIVE ^
            /MERGE:.rdata=.text ^
            /INTEGRITYCHECK ^
            "%BUILD_DIR%\wfp\aegis_wfp.obj" ^
            "%BUILD_DIR%\wfp\aegis_wfp_callout.obj" ^
            "%BUILD_DIR%\wfp\aegis_wfp_comm.obj" ^
            ntoskrnl.lib hal.lib ndis.lib fwpkclnt.lib uuid.lib

        if !errorlevel! equ 0 (
            echo [OK] aegis_wfp.sys built successfully
            copy /y "%BUILD_DIR%\wfp\aegis_wfp.sys" "%AEGIS_ROOT%\build\Release\aegis_wfp.sys" 2>nul
        ) else (
            echo [ERROR] WFP driver linking failed
        )
    )

    popd
    echo.
)

:minifilter_build

REM ====== Build Minifilter Driver ======
if "%BUILD_MF%"=="1" (
    echo [2/2] Building Minifilter Driver (aegis_minifilter.sys)...
    echo.

    pushd "%DRIVERS_DIR%\minifilter"

    set CL_PATH=%WDK_BIN%\x64\cl.exe
    set LINK_PATH=%WDK_BIN%\x64\link.exe

    if not exist "!CL_PATH!" (
        echo [WARN] WDK x64 compiler not found
        echo        Using MSBuild approach instead...

        if exist "aegis_minifilter.vcxproj" (
            msbuild aegis_minifilter.vcxproj /p:Configuration=%CONFIG% /p:Platform=x64
        ) else (
            echo [SKIP] No vcxproj found — Minifilter driver needs manual WDK build
        )
    ) else (
        echo        Compiling with WDK compiler...

        REM Compile C sources
        "!CL_PATH!" /Zi /W4 /kernel /Gs /D_AMD64_ /DWINNT=1 ^
            /I"%WDK_PATH%\Include\km" ^
            /I"%WDK_PATH%\Include\shared" ^
            /I"%WDK_PATH%\Include\km\crt" ^
            /I"%WDK_PATH%\Include\km\fltmanager" ^
            /Fo"%BUILD_DIR%\minifilter\\" ^
            /c aegis_minifilter.c aegis_minifilter_file.c aegis_minifilter_proc.c aegis_minifilter_comm.c

        if !errorlevel! neq 0 (
            echo [ERROR] Minifilter driver compilation failed
            popd
            goto :done
        )

        REM Link into .sys
        "!LINK_PATH!" /kernel /out:"%BUILD_DIR%\minifilter\aegis_minifilter.sys" ^
            /LIBPATH:"%WDK_PATH%\Lib\km\x64" ^
            /ENTRY:GsDriverEntry ^
            /SUBSYSTEM:NATIVE ^
            /MERGE:.rdata=.text ^
            /INTEGRITYCHECK ^
            "%BUILD_DIR%\minifilter\aegis_minifilter.obj" ^
            "%BUILD_DIR%\minifilter\aegis_minifilter_file.obj" ^
            "%BUILD_DIR%\minifilter\aegis_minifilter_proc.obj" ^
            "%BUILD_DIR%\minifilter\aegis_minifilter_comm.obj" ^
            ntoskrnl.lib hal.lib fltMgr.lib uuid.lib

        if !errorlevel! equ 0 (
            echo [OK] aegis_minifilter.sys built successfully
            copy /y "%BUILD_DIR%\minifilter\aegis_minifilter.sys" "%AEGIS_ROOT%\build\Release\aegis_minifilter.sys" 2>nul
        ) else (
            echo [ERROR] Minifilter driver linking failed
        )
    )

    popd
    echo.
)

:done

REM ====== Summary ======
echo ============================================================
echo [SUMMARY] Driver build complete
echo.

if exist "%BUILD_DIR%\wfp\aegis_wfp.sys" (
    echo   [OK] aegis_wfp.sys     — WFP Callout Driver
) else (
    echo   [--] aegis_wfp.sys     — Not built (needs WDK)
)

if exist "%BUILD_DIR%\minifilter\aegis_minifilter.sys" (
    echo   [OK] aegis_minifilter.sys — Minifilter Driver
) else (
    echo   [--] aegis_minifilter.sys — Not built (needs WDK)
)

echo.
echo   Next step: install_drivers.bat
echo ============================================================

endlocal
