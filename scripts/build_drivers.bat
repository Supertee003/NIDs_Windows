@echo off
setlocal enabledelayedexpansion

:: === AEGIS Auto-Detect Project Root ===
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT="

:: Method 1: Running from scripts/ -- go up 1 level
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\src" set "PROJECT_ROOT=%SCRIPT_DIR%.."
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\brain" set "PROJECT_ROOT=%SCRIPT_DIR%.."
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\mouth" set "PROJECT_ROOT=%SCRIPT_DIR%.."
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\build.zig" set "PROJECT_ROOT=%SCRIPT_DIR%.."
)

:: Method 2: Running from project root itself
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%src" set "PROJECT_ROOT=%SCRIPT_DIR%"
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%brain" set "PROJECT_ROOT=%SCRIPT_DIR%"
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%mouth" set "PROJECT_ROOT=%SCRIPT_DIR%"
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%build.zig" set "PROJECT_ROOT=%SCRIPT_DIR%"
)

:: Method 3: Running from scripts/sub/ -- go up 2 levels
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\..\src" set "PROJECT_ROOT=%SCRIPT_DIR%..\.."
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\..\brain" set "PROJECT_ROOT=%SCRIPT_DIR%..\.."
)

:: Fallback: assume parent of scripts/
if not defined PROJECT_ROOT (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
)

cd /d "%PROJECT_ROOT%"
echo  [AEGIS] Project root: %CD%
:: === End Auto-Detect ===

REM =====================================================================
REM build_drivers.bat " AEGIS NIDS Kernel Driver Build Script
REM
REM Builds WFP Callout + Minifilter drivers using Windows Driver Kit (WDK)
REM
REM Prerequisites:
REM   - Windows Driver Kit (WDK) installed
REM   - Visual Studio Build Tools with C++ desktop workload
REM   - Test signing enabled: bcdedit /set testsigning on
REM
REM Usage:
REM   build_drivers.bat          " Build both drivers (Release)
REM   build_drivers.bat debug    " Build both drivers (Debug)
REM   build_drivers.bat wfp      " Build WFP Callout only
REM   build_drivers.bat miniflt  " Build Minifilter only
REM =====================================================================

setlocal enabledelayedexpansion

echo.
echo =======================================================
echo        AEGIS NIDS - Kernel Driver Build System
echo        WFP Callout + Minifilter (WDK)
echo =======================================================
echo.

REM ====== Configuration ======
set AEGIS_ROOT=%~dp0..
set DRIVERS_DIR=%AEGIS_ROOT%\drivers
set BUILD_DIR=%AEGIS_ROOT%\build\drivers
set CONFIG=Release

if "%1"=="debug" set CONFIG=Debug

REM ====== Detect WDK ======
set WDK_PATH=
set WDK_VERSION=
set WDK_INCLUDE=
set WDK_LIB=
set WDK_UM_LIB=
set MSVC_LIB=

REM Check WDK 11 first (Windows 11 24H2+)
for /f "delims=" %%p in ('dir /b /ad "C:\Progra~2\Windows Kits\11\bin\wdk" 2^>nul') do (
    set WDK_PATH=C:\Progra~2\Windows Kits\11
    set WDK_BIN=C:\Progra~2\Windows Kits\11\bin\%%p
)

REM Check WDK 10
if not defined WDK_PATH (
    for /f "delims=" %%p in ('dir /b /ad /o-n "C:\Progra~2\Windows Kits\10\bin\10*" 2^>nul') do if not defined WDK_VERSION set WDK_VERSION=%%p
    if defined WDK_VERSION (
        set WDK_PATH=C:\Progra~2\Windows Kits\10
        set WDK_BIN=C:\Progra~2\Windows Kits\10\bin\!WDK_VERSION!
        set WDK_INCLUDE=C:\Progra~2\Windows Kits\10\Include\!WDK_VERSION!
        set WDK_LIB=C:\Progra~2\Windows Kits\10\Lib\!WDK_VERSION!
        set WDK_UM_LIB=C:\Progra~2\Windows Kits\10\Lib\!WDK_VERSION!\um\x64
    )
)

if defined WDK_PATH if not exist "!WDK_INCLUDE!\km" (
    echo [ERROR] WDK Include\km not found under !WDK_INCLUDE!
    exit /b 1
)

if not defined WDK_PATH (
    echo [ERROR] Windows Driver Kit [WDK] not found!
    echo         Install WDK from: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
    echo.
    echo         Alternatively, build only the user-mode Bridge:
    echo           cmake -B build -S . && cmake --build build --config Release
    exit /b 1
)

echo [OK] WDK found: %WDK_PATH%
echo [OK] WDK version: %WDK_VERSION%
echo [OK] WDK bin:   %WDK_BIN%
echo [OK] WDK include: %WDK_INCLUDE%
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
    echo [1/2] Building WFP Callout Driver [aegis_wfp.sys]...
    echo.

    pushd "%DRIVERS_DIR%\wfp_callout"

    REM Use MSBuild with WDK toolset
    REM The WFP callout is a NDIS/classic WFP driver compiled with WDK
    REM We need to create a vcxproj or use direct compiler invocation

    REM Direct WDK compiler invocation for kernel-mode WFP driver:
    REM cl /Zi /W4 /kernel /Gs /MDd -c aegis_wfp.c aegis_wfp_callout.c aegis_wfp_comm.c
    REM link /kernel /out:aegis_wfp.sys aegis_wfp.obj aegis_wfp_callout.obj aegis_wfp_comm.obj

    REM For WDK 10/11, use the Visual Studio x64 compiler with WDK headers/libs.

    set CL_PATH=
    set LINK_PATH=
    for /f "delims=" %%p in ('where cl.exe 2^>nul') do if not defined CL_PATH set CL_PATH=%%p
    for /f "delims=" %%p in ('where link.exe 2^>nul') do if not defined LINK_PATH set LINK_PATH=%%p
    if not defined CL_PATH for /d %%v in ("C:\Progra~1\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\*") do if exist "%%~v\bin\Hostx64\x64\cl.exe" if not defined CL_PATH set CL_PATH=%%~v\bin\Hostx64\x64\cl.exe
    if not defined LINK_PATH for /d %%v in ("C:\Progra~1\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\*") do if exist "%%~v\bin\Hostx64\x64\link.exe" if not defined LINK_PATH set LINK_PATH=%%~v\bin\Hostx64\x64\link.exe
    for /d %%v in ("C:\Progra~1\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\*") do if exist "%%~v\lib\x64\libcmt.lib" if not defined MSVC_LIB set MSVC_LIB=%%~v\lib\x64

    if not exist "!CL_PATH!" (
        echo [WARN] WDK x64 compiler not found at !CL_PATH!
        echo        Using MSBuild approach instead...

        REM Try MSBuild if vcxproj exists
        if exist "aegis_wfp.vcxproj" (
            msbuild aegis_wfp.vcxproj /p:Configuration=%CONFIG% /p:Platform=x64
        ) else (
            echo [SKIP] No vcxproj found " WFP driver needs manual WDK build
            echo        See: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/wfp-version-2-names2
        )
    ) else (
        echo        Compiling with WDK compiler...

        REM Compile C sources
        "!CL_PATH!" /Zi /W4 /kernel /Gs /GS- /D_AMD64_ /DWINNT=1 /DNDIS60=1 ^
            /I"!WDK_INCLUDE!\km" ^
            /I"!WDK_INCLUDE!\shared" ^
            /I"!WDK_INCLUDE!\km\crt" ^
            /Fo"%BUILD_DIR%\wfp\\" ^
            /c aegis_wfp.c aegis_wfp_callout.c aegis_wfp_comm.c

        if !errorlevel! neq 0 (
            echo [ERROR] WFP driver compilation failed
            popd
            goto :minifilter_build
        )

        REM Link into .sys
        "!LINK_PATH!" /kernel /NODEFAULTLIB /out:"%BUILD_DIR%\wfp\aegis_wfp.sys" ^
            /LIBPATH:"!WDK_LIB!\km\x64" ^
            /LIBPATH:"!WDK_UM_LIB!" ^
            /LIBPATH:"!MSVC_LIB!" ^
            /ENTRY:DriverEntry ^
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
    echo [2/2] Building Minifilter Driver [aegis_minifilter.sys]...
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
            echo [SKIP] No vcxproj found " Minifilter driver needs manual WDK build
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
    echo   [OK] aegis_wfp.sys     " WFP Callout Driver
) else (
    echo   [--] aegis_wfp.sys     " Not built [needs WDK]
)

if exist "%BUILD_DIR%\minifilter\aegis_minifilter.sys" (
    echo   [OK] aegis_minifilter.sys " Minifilter Driver
) else (
    echo   [--] aegis_minifilter.sys " Not built [needs WDK]
)

echo.
echo   Next step: install_drivers.bat
echo ============================================================

endlocal
