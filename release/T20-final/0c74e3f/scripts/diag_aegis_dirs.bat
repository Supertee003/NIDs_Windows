@echo off
setlocal enabledelayedexpansion
REM chcp 65001 removed (causes encoding issues)
:: AEGIS — Directory Structure Diagnostic
:: ตรวจโครงสร้าง directory และไฟล์ที่ BAT ต้องการ
echo ================================================================
echo  AEGIS NIDS - Directory Diagnostic
echo ================================================================
echo.

:: 1. Current directory
echo [1] Current directory:
echo     %CD%
echo.

:: 2. SCRIPT_DIR and PROJECT_ROOT
set "SCRIPT_DIR=%~dp0"
echo [2] SCRIPT_DIR: %SCRIPT_DIR%

:: Try to find PROJECT_ROOT (same logic as run_aegis.bat)
set "PROJECT_ROOT="
if exist "%SCRIPT_DIR%..\core" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
    echo     Method 1: Found ..\core
) else if exist "%SCRIPT_DIR%..\brain" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
    echo     Method 1: Found ..\brain
) else if exist "%SCRIPT_DIR%..\build.zig" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
    echo     Method 1: Found ..\build.zig
) else if exist "%SCRIPT_DIR%..\mouth" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
    echo     Method 1: Found ..\mouth
)

if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%core" (
        set "PROJECT_ROOT=%SCRIPT_DIR%"
        echo     Method 2: Found .\core
    ) else if exist "%SCRIPT_DIR%brain" (
        set "PROJECT_ROOT=%SCRIPT_DIR%"
        echo     Method 2: Found .\brain
    )
)

if not defined PROJECT_ROOT (
    echo     [ERROR] PROJECT_ROOT not found!
    echo     Looking for: core, brain, build.zig, mouth
)

:: Resolve .. to absolute path (cd /d does NOT resolve .. in CMD)
for %%i in ("%PROJECT_ROOT%") do set "PROJECT_ROOT=%%~fi"

echo     PROJECT_ROOT: %PROJECT_ROOT%
echo.

:: 3. CD to PROJECT_ROOT and verify
cd /d "%PROJECT_ROOT%"
echo [3] After cd /d PROJECT_ROOT:
echo     CD = !CD!
echo.

:: 4. Check all critical paths
echo [4] Critical file checks:
echo     --- Directories ---
for %%d in (brain brain_python mouth nose core shield dist build build\Release zig-out\bin scripts) do (
    if exist "%%d" (
        echo     [OK]   %%d\ exists
    ) else (
        echo     [MISS] %%d\ not found
    )
)

echo.
echo     --- DLL files ---
for %%f in (build\Release\aegis_ipc.dll dist\aegis_ipc.dll aegis_ipc.dll) do (
    if exist "%%f" (
        echo     [OK]   %%f
    ) else (
        echo     [MISS] %%f
    )
)

echo.
echo     --- EXE files ---
for %%f in (build\Release\aegis_bridge.exe dist\aegis_bridge.exe zig-out\bin\aegis-nids.exe dist\aegis-nids.exe dist\aegis-nose.exe dist\windows_sec_monitor.exe) do (
    if exist "%%f" (
        echo     [OK]   %%f
    ) else (
        echo     [MISS] %%f
    )
)

echo.
echo     --- Source files ---
for %%f in (brain\windows_brain.py brain_python\windows_brain.py mouth\windows_sec_monitor.rs mouth\src\main.rs nose\windows_perf.go nose\go.mod core\build.zig) do (
    if exist "%%f" (
        echo     [OK]   %%f
    ) else (
        echo     [MISS] %%f
    )
)

echo.
echo     --- Shield DLL ---
for %%f in (shield\target\release\sec_monitor.dll zig-out\bin\sec_monitor.dll dist\sec_monitor.dll) do (
    if exist "%%f" (
        echo     [OK]   %%f
    ) else (
        echo     [MISS] %%f
    )
)

echo.
echo ================================================================
echo  Diagnostic complete.
echo ================================================================
pause
