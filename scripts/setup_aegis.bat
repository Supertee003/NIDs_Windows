@echo off
setlocal enabledelayedexpansion

REM ================================================================
REM  AEGIS NIDS - First-Time Setup v1.0
REM  Create folder structure + verify dependencies
REM ================================================================

echo.
echo ================================================================
echo  AEGIS NIDS - First-Time Setup
echo ================================================================
echo.

REM -- Auto-detect root --
set "SCRIPT_DIR=%~dp0"
set "ROOT="
if exist "%SCRIPT_DIR%..\nose" set "ROOT=%SCRIPT_DIR%.."
if not defined ROOT if exist "%SCRIPT_DIR%nose" set "ROOT=%SCRIPT_DIR%"
if not defined ROOT set "ROOT=%SCRIPT_DIR%"

for %%i in ("%ROOT%") do set "ROOT=%%~fi"
cd /d "%ROOT%"

echo  Project: %ROOT%
echo.

REM -- Step 1: Create folder structure --
echo [1/3] Creating folder structure...

if not exist "dist" mkdir "dist"
if not exist "logs" mkdir "logs"
if not exist "logs\pids" mkdir "logs\pids"
if not exist "config" mkdir "config"

echo   [OK] dist\          - compiled binaries
echo   [OK] logs\          - runtime logs
echo   [OK] logs\pids\     - process ID files
echo   [OK] config\        - rules and configuration

REM -- Create empty anomalous.json if not exists --
if not exist "logs\anomalous.json" (
    echo []> "logs\anomalous.json"
    echo   [OK] logs\anomalous.json - created (empty array)
) else (
    echo   [OK] logs\anomalous.json - exists
)

echo.

REM -- Step 2: Check dependencies --
echo [2/3] Checking dependencies...
echo.

set "DEPS_OK=1"

where go >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=3" %%v in ('go version 2^>nul') do echo   [OK] Go: %%v
) else (
    echo   [MISSING] Go - install from https://go.dev/dl/
    set "DEPS_OK=0"
)

where rustc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=2" %%v in ('rustc --version 2^>nul') do echo   [OK] Rust: %%v
) else (
    echo   [MISSING] Rust - install from https://rustup.rs
    set "DEPS_OK=0"
)

where zig >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=3" %%v in ('zig version 2^>nul') do echo   [OK] Zig: %%v
) else (
    echo   [--] Zig: not found (optional for CORE)
)

where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    for /f "tokens=2" %%v in ('python --version 2^>nul') do echo   [OK] Python: %%v
) else (
    echo   [--] Python: not found (optional for BRAIN)
)

echo.

REM -- Step 3: Verify source files --
echo [3/3] Verifying source files...
echo.

echo   -- NOSE v5.0 --
if exist "nose\go.mod" (
    echo   [OK] nose\go.mod
) else (
    echo   [MISSING] nose\go.mod
    set "DEPS_OK=0"
)
if exist "nose\main.go" (
    echo   [OK] nose\main.go
) else (
    echo   [MISSING] nose\main.go
    set "DEPS_OK=0"
)

echo.
echo   -- MOUTH v3.0 --
if exist "mouth\windows_sec_monitor.rs" (
    echo   [OK] mouth\windows_sec_monitor.rs
) else (
    echo   [MISSING] mouth\windows_sec_monitor.rs
    set "DEPS_OK=0"
)

echo.

REM -- Summary --
echo ================================================================
if "!DEPS_OK!"=="1" (
    echo  Setup complete - ready to run!
    echo  Next: run_aegis.bat
) else (
    echo  Setup incomplete - fix MISSING items above
)
echo ================================================================

echo.
pause
exit /b 0
