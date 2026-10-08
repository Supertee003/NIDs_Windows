@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  AEGIS MOUTH v3.0 - Build Script v2.0 (CMD-safe)
REM  Canonical build is cargo (mouth/Cargo.toml builds the single
REM  windows_sec_monitor binary). The legacy bare-rustc flow and the
REM  aegis_mouth_tui.rs input are retired (EVT-107): the TUI source was
REM  never committed, so no build may require it.
REM  Paths are repo-relative (this file lives in mouth\).
REM ============================================================

echo.
echo ============================================================
echo  AEGIS MOUTH v3.0 - Build Script
echo ============================================================
echo.

set "MOUTH=%~dp0"
set "DIST=%~dp0..\dist"
set "ERR=0"

REM ============================================================
REM  [1/3] Check prerequisites
REM ============================================================
echo [1/3] Checking prerequisites...
echo.

where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [ERR] cargo not found - install Rust first
    echo         https://rustup.rs
    goto :fail
)
echo   [OK] cargo found

if exist "%MOUTH%\windows_sec_monitor.rs" (
    echo   [OK] windows_sec_monitor.rs
) else (
    echo   [MISSING] windows_sec_monitor.rs - must place this file first!
    set "ERR=1"
)

if exist "%MOUTH%\Cargo.toml" (
    echo   [OK] Cargo.toml
) else (
    echo   [MISSING] Cargo.toml - canonical build manifest!
    set "ERR=1"
)

if "!ERR!"=="1" goto :fail

echo.

REM ============================================================
REM  [2/3] Compile MOUTH
REM ============================================================
echo [2/3] Compiling MOUTH v3.0...
echo.

pushd "%MOUTH%"
cargo build --release
if %ERRORLEVEL% neq 0 (
    echo   [ERR] Build FAILED for windows_sec_monitor
    popd
    goto :fail
)
popd
echo   [OK] target\release\windows_sec_monitor.exe

echo.

REM ============================================================
REM  [3/3] Verify output and stage to dist
REM ============================================================
echo [3/3] Verifying build output...
echo.

if not exist "%DIST%" mkdir "%DIST%"

if exist "%MOUTH%\target\release\windows_sec_monitor.exe" (
    echo   [OK] target\release\windows_sec_monitor.exe
    copy /y "%MOUTH%\target\release\windows_sec_monitor.exe" "%DIST%\" >nul
) else (
    echo   [MISSING] target\release\windows_sec_monitor.exe
    goto :fail
)

echo.
echo ============================================================
echo  MOUTH v3.0 build complete!
echo  Run:  dist\windows_sec_monitor.exe --log logs\aegis_core.ndjson --refresh 1000
echo ============================================================
echo.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo  MOUTH build FAILED - see errors above
echo ============================================================
echo.
pause
exit /b 1
