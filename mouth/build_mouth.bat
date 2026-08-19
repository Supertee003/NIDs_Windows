@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  AEGIS MOUTH v3.0 - Build Script v1.1 (CMD-safe)
REM  Compile windows_sec_monitor.rs + aegis_mouth_tui.rs
REM  FIX: CRLF endings, goto:EOF before subroutines
REM ============================================================

echo.
echo ============================================================
echo  AEGIS MOUTH v3.0 - Build Script
echo ============================================================
echo.

set "MOUTH=D:\NIds_Windows\mouth"
set "DIST=D:\NIds_Windows\dist"
set "ERR=0"

REM ============================================================
REM  [1/3] Check prerequisites
REM ============================================================
echo [1/3] Checking prerequisites...
echo.

where rustc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo   [ERR] rustc not found - install Rust first
    echo         https://rustup.rs
    goto :fail
)
echo   [OK] rustc found

if exist "%MOUTH%\windows_sec_monitor.rs" (
    echo   [OK] windows_sec_monitor.rs
) else (
    echo   [MISSING] windows_sec_monitor.rs - must place this file first!
    set "ERR=1"
)

if exist "%MOUTH%\aegis_mouth_tui.rs" (
    echo   [OK] aegis_mouth_tui.rs
) else (
    echo   [MISSING] aegis_mouth_tui.rs - must place this file first!
    set "ERR=1"
)

if "!ERR!"=="1" goto :fail

echo.

REM ============================================================
REM  [2/3] Compile MOUTH
REM ============================================================
echo [2/3] Compiling MOUTH v3.0...
echo.

if not exist "%DIST%" mkdir "%DIST%"

echo   Compiling: windows_sec_monitor.rs
pushd "%MOUTH%"
rustc -O windows_sec_monitor.rs -o "%DIST%\windows_sec_monitor.exe"
if %ERRORLEVEL% neq 0 (
    echo   [ERR] Build FAILED for windows_sec_monitor.rs
    popd
    goto :fail
)
echo   [OK] windows_sec_monitor.exe -^> %DIST%
popd

echo   Compiling: aegis_mouth_tui.rs
pushd "%MOUTH%"
rustc -O aegis_mouth_tui.rs -o "%DIST%\aegis_mouth_tui.exe"
if %ERRORLEVEL% neq 0 (
    echo   [ERR] Build FAILED for aegis_mouth_tui.rs
    popd
    goto :fail
)
echo   [OK] aegis_mouth_tui.exe -^> %DIST%
popd

echo.

REM ============================================================
REM  [3/3] Verify output
REM ============================================================
echo [3/3] Verifying build output...
echo.

if exist "%DIST%\windows_sec_monitor.exe" (
    echo   [OK] dist\windows_sec_monitor.exe
) else (
    echo   [MISSING] dist\windows_sec_monitor.exe
)

if exist "%DIST%\aegis_mouth_tui.exe" (
    echo   [OK] dist\aegis_mouth_tui.exe
) else (
    echo   [MISSING] dist\aegis_mouth_tui.exe
)

echo.
echo ============================================================
echo  MOUTH v3.0 build complete!
echo  Run:  dist\windows_sec_monitor.exe --log logs\anomalous.json
echo ============================================================
echo.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo  BUILD FAILED - fix errors above and retry
echo ============================================================
echo.
pause
exit /b 1
