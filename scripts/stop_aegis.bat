@echo off
REM Stop AEGIS NIDS - uses aegisctl if available, otherwise fallback
setlocal enabledelayedexpansion
echo.
echo ================================================================
echo  AEGIS NIDS - Stopping
echo ================================================================
echo.

:: -- Use aegisctl if available --
if exist "tools\aegisctl.py" (
    python tools\aegisctl.py stop --all
) else (
    echo  [WARN] aegisctl not found, using fallback stop
    set "S=0"
    tasklist /NH 2>nul | find /I "aegis-nose.exe" >nul
    if %ERRORLEVEL% equ 0 ( taskkill /IM aegis-nose.exe >nul 2>&1 & echo   [OK] Stopped NOSE & set "S=1" ) else ( echo   [--] NOSE not running )
    tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul
    if %ERRORLEVEL% equ 0 ( taskkill /IM windows_sec_monitor.exe >nul 2>&1 & echo   [OK] Stopped MOUTH & set "S=1" ) else ( echo   [--] MOUTH not running )
    tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul
    if %ERRORLEVEL% equ 0 ( taskkill /IM aegis_bridge.exe >nul 2>&1 & echo   [OK] Stopped BRIDGE & set "S=1" )
    tasklist /NH 2>nul | find /I "aegis_nids.exe" >nul
    if %ERRORLEVEL% equ 0 ( taskkill /IM aegis_nids.exe >nul 2>&1 & echo   [OK] Stopped CORE & set "S=1" )
    if exist "logs\pids" del /Q "logs\pids\*.pid" >nul 2>&1
)
:: Brain is a Python process and may outlive the supervisor stop request.
:: Terminate only the process whose command line owns windows_brain.py;
:: never kill unrelated Python processes.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { `$_.Name -eq 'python.exe' -and `$_.CommandLine -match 'windows_brain\.py' } | ForEach-Object { Stop-Process -Id `$_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
echo.
pause
