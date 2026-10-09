@echo off
REM AEGIS NIDS -- System Launcher (service topology edition)
REM
REM Thin wrapper around scripts\aegis_open.py, which owns all logic
REM (preflight, start-missing, verify). This file exists so opening the
REM system stays one double-click: open a console here (or double-click)
REM and the opener does the rest.
REM
REM WHY A WRAPPER (Oct 2026): the old v5.0 phases below started a SECOND
REM copy of every subsystem as plain background processes -- including a
REM second aegis_nids.exe fighting the Windows service for ETW sessions,
REM pipes, and logs -- with stale binary paths (aegis_bridge.exe,
REM shield\sec_monitor.dll, dist\nose_dashboard.exe) and Mouth pointed
REM at the dead anomalous.json feed. That model predates the service and
REM must not run against it. All of it now lives in ONE tested place:
REM scripts\aegis_open.py (status/open/close + verify). Do not
REM re-implement startup logic here; extend the Python opener instead.
REM
REM Usage:  run_aegis.bat [options]
REM   (no args)      open missing parts + start all displays, then verify
REM   --status       check everything, start nothing
REM   --stop         stop displays + supervised parts AND the service
REM   --no-displays  open the system without starting displays
REM   --skip-build   retired: builds are a separate step (build_all.bat)
REM   --no-dashboard retired alias for --no-displays
REM   --skip-check   accepted, no separate check phase exists anymore
setlocal enabledelayedexpansion

:: -- Auto-detect Project Root (kept from v5.0: robust, works from anywhere)
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT="
if exist "%SCRIPT_DIR%..\src" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\brain" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\build.zig" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%src" set "PROJECT_ROOT=%SCRIPT_DIR%"
if not defined PROJECT_ROOT (
    echo.
    echo  [ERROR] Cannot find AEGIS NIDS project root!
    echo         Run from D:\NIDs_Windows\ or D:\NIDs_Windows\scripts\
    echo.
    exit /b 1
)
for %%i in ("%PROJECT_ROOT%") do set "PROJECT_ROOT=%%~fi"
cd /d "%PROJECT_ROOT%"

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] python not found in PATH -- the opener needs it.
    echo.
    exit /b 1
)
if not exist "scripts\aegis_open.py" (
    echo.
    echo  [ERROR] scripts\aegis_open.py not found -- nothing to delegate to.
    echo.
    exit /b 1
)

:: -- Map legacy flags to opener commands --
set "CMD=open"
set "DISPLAYS=displays"
:parse_args
if "%~1"=="" goto :done_parse
if /I "%~1"=="--status" set "CMD=status" & set "DISPLAYS="
if /I "%~1"=="--stop" set "CMD=close --with-service" & set "DISPLAYS=displays --stop"
if /I "%~1"=="--no-displays" set "DISPLAYS="
if /I "%~1"=="--skip-build" echo  [note] --skip-build retired: builds are separate (scripts\build_all.bat); opening as-is.
if /I "%~1"=="--no-dashboard" echo  [note] --no-dashboard retired: use --no-displays to skip all displays.
if /I "%~1"=="--skip-check" echo  [note] --skip-check accepted: opener verifies as it goes, no separate phase.
shift
goto :parse_args
:done_parse

echo.
echo  +============================================================+
echo  ^|           AEGIS NIDS -- System Launcher                    ^|
echo  ^|     service topology: service + nose + brain + verify      ^|
echo  +============================================================+
echo  Start time: %DATE% %TIME%
echo.
python scripts\aegis_open.py %CMD%
set "RC=%errorlevel%"
if defined DISPLAYS (
    echo.
    python scripts\aegis_open.py %DISPLAYS%
    if %errorlevel% neq 0 set "RC=%errorlevel%"
)
echo.
echo  Tips:
echo    - Run 'scripts\run_aegis.bat --status' to check anytime
echo    - Run 'scripts\run_aegis.bat --stop' to stop everything
echo    - Run 'python tools\aegisctl.py dashboard --watch' for live terminal view
echo    - Run '.\aegis_dashboard\target\release\aegis_dashboard.exe' for the GUI
echo    - Never run the old v5.0 phase launcher against the service
echo.
pause
exit /b %RC%
