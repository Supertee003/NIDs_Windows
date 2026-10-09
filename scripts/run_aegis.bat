@echo off
setlocal enabledelayedexpansion
REM AEGIS NIDS -- System Launcher (service topology edition)
REM
REM Thin wrapper around scripts\aegis_open.py, which owns all logic
REM (preflight, start-missing, verify, displays). This file exists so
REM opening the system stays one double-click: open a console here (or
REM double-click) and the opener does the rest.
REM
REM WHY A WRAPPER (Oct 2026): the old v5.0 phases below started a SECOND
REM copy of every subsystem as plain background processes -- including a
REM second aegis_nids.exe fighting the Windows service for ETW sessions,
REM pipes, and logs -- with stale binary paths (aegis_bridge.exe,
REM shield\sec_monitor.dll, dist\nose_dashboard.exe) and Mouth pointed
REM at the dead anomalous.json feed. That model predates the service and
REM must not run against it. All of it now lives in ONE tested place:
REM scripts\aegis_open.py (status/open/close/displays + verify). Do not
REM re-implement startup logic here; extend the Python opener instead.
REM
REM ASCII-ONLY FILE (no chcp, no box glyphs): cmd's batch parser is
REM unreliable under codepage 65001 and chokes on multi-byte UTF-8 echo
REM lines, so the wrapper stays pure ASCII by design.
REM
REM Usage:  run_aegis.bat [options]
REM   (no args)      open missing parts + start all displays, then verify
REM   --status       check everything, start nothing
REM   --stop         stop displays + supervised parts AND the service
REM   --no-displays  open the system without starting displays
REM   --skip-build   retired: builds are a separate step (build_all.bat)
REM   --no-dashboard retired alias for --no-displays
REM   --skip-check   accepted, no separate check phase exists anymore

:: -- Auto-detect Project Root (kept from v5.0: robust, works from anywhere)
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT="
if exist "%SCRIPT_DIR%..\src" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\brain" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\build.zig" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%src" set "PROJECT_ROOT=%SCRIPT_DIR%"
if not defined PROJECT_ROOT (
    echo.
    echo   [ERROR] Cannot find AEGIS NIDS project root!
    echo          Run from D:\NIDs_Windows\ or D:\NIDs_Windows\scripts\
    echo.
    exit /b 1
)
for %%i in ("%PROJECT_ROOT%") do set "PROJECT_ROOT=%%~fi"
cd /d "%PROJECT_ROOT%"

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [ERROR] python not found in PATH -- the opener needs it.
    echo.
    exit /b 1
)
if not exist "scripts\aegis_open.py" (
    echo.
    echo   [ERROR] scripts\aegis_open.py not found -- nothing to delegate to.
    echo.
    exit /b 1
)

:: -- Map legacy flags to opener commands --
set "CMD=open"
set "DISPLAYS=displays"
set "HAD_ARGS="
:parse_args
if "%~1"=="" goto :done_parse
set "HAD_ARGS=1"
set "KNOWN="
if /I "%~1"=="--status" set "CMD=status" & set "DISPLAYS=" & set "KNOWN=1"
if /I "%~1"=="--stop" set "CMD=close --with-service" & set "DISPLAYS=displays --stop" & set "KNOWN=1"
if /I "%~1"=="--no-displays" set "DISPLAYS=" & set "KNOWN=1"
if /I "%~1"=="--help" goto :usage
if /I "%~1"=="-h" goto :usage
if /I "%~1"=="-?" goto :usage
if /I "%~1"=="--skip-build" echo   [note] --skip-build retired: builds are separate (scripts\build_all.bat); opening as-is.
if /I "%~1"=="--skip-build" set "KNOWN=1"
if /I "%~1"=="--no-dashboard" echo   [note] --no-dashboard retired: use --no-displays to skip all displays.
if /I "%~1"=="--no-dashboard" set "KNOWN=1"
if /I "%~1"=="--skip-check" echo   [note] --skip-check accepted: opener verifies as it goes, no separate phase.
if /I "%~1"=="--skip-check" set "KNOWN=1"
if not defined KNOWN echo   [warn] unknown flag "%~1" ignored -- continuing with: %CMD%
shift
goto :parse_args
:usage
echo.
echo   Usage: run_aegis.bat [--status] [--stop] [--no-displays] [--help]
echo     (no args)   open missing parts + start all displays, then verify
echo     --status    check everything, start nothing
echo     --stop      stop displays + supervised parts AND the service
echo     --no-displays  open the system without starting displays
echo.
exit /b 0
:done_parse

echo.
echo   +--------------------------------------------------------------+
echo   ^|   A E G I S   N I D S   -   S y s t e m   L a u n c h e r    ^|
echo   ^|   service + nose + brain + 4 displays, one command           ^|
echo   +--------------------------------------------------------------+
echo.
echo   Started: %DATE% %TIME%
echo   Mode:    %CMD%  (%DISPLAYS%)
echo.
if not defined DISPLAYS (
    echo   Displays skipped -- core system only, no display surfaces.
    echo.
)

python scripts\aegis_open.py %CMD%
set "RC=%errorlevel%"
if defined DISPLAYS (
    echo.
    echo   Display surfaces - web console, GUI, mouth, dashboard watch:
    echo   ---------------------------------------------------------------
    python scripts\aegis_open.py %DISPLAYS%
    if !errorlevel! equ 2 (
        echo.
        echo   [note] all display surfaces were already running - nothing started.
    ) else if !errorlevel! neq 0 (
        set "RC=!errorlevel!"
    )
)
echo.
echo   ---------------------------------------------------------------
echo.
echo   Tips:
echo     - run_aegis.bat --status         check anytime (starts nothing)
echo     - run_aegis.bat --stop           stop everything
echo     - aegis_open.py displays --stop  close the display windows
echo     - aegis_open.py displays --help  surfaces and overrides
echo     - Never run the old v5.0 phase launcher against the service
echo.
if not defined HAD_ARGS pause
exit /b %RC%