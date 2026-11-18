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
    echo  [ERROR] aegisctl not found - refusing blind stop.
    echo          The fallback taskkill path was retired (EVT-167):
    echo          killing the service binary orphans SCM state, and the
    echo          brain kill could take down unrelated Python processes.
    echo          Restore tools\aegisctl.py, then re-run.
    exit /b 1
)
echo.
pause
