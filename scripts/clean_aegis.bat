@echo off
setlocal enabledelayedexpansion

:: ================================================================
::  AEGIS NIDS - Project Cleanup Script v2.4
::  Clean build artifacts, logs, temp files, and caches
::
::  Usage:  clean_aegis.bat [option] [--dry-run]
::  Options:
::    all       Clean everything (default)
::    build     Clean only build artifacts
::    logs      Clean only logs and PID files
::    cache     Clean only language caches
::    dist      Clean only dist/ output binaries
::    drivers   Clean only driver build artifacts
::    --dry-run Show what would be deleted without deleting
:: ================================================================

:: -- Auto-detect Project Root --
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT="

if exist "%SCRIPT_DIR%..\core" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\brain" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\build.zig" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%..\mouth" set "PROJECT_ROOT=%SCRIPT_DIR%.."
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%core" set "PROJECT_ROOT=%SCRIPT_DIR%"
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%brain" set "PROJECT_ROOT=%SCRIPT_DIR%"
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%build.zig" set "PROJECT_ROOT=%SCRIPT_DIR%"
if not defined PROJECT_ROOT if exist "%SCRIPT_DIR%mouth" set "PROJECT_ROOT=%SCRIPT_DIR%"

if not defined PROJECT_ROOT (
    echo  [ERROR] Cannot find AEGIS NIDS project root!
    exit /b 1
)

cd /d "%PROJECT_ROOT%"

:: -- Parse options --
set "MODE=all"
set "DRY_RUN=0"

if /I "%~1"=="--dry-run" set "DRY_RUN=1"
if /I "%~1"=="build" set "MODE=build"
if /I "%~1"=="logs" set "MODE=logs"
if /I "%~1"=="cache" set "MODE=cache"
if /I "%~1"=="dist" set "MODE=dist"
if /I "%~1"=="drivers" set "MODE=drivers"
if /I "%~2"=="--dry-run" set "DRY_RUN=1"

echo.
echo ================================================================
echo      AEGIS NIDS Cleanup [%MODE%]
echo ================================================================
echo.

if "%DRY_RUN%"=="1" echo  [DRY RUN] Preview only - no files will be deleted
if "%DRY_RUN%"=="1" echo.

:: ================================================================
:: [0] Stop running AEGIS processes
:: ================================================================
if "%DRY_RUN%"=="1" goto :skip_stop

set "FOUND_PROC=0"
tasklist /NH 2>nul | find /I "aegis-nids.exe" >nul && set "FOUND_PROC=1"
tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul && set "FOUND_PROC=1"
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul && set "FOUND_PROC=1"
tasklist /NH 2>nul | find /I "nose_dashboard.exe" >nul && set "FOUND_PROC=1"

if not "!FOUND_PROC!"=="1" goto :skip_stop

echo [0/5] Stopping running AEGIS processes...
echo   Graceful stop...
taskkill /IM aegis-nids.exe >nul 2>&1
taskkill /IM aegis_bridge.exe >nul 2>&1
taskkill /IM windows_sec_monitor.exe >nul 2>&1
taskkill /IM nose_dashboard.exe >nul 2>&1
timeout /t 3 /nobreak >nul
echo   Force stop if still running...
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM aegis_bridge.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM nose_dashboard.exe >nul 2>&1
timeout /t 2 /nobreak >nul
echo   [OK] AEGIS processes stopped
echo.

:skip_stop

:: ================================================================
:: [1] Build Artifacts
:: ================================================================
if "%MODE%"=="all" goto :do_build
if "%MODE%"=="build" goto :do_build
goto :skip_build

:do_build
echo [1/5] Build Artifacts...

if "%DRY_RUN%"=="1" goto :dry_build

if not exist "zig-out" goto :no_zigout
rmdir /s /q "zig-out" 2>nul
if exist "zig-out" (echo   [LOCKED] zig-out) else (echo   [OK] Removed zig-out)
:no_zigout

if not exist ".zig-cache" goto :no_zigcache
rmdir /s /q ".zig-cache" 2>nul
if exist ".zig-cache" (echo   [LOCKED] .zig-cache) else (echo   [OK] Removed .zig-cache)
:no_zigcache

if not exist "bridge\build" goto :no_bridgebuild
rmdir /s /q "bridge\build" 2>nul
if exist "bridge\build" (echo   [LOCKED] bridge\build) else (echo   [OK] Removed bridge\build)
:no_bridgebuild

if not exist "build" goto :no_rootbuild
rmdir /s /q "build" 2>nul
if not exist "build" goto :rootbuild_ok

:: build/ is locked - try aggressive unlock
echo   [LOCKED] build - attempting unlock...

:: Step 1: Kill build tools
echo     Step 1: Killing cmake/msbuild...
taskkill /F /IM cmake.exe >nul 2>&1
taskkill /F /IM msbuild.exe >nul 2>&1
taskkill /F /IM ninja.exe >nul 2>&1
timeout /t 1 /nobreak >nul
rmdir /s /q "build" 2>nul
if not exist "build" goto :rootbuild_unlocked

:: Step 2: Reset NTFS permissions (needs Admin)
echo    ! Step 2: Resetting permissions...
takeown /f "build" /r /d y >nul 2>&1
icacls "build" /grant Everyone:F /t /q >nul 2>&1
timeout /t 1 /nobreak >nul
rmdir /s /q "build" 2>nul
if not exist "build" goto :rootbuild_unlocked

:: Step 3: Delete file-by-file (handles individual locked files)
echo     Step 3: File-by-file deletion...
for /r "build" %%f in (*) do del /f /q "%%f" 2>nul
rmdir /s /q "build" 2>nul
if not exist "build" goto :rootbuild_unlocked

:: Step 4: Restart Explorer to release folder locks
echo     Step 4: Restarting Explorer shell...
taskkill /F /IM explorer.exe >nul 2>&1
timeout /t 2 /nobreak >nul
start explorer.exe
timeout /t 2 /nobreak >nul
rmdir /s /q "build" 2>nul
if not exist "build" goto :rootbuild_unlocked

:: Still locked - give diagnostic info
echo   [WARN] build STILL locked after 4 unlock attempts.
echo   Likely cause: antivirus, Search Indexer, or kernel handle.
echo   Try: handle.exe -accepteula build
echo   Or:  close all Explorer windows and re-run
goto :rootbuild_done

:rootbuild_unlocked
echo   [OK] Removed build (unlocked)
goto :rootbuild_done
:rootbuild_ok
echo   [OK] Removed build
:rootbuild_done
:no_rootbuild

if not exist "shield\target" goto :no_shieldtarget
rmdir /s /q "shield\target" 2>nul
if exist "shield\target" (echo   [LOCKED] shield\target) else (echo   [OK] Removed shield\target)
:no_shieldtarget

if not exist "brain\cython\build" goto :no_cythonbuild
rmdir /s /q "brain\cython\build" 2>nul
if exist "brain\cython\build" (echo   [LOCKED] brain\cython\build) else (echo   [OK] Removed brain\cython\build)
:no_cythonbuild

del /q "bridge\*.obj" 2>nul
del /q "bridge\*.o"    2>nul
del /q "bridge\*.pdb"  2>nul
del /q "bridge\*.ilk"  2>nul
echo   [OK] Cleaned bridge temp files
goto :after_build

:dry_build
echo   [WOULD DELETE] zig-out
echo   [WOULD DELETE] .zig-cache
echo   [WOULD DELETE] bridge\build
echo   [WOULD DELETE] build (root CMake)
echo   [WOULD DELETE] shield\target
echo   [WOULD DELETE] brain\cython\build
echo   [WOULD DELETE] bridge temp files

:after_build
echo.

:skip_build

:: ================================================================
:: [2] Dist Binaries
:: ================================================================
if "%MODE%"=="all" goto :do_dist
if "%MODE%"=="dist" goto :do_dist
goto :skip_dist

:do_dist
echo [2/5] Dist Binaries...

if "%DRY_RUN%"=="1" goto :dry_dist

if not exist "dist" goto :dist_done

rmdir /s /q "dist" 2>nul
if not exist "dist" goto :dist_ok1

echo   [LOCKED] dist\ - force killing processes...
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM aegis_bridge.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM nose_dashboard.exe >nul 2>&1
timeout /t 2 /nobreak >nul

rmdir /s /q "dist" 2>nul
if not exist "dist" goto :dist_ok2

echo   Still locked - deleting file-by-file...
del /f /q "dist\*.exe" 2>nul
del /f /q "dist\*.dll" 2>nul
del /f /q "dist\*.lib" 2>nul
del /f /q "dist\*.pdb" 2>nul
del /f /q "dist\*.exp" 2>nul
rmdir /q "dist" 2>nul
if exist "dist" (echo   [WARN] dist\ partially cleaned - close apps and retry) else (echo   [OK] Removed dist\)
goto :dist_done

:dist_ok1
echo   [OK] Removed dist\
goto :dist_done

:dist_ok2
echo   [OK] Removed dist\ (after force stop)

:dist_done
goto :after_dist

:dry_dist
echo   [WOULD DELETE] dist\  (all compiled binaries)

:after_dist
echo.

:skip_dist

:: ================================================================
:: [3] Logs and PID Files
:: ================================================================
if "%MODE%"=="all" goto :do_logs
if "%MODE%"=="logs" goto :do_logs
goto :skip_logs

:do_logs
echo [3/5] Logs and PID Files...

if "%DRY_RUN%"=="1" goto :dry_logs

del /q "logs\*.log"      2>nul
del /q "logs\*.json"     2>nul
del /q "logs\*.tmp"      2>nul
del /q "logs\pids\*.pid" 2>nul
echo   [OK] Cleaned logs\
goto :after_logs

:dry_logs
echo   [WOULD DELETE] logs\*.log, *.json, *.tmp, pids\*.pid

:after_logs
echo.

:skip_logs

:: ================================================================
:: [4] Language Caches
:: ================================================================
if "%MODE%"=="all" goto :do_cache
if "%MODE%"=="cache" goto :do_cache
goto :skip_cache

:do_cache
echo [4/5] Language Caches...

if "%DRY_RUN%"=="1" goto :dry_cache

if exist "__pycache__"         rmdir /s /q "__pycache__"         2>nul
if exist "brain\__pycache__"   rmdir /s /q "brain\__pycache__"   2>nul
if exist "shared\__pycache__"  rmdir /s /q "shared\__pycache__"  2>nul
if exist "scripts\__pycache__" rmdir /s /q "scripts\__pycache__" 2>nul
if exist "tests\__pycache__"   rmdir /s /q "tests\__pycache__"   2>nul
del /q "brain\*.pyc"   2>nul
del /q "shared\*.pyc"  2>nul
del /q "scripts\*.pyc" 2>nul
del /q "tests\*.pyc"   2>nul
echo   [OK] Cleaned Python caches
goto :after_cache

:dry_cache
echo   [WOULD DELETE] __pycache__ (all locations), *.pyc

:after_cache
echo.

:skip_cache

:: ================================================================
:: [5] Driver Build Artifacts
:: ================================================================
if "%MODE%"=="all" goto :do_drivers
if "%MODE%"=="drivers" goto :do_drivers
goto :skip_drivers

:do_drivers
echo [5/5] Driver Build Artifacts...

if "%DRY_RUN%"=="1" goto :dry_drivers

if exist "drivers\minifilter\build"       rmdir /s /q "drivers\minifilter\build"       2>nul
if exist "drivers\minifilter\x64"         rmdir /s /q "drivers\minifilter\x64"         2>nul
if exist "drivers\minifilter_cpp\build"   rmdir /s /q "drivers\minifilter_cpp\build"   2>nul
if exist "drivers\minifilter_cpp\x64"     rmdir /s /q "drivers\minifilter_cpp\x64"     2>nul
if exist "drivers\wfp_callout\build"      rmdir /s /q "drivers\wfp_callout\build"      2>nul
if exist "drivers\wfp_callout\x64"        rmdir /s /q "drivers\wfp_callout\x64"        2>nul
if exist "drivers\wfp_callout_cpp\build"  rmdir /s /q "drivers\wfp_callout_cpp\build"  2>nul
if exist "drivers\wfp_callout_cpp\x64"    rmdir /s /q "drivers\wfp_callout_cpp\x64"    2>nul
del /q "drivers\minifilter\*.obj"       2>nul
del /q "drivers\minifilter\*.o"         2>nul
del /q "drivers\minifilter_cpp\*.obj"   2>nul
del /q "drivers\minifilter_cpp\*.o"     2>nul
del /q "drivers\wfp_callout\*.obj"      2>nul
del /q "drivers\wfp_callout\*.o"        2>nul
del /q "drivers\wfp_callout_cpp\*.obj"  2>nul
del /q "drivers\wfp_callout_cpp\*.o"    2>nul
echo   [OK] Cleaned driver build artifacts
goto :after_drivers

:dry_drivers
echo   [WOULD DELETE] drivers build dirs, x64, *.obj, *.o

:after_drivers
echo.

:skip_drivers

:: ================================================================
:: Summary
:: ================================================================
echo ================================================================
echo      Cleanup Complete
echo ================================================================
echo.
if "%DRY_RUN%"=="1" goto :summary_dry
echo   Project is clean. Run build_windows.bat to rebuild.
goto :summary_end
:summary_dry
echo   Run without --dry-run to actually delete files.
:summary_end
echo.
echo   Usage:
echo     clean_aegis.bat              Clean everything
echo     clean_aegis.bat build        Clean only build artifacts
echo     clean_aegis.bat logs         Clean only logs
echo     clean_aegis.bat cache        Clean only language caches
echo     clean_aegis.bat dist         Clean only dist/ binaries
echo     clean_aegis.bat drivers      Clean only driver builds
echo     clean_aegis.bat all --dry-run  Preview without deleting
echo.

endlocal
