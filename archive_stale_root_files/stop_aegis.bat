@echo off
setlocal enabledelayedexpansion

:: ================================================================
::  AEGIS NIDS — Graceful Shutdown Script
::  หยุดระบบทั้ง 5 subsystems อย่างเป็นลำดับ
::  Usage: stop_aegis.bat [--force]
::    --force  ฆ่าทันทีโดยไม่รอ graceful timeout
:: ================================================================

set "MODE=graceful"
if /I "%~1"=="--force" set "MODE=force"
if /I "%~1"=="-f" set "MODE=force"

echo ================================================================
echo      AEGIS NIDS Shutdown [%MODE%]
echo ================================================================
echo.

:: -- ฟังก์ชั่น: หยุด process และรอยืนยัน --
:: Parameters: %1=executable name, %2=display name, %3=graceful timeout (ms)

set "KILLED=0"
set "FAILED=0"

:: -- Step 1: หยุด Brain (Python) ก่อน — ส่ง stop ทาง IPC --
echo [1/5] Stopping AEGIS BRAIN (Python)...
tasklist /FI "IMAGENAME eq python.exe" /FI "STATUS eq running" /NH 2>nul | find /I "python.exe" >nul
if %errorlevel% equ 0 (
    :: หา Brain process โดย command line
    for /f "tokens=2 delims=," %%p in ('wmic process where "CommandLine like '%%windows_brain%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
        echo       Sending CTRL+C to Brain PID %%p...
        taskkill /PID %%p >nul 2>&1
        set /a KILLED+=1
    )
) else (
    echo       Brain not running
)

:: -- Step 2: หยุด Nose (Go) --
echo [2/5] Stopping AEGIS NOSE (Go)...
tasklist /FI "IMAGENAME eq aegis-nose.exe" /NH 2>nul | find /I "aegis-nose.exe" >nul
if %errorlevel% equ 0 (
    taskkill /IM aegis-nose.exe >nul 2>&1
    echo       Killed aegis-nose.exe
    set /a KILLED+=1
) else (
    :: อาจจะยังเป็น go.exe ที่ run
    for /f "tokens=2 delims=," %%p in ('wmic process where "CommandLine like '%%windows_perf%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
        taskkill /PID %%p >nul 2>&1
        echo       Killed Go Nose PID %%p
        set /a KILLED+=1
    )
    if !KILLED!==0 echo       Nose not running
)

:: -- Step 3: หยุด Mouth (Rust) --
echo [3/5] Stopping AEGIS MOUTH (Rust)...
tasklist /FI "IMAGENAME eq windows_sec_monitor.exe" /NH 2>nul | find /I "windows_sec_monitor.exe" >nul
if %errorlevel% equ 0 (
    taskkill /IM windows_sec_monitor.exe >nul 2>&1
    echo       Killed windows_sec_monitor.exe
    set /a KILLED+=1
) else (
    echo       Mouth not running
)

:: -- Step 4: หยุด Core (Zig) --
echo [4/5] Stopping AEGIS CORE (Zig)...
tasklist /FI "IMAGENAME eq aegis-nids.exe" /NH 2>nul | find /I "aegis-nids.exe" >nul
if %errorlevel% equ 0 (
    taskkill /IM aegis-nids.exe >nul 2>&1
    echo       Killed aegis-nids.exe
    set /a KILLED+=1
) else (
    echo       Core not running
)

:: -- Step 5: หยุด Bridge (C++) — หยุดสุดท้ายเพราะเป็น IPC hub --
echo [5/5] Stopping AEGIS BRIDGE (C++)...
tasklist /FI "IMAGENAME eq aegis_bridge.exe" /NH 2>nul | find /I "aegis_bridge.exe" >nul
if %errorlevel% equ 0 (
    if "%MODE%"=="graceful" (
        :: รอให้ Bridge flush IPC queue (2 วินาที)
        echo       Waiting for IPC queue flush...
        timeout /t 2 /nobreak >nul
    )
    taskkill /IM aegis_bridge.exe >nul 2>&1
    echo       Killed aegis_bridge.exe
    set /a KILLED+=1
) else (
    echo       Bridge not running
)

:: -- Force cleanup: ฆ่า process ที่อาจค้าง --
if "%MODE%"=="force" (
    echo.
    echo [FORCE] Killing any remaining AEGIS processes...
    taskkill /F /IM aegis-nids.exe >nul 2>&1
    taskkill /F /IM aegis_bridge.exe >nul 2>&1
    taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
    taskkill /F /IM aegis-nose.exe >nul 2>&1
    for /f "tokens=2 delims=," %%p in ('wmic process where "CommandLine like '%%windows_brain%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
    for /f "tokens=2 delims=," %%p in ('wmic process where "CommandLine like '%%windows_perf%%'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
        taskkill /F /PID %%p >nul 2>&1
    )
)

:: -- รอยืนยันว่า process ตายหมด --
echo.
echo Waiting for processes to exit...
timeout /t 2 /nobreak >nul

set "STILL_RUNNING=0"
tasklist /NH 2>nul | find /I "aegis-nids.exe" >nul && set "STILL_RUNNING=1"
tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul && set "STILL_RUNNING=1"
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul && set "STILL_RUNNING=1"

if !STILL_RUNNING!==1 (
    echo.
    echo [!] Some processes still running. Use --force to kill immediately.
    echo     stop_aegis.bat --force
) else (
    echo.
    echo ================================================================
    echo  AEGIS NIDS stopped successfully
    echo ================================================================
)

endlocal
