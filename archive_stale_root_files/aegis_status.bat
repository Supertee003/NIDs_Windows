@echo off
setlocal enabledelayedexpansion

:: ================================================================
::  AEGIS NIDS — Quick Status Check
::  แสดงสถานะระบบทั้ง 5 subsystems + IPC + DEFCON
::  Usage: aegis_status.bat [--watch] [--json]
::    --watch  รีเฟรชทุก 2 วินาที
::    --json   แสดงผลเป็น JSON (สำหรับ script)
:: ================================================================

set "MODE=single"
if /I "%~1"=="--watch" set "MODE=watch"
if /I "%~1"=="--json" set "MODE=json"
if /I "%~1"=="-w" set "MODE=watch"

:status_loop

set "RUNNING=0"
set "TOTAL=5"

:: -- Bridge --
set "BRIDGE=0"
tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul && set "BRIDGE=1"
if !BRIDGE!==1 set /a RUNNING+=1

:: -- Core --
set "CORE=0"
tasklist /NH 2>nul | find /I "aegis-nids.exe" >nul && set "CORE=1"
if !CORE!==1 set /a RUNNING+=1

:: -- Brain --
set "BRAIN=0"
for /f "tokens=2 delims=," %%p in ('wmic process where "CommandLine like '%%windows_brain%%' and Status='Running'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
    set "BRAIN=1"
)
if !BRAIN!==1 set /a RUNNING+=1

:: -- Nose --
set "NOSE=0"
tasklist /NH 2>nul | find /I "aegis-nose.exe" >nul && set "NOSE=1"
if !NOSE!==0 (
    for /f "tokens=2 delims=," %%p in ('wmic process where "CommandLine like '%%windows_perf%%' and Status='Running'" get ProcessId /format:csv 2^>nul ^| find /V "Node"') do (
        set "NOSE=1"
    )
)
if !NOSE!==1 set /a RUNNING+=1

:: -- Mouth --
set "MOUTH=0"
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul && set "MOUTH=1"
if !MOUTH!==1 set /a RUNNING+=1

:: -- Timestamp --
for /f "tokens=2 delims==" %%d in ('wmic os get localdatetime /value 2^>nul') do set "DT=%%d"
set "NOW=%DT:~0,4%-%DT:~4,2%-%DT:~6,2% %DT:~8,2%:%DT:~10,2%:%DT:~12,2%"

:: -- Output --
if "%MODE%"=="json" (
    echo {"timestamp":"%NOW%","running":!RUNNING!,"total":!TOTAL!,"bridge":!BRIDGE!,"core":!CORE!,"brain":!BRAIN!,"nose":!NOSE!,"mouth":!MOUTH!}
    goto :eof
)

echo.
echo ============================================================
echo  AEGIS NIDS Status — %NOW%
echo ============================================================
echo.

:: Status icons
if !BRIDGE!==1 (echo  [OK] BRIDGE  ^(C++^)   — running) else (echo  [  ] BRIDGE  ^(C++^)   — stopped)
if !CORE!==1   (echo  [OK] CORE    ^(Zig^)   — running) else (echo  [  ] CORE    ^(Zig^)   — stopped)
if !BRAIN!==1  (echo  [OK] BRAIN   ^(Python^) — running) else (echo  [  ] BRAIN   ^(Python^) — stopped)
if !NOSE!==1   (echo  [OK] NOSE    ^(Go^)    — running) else (echo  [  ] NOSE    ^(Go^)    — stopped)
if !MOUTH!==1  (echo  [OK] MOUTH   ^(Rust^)  — running) else (echo  [  ] MOUTH   ^(Rust^)  — stopped)

echo.
echo  !RUNNING!/!TOTAL! subsystems running

if !RUNNING!==!TOTAL! (
    echo.
    echo  *** AEGIS FULLY OPERATIONAL ***
) else if !RUNNING! gtr 0 (
    echo.
    echo  *** AEGIS PARTIALLY RUNNING ***
) else (
    echo.
    echo  *** AEGIS STOPPED ***
)

:: -- IPC Quick Check --
if exist "aegis_ipc.dll" (
    if !BRIDGE!==1 (
        echo.
        echo  IPC: aegis_ipc.dll available
    )
)

:: -- Memory Usage --
if !RUNNING! gtr 0 (
    echo.
    echo  Memory Usage:
    if !BRIDGE!==1 (
        for /f "tokens=5" %%m in ('tasklist /FI "IMAGENAME eq aegis_bridge.exe" /FO TABLE /NH 2^>nul ^| find "aegis_bridge"') do echo     Bridge:  %%m K
    )
    if !CORE!==1 (
        for /f "tokens=5" %%m in ('tasklist /FI "IMAGENAME eq aegis-nids.exe" /FO TABLE /NH 2^>nul ^| find "aegis-nids"') do echo     Core:    %%m K
    )
    if !MOUTH!==1 (
        for /f "tokens=5" %%m in ('tasklist /FI "IMAGENAME eq windows_sec_monitor.exe" /FO TABLE /NH 2^>nul ^| find "windows_sec_monitor"') do echo     Mouth:   %%m K
    )
)

echo.

if "%MODE%"=="watch" (
    timeout /t 2 /nobreak >nul
    cls
    goto :status_loop
)

endlocal

