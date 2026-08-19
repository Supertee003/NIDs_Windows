@echo off
setlocal enabledelayedexpansion
REM chcp 65001 removed (causes encoding issues)

:: ================================================================
::  AEGIS NIDS — Full System Launcher v2.1
::  เปิดระบบ AEGIS NIDS ทั้ง 5 subsystems พร้อม pre-flight checks
::  NOSE upgraded to v4.0 (DevDash-style TUI dashboard)
::
::  Usage:  run_aegis.bat [options]
::  Options:
::    --skip-build    ข้ามขั้นตอน build (ใช้ binary เดิม)
::    --skip-check    ข้าม pre-flight checks
::    --no-dashboard  ไม่เปิด CLI dashboard หลัง start
::    --stop          หยุดระบบ (เรียก stop_aegis.bat)
::    --status        แสดงสถานะเท่านั้น (ไม่ start)
:: ================================================================

:: -- Auto-detect Project Root --
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT="

:: Method 1: รันจาก scripts/ subdirectory — ขึ้น 1 ระดับ
if exist "%SCRIPT_DIR%..\core" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
) else if exist "%SCRIPT_DIR%..\brain" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
) else if exist "%SCRIPT_DIR%..\build.zig" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
) else if exist "%SCRIPT_DIR%..\mouth" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
)

:: Method 2: รันจาก project root เอง — อยู่ที่เดิม
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%core" (
        set "PROJECT_ROOT=%SCRIPT_DIR%"
    ) else if exist "%SCRIPT_DIR%brain" (
        set "PROJECT_ROOT=%SCRIPT_DIR%"
    ) else if exist "%SCRIPT_DIR%build.zig" (
        set "PROJECT_ROOT=%SCRIPT_DIR%"
    ) else if exist "%SCRIPT_DIR%mouth" (
        set "PROJECT_ROOT=%SCRIPT_DIR%"
    )
)

:: Method 3: Fallback
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%..\..\core" set "PROJECT_ROOT=%SCRIPT_DIR%..\.."
)

if not defined PROJECT_ROOT (
    echo.
    echo  [ERROR] Cannot find AEGIS NIDS project root!
    echo         Looked for markers: core/, brain/, mouth/, build.zig
    echo         Script dir: %SCRIPT_DIR%
    echo         Run from D:\NIDs_Windows\ or D:\NIDs_Windows\scripts\
    echo.
    exit /b 1
)

:: -- Resolve PROJECT_ROOT --
for %%i in ("%PROJECT_ROOT%") do set "PROJECT_ROOT=%%~fi"
cd /d "%PROJECT_ROOT%"
echo  [AEGIS] Project root: %CD%

:: -- Parse arguments --
set "SKIP_BUILD=0"
set "SKIP_CHECK=0"
set "NO_DASHBOARD=0"
set "ACTION=start"

:parse_args
if "%~1"=="" goto :done_parse
if /I "%~1"=="--skip-build" set "SKIP_BUILD=1"
if /I "%~1"=="--skip-check" set "SKIP_CHECK=1"
if /I "%~1"=="--no-dashboard" set "NO_DASHBOARD=1"
if /I "%~1"=="--stop" set "ACTION=stop"
if /I "%~1"=="--status" set "ACTION=status"
shift
goto :parse_args
:done_parse

:: -- Handle --stop --
if "%ACTION%"=="stop" (
    if exist "%~dp0stop_aegis.bat" (
        call "%~dp0stop_aegis.bat" --force
    ) else (
        echo [!] stop_aegis.bat not found -- killing manually...
        taskkill /F /IM aegis-nids.exe >nul 2>&1
        taskkill /F /IM aegis_bridge.exe >nul 2>&1
        taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
        taskkill /F /IM aegis-nose.exe >nul 2>&1
    )
    goto :eof
)

:: -- Handle --status --
if "%ACTION%"=="status" goto :show_status

:: ================================================================
echo.
echo  +==========================================================+
echo  |           AEGIS NIDS -- Full System Launcher v2.1        |
echo  |     5-Language Network Intrusion Detection System        |
echo  +==========================================================+
echo.

:: -- Timestamp --
for /f "tokens=2 delims==" %%d in ('wmic os get localdatetime /value 2^>nul') do set "DT=%%d"
set "START_TIME=%DT:~0,4%-%DT:~4,2%-%DT:~6,2% %DT:~8,2%:%DT:~10,2%:%DT:~12,2%"
echo  Start time: %START_TIME%
echo.

:: ================================================================
::  PHASE 0: Cleanup Old Processes
:: ================================================================
echo ----------------------------------------------------------------
echo  [Phase 0] Cleaning up old AEGIS processes...
echo ----------------------------------------------------------------

set "FOUND_OLD=0"
tasklist /NH 2>nul | find /I "aegis-nids.exe" >nul && set "FOUND_OLD=1"
tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul && set "FOUND_OLD=1"
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul && set "FOUND_OLD=1"

if !FOUND_OLD!==1 (
    echo  Found running AEGIS processes -- stopping...
    if exist "%~dp0stop_aegis.bat" (
        call "%~dp0stop_aegis.bat" --force
    ) else (
        taskkill /F /IM aegis-nids.exe >nul 2>&1
        taskkill /F /IM aegis_bridge.exe >nul 2>&1
        taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
        taskkill /F /IM aegis-nose.exe >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
    echo  Old processes stopped.
) else (
    echo  No old processes found. Clean start.
)
echo.

:: ================================================================
::  PHASE 1: Pre-flight Checks
:: ================================================================
if %SKIP_CHECK%==1 goto :skip_checks

echo ----------------------------------------------------------------
echo  [Phase 1] Pre-flight Checks
echo ----------------------------------------------------------------

set "CHECK_PASS=0"
set "CHECK_FAIL=0"
set "CHECK_WARN=0"

:: -- Check: Npcap --
if exist "C:\Windows\System32\Npcap" (
    echo  [OK] Npcap installed
    set /a CHECK_PASS+=1
) else if exist "wpcap.dll" (
    echo  [OK] wpcap.dll found in project dir
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] Npcap not found -- packet capture may not work
    set /a CHECK_WARN+=1
)

:: -- Check: C++ Bridge DLL --
if exist "build\Release\aegis_ipc.dll" (
    echo  [OK] aegis_ipc.dll found
    set /a CHECK_PASS+=1
) else if exist "dist\aegis_ipc.dll" (
    echo  [OK] aegis_ipc.dll found ^(dist^)
    set /a CHECK_PASS+=1
) else if exist "aegis_ipc.dll" (
    echo  [OK] aegis_ipc.dll found ^(root^)
    set /a CHECK_PASS+=1
) else (
    echo  [FAIL] aegis_ipc.dll not found -- build C++ Bridge first
    set /a CHECK_FAIL+=1
)

:: -- Check: C++ Bridge EXE --
if exist "build\Release\aegis_bridge.exe" (
    echo  [OK] aegis_bridge.exe found
    set /a CHECK_PASS+=1
) else if exist "dist\aegis_bridge.exe" (
    echo  [OK] aegis_bridge.exe found ^(dist^)
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] aegis_bridge.exe not found -- will build
    set /a CHECK_WARN+=1
)

:: -- Check: Rust Shield DLL --
if exist "shield\target\release\sec_monitor.dll" (
    echo  [OK] sec_monitor.dll found
    set /a CHECK_PASS+=1
) else if exist "zig-out\bin\sec_monitor.dll" (
    echo  [OK] sec_monitor.dll found ^(zig-out^)
    set /a CHECK_PASS+=1
) else if exist "dist\sec_monitor.dll" (
    echo  [OK] sec_monitor.dll found ^(dist^)
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] sec_monitor.dll not found -- will build
    set /a CHECK_WARN+=1
)

:: -- Check: Rust Mouth EXE --
if exist "dist\windows_sec_monitor.exe" (
    echo  [OK] windows_sec_monitor.exe found ^(pre-built^)
    set /a CHECK_PASS+=1
) else if exist "mouth\windows_sec_monitor.rs" (
    echo  [WARN] dist\windows_sec_monitor.exe not found -- will compile from .e .rs
    set /a CHECK_WARN+=1
) else if exist "mouth\src\main.rs" (
    echo  [WARN] Mouth source found ^(cargo project^) -- will build
    set /a CHECK_WARN+=1
) else (
    echo  [WARN] Mouth source not found -- will skip if exe missing
    set /a CHECK_WARN+=1
)

:: -- Check: Zig Core EXE --
if exist "zig-out\bin\aegis-nids.exe" (
    echo  [OK] aegis-nids.exe found
    set /a CHECK_PASS+=1
) else if exist "dist\aegis-nids.exe" (
    echo  [OK] aegis-nids.exe found ^(dist^)
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] aegis-nids.exe not found -- will build
    set /a CHECK_WARN+=1
)

:: -- Check: Python Brain --
if exist "brain\windows_brain.py" (
    echo  [OK] brain\windows_brain.py found
    set /a CHECK_PASS+=1
) else if exist "brain_python\windows_brain.py" (
    echo  [OK] brain_python\windows_brain.py found
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] brain\windows_brain.py not found -- will skip
    set /a CHECK_WARN+=1
)

:: -- Check: Go Nose v4.0 --
if exist "nose\windows_perf.go" (
    echo  [OK] nose\windows_perf.go found ^(v4.0 DevDash TUI^)
    set /a CHECK_PASS+=1
) else if exist "dist\aegis-nose.exe" (
    echo  [OK] dist\aegis-nose.exe found ^(pre-built fallback^)
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] nose source not found -- Nose will be skipped
    set /a CHECK_WARN+=1
)

:: -- Check: Python --
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [OK] %%v
    set /a CHECK_PASS+=1
) else (
    echo  [FAIL] python not found in PATH
    set /a CHECK_FAIL+=1
)

:: -- Check: Go --
where go >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('go version 2^>^&1') do echo  [OK] %%v
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] go not found -- Nose will be skipped
    set /a CHECK_WARN+=1
)

:: -- Check: go.mod --
if exist "nose\go.mod" (
    echo  [OK] go.mod found
    set /a CHECK_PASS+=1
) else (
    echo  [WARN] go.mod not found -- Go Nose may fail
    set /a CHECK_WARN+=1
)

echo.
echo  Checks: !CHECK_PASS! passed, !CHECK_WARN! warnings, !CHECK_FAIL! failed

if !CHECK_FAIL! gtr 0 (
    echo.
    echo  [!] Critical checks failed. Fix issues above before starting.
    echo      Use --skip-check if you want to skip checks and start anyway.
    set /p "CONTINUE=Continue anyway? (y/N) "
    if /I not "!CONTINUE!"=="y" exit /b 1
)
echo.

:skip_checks

:: ================================================================
::  PHASE 2: Build (if needed)
:: ================================================================
if %SKIP_BUILD%==1 goto :skip_build

echo ----------------------------------------------------------------
echo  [Phase 2] Building Components
echo ----------------------------------------------------------------

:: -- Build C++ Bridge --
if exist "build\Release\aegis_bridge.exe" if exist "build\Release\aegis_ipc.dll" (
    echo  [skip] C++ Bridge already built
    goto :bridge_done
)

echo  [2a] Building C++ IPC Bridge ^(CMake^)...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] cmake not found -- skipping C++ Bridge build
    goto :bridge_done
)

cmake -B build -S bridge -DCMAKE_BUILD_TYPE=Release >nul 2>&1
if %errorlevel% neq 0 (
    echo  [FAIL] CMake configure failed
    goto :bridge_done
)
cmake --build build --config Release >nul 2>&1
if %errorlevel% neq 0 (
    echo  [FAIL] CMake build failed
    goto :bridge_done
)
echo  [OK] C++ Bridge built: aegis_ipc.dll + aegis_bridge.exe
:bridge_done

:: -- Build Rust Shield (cargo) --
if exist "shield\target\release\sec_monitor.dll" (
    echo  [skip] Rust Shield already built
    goto :rust_done
)

echo  [2b] Building Rust FFI Shield ^(cargo^)...
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] cargo not found -- skipping Rust build
    goto :rust_done
)

cargo build --release --manifest-path shield\Cargo.toml 2>nul
if %errorlevel% neq 0 (
    echo  [FAIL] Rust build failed
    goto :rust_done
)
echo  [OK] Rust Shield built: sec_monitor.dll
:rust_done

:: -- Build Rust Mouth (pre-compile) --
if exist "dist\windows_sec_monitor.exe" (
    echo  [skip] Rust Mouth already compiled
    goto :mouth_done
)

echo  [2c] Pre-compiling Rust Mouth ^(rustc^)...
where rustc >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] rustc not found -- will compile at start time
    goto :mouth_done
)

rustc -O mouth\windows_sec_monitor.rs -o dist\windows_sec_monitor.exe 2>nul
if %errorlevel% neq 0 (
    echo  [WARN] rustc compile failed -- will try at start time
    goto :mouth_done
)
echo  [OK] Rust Mouth pre-compiled: dist\windows_sec_monitor.exe
:mouth_done

:: -- Build Zig Core --
if exist "zig-out\bin\aegis-nids.exe" (
    echo  [skip] Zig Core already built
    goto :zig_done
)

echo  [2d] Building Zig Core ^(zig build^)...
where zig >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] zig not found -- will try 'zig build run' at start
    goto :zig_done
)

zig build >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] zig build failed -- will try at start time
    goto :zig_done
)
echo  [OK] Zig Core built: aegis-nids.exe
:zig_done

:: -- Build Go Nose v4.0 (pre-compile + dependencies) --
if exist "dist\aegis-nose.exe" (
    echo  [skip] Go Nose already compiled
    goto :go_done
)

if not exist "nose\go.mod" goto :go_done

echo  [2e] Downloading Go Nose v4.0 dependencies...
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo  [WARN] go not found -- will use 'go run' at start time
    goto :go_done
)

cd nose && go mod tidy 2>nul && cd ..
echo  [2e] Pre-compiling Go Nose v4.0 ^(go build^)...
cd nose && go build -o ..\dist\aegis-nose.exe windows_perf.go 2>nul && cd ..
if %errorlevel% neq 0 (
    echo  [WARN] go build failed -- will use 'go run' at start time
    goto :go_done
)
echo  [OK] Go Nose v4.0 pre-compiled: dist\aegis-nose.exe
:go_done

echo.

:skip_build

:: ================================================================
::  PHASE 3: Setup Environment
:: ================================================================
echo ----------------------------------------------------------------
echo  [Phase 3] Environment Setup
echo ----------------------------------------------------------------

if not exist "logs" mkdir logs
type nul > logs\anomalous.json

set "LOG_FILE=logs\startup_%DT:~0,8%_%DT:~8,6%.log"
echo AEGIS NIDS Startup Log - %START_TIME% > "%LOG_FILE%"

if exist "build\Release\aegis_ipc.dll" (
    if not exist "zig-out\bin\aegis_ipc.dll" (
        copy /Y "build\Release\aegis_ipc.dll" "zig-out\bin\" >nul 2>&1
    )
)
if exist "shield\target\release\sec_monitor.dll" (
    if not exist "zig-out\bin\sec_monitor.dll" (
        copy /Y "shield\target\release\sec_monitor.dll" "zig-out\bin\" >nul 2>&1
    )
)

echo  Log file: %LOG_FILE%
echo  DLLs synced to zig-out\bin\
echo.

:: ================================================================
::  PHASE 4: Start Subsystems (Ordered)
:: ================================================================
echo ----------------------------------------------------------------
echo  [Phase 4] Starting AEGIS NIDS Subsystems
echo ----------------------------------------------------------------
echo.

:: -- Bridge --
echo  [4.1] Starting C++ IPC Bridge...
if exist "build\Release\aegis_bridge.exe" (
    start "AEGIS BRIDGE (C++)" /MIN cmd /k "build\Release\aegis_bridge.exe"
    echo       build\Release\aegis_bridge.exe
) else (
    echo  [FAIL] aegis_bridge.exe not found!
)
echo       Waiting for IPC hub to initialize...
timeout /t 3 /nobreak >nul

:: -- Core (Zig) --
echo  [4.2] Starting Zig Core...
if exist "zig-out\bin\aegis-nids.exe" (
    start "AEGIS CORE (Zig)" /MIN cmd /k "zig-out\bin\aegis-nids.exe"
    echo       zig-out\bin\aegis-nids.exe
) else (
    where zig >nul 2>&1
    if %errorlevel% equ 0 (
        start "AEGIS CORE (Zig)" /MIN cmd /k "zig build run"
        echo       zig build run
    ) else (
        echo  [FAIL] Zig Core not available!
    )
)
echo       Waiting for Core threads to spawn...
timeout /t 3 /nobreak >nul

:: -- Brain (Python) --
echo  [4.3] Starting Python Brain...
if exist "brain\windows_brain.py" (
    start "AEGIS BRAIN (Python)" /MIN cmd /k "python brain\windows_brain.py"
    echo       python brain\windows_brain.py
) else (
    echo  [FAIL] brain\windows_brain.py not found!
)
echo       Waiting for Brain to load rules...
timeout /t 2 /nobreak >nul

:: -- Nose (Go) v4.0 — DevDash-style TUI Dashboard (minimized window) --
echo  [4.4] Starting Go Nose v4.0 ^(DevDash TUI Dashboard^)...
if exist "dist\aegis-nose.exe" (
    start "AEGIS NOSE (Go) v4.0" /MIN cmd /k "dist\aegis-nose.exe"
    echo       dist\aegis-nose.exe ^(pre-built v4.0^)
) else if exist "nose\windows_perf.go" (
    start "AEGIS NOSE (Go) v4.0" /MIN cmd /k "cd nose && go run windows_perf.go"
    echo       go run windows_perf.go ^(DevDash TUI v4.0^)
) else (
    echo  [SKIP] Nose not available
)

:: -- Mouth (Rust) --
echo  [4.5] Starting Rust Mouth ^(sole TUI window^)...
if exist "dist\windows_sec_monitor.exe" (
    start "AEGIS MOUTH (Rust)" cmd /k "dist\windows_sec_monitor.exe"
    echo       dist\windows_sec_monitor.exe ^(sole DEFCON TUI^)
) else if exist "mouth\windows_sec_monitor.rs" (
    start "AEGIS MOUTH (Rust)" cmd /k "rustc -O mouth\windows_sec_monitor.rs -o dist\windows_sec_monitor.exe && dist\windows_sec_monitor.exe"
    echo       rustc compile + run ^(sole TUI^)
) else (
    echo  [SKIP] Mouth not available
)

echo.
echo       Waiting for all subsystems to stabilize...
timeout /t 3 /nobreak >nul

:: ================================================================
::  PHASE 5: Health Check
:: ================================================================
echo ----------------------------------------------------------------
echo  [Phase 5] Health Check
echo ----------------------------------------------------------------

set "HEALTH_OK=0"
set "HEALTH_FAIL=0"

:: -- Check Bridge --
tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul
if %errorlevel% equ 0 (
    echo  [OK] Bridge  -- running
    set /a HEALTH_OK+=1
) else (
    echo  [FAIL] Bridge -- NOT running
    set /a HEALTH_FAIL+=1
)

:: -- Check Core --
tasklist /NH 2>nul | find /I "aegis-nids.exe" >nul
if %errorlevel% equ 0 (
    echo  [OK] Core    -- running
    set /a HEALTH_OK+=1
) else (
    echo  [FAIL] Core   -- NOT running
    set /a HEALTH_FAIL+=1
)

:: -- Check Brain --
set "BRAIN_OK=0"
wmic process where "Name='python.exe'" get CommandLine 2>nul | find /I "windows_brain" >nul && set "BRAIN_OK=1"
if !BRAIN_OK!==1 (
    echo  [OK] Brain   -- running
    set /a HEALTH_OK+=1
) else (
    echo  [FAIL] Brain  -- NOT running
    set /a HEALTH_FAIL+=1
)

:: -- Check Nose --
set "NOSE_OK=0"
tasklist /NH 2>nul | find /I "aegis-nose.exe" >nul && set "NOSE_OK=1"
if !NOSE_OK!==0 (
    wmic process where "Name='go.exe'" get CommandLine 2>nul | find /I "windows_perf" >nul && set "NOSE_OK=1"
)
if !NOSE_OK!==1 (
    echo  [OK] Nose    -- running
    set /a HEALTH_OK+=1
) else (
    echo  [FAIL] Nose   -- NOT running
    set /a HEALTH_FAIL+=1
)

:: -- Check Mouth --
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul
if %errorlevel% equ 0 (
    echo  [OK] Mouth   -- running
    set /a HEALTH_OK+=1
) else (
    echo  [FAIL] Mouth  -- NOT running
    set /a HEALTH_FAIL+=1
)

echo.
echo  Health: !HEALTH_OK!/5 subsystems running

:: ================================================================
::  Summary
:: ================================================================
echo.
echo +==========================================================+
echo |              AEGIS NIDS System Status                    |
echo +==========================================================+
echo |  BRIDGE  ^(C++^)   : IPC hub + Packet Parser + DEFCON     |
echo |  CORE    ^(Zig^)   : NIDS engine + 5 threads + Bridge     |
echo |  BRAIN   ^(Python^): Tier-2/3 regex + IPS + Bridge        |
echo |  NOSE    ^(Go^)    : DevDash TUI Dashboard v4.0          |
echo |  MOUTH   ^(Rust^)  : Security monitor + DEFCON display    |
echo +==========================================================+
echo |  Health: !HEALTH_OK!/5    Start: %START_TIME%            |
echo +==========================================================+
echo |  Data Flow:                                              |
echo |    Zig Core -^> C++ Bridge -^> Dashboard                 |
echo |    Zig Core -^> Brain ^(UDP^) -^> Bridge -^> Dashboard    |
echo +==========================================================+
echo.

:: -- Write to log --
echo Subsystems started: !HEALTH_OK!/5 >> "%LOG_FILE%"
echo Health check at: %START_TIME% >> "%LOG_FILE%"

:: -- Launch Command Control Center (optional) --
if %NO_DASHBOARD%==1 goto :no_dashboard

if exist "scripts\aegis_console.py" (
    echo  Launching AEGIS Command Control Center...
    echo.
    start "AEGIS COMMAND CENTER" cmd /k "python scripts\aegis_console.py"
) else if exist "scripts\aegis_dashboard.py" (
    echo  Launching real-time CLI dashboard...
    start "AEGIS DASHBOARD" cmd /k "python scripts\aegis_dashboard.py"
) else if exist "scripts\Dashboard.py" (
    echo  Launching web dashboard...
    start "AEGIS DASHBOARD" cmd /k "python scripts\Dashboard.py"
)
:no_dashboard

echo  Tips:
echo    - Run 'scripts\stop_aegis.bat' to shutdown gracefully
echo    - Run 'scripts\aegis_status.bat' to check status anytime
echo    - Run 'python scripts\aegis_console.py' for Command Control Center
echo    - NOSE: Ctrl+Q to quit, Ctrl+R to force refresh
echo.

pause
goto :eof

:: ================================================================
::  :show_status
:: ================================================================
:show_status
echo.
echo ============================================================
echo  AEGIS NIDS -- System Status
echo ============================================================
echo.

set "TOTAL=0"
set "RUNNING=0"

:: Bridge
set /a TOTAL+=1
tasklist /NH 2>nul | find /I "aegis_bridge.exe" >nul
if %errorlevel% equ 0 (
    echo  [RUNNING] BRIDGE  ^(C++^)   -- aegis_bridge.exe
    set /a RUNNING+=1
) else (
    echo  [STOPPED] BRIDGE  ^(C++^)
)

:: Core
set /a TOTAL+=1
tasklist /NH 2>nul | find /I "aegis-nids.exe" >nul
if %errorlevel% equ 0 (
    echo  [RUNNING] CORE    ^(Zig^)   -- aegis-nids.exe
    set /a RUNNING+=1
) else (
    echo  [STOPPED] CORE    ^(Zig^)
)

:: Brain
set /a TOTAL+=1
set "BRAIN_STATUS=STOPPED"
wmic process where "Name='python.exe'" get CommandLine 2>nul | find /I "windows_brain" >nul && set "BRAIN_STATUS=RUNNING"
if "!BRAIN_STATUS!"=="RUNNING" (
    echo  [RUNNING] BRAIN   ^(Python^) -- windows_brain.py
    set /a RUNNING+=1
) else (
    echo  [STOPPED] BRAIN   ^(Python^)
)

:: Nose
set /a TOTAL+=1
set "NOSE_STATUS=STOPPED"
tasklist /NH 2>nul | find /I "aegis-nose.exe" >nul && set "NOSE_STATUS=RUNNING"
if "!NOSE_STATUS!"=="STOPPED" (
    wmic process where "Name='go.exe'" get CommandLine 2>nul | find /I "windows_perf" >nul && set "NOSE_STATUS=RUNNING"
)
if "!NOSE_STATUS!"=="RUNNING" (
    echo  [RUNNING] NOSE    ^(Go^)    -- aegis-nose / windows_perf.go v4.0
    set /a RUNNING+=1
) else (
    echo  [STOPPED] NOSE    ^(Go^)
)

:: Mouth
set /a TOTAL+=1
tasklist /NH 2>nul | find /I "windows_sec_monitor.exe" >nul
if %errorlevel% equ 0 (
    echo  [RUNNING] MOUTH   ^(Rust^)  -- windows_sec_monitor.exe
    set /a RUNNING+=1
) else (
    echo  [STOPPED] MOUTH   ^(Rust^)
)

echo.
echo  Status: !RUNNING!/!TOTAL! subsystems running
echo.

if !RUNNING!==!TOTAL! (
    echo  *** AEGIS FULLY OPERATIONAL ***
) else if !RUNNING! gtr 0 (
    echo  *** AEGIS PARTIALLY RUNNING ***
) else (
    echo  *** AEGIS STOPPED ***
)
echo.

endlocal
