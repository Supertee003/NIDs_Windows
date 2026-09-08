@echo off
setlocal enabledelayedexpansion
REM ============================================================================
REM AEGIS NIDS - Deep System Diagnostic
REM Tests console, IPC bridge, Brain UDP, all subsystems
REM Run from: D:\NIDs_Windows (while AEGIS is running)
REM Usage: scripts\diag_deep.bat
REM ============================================================================

echo.
echo ============================================================
echo  AEGIS NIDS - Deep System Diagnostic
echo ============================================================
echo.

set "ROOT=%~dp0.."
if not exist "%ROOT%\brain" set "ROOT=."

REM ============================================================
echo [1] Python Environment
echo ============================================================
echo.

python --version 2>&1
echo.
echo   Python path:
where python 2>NUL
echo.

REM ============================================================
echo [2] Python Dependencies
echo ============================================================
echo.

python -c "import psutil; print('  [OK] psutil', psutil.__version__)" 2>NUL
if !errorlevel! NEQ 0 echo   [MISSING] psutil - console needs this!

python -c "import aegis_graph; print('  [OK] aegis_graph available')" 2>NUL
if !errorlevel! NEQ 0 echo   [MISSING] aegis_graph - optional for threat graph

python -c "import json; print('  [OK] json')" 2>NUL
python -c "import ctypes; print('  [OK] ctypes')" 2>NUL
python -c "import socket; print('  [OK] socket')" 2>NUL
python -c "import subprocess; print('  [OK] subprocess')" 2>NUL

echo.

REM ============================================================
echo [3] AEGIS Bridge ctypes Import
echo ============================================================
echo.

echo   Testing: import aegis_bridge_ctypes from shared/...
python -c "import sys; sys.path.insert(0, 'shared'); import aegis_bridge_ctypes as b; print('  [OK] aegis_bridge_ctypes imported'); print('  DLL loaded:', b._bridge_dll is not None)" 2>&1

echo.

REM ============================================================
echo [4] Bridge IPC Connection Test
echo ============================================================
echo.

echo   Testing bridge_init()...
python -c "import sys; sys.path.insert(0, 'shared'); import aegis_bridge_ctypes as b; rc = b.bridge_init(); print('  bridge_init() rc =', rc); print('  Result:', 'OK - connected' if rc == 0 else 'FAILED - bridge not ready or DLL issue'); b.bridge_shutdown() if rc == 0 else None" 2>&1

echo.

echo   Testing DEFCON level...
python -c "import sys; sys.path.insert(0, 'shared'); import aegis_bridge_ctypes as b; rc = b.bridge_init(); level = b.get_defcon_level() if rc == 0 else -1; label = b.get_defcon_label() if rc == 0 else 'N/A'; print('  DEFCON level:', level); print('  DEFCON label:', label); b.bridge_shutdown() if rc == 0 else None" 2>&1

echo.

echo   Testing event count...
python -c "import sys; sys.path.insert(0, 'shared'); import aegis_bridge_ctypes as b; rc = b.bridge_init(); cnt = b.get_event_count() if rc == 0 else -1; drop = b.get_dropped_count() if rc == 0 else -1; print('  Event count:', cnt); print('  Dropped:', drop); b.bridge_shutdown() if rc == 0 else None" 2>&1

echo.

REM ============================================================
echo [5] Brain UDP Communication Test
echo ============================================================
echo.

echo   Checking UDP port 9999...
netstat -anop udp 2>NUL | find "9999" >NUL 2>&1
if !errorlevel!==0 (
    echo   [OK] UDP 9999 is OPEN
    netstat -anop udp 2>NUL | find "9999"
    echo.
    echo   Sending test packet to Brain...
    python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b'DIAG_PING', ('127.0.0.1', 9999)); print('  [OK] Sent DIAG_PING to UDP 9999'); s.close()" 2>&1
) else (
    echo   [FAIL] UDP 9999 is CLOSED - Brain not listening
)

echo.

REM ============================================================
echo [6] Console Import Test
echo ============================================================
echo.

echo   Testing aegis_console.py import chain...
python -c "import sys, os; sys.path.insert(0, os.path.join('scripts')); sys.path.insert(0, 'shared'); print('  Step 1: sys.path setup OK')" 2>&1

python -c "import sys, os; sys.path.insert(0, 'shared'); import aegis_bridge_ctypes as bridge; print('  Step 2: bridge import OK, available =', bridge._bridge_dll is not None)" 2>&1

python -c "import psutil; print('  Step 3: psutil OK')" 2>NUL
if !errorlevel! NEQ 0 echo   Step 3: psutil MISSING - install with: pip install psutil

echo.

REM ============================================================
echo [7] Rules.json
echo ============================================================
echo.

if exist "%ROOT%\config\Rules.json" (
    echo   [OK] config\Rules.json found
    python -c "import json; r=json.load(open('config/Rules.json')); print('  Rules count:', len(r) if isinstance(r, list) else 'dict with', len(r), 'keys')" 2>&1
) else (
    echo   [MISSING] config\Rules.json
)

echo.

REM ============================================================
echo [8] DLL Availability
echo ============================================================
echo.

echo   Checking DLLs:
if exist "%ROOT%\dist\aegis_ipc.dll" (echo   [OK] dist\aegis_ipc.dll) else (echo   [MISSING] dist\aegis_ipc.dll)
if exist "%ROOT%\build\Release\aegis_ipc.dll" (echo   [OK] build\Release\aegis_ipc.dll) else (echo   [--] build\Release\aegis_ipc.dll)
if exist "%ROOT%\dist\sec_monitor.dll" (echo   [OK] dist\sec_monitor.dll) else (echo   [MISSING] dist\sec_monitor.dll)

echo.

REM ============================================================
echo [9] All Running Processes
echo ============================================================
echo.

echo   AEGIS processes:
tasklist /FI "IMAGENAME eq aegis_bridge.exe" /FO TABLE 2>NUL | find "aegis"
tasklist /FI "IMAGENAME eq aegis-nids.exe" /FO TABLE 2>NUL | find "aegis"
tasklist /FI "IMAGENAME eq python.exe" /FO TABLE 2>NUL | find "python"
tasklist /FI "IMAGENAME eq aegis-nose.exe" /FO TABLE 2>NUL | find "nose"
tasklist /FI "IMAGENAME eq windows_sec_monitor.exe" /FO TABLE 2>NUL | find "windows"

echo.

REM ============================================================
echo [10] psutil Install Check
echo ============================================================
echo.

python -c "import psutil" 2>NUL
if !errorlevel! NEQ 0 (
    echo   [MISSING] psutil is NOT installed!
    echo.
    echo   The AEGIS console REQUIRES psutil for process detection.
    echo   Without it, the console falls back to tasklist which is
    echo   less reliable and may not detect subsystems correctly.
    echo.
    echo   Install with:
    echo     pip install psutil
) else (
    echo   [OK] psutil is installed
)

echo.

REM ============================================================
echo [11] Console Launch Test
echo ============================================================
echo.

echo   Testing console launch directly...
echo   Running: python -c "import sys; sys.path.insert(0,'shared'); exec(open('scripts/aegis_console.py').read())"
echo   (Timeout 10 sec)
echo.

start /MIN cmd /c "python scripts\aegis_console.py 2>console_error.log"
timeout /T 10 /NOBREAK >NUL 2>&1

tasklist /FI "IMAGENAME eq python.exe" 2>NUL | find /I "python" >NUL 2>&1
if !errorlevel!==0 (
    echo   [OK] Console python.exe is running
) else (
    echo   [FAIL] Console python.exe not running - crashed!
    if exist "console_error.log" (
        echo   Error log:
        type console_error.log
    )
)

echo.

REM ============================================================
echo ============================================================
echo  DEEP DIAGNOSTIC COMPLETE
echo ============================================================
echo.
echo  Most common console fix: pip install psutil
echo.

endlocal