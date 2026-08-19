@echo off
cd /d "%~dp0"
echo ===================================================
echo   AEGIS NIDS - Full System Launcher (v3)
echo ===================================================
echo.
echo [0] Cleaning up old processes...
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM aegis_bridge.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM aegis_perf.exe >nul 2>&1
echo.
echo [1/6] Building C++ IPC Bridge...
cmake -B build -DCMAKE_BUILD_TYPE=Release >nul 2>&1
cmake --build build --config Release
if errorlevel 1 ( echo [FAIL] C++ build! & pause & exit /b 1 )
echo [OK]
echo.
echo [2/6] Building Rust FFI...
cargo build --release --manifest-path "%~dp0Cargo.toml"
if errorlevel 1 ( echo [WARN] Rust issues ) else ( echo [OK] )
echo.
echo [3/6] Deploying DLLs...
if not exist "build\Release" mkdir build\Release
for %%F in (aegis_shield.dll aegis_packet_parser.dll sec_monitor.dll) do (
    if exist "target\release\%%F" copy /Y "target\release\%%F" "build\Release\" >nul 2>&1
    if exist "%%F" copy /Y "%%F" "build\Release\" >nul 2>&1
    if exist "%%F" copy /Y "%%F" "." >nul 2>&1
)
echo [OK]
echo.
if not exist "logs" mkdir logs
type nul > logs\anomalous.json 2>nul
echo ===================================================
echo   Launching AEGIS Subsystems (5 windows)...
echo ===================================================
echo.
echo [4/6] C++ Bridge + Zig Core + Python Brain...
start "AEGIS BRIDGE (C++)" cmd /k "mode con cols=100 lines=30 & color 1B & echo  AEGIS BRIDGE (C++) - IPC Hub & echo  ==================================== & build\Release\aegis_bridge.exe"
timeout /t 2 /nobreak >nul
start "AEGIS CORE (Zig)" cmd /k "mode con cols=120 lines=40 & color 2F & echo  AEGIS CORE (Zig) - NIDS Engine & echo  ==================================== & zig build run"
timeout /t 2 /nobreak >nul
start "AEGIS BRAIN (Python)" cmd /k "mode con cols=110 lines=35 & color 4E & echo  AEGIS BRAIN (Python) - Tier-2 & echo  ==================================== & python windows_brain.py"
echo   Bridge + Core + Brain launched
echo.
echo [5/6] Go Nose (perf monitor)...
timeout /t 1 /nobreak >nul
start "AEGIS NOSE (Go)" cmd /k "mode con cols=100 lines=30 & color 3F & echo  AEGIS NOSE (Go) - Perf Monitor & echo  ==================================== & start "AEGIS NOSE" aegis-nose.exe"
echo   [OK] Nose launched
echo.
echo [6/6] Rust Mouth (DEFCON)...
timeout /t 1 /nobreak >nul
if exist "windows_sec_monitor.exe" (
    start "AEGIS MOUTH (Rust)" cmd /k "mode con cols=80 lines=25 & color 5F & echo  AEGIS MOUTH (Rust) - DEFCON & echo  ==================================== & windows_sec_monitor.exe"
    echo   [OK] Mouth launched
) else (
    echo   [SKIP] Mouth not available
)
echo.
echo ===================================================
echo   All subsystems launched!
echo   Press Alt+Tab: BRIDGE CORE BRAIN NOSE MOUTH
echo ===================================================
pause
