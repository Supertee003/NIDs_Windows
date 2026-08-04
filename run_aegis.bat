@echo off
echo ===================================================
echo      Cleaning up old Aegis processes...
echo ===================================================
:: ปิด process เก่า ๆ ก่อน start ใหม่
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM aegis_bridge.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1
taskkill /F /IM go.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1

echo ===================================================
echo      [1/6] Building C++ IPC Bridge (CMake)...
echo ===================================================
:: Build C++ Bridge DLL + executable ก่อน — Zig และ Python ต้องการ aegis_ipc.dll
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] cmake not found in PATH — skip C++ Bridge build
    echo     จะใช้ build/Release/aegis_ipc.dll เดิม (ถ้ามี)
) else (
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    if %errorlevel% neq 0 (
        echo [!] CMake configure failed — กรุณาตรวจสอบ Visual Studio 2022
        pause
        exit /b 1
    )
    cmake --build build --config Release
    if %errorlevel% neq 0 (
        echo [!] CMake build failed — กรุณาตรวจสอบ bridge/*.cpp
        pause
        exit /b 1
    )
    echo [OK] C++ Bridge built successfully
)

echo ===================================================
echo      [2/6] Building Rust FFI (sec_monitor.dll)...
echo ===================================================
:: Build Rust FFI library — Zig ต้องการ sec_monitor.dll
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] cargo not found in PATH — skip Rust build
    echo     จะใช้ target/release/sec_monitor.dll เดิม (ถ้ามี)
) else (
    cargo build --release
    if %errorlevel% neq 0 (
        echo [!] Rust build failed — กรุณาตรวจสอบ Cargo.toml และ src/lib.rs
        pause
        exit /b 1
    )
    echo [OK] Rust FFI built successfully
)

echo ===================================================
echo      Starting AEGIS NIDS Full Architecture...
echo ===================================================

:: สร้างโฟลเดอร์ logs ถ้ายังไม่มี และ clear log file
if not exist "logs" mkdir logs
type nul > logs\anomalous.json

:: 3. เปิดหน้าต่าง C++ Bridge (daemon mode)
echo [3/6] Starting C++ IPC Bridge (daemon)...
start "AEGIS BRIDGE (C++)" cmd /k "build\Release\aegis_bridge.exe"
timeout /t 2 /nobreak > NUL

:: 4. เปิดหน้าต่าง Zig Core
echo [4/6] Compiling and Starting Zig Core...
start "AEGIS CORE (Zig)" cmd /k "zig build run"

:: 5. เปิดหน้าต่าง Python Brain (รอ 2 วินาทีให้ Zig พร้อม)
echo [5/6] Starting Python Brain...
timeout /t 2 /nobreak > NUL
start "AEGIS BRAIN (Python)" cmd /k "python windows_brain.py"

:: 6. เปิดหน้าต่าง Go Perf + Rust Sec Monitor
echo [6/6] Starting remaining subsystems...
timeout /t 1 /nobreak > NUL
start "AEGIS NOSE (Go)" cmd /k "go run windows_perf.go"
start "AEGIS MOUTH (Rust)" cmd /k "rustc windows_sec_monitor.rs && windows_sec_monitor.exe"

echo.
echo ===================================================
echo  All subsystems started!
echo  - AEGIS BRIDGE (C++)       : IPC hub + Packet Parser + DEFCON
echo  - AEGIS CORE (Zig)         : NIDS engine + 5 threads + Bridge
echo  - AEGIS BRAIN (Python)     : Tier-2/3 regex + IPS + Bridge
echo  - AEGIS NOSE (Go)          : Perf monitor
echo  - AEGIS MOUTH (Rust)       : DEFCON display
echo ===================================================
echo.
echo  Data Flow: Zig Core → C++ Bridge → Dashboard
echo             Zig Core → Brain (UDP) → Bridge → Dashboard
echo.
echo  Optional: run 'python aegis_console.py' in another terminal
echo  for rule management UI + threat graph viewer.
echo.
echo  Next.js Dashboard: cd to dashboard dir and run 'npm run dev'
echo.
pause
