@echo off
echo ===================================================
echo      Cleaning up old Aegis processes...
echo ===================================================
:: ปิด process เก่า ๆ ก่อน start ใหม่
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1
taskkill /F /IM go.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1

echo ===================================================
echo      Building dependencies (Rust FFI)...
echo ===================================================
:: Build Rust FFI library ก่อน — Zig ต้องการ sec_monitor.dll
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
)

echo ===================================================
echo      Starting AEGIS NIDS Full Architecture...
echo ===================================================

:: สร้างโฟลเดอร์ logs ถ้ายังไม่มี และ clear log file
if not exist "logs" mkdir logs
type nul > logs\anomalous.json

:: 1. เปิดหน้าต่าง Zig Core
echo [1/5] Compiling and Starting Zig Core...
start "AEGIS CORE (Zig)" cmd /k "zig build run"

:: 2. เปิดหน้าต่าง Python Brain (รอ 2 วินาทีให้ Zig พร้อม)
echo [2/5] Starting Python Brain...
timeout /t 2 /nobreak > NUL
start "AEGIS BRAIN (Python)" cmd /k "python windows_brain.py"

:: 3. เปิดหน้าต่าง Python Dashboard
echo [3/5] Starting Python Dashboard...
start "AEGIS DASHBOARD (Python)" cmd /k "python Dashboard.py"

:: 4. เปิดหน้าต่าง Go Perf
echo [4/5] Starting Go Perf Sensor...
start "AEGIS NOSE (Go)" cmd /k "go run windows_perf.go"

:: 5. เปิดหน้าต่าง Rust Sec Monitor
echo [5/5] Starting Rust Sec Monitor...
start "AEGIS MOUTH (Rust)" cmd /k "rustc windows_sec_monitor.rs && windows_sec_monitor.exe"

echo.
echo ===================================================
echo  All subsystems started!
echo  - AEGIS CORE (Zig)         : NIDS engine + 5 threads
echo  - AEGIS BRAIN (Python)     : Tier-2/3 regex + IPS
echo  - AEGIS DASHBOARD (Python) : TUI log viewer
echo  - AEGIS NOSE (Go)          : Perf monitor
echo  - AEGIS MOUTH (Rust)       : DEFCON display
echo ===================================================
echo.
echo  Optional: run 'python aegis_console.py' in another terminal
echo  for rule management UI + threat graph viewer.
echo.
pause
