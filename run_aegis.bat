@echo off
echo ===================================================
echo      Cleaning up old Aegis processes...
echo ===================================================
:: เปลี่ยนชื่อ Process ของ Zig ให้ตรงกับใน build.zig (aegis-nids.exe)
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1
taskkill /F /IM go.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1

echo ===================================================
echo      Starting AEGIS NIDS Full Architecture...
echo ===================================================

:: สร้างโฟลเดอร์ logs ถ้ายังไม่มี
if not exist "logs" mkdir logs
type nul > logs\anomalous.json

:: 1. เปิดหน้าต่าง Zig Core (เปลี่ยนมาใช้ zig build run จะเสถียรกว่า)
echo [1/5] Compiling and Starting Zig Core...
start "AEGIS CORE (Zig)" cmd /k "zig build run"

:: 2. เปิดหน้าต่าง Python Brain (รอให้ Zig พร้อมก่อน 2 วินาที)
echo [2/5] Starting Python Brain...
timeout /t 2 /nobreak > NUL 
start "AEGIS BRAIN (Python)" cmd /k "python windows_brain.py"

:: 3. เปิดหน้าต่าง Python Dashboard (อันนี้คุณลืมใส่ในไฟล์เดิม!)
echo [3/5] Starting Python Dashboard...
start "AEGIS DASHBOARD (Python)" cmd /k "python Dashboard.py"

:: 4. เปิดหน้าต่าง Go Perf (ไฟล์ที่คุณเพิ่งส่งมา)
echo [4/5] Starting Go Perf Sensor...
start "AEGIS NOSE (Go)" cmd /k "go run windows_perf.go"

:: 5. เปิดหน้าต่าง Rust Sec Monitor
echo [5/5] Starting Rust Sec Monitor...
start "AEGIS MOUTH (Rust)" cmd /k "rustc windows_sec_monitor.rs && windows_sec_monitor.exe"