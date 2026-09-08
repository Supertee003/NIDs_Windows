@echo off
REM =====================================================
REM  AEGIS NIDS - Build All Components (Phase B)
REM  Builds every component, detects toolchains, reports
REM  success/failure for each step.
REM =====================================================
setlocal enabledelayedexpansion

:: ── Auto-detect Project Root ──
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

:: Method 2: รันจาก project root เอง
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

if not defined PROJECT_ROOT (
    echo  [ERROR] Cannot find AEGIS NIDS project root!
    exit /b 1
)

cd /d "%PROJECT_ROOT%"

set PASS=0
set FAIL=0
set SKIP=0

echo.
echo  ===================================================
echo       AEGIS NIDS - Build All Components (Phase B)
echo  ===================================================
echo.

REM ====== [1/7] C++ IPC Bridge ======
echo [1/7] C++ IPC Bridge (CMake)...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] cmake not found
    set /a SKIP+=1
    goto step2
)
cmake -B build -S bridge -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    echo   [FAIL] CMake configure failed
    set /a FAIL+=1
    goto step2
)
cmake --build build --config Release
if %errorlevel% neq 0 (
    echo   [FAIL] CMake build failed - check bridge/*.cpp
    set /a FAIL+=1
    goto step2
)
echo   [OK] C++ Bridge: aegis_ipc.dll + aegis_bridge.exe + aegis_bridge_test.exe
set /a PASS+=1

:step2
echo [2/7] Rust Tier-3 Shield (sec_monitor.dll)...
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] cargo not found
    set /a SKIP+=1
    goto step3
)
cargo build --release --manifest-path shield\Cargo.toml
if %errorlevel% neq 0 (
    echo   [FAIL] Rust build failed
    set /a FAIL+=1
    goto step3
)
echo   [OK] Rust FFI: shield/target/release/sec_monitor.dll
set /a PASS+=1

:step3
echo [3/7] Go Nose (nose_dashboard.exe)...
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] go not found
    set /a SKIP+=1
    goto step4
)
cd nose && go build -o ..\dist\nose_dashboard.exe . && cd ..
if %errorlevel% neq 0 (
    echo   [FAIL] Go build failed
    set /a FAIL+=1
    goto step4
)
echo   [OK] Go Nose: dist\nose_dashboard.exe
set /a PASS+=1

:step4
echo [4/7] Zig Tier-1 Core...
where zig >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] zig not found
    set /a SKIP+=1
    goto step5
)
zig build
if %errorlevel% neq 0 (
    echo   [FAIL] Zig build failed
    set /a FAIL+=1
    goto step5
)
echo   [OK] Zig Core: zig-out/bin/aegis-nids.exe (DLLs loaded at runtime)
set /a PASS+=1

:step5
echo [5/7] egui Dashboard...
if not exist "aegis_dashboard\Cargo.toml" (
    echo   [SKIP] aegis_dashboard/Cargo.toml not found
    set /a SKIP+=1
    goto step6
)
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] cargo not found
    set /a SKIP+=1
    goto step6
)
cd aegis_dashboard
cargo build --release
if %errorlevel% neq 0 (
    echo   [FAIL] egui Dashboard build failed
    set /a FAIL+=1
    cd ..
    goto step6
)
cd ..
echo   [OK] egui Dashboard: aegis_dashboard/target/release/aegis_dashboard.exe
set /a PASS+=1

:step6
echo [6/7] Rust Mouth (DEFCON TUI)...
if not exist "mouth\windows_sec_monitor.rs" (
    echo   [SKIP] mouth/windows_sec_monitor.rs not found
    set /a SKIP+=1
    goto step7
)
where rustc >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] rustc not found - install Rust or use rustup
    set /a SKIP+=1
    goto step7
)
REM G34: build Mouth to dist/ (was: mouth/windows_sec_monitor.exe)
REM      using rustc directly because mouth/ has no Cargo.toml.
if not exist dist mkdir dist
rustc -O mouth\windows_sec_monitor.rs -o dist\windows_sec_monitor.exe
if %errorlevel% neq 0 (
    echo   [FAIL] Rust Mouth build failed
    set /a FAIL+=1
    goto step7
)
echo   [OK] Rust Mouth: dist\windows_sec_monitor.exe
set /a PASS+=1

:step7
echo [7/7] Go Aggregator (REST API)...
if not exist "go\aggregator\main.go" (
    echo   [SKIP] go/aggregator/main.go not found
    set /a SKIP+=1
    goto summary
)
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] go not found
    set /a SKIP+=1
    goto summary
)
cd go\aggregator
go build -o aegis-aggregator.exe .
if %errorlevel% neq 0 (
    echo   [FAIL] Go Aggregator build failed
    set /a FAIL+=1
    cd ..\..
    goto summary
)
cd ..\..
echo   [OK] Go Aggregator: go\aggregator\aegis-aggregator.exe
set /a PASS+=1

:summary
echo.
echo  ===================================================
echo       BUILD SUMMARY
echo  ===================================================
echo   Passed : %PASS%
echo   Failed : %FAIL%
echo   Skipped: %SKIP%
echo  ===================================================
echo.

if %FAIL% gtr 0 (
    echo  [!] Some builds FAILED - fix errors before running.
    exit /b 1
)
if %PASS% equ 0 (
    echo  [!] No builds attempted - check your toolchains.
    exit /b 1
)
echo  [OK] All available components built successfully!
echo      Run 'run_aegis.bat' to start the system.
exit /b 0
