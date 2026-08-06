@echo off
REM =====================================================
REM  AEGIS NIDS - Build All Components (Phase B)
REM  Builds every component, detects toolchains, reports
REM  success/failure for each step.
REM =====================================================
setlocal enabledelayedexpansion

set PASS=0
set FAIL=0
set SKIP=0

echo.
echo  ===================================================
echo       AEGIS NIDS - Build All Components (Phase B)
echo  ===================================================
echo.

REM ====== [1/5] C++ IPC Bridge ======
echo [1/5] C++ IPC Bridge (CMake)...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] cmake not found
    set /a SKIP+=1
    goto step2
)
cmake -B build -DCMAKE_BUILD_TYPE=Release
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
echo [2/5] Rust Tier-3 Shield (sec_monitor.dll)...
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] cargo not found
    set /a SKIP+=1
    goto step3
)
cargo build --release
if %errorlevel% neq 0 (
    echo   [FAIL] Rust build failed
    set /a FAIL+=1
    goto step3
)
echo   [OK] Rust FFI: target/release/sec_monitor.dll
set /a PASS+=1

:step3
echo [3/5] Go Perf Monitor (windows_perf.exe)...
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] go not found
    set /a SKIP+=1
    goto step4
)
go build -o windows_perf.exe windows_perf.go
if %errorlevel% neq 0 (
    echo   [FAIL] Go build failed
    set /a FAIL+=1
    goto step4
)
echo   [OK] Go Nose: windows_perf.exe
set /a PASS+=1

:step4
echo [4/5] Zig Tier-1 Core...
where zig >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] zig not found
    set /a SKIP+=1
    goto step5
)
<<<<<<< HEAD
zig build
=======
REM Build Zig with optional bridge/rust linking
REM Only add -Dlink-bridge / -Dlink-rust if the DLLs exist
set ZIG_FLAGS=
if exist "build\Release\aegis_ipc.dll" (
    set ZIG_FLAGS=%ZIG_FLAGS% -Dlink-bridge
)
if exist "target\release\sec_monitor.dll" (
    set ZIG_FLAGS=%ZIG_FLAGS% -Dlink-rust
)
zig build %ZIG_FLAGS%
>>>>>>> fix: Brain UnboundLocalError, Zig optional linking, DLL search paths, build_all.bat Zig flags
if %errorlevel% neq 0 (
    echo   [FAIL] Zig build failed
    set /a FAIL+=1
    goto step5
)
<<<<<<< HEAD
echo   [OK] Zig Core: zig-out/bin/aegis-nids.exe (DLLs loaded at runtime)
=======
echo   [OK] Zig Core: zig-out/bin/aegis-nids.exe
>>>>>>> fix: Brain UnboundLocalError, Zig optional linking, DLL search paths, build_all.bat Zig flags
set /a PASS+=1

:step5
echo [5/5] egui Dashboard...
if not exist "aegis_dashboard\Cargo.toml" (
    echo   [SKIP] aegis_dashboard/Cargo.toml not found
    set /a SKIP+=1
    goto summary
)
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] cargo not found
    set /a SKIP+=1
    goto summary
)
cd aegis_dashboard
cargo build --release
if %errorlevel% neq 0 (
    echo   [FAIL] egui Dashboard build failed
    set /a FAIL+=1
    cd ..
    goto summary
)
cd ..
echo   [OK] egui Dashboard: aegis_dashboard/target/release/aegis_dashboard.exe
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
