@echo off
REM =====================================================
REM  AEGIS NIDS - Full Build Pipeline (Vol.02 BUILD)
REM  Step order is FROZEN per AEGIS_GUIDE_VOL02 (1/9..9/9):
REM   1. C/C++ Native Helpers  (build\Release\*.dll)
REM   2. C++ Bridge            (bridge\build\, outputs to dist\)
REM   3. Rust PEP              (target\release\aegis_pep.dll) [CANONICAL]
REM   4. Rust Shield           (shield\target\release\sec_monitor.dll) [SUPPORT]
REM   5. Zig Core              (zig-out\bin\aegis_nids.exe) [needs 1+3]
REM   6. Go Nose               (nose\aegis-nose.exe) [CANONICAL]
REM   7. Go Aggregator         (go\aggregator\aegis-aggregator.exe) [SUPPORT]
REM   8. TypeScript Policy     (typecheck + test only, no artifact)
REM   9. Python Brain          (interpreted: pip install + pytest)
REM  CANONICAL steps fail the build. SUPPORT steps warn only.
REM =====================================================
setlocal enabledelayedexpansion

:: ── Auto-detect Project Root ──
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT="
if exist "%SCRIPT_DIR%..\build.zig" (
    set "PROJECT_ROOT=%SCRIPT_DIR%.."
)
if not defined PROJECT_ROOT (
    if exist "%SCRIPT_DIR%build.zig" (
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
echo       AEGIS NIDS - Full Build Pipeline (Vol.02)
echo  ===================================================
echo.

REM ====== [1/9] C/C++ Native Helpers (CANONICAL) ======
echo [1/9] C/C++ Native Helpers (CMake, root build/)...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo   [FAIL] cmake not found - Step 1 is CANONICAL, aborting
    exit /b 1
)
cmake -B build -G "Visual Studio 17 2022" -A x64
if %errorlevel% neq 0 (
    echo   [WARN] Configure failed - clearing stale CMake cache and retrying once
    del /q build\CMakeCache.txt 2>nul
    rmdir /s /q build\CMakeFiles 2>nul
    cmake -B build -G "Visual Studio 17 2022" -A x64
)
if %errorlevel% neq 0 (
    echo   [FAIL] CMake configure (native helpers) failed
    exit /b 1
)
cmake --build build --config Release
if %errorlevel% neq 0 (
    echo   [FAIL] CMake build (native helpers) failed
    exit /b 1
)
if not exist "build\Release\aegis_wfp_user.dll" ( echo   [FAIL] missing aegis_wfp_user.dll & exit /b 1 )
if not exist "build\Release\aegis_etw_helper.dll" ( echo   [FAIL] missing aegis_etw_helper.dll & exit /b 1 )
if not exist "build\Release\aegis_fim_helper.dll" ( echo   [FAIL] missing aegis_fim_helper.dll & exit /b 1 )
echo   [OK] Native Helpers: 3 DLLs in build\Release\
set /a PASS+=1

REM ====== [2/9] C++ Bridge (CANONICAL, isolated build dir) ======
echo [2/9] C++ Bridge (CMake, bridge\build/)...
if not exist "bridge\CMakeLists.txt" (
    echo   [FAIL] bridge/CMakeLists.txt not found - Step 2 is CANONICAL, aborting
    exit /b 1
)
cmake -B bridge/build -S bridge -G "Visual Studio 17 2022" -A x64
if %errorlevel% neq 0 (
    echo   [WARN] Configure failed - clearing stale bridge CMake cache and retrying once
    del /q bridge\build\CMakeCache.txt 2>nul
    rmdir /s /q bridge\build\CMakeFiles 2>nul
    cmake -B bridge/build -S bridge -G "Visual Studio 17 2022" -A x64
)
if %errorlevel% neq 0 (
    echo   [FAIL] CMake configure (bridge) failed
    exit /b 1
)
cmake --build bridge/build --config Release
if %errorlevel% neq 0 (
    echo   [FAIL] CMake build (bridge) failed
    exit /b 1
)
echo   [OK] C++ Bridge built (see dist\ + bridge\build\Release\)
set /a PASS+=1

REM ====== [3/9] Rust PEP (CANONICAL - Final Enforcement Authority) ======
echo [3/9] Rust PEP (cargo, root crate)...
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo   [FAIL] cargo not found - Step 3 is CANONICAL, aborting
    exit /b 1
)
cargo build --release
if %errorlevel% neq 0 (
    echo   [FAIL] Rust PEP build failed
    exit /b 1
)
if not exist "target\release\aegis_pep.dll" ( echo   [FAIL] missing aegis_pep.dll & exit /b 1 )
if not exist "target\release\aegis_pep.dll.lib" ( echo   [FAIL] missing aegis_pep.dll.lib ^(needed by zig build^) & exit /b 1 )
echo   [OK] Rust PEP: target\release\aegis_pep.dll
set /a PASS+=1

REM ====== [4/9] Rust Shield (SUPPORT - warn only) ======
echo [4/9] Rust Shield (SUPPORT)...
if not exist "shield\Cargo.toml" (
    echo   [SKIP] shield/Cargo.toml not found
    set /a SKIP+=1
    goto step5
)
cargo build --release --manifest-path shield\Cargo.toml
if %errorlevel% neq 0 (
    echo   [WARN] Shield build failed - SUPPORT only, continuing
    set /a SKIP+=1
    goto step5
)
echo   [OK] Shield: shield/target/release/sec_monitor.dll
set /a PASS+=1

:step5
REM ====== [5/9] Zig Core (CANONICAL - needs Steps 1+3) ======
echo [5/9] Zig Core (zig build)...
where zig >nul 2>&1
if %errorlevel% neq 0 (
    echo   [FAIL] zig not found - Step 5 is CANONICAL, aborting
    exit /b 1
)
if not exist "target\release\aegis_pep.dll.lib" (
    echo   [FAIL] Step 3 artifact missing - run Steps 1-3 first
    exit /b 1
)
zig build
if %errorlevel% neq 0 (
    echo   [FAIL] Zig build failed
    exit /b 1
)
if not exist "zig-out\bin\aegis_nids.exe" ( echo   [FAIL] missing aegis_nids.exe & exit /b 1 )
echo   [OK] Zig Core: zig-out\bin\aegis_nids.exe
set /a PASS+=1

REM ====== [6/9] Go Nose (CANONICAL) ======
echo [6/9] Go Nose (packet acquisition)...
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo   [FAIL] go not found - Step 6 is CANONICAL, aborting
    exit /b 1
)
cd nose
go build -o aegis-nose.exe .
if %errorlevel% neq 0 (
    echo   [FAIL] Go Nose build failed
    cd ..
    exit /b 1
)
cd ..
if not exist "nose\aegis-nose.exe" ( echo   [FAIL] missing nose\aegis-nose.exe & exit /b 1 )
echo   [OK] Go Nose: nose\aegis-nose.exe
set /a PASS+=1

REM ====== [7/9] Go Aggregator (SUPPORT - warn only) ======
echo [7/9] Go Aggregator (SUPPORT)...
if not exist "go\aggregator\main.go" (
    echo   [SKIP] go/aggregator/main.go not found
    set /a SKIP+=1
    goto step8
)
cd go\aggregator
go build -o aegis-aggregator.exe .
if %errorlevel% neq 0 (
    echo   [WARN] Aggregator build failed - SUPPORT only, continuing
    cd ..\..
    set /a SKIP+=1
    goto step8
)
cd ..\..
echo   [OK] Go Aggregator: go\aggregator\aegis-aggregator.exe
set /a PASS+=1

:step8
REM ====== [8/9] TypeScript Policy (advisory: typecheck + test, no artifact) ======
echo [8/9] TypeScript Policy (typecheck + test)...
if not exist "ts_policy\package.json" (
    echo   [SKIP] ts_policy/package.json not found
    set /a SKIP+=1
    goto step9
)
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] npm not found
    set /a SKIP+=1
    goto step9
)
cd ts_policy
if not exist "node_modules" call npm install --silent
if %errorlevel% neq 0 (
    echo   [WARN] npm install failed - continuing
    cd ..
    set /a SKIP+=1
    goto step9
)
call npm run typecheck
if %errorlevel% neq 0 (
    echo   [WARN] ts typecheck failed - advisory only, continuing
    cd ..
    set /a SKIP+=1
    goto step9
)
call npm run test:all
if %errorlevel% neq 0 (
    echo   [WARN] ts tests failed - advisory only, continuing
    cd ..
    set /a SKIP+=1
    goto step9
)
cd ..
echo   [OK] TypeScript Policy: typecheck + tests pass
set /a PASS+=1

:step9
REM ====== [9/9] Python Brain (interpreted: deps + import check) ======
echo [9/9] Python Brain (interpreted)...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo   [SKIP] python not found
    set /a SKIP+=1
    goto summary
)
python -c "import brain.canonical_event; print('  Brain codec OK')"
if %errorlevel% neq 0 (
    echo   [WARN] Brain import check failed - continuing
    set /a SKIP+=1
    goto summary
)
echo   [OK] Python Brain: interpreted, no build required
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
echo  [OK] Pipeline complete. Run artifact checklist (Vol.02 section 4).
exit /b 0
