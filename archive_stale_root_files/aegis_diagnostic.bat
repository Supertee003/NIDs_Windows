@echo off
REM =====================================================
REM  AEGIS NIDS — Pre-flight Diagnostic & Auto-Fix
REM  รันไฟล์นี้ก่อน run_aegis.bat เพื่อตรวจสอบปัญหา
REM =====================================================
setlocal enabledelayedexpansion
set PASS=0
set FAIL=0
set WARN=0

echo.
echo  ===================================================
echo   AEGIS NIDS — Pre-flight Diagnostic
echo  ===================================================
echo.

REM ====== 1. Check stray Cargo.toml on drive roots ======
echo  [1] Checking for stray Cargo.toml on drive roots...
for %%D in (C D E F G) do (
    if exist "%%D:\Cargo.toml" (
        REM Check if this is a real Rust project (has src/ dir)
        if not exist "%%D:\src" (
            echo   [CRITICAL] Stray Cargo.toml found: %%D:\Cargo.toml
            echo             This will break cargo builds!
            echo             Recommendation: DELETE it with:  del "%%D:\Cargo.toml"
            set /a FAIL+=1
        ) else (
            echo   [OK] %%D:\Cargo.toml is a valid Rust project (has src/)
            set /a PASS+=1
        )
    )
)
if %FAIL% equ 0 (
    echo   [OK] No stray Cargo.toml found on drive roots
    set /a PASS+=1
)

echo.

REM ====== 2. Check CWD and project Cargo.toml ======
echo  [2] Checking project Cargo.toml...
if not exist "Cargo.toml" (
    echo   [CRITICAL] Cargo.toml not found in current directory!
    echo             Run this script from D:\NIDs_Windows\
    set /a FAIL+=1
) else (
    findstr /C:"[lib]" Cargo.toml >nul 2>&1
    if %errorlevel% neq 0 (
        echo   [WARN] Cargo.toml has no [lib] section
        set /a WARN+=1
    ) else (
        echo   [OK] Cargo.toml has [lib] section
        set /a PASS+=1
    )
    findstr /C:"[[bin]]" Cargo.toml >nul 2>&1
    if %errorlevel% neq 0 (
        echo   [WARN] Cargo.toml has no [[bin]] section
        set /a WARN+=1
    ) else (
        echo   [OK] Cargo.toml has [[bin]] section
        set /a PASS+=1
    )
)

echo.

REM ====== 3. Check src/lib.rs exists ======
echo  [3] Checking Rust source files...
if not exist "src\lib.rs" (
    echo   [CRITICAL] src/lib.rs not found! Rust FFI will fail.
    set /a FAIL+=1
) else (
    echo   [OK] src/lib.rs exists
    set /a PASS+=1
)
if not exist "windows_sec_monitor.rs" (
    echo   [WARN] windows_sec_monitor.rs not found — Mouth build will fail
    set /a WARN+=1
) else (
    echo   [OK] windows_sec_monitor.rs exists
    set /a PASS+=1
)

echo.

REM ====== 4. Check toolchains ======
echo  [4] Checking toolchains...
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] cmake not in PATH
    set /a WARN+=1
) else (
    echo   [OK] cmake found
    set /a PASS+=1
)
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo   [CRITICAL] cargo not in PATH — Rust builds will fail
    set /a FAIL+=1
) else (
    for /f "tokens=*" %%v in ('cargo --version') do echo   [OK] cargo: %%v
    set /a PASS+=1
)
where rustc >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] rustc not in PATH
    set /a WARN+=1
) else (
    for /f "tokens=*" %%v in ('rustc --version') do echo   [OK] rustc: %%v
    set /a PASS+=1
)
where zig >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] zig not in PATH — Core build will fail
    set /a WARN+=1
) else (
    for /f "tokens=*" %%v in ('zig version') do echo   [OK] zig: %%v
    set /a PASS+=1
)
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] go not in PATH — Nose will fail
    set /a WARN+=1
) else (
    for /f "tokens=*" %%v in ('go version') do echo   [OK] go: %%v
    set /a PASS+=1
)
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] python not in PATH — Brain will fail
    set /a WARN+=1
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo   [OK] %%v
    set /a PASS+=1
)

echo.

REM ====== 5. Check existing build artifacts ======
echo  [5] Checking existing build artifacts...
if exist "build\Release\aegis_ipc.dll" (
    echo   [OK] aegis_ipc.dll exists
    set /a PASS+=1
) else (
    echo   [INFO] aegis_ipc.dll not found — will build with cmake
)
if exist "target\release\sec_monitor.dll" (
    echo   [OK] sec_monitor.dll exists
    set /a PASS+=1
) else (
    echo   [INFO] sec_monitor.dll not found — will build with cargo
)
if exist "zig-out\bin\aegis-nids.exe" (
    echo   [OK] aegis-nids.exe exists
    set /a PASS+=1
) else (
    echo   [INFO] aegis-nids.exe not found — will build with zig
)
if exist "windows_sec_monitor.exe" (
    echo   [OK] windows_sec_monitor.exe exists
    set /a PASS+=1
) else (
    echo   [INFO] windows_sec_monitor.exe not found — will build with rustc
)

echo.

REM ====== 6. Check aegis_dashboard ======
echo  [6] Checking aegis_dashboard...
if exist "aegis_dashboard\Cargo.toml" (
    echo   [OK] aegis_dashboard/Cargo.toml exists
    set /a PASS+=1
    if exist "aegis_dashboard\src\main.rs" (
        echo   [OK] aegis_dashboard/src/main.rs exists
        set /a PASS+=1
    ) else (
        echo   [CRITICAL] aegis_dashboard/src/main.rs not found
        set /a FAIL+=1
    )
) else (
    echo   [INFO] aegis_dashboard/ not found — Dashboard unavailable
)

echo.

REM ====== 7. Auto-fix: Delete stray D:\Cargo.toml ======
echo  [7] Auto-fix options...
echo   If you have a stray D:\Cargo.toml, run:
echo     del D:\Cargo.toml
echo.
echo   To auto-fix now, press Y:
choice /C YN /N /T 5 /D N /M "  Delete stray Cargo.toml files? [Y/N] "
if %errorlevel% equ 1 (
    for %%D in (C D E F G) do (
        if exist "%%D:\Cargo.toml" (
            if not exist "%%D:\src" (
                del "%%D:\Cargo.toml" 2>nul
                if not exist "%%D:\Cargo.toml" (
                    echo   [FIXED] Deleted %%D:\Cargo.toml
                ) else (
                    echo   [FAILED] Could not delete %%D:\Cargo.toml — try manually
                )
            )
        )
    )
)

echo.

REM ====== Summary ======
echo  ===================================================
echo   DIAGNOSTIC SUMMARY
echo  ===================================================
echo   Passed  : %PASS%
echo   Failed  : %FAIL%
echo   Warnings: %WARN%
echo  ===================================================
echo.

if %FAIL% gtr 0 (
    echo  [!] CRITICAL issues found — fix them before running AEGIS
    echo      Most common fix: Delete stray D:\Cargo.toml
    echo      del D:\Cargo.toml
) else (
    echo  [OK] No critical issues — safe to run run_aegis.bat
)

echo.
pause
