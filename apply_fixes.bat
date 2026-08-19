@echo off
REM =====================================================
REM  apply_fixes.bat - Apply AEGIS v3 fixes and clean rebuild
REM  Run from D:\NIDs_Windows\
REM =====================================================
echo.
echo =====================================================
echo  AEGIS NIDS - Apply Fixes + Clean Rebuild
echo =====================================================
echo.

REM -- Step 1: Copy fixed source files --
echo [1] Copying fixed source files...

if exist "aegis_fix_v3\nids_analyze.zig" (
    copy /Y "aegis_fix_v3\nids_analyze.zig" "core\nids_analyze.zig"
    echo   [OK] core\nids_analyze.zig updated
) else (
    echo   [--] aegis_fix_v3\nids_analyze.zig not found
)

if exist "aegis_fix_v3\nids_capture.zig" (
    copy /Y "aegis_fix_v3\nids_capture.zig" "core\nids_capture.zig"
    echo   [OK] core\nids_capture.zig updated
) else (
    echo   [--] aegis_fix_v3\nids_capture.zig not found
)

if exist "aegis_fix_v3\CMakeLists_bridge.txt" (
    copy /Y "aegis_fix_v3\CMakeLists_bridge.txt" "bridge\CMakeLists.txt"
    echo   [OK] bridge\CMakeLists.txt updated
) else (
    echo   [--] aegis_fix_v3\CMakeLists_bridge.txt not found
)

if exist "aegis_fix_v3\run_aegis.bat" (
    copy /Y "aegis_fix_v3\run_aegis.bat" "scripts\run_aegis.bat"
    echo   [OK] scripts\run_aegis.bat updated
) else (
    echo   [--] aegis_fix_v3\run_aegis.bat not found
)

if exist "aegis_fix_v3\build_all.bat" (
    copy /Y "aegis_fix_v3\build_all.bat" "scripts\build_all.bat"
    echo   [OK] scripts\build_all.bat updated
) else (
    echo   [--] aegis_fix_v3\build_all.bat not found
)

echo.

REM -- Step 2: Nuclear clean of CMake build directory --
echo [2] Nuclear clean: removing entire build\ directory...
if exist "build" (
    rmdir /S /Q "build"
    echo   [OK] build\ removed
) else (
    echo   [OK] build\ not present
)

REM -- Step 3: Clean Zig cache --
echo [3] Cleaning Zig cache...
if exist ".zig-cache" (
    rmdir /S /Q ".zig-cache"
    echo   [OK] .zig-cache removed
) else (
    echo   [OK] .zig-cache not present
)

REM -- Step 4: Delete old DLLs that might be locked --
echo [4] Deleting old DLLs (avoid file locks)...
if exist "build\Release\aegis_ipc.dll" del /Q "build\Release\aegis_ipc.dll" 2>nul
if exist "dist\aegis_ipc.dll" del /Q "dist\aegis_ipc.dll" 2>nul
echo   [OK] old DLLs cleared

REM -- Step 5: Ensure dist directory exists --
if not exist "dist" mkdir "dist"

echo.
echo =====================================================
echo  All fixes applied. Now run:
echo    scripts\build_all.bat
echo  Then:
echo    scripts\run_aegis.bat
echo =====================================================
echo.
pause
