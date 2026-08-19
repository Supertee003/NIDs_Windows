@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  AEGIS NIDS - Cleanup Script v2.1 (CMD-safe)
REM  Delete old v4.0/v2.0 files before deploy v5.0/v3.0
REM  FIX: No Unicode, no 2>nul inside parens, no emoji
REM ============================================================

echo.
echo ============================================================
echo  AEGIS NIDS - Full Cleanup Script v2.1
echo  Delete old v4.0/v2.0 files before deploy v5.0/v3.0
echo ============================================================
echo.

set "NOSE=D:\NIds_Windows\nose"
set "MOUTH=D:\NIds_Windows\mouth"
set "NOSE_ERR=0"

REM ============================================================
REM  [1/4] NOSE: Delete old files
REM ============================================================
echo [1/4] Cleaning NOSE old files...
echo.

call :del_if_exist "%NOSE%\windows_perf.go"         "windows_perf.go"
call :del_if_exist "%NOSE%\windows_perf.go.v3.bak"  "windows_perf.go.v3.bak"
call :del_if_exist "%NOSE%\windows_perf_test.go"    "windows_perf_test.go"
call :del_if_exist "%NOSE%\aegis-nose.exe"           "aegis-nose.exe"
call :del_if_exist "%NOSE%\go.sum"                  "go.sum [will regen]"
call :del_if_exist "%NOSE%\go.mod.v3.bak"           "go.mod.v3.bak"
call :del_if_exist "%NOSE%\install_nose_v4.py"      "install_nose_v4.py"
call :del_if_exist "%NOSE%\run_nose.bat"            "run_nose.bat"
call :del_if_exist "%NOSE%\run_aegis.bat"           "run_aegis.bat"
call :del_if_exist "%NOSE%\README.md"               "README.md"
call :del_if_exist "%NOSE%\scan_nose_folder.py"     "scan_nose_folder.py"

REM Also delete tui_*.go and perf_types.go if they exist
call :del_if_exist "%NOSE%\tui_styles.go"           "tui_styles.go"
call :del_if_exist "%NOSE%\tui_model.go"            "tui_model.go"
call :del_if_exist "%NOSE%\tui_view.go"             "tui_view.go"
call :del_if_exist "%NOSE%\perf_types.go"           "perf_types.go"

echo.

REM ============================================================
REM  [2/4] MOUTH: Delete old files + build cache
REM ============================================================
echo [2/4] Cleaning MOUTH old files...
echo.

if exist "%MOUTH%\target" (
    echo   [DEL] target\ [build cache]
    rmdir /s /q "%MOUTH%\target"
) else (
    echo   [SKIP] target\ [not found]
)

if exist "%MOUTH%\src" (
    echo   [DEL] src\ [v2.0 Cargo structure]
    rmdir /s /q "%MOUTH%\src"
) else (
    echo   [SKIP] src\ [not found]
)

call :del_if_exist "%MOUTH%\Cargo.toml"       "Cargo.toml"
call :del_if_exist "%MOUTH%\Cargo.lock"       "Cargo.lock"
call :del_if_exist "%MOUTH%\.gitignore"       ".gitignore"
call :del_if_exist "%MOUTH%\install_mouth_v2.py" "install_mouth_v2.py"
call :del_if_exist "%MOUTH%\run_mouth.bat"    "run_mouth.bat"
call :del_if_exist "%MOUTH%\README.md"        "README.md"

echo.

REM ============================================================
REM  [3/4] Verify: Check v5.0/v3.0 files exist
REM ============================================================
echo [3/4] Verifying files...
echo.
echo   -- NOSE v5.0 --

call :check_file "%NOSE%\main.go"        "main.go"
call :check_file "%NOSE%\model.go"       "model.go"
call :check_file "%NOSE%\collectors.go"  "collectors.go"
call :check_file "%NOSE%\styles.go"      "styles.go"
call :check_file "%NOSE%\go.mod"         "go.mod"

echo.
echo   -- MOUTH v3.0 --

call :check_file "%MOUTH%\windows_sec_monitor.rs" "windows_sec_monitor.rs"
call :check_file "%MOUTH%\aegis_mouth_tui.rs"     "aegis_mouth_tui.rs"

echo.

REM ============================================================
REM  [4/4] NOSE: go mod tidy + build test
REM ============================================================
echo [4/4] NOSE go mod tidy + build test...
echo.

if not exist "%NOSE%\go.mod" goto :no_gomod

pushd "%NOSE%"

echo   Running: go mod tidy
go mod tidy
echo.

if exist "%NOSE%\go.sum" (
    echo   [OK] go.sum created
) else (
    echo   [ERR] go.sum not created
)

echo.
echo   Running: go build test ...
go build -o nose_v5_test.exe .

if exist "%NOSE%\nose_v5_test.exe" (
    echo   [OK] Build OK - nose_v5_test.exe created
    del /f "%NOSE%\nose_v5_test.exe"
) else (
    echo   [ERR] Build FAILED - showing errors:
    go build .
)

popd
goto :final

:no_gomod
echo   [ERR] Cannot build - go.mod not found in %NOSE%

:final
echo.

REM ============================================================
REM  Final listing
REM ============================================================
echo ============================================================
echo  Final state:
echo ============================================================
echo.
echo   NOSE files:
dir /b "%NOSE%\*.go" "%NOSE%\*.mod" "%NOSE%\*.sum" 2>nul
echo.
echo   MOUTH files:
dir /b "%MOUTH%\*.rs" 2>nul
echo.
echo ============================================================
echo  Done!
echo ============================================================
echo.
pause
exit /b 0

REM ============================================================
REM  Subroutines (outside any if/for blocks - CMD safe)
REM ============================================================

:del_if_exist
REM Usage: call :del_if_exist "fullpath" "displayname"
if exist "%~1" (
    del /f "%~1"
    echo   [DEL] %~2
) else (
    echo   [SKIP] %~2 [not found]
)
exit /b 0

:check_file
REM Usage: call :check_file "fullpath" "displayname"
if exist "%~1" (
    echo   [OK] %~2
) else (
    echo   [MISSING] %~2 - must place this file!
    set "NOSE_ERR=1"
)
exit /b 0
