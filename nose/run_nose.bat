@echo off
setlocal enabledelayedexpansion

REM ============================================================
REM  AEGIS NOSE v5.0 - Run Script v1.0 (CMD-safe)
REM  go mod tidy + go run . (one step)
REM ============================================================

echo.
echo ============================================================
echo  AEGIS NOSE v5.0 - Starting...
echo ============================================================
echo.

set "NOSE=D:\NIds_Windows\nose"

if not exist "%NOSE%\go.mod" (
    echo   [ERR] go.mod not found in %NOSE%
    echo   Place v5.0 files first
    goto :end
)

pushd "%NOSE%"

REM Auto-tidy if go.sum missing
if not exist "%NOSE%\go.sum" (
    echo   go.sum not found - running go mod tidy ...
    go mod tidy
    if %ERRORLEVEL% neq 0 (
        echo   [ERR] go mod tidy failed
        popd
        goto :end
    )
    echo   [OK] go.sum created
    echo.
)

echo   Running NOSE v5.0 ...
echo   Press Ctrl+C to stop
echo.

go run .

popd

:end
echo.
pause
exit /b 0
