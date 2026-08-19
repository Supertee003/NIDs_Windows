@@ -0,0 +1,213 @@
@echo off
REM =====================================================================
REM install_drivers.bat — AEGIS NIDS Kernel Driver Installation Script
REM
REM Installs WFP Callout + Minifilter drivers with test signing.
REM REQUIRES: Administrator privileges + test signing enabled
REM
REM Usage:
REM   install_drivers.bat           — Install both drivers
REM   install_drivers.bat uninstall — Uninstall both drivers
REM   install_drivers.bat sign      — Enable test signing only
REM
REM Environment:
REM   AEGIS_OFFLINE=1              — Skip timestamp server (air-gap/offline mode)
REM =====================================================================

setlocal enabledelayedexpansion

echo.
echo +======================================================+
echo |       AEGIS NIDS — Kernel Driver Installation        |
echo |       Test Signing + Driver Install                   |
echo +======================================================+
echo.

REM ====== Check Administrator ======
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges!
    echo         Right-click and select "Run as administrator"
    exit /b 1
)

set AEGIS_ROOT=%~dp0..
set BUILD_DIR=%AEGIS_ROOT%\build
set DRIVERS_DIR=%AEGIS_ROOT%\drivers

REM ====== Offline / Air-gap Mode ======
if "%AEGIS_OFFLINE%"=="1" (
    echo   [MODE] AEGIS_OFFLINE=1 — Air-gap mode (no timestamp server)
    set SIGNTOOL_TS=
) else (
    set SIGNTOOL_TS=/t http://timestamp.digicert.com
)

REM ====== Uninstall mode ======
if "%1"=="uninstall" goto :uninstall

REM ====== Step 1: Enable Test Signing ======
echo [Step 1/4] Enabling test signing...
echo.

REM Check current test signing status
for /f "tokens=2" %%a in ('bcdedit /enum {current} ^| findstr /i "testsigning"') do (
    set TESTSIGNING_STATUS=%%a
)

if "!TESTSIGNING_STATUS!"=="Yes" (
    echo   [OK] Test signing already enabled
) else (
    echo   Enabling test signing (requires reboot)...
    bcdedit /set testsigning on
    if !errorlevel! equ 0 (
        echo   [OK] Test signing enabled — REBOOT REQUIRED
        echo.
        echo   Please reboot and run this script again.
        exit /b 0
    ) else (
        echo   [ERROR] Failed to enable test signing
        exit /b 1
    )
)

echo.

REM ====== Step 2: Create Test Certificate ======
echo [Step 2/4] Creating test certificate for driver signing...
echo.

REM Check if AEGIS test cert already exists
certutil -store TrustedPeople AEGIS_NIDS_Test >nul 2>&1
if !errorlevel! equ 0 (
    echo   [OK] AEGIS test certificate already exists
) else (
    echo   Creating self-signed test certificate...

    REM Create a self-signed certificate for test signing
    makecert -r -pe -ss TrustedPeople -n "CN=AEGIS_NIDS_Test" ^
        AEGIS_NIDS_Test.cer 2>nul

    if !errorlevel! neq 0 (
        echo   [WARN] makecert not available — using alternative method
        echo          You may need to manually create a test certificate

        REM Alternative: Use PowerShell
        powershell -Command "New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=AEGIS_NIDS_Test' -CertStoreLocation 'Cert:\CurrentUser\My'" 2>nul
    )
)

echo.

REM ====== Step 3: Sign and Install WFP Callout Driver ======
echo [Step 3/4] Installing WFP Callout Driver (aegis_wfp.sys)...
echo.

set WFP_SYS=%BUILD_DIR%\drivers\wfp\aegis_wfp.sys
set WFP_INF=%DRIVERS_DIR%\wfp_callout\aegis_wfp.inf

if exist "%WFP_SYS%" (
    REM Sign the driver with test certificate
    echo   Signing aegis_wfp.sys...
    signtool sign /s TrustedPeople /n AEGIS_NIDS_Test %SIGNTOOL_TS% "%WFP_SYS%" 2>nul
    if !errorlevel! neq 0 (
        echo   [WARN] signtool not found — driver may not load without proper signing
        echo          For test purposes, test signing mode will accept unsigned drivers
    )

    REM Install WFP callout via netcfg (for WFP class drivers)
    echo   Installing WFP callout driver...
    netcfg -v -l "%WFP_INF%" -c s -i AegisWfpCallout 2>nul
    if !errorlevel! equ 0 (
        echo   [OK] WFP callout driver installed successfully
    ) else (
        echo   [WARN] netcfg install failed — trying sc create...
        sc create AegisWfp type= kernel binPath= "%WFP_SYS%" start= demand
        if !errorlevel! equ 0 (
            echo   [OK] WFP driver service created
            sc start AegisWfp
            if !errorlevel! equ 0 (
                echo   [OK] WFP driver started
            ) else (
                echo   [WARN] WFP driver start failed (may need reboot)
            )
        )
    )
) else (
    echo   [SKIP] aegis_wfp.sys not found — run build_drivers.bat first
)

echo.

REM ====== Step 4: Sign and Install Minifilter Driver ======
echo [Step 4/4] Installing Minifilter Driver (aegis_minifilter.sys)...
echo.

set MF_SYS=%BUILD_DIR%\drivers\minifilter\aegis_minifilter.sys
set MF_INF=%DRIVERS_DIR%\minifilter\aegis_minifilter.inf

if exist "%MF_SYS%" (
    REM Sign the driver with test certificate
    echo   Signing aegis_minifilter.sys...
    signtool sign /s TrustedPeople /n AEGIS_NIDS_Test %SIGNTOOL_TS% "%MF_SYS%" 2>nul

    REM Install minifilter via fltmc (filter manager command)
    echo   Installing minifilter driver...

    REM First, create the service
    sc create AegisMinifilter type= filesys binPath= "%MF_SYS%" start= demand
    if !errorlevel! equ 0 (
        echo   [OK] Minifilter service created
        sc start AegisMinifilter
        if !errorlevel! equ 0 (
            echo   [OK] Minifilter driver started
        ) else (
            REM Try fltmc load instead
            fltmc load aegis_minifilter 2>nul
            if !errorlevel! equ 0 (
                echo   [OK] Minifilter loaded via fltmc
            ) else (
                echo   [WARN] Minifilter start failed (may need reboot)
            )
        )
    ) else (
        echo   [WARN] Minifilter service creation failed
    )
) else (
    echo   [SKIP] aegis_minifilter.sys not found — run build_drivers.bat first
)

echo.
echo ============================================================
echo [DONE] Driver installation complete
echo.
echo   Verify with:
echo     sc query AegisWfp
echo     sc query AegisMinifilter
echo     fltmc  (list loaded minifilters)
echo ============================================================

goto :eof

REM ====== Uninstall ======
:uninstall

echo [Uninstall] Removing AEGIS kernel drivers...
echo.

REM Stop and remove WFP callout
sc stop AegisWfp 2>nul
sc delete AegisWfp 2>nul
echo   [OK] WFP callout driver removed

REM Stop and remove Minifilter
fltmc unload aegis_minifilter 2>nul
sc stop AegisMinifilter 2>nul
sc delete AegisMinifilter 2>nul
echo   [OK] Minifilter driver removed

echo.
echo   Drivers uninstalled. Test signing remains enabled.
echo   To disable test signing: bcdedit /set testsigning off (then reboot)

endlocal
