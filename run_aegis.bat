@echo off
cd /d "%~dp0"

REM ====== SAFETY CHECK: Detect stray D:\Cargo.toml ======
for %%D in (C D E F) do (
    if exist "%%D:\Cargo.toml" (
        if not exist "%%D:\NIDs_Windows" (
            echo [WARN] Stray Cargo.toml found at %%D:\Cargo.toml
            echo        This will break Rust builds! Please DELETE it:
            echo        del "%%D:\Cargo.toml"
        )
    )
)

echo ===================================================
echo      Cleaning up old Aegis processes...
echo ===================================================
taskkill /F /IM aegis-nids.exe >nul 2>&1
taskkill /F /IM aegis_bridge.exe >nul 2>&1
taskkill /F /IM windows_sec_monitor.exe >nul 2>&1
taskkill /F /IM aegis_dashboard.exe >nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1
taskkill /F /IM go.exe /FI "WINDOWTITLE eq AEGIS*" >nul 2>&1

echo ===================================================
echo      [1/6] Building C++ IPC Bridge (CMake)...
echo ===================================================
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] cmake not found in PATH — skip C++ Bridge build
    echo     Will use existing build/Release/aegis_ipc.dll
) else (
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    if %errorlevel% neq 0 (
        echo [!] CMake configure failed
        pause
        exit /b 1
    )
    cmake --build build --config Release
    if %errorlevel% neq 0 (
        echo [!] CMake build failed
        pause
        exit /b 1
    )
    echo [OK] C++ Bridge built successfully
)

echo ===================================================
echo      [2/6] Building Rust FFI (sec_monitor.dll)...
echo ===================================================
where cargo >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] cargo not found in PATH — skip Rust build
    echo     Will use existing target/release/sec_monitor.dll
) else (
    cargo build --release --manifest-path "%~dp0Cargo.toml"
    if %errorlevel% neq 0 (
        echo [!] Rust build failed
        echo     If error says "no targets" at D:\Cargo.toml:
        echo     Delete D:\Cargo.toml  (stray file)
        pause
        exit /b 1
    )
    echo [OK] Rust FFI built successfully
)

echo ===================================================
echo      Starting AEGIS NIDS Full Architecture...
echo ===================================================

if not exist "logs" mkdir logs
type nul > logs\anomalous.json

REM ====== DETECT: Windows Terminal vs Legacy CMD ======
REM Windows Terminal (wt.exe) supports tabs, better colors, Unicode
REM If available, launch all subsystems as tabs in one window
set "USE_WT=0"
where wt.exe >nul 2>&1
if %errorlevel% equ 0 (
    set "USE_WT=1"
    echo [INFO] Windows Terminal detected — launching with tabs
) else (
    echo [INFO] Using legacy CMD — launching separate windows
)

REM ====== LAUNCH MODE 1: Windows Terminal (tabs) ======
if "%USE_WT%"=="1" goto :launch_wt

REM ====== LAUNCH MODE 2: Legacy CMD (colored windows) ======

:: [3/6] C++ Bridge — Cyan on DarkBlue (IPC hub)
echo [3/6] Starting C++ IPC Bridge (daemon)...
start "AEGIS BRIDGE (C++)" cmd /k "mode con cols=100 lines=30 & color 1B & echo  AEGIS BRIDGE (C++) — IPC Hub + Packet Parser + DEFCON & echo ==================================== & build\Release\aegis_bridge.exe"
timeout /t 2 /nobreak > NUL

:: [4/6] Zig Core — White on DarkGreen (Tier-1 engine)
echo [4/6] Compiling and Starting Zig Core...
start "AEGIS CORE (Zig)" cmd /k "mode con cols=120 lines=40 & color 2F & echo  AEGIS CORE (Zig) — Tier-1 Aho-Corasick + 5 Threads & echo ==================================== & zig build run"

:: [5/6] Python Brain — Yellow on DarkRed (Tier-2 deep inspection)
echo [5/6] Starting Python Brain...
timeout /t 2 /nobreak > NUL
start "AEGIS BRAIN (Python)" cmd /k "mode con cols=110 lines=35 & color 4E & echo  AEGIS BRAIN (Python) — Tier-2 Regex + IPS + Bridge & echo ==================================== & python windows_brain.py"

:: [6/6] Go Nose + Rust Mouth
echo [6/6] Starting remaining subsystems...
timeout /t 1 /nobreak > NUL

:: Go Nose — LightGray on DarkCyan (perf monitor)
start "AEGIS NOSE (Go)" cmd /k "mode con cols=100 lines=30 & color 3F & echo  AEGIS NOSE (Go) — 3-Goroutine Perf Monitor & echo ==================================== & go run windows_perf.go"

:: Rust Mouth — build first if needed
echo   Building AEGIS MOUTH (Rust)...
if exist "windows_sec_monitor.exe" (
    echo   [OK] windows_sec_monitor.exe already exists
    goto :mouth_start
)
echo   [rustc] Compiling windows_sec_monitor.rs...
rustc windows_sec_monitor.rs -o windows_sec_monitor.exe
if not errorlevel 1 (
    echo   [OK] Built with rustc
    goto :mouth_start
)
echo   [!] rustc failed — trying cargo build...
cargo build --release --manifest-path "%~dp0Cargo.toml" --bin windows_sec_monitor
if not errorlevel 1 (
    if exist "target\release\windows_sec_monitor.exe" (
        copy /Y "target\release\windows_sec_monitor.exe" "windows_sec_monitor.exe" >nul
        echo   [OK] Built with cargo
        goto :mouth_start
    )
)
echo   [!] cargo also failed — trying cargo build (lib only) then rustc...
cargo build --release --manifest-path "%~dp0Cargo.toml"
rustc windows_sec_monitor.rs -o windows_sec_monitor.exe
if errorlevel 1 (
    echo   [FAIL] Could not build windows_sec_monitor.exe
    echo          Mouth window will be unavailable
    goto :mouth_done
)

:mouth_start
:: Rust Mouth — BrightWhite on DarkMagenta (DEFCON display)
start "AEGIS MOUTH (Rust)" cmd /k "mode con cols=80 lines=25 & color 5F & echo  AEGIS MOUTH (Rust) — DEFCON Security Monitor & echo ==================================== & windows_sec_monitor.exe"
echo   [OK] AEGIS MOUTH window launched

:mouth_done

:: Dashboard — egui native GUI (no CMD needed)
echo   Starting AEGIS DASHBOARD (Rust egui)...
if exist "aegis_dashboard\target\release\aegis_dashboard.exe" (
    start "AEGIS DASHBOARD (Rust)" aegis_dashboard\target\release\aegis_dashboard.exe
    echo   [OK] Dashboard window launched
) else if exist "aegis_dashboard\Cargo.toml" (
    echo   [BUILD] Compiling egui Dashboard...
    cd aegis_dashboard
    cargo build --release --manifest-path Cargo.toml
    if not errorlevel 1 (
        cd ..
        start "AEGIS DASHBOARD (Rust)" aegis_dashboard\target\release\aegis_dashboard.exe
        echo   [OK] Dashboard built + launched
    ) else (
        cd ..
        echo   [SKIP] Dashboard build failed
    )
) else (
    echo   [SKIP] aegis_dashboard/ not found — run Dashboard.py for Python TUI
)

goto :summary

REM ====== WINDOWS TERMINAL LAUNCH (tabs)- ======
:launch_wt
:: Launch all 6 subsystems as tabs in one Windows Terminal window
:: wt.exe syntax: wt -w 0 (new window) nt (new tab) -d <dir> cmd /k <command>

echo [3/6] Starting all subsystems in Windows Terminal tabs...

:: Tab 1: Bridge
start "" wt.exe -w 0 -p "Command Prompt" --title "AEGIS BRIDGE (C++)" -d "%~dp0" cmd /k "color 1B & mode con cols=100 lines=30 & build\Release\aegis_bridge.exe"
timeout /t 2 /nobreak > NUL

:: Tab 2: Core
start "" wt.exe -w 0 nt -p "Command Prompt" --title "AEGIS CORE (Zig)" -d "%~dp0" cmd /k "color 2F & mode con cols=120 lines=40 & zig build run"

:: Tab 3: Brain
timeout /t 2 /nobreak > NUL
start "" wt.exe -w 0 nt -p "Command Prompt" --title "AEGIS BRAIN (Python)" -d "%~dp0" cmd /k "color 4E & mode con cols=110 lines=35 & python windows_brain.py"

:: Tab 4: Nose
timeout /t 1 /nobreak > NUL
start "" wt.exe -w 0 nt -p "Command Prompt" --title "AEGIS NOSE (Go)" -d "%~dp0" cmd /k "color 3F & mode con cols=100 lines=30 & go run windows_perf.go"

:: Tab 5: Mouth (8uild if needed)
if not exist "windows_sec_monitor.exe" (
    rustc windows_sec_monitor.rs -o windows_sec_monitor.exe 2>nul
    if errorlevel 1 (
        cargo build --release --manifest-path "%~dp0Cargo.toml" --bin windows_sec_monitor 2>nul
        if exist "target\release\windows_sec_monitor.exe" (
            copy /Y "target\release\windows_sec_monitor.exe" "windows_sec_monitor.exe" >nul
        )
    )
)
if exist "windows_sec_monitor.exe" (
    start "" wt.exe -w 0 nt -p "Command Prompt" --title "AEGIS MOUTH (;Rust)" -d "%~dp0" cmd /k "color 5F & mode con cols=80 lines=25 & windows_sec_monitor.exe"
)

:: Tab 6: Dashboard
if exist "aegis_dashboard\target\release\aegis_dashboard.exe" (
    start "" aegis_dashboard\target\release\aegis_dashboard.exe
) else if exist "aegis_dashboard\Cargo.toml" (
    cd aegis_dashboard
    cargo build --release --manifest-path Cargo.toml 2>nul
    cd ..
    if exist "aegis_dashboard\target\release\aegis_dashboard.exe" (
        start "" aegis_dashboard\target\release\aegis_dashboard.exe
    )
)

:summary
echo.
echo ===================================================
echo  All subsystems started!
echo  - AEGIS BRIDGE (C++)       : IPC hub + Packet Parser + DEFCON
echo  - AEGIS CORE (Zig)         : NIDS engine + 5 threads + Bridge
echo  - AEGIS BRAIN (Python)     : Tier-2/3 regex + IPS + Bridge
echo  - AEGIS NOSE (Go)          : Perf monitor
echo  - AEGIS MOUTH (Rust)       : DEFCON display
echo  - AEGIS DASHBOARD (Rust)   : egui GUI Command Center
echo ===================================================
echo.
echo  Window Color Codes:
echo    Bridge = Cyan on Blue  (1B)   Core = White on Green  (2F)
echo    Brain  = Yellow on Red (4E)   Nose  = White on Cyan  (3F)
echo    Mouth  = White on Magenta(5F) Dashboard = Native egui
echo.
echo  Data Flow: Core -^> Bridge -^> Dashboard
echo             Core -^> Brain (UDP) -^> Bridge -^> Dashboard
echo.
echo  Console UI:    python aegis_console.py
echo  Daemon CLI:    python aegis_daemon.py status
echo.
pause
