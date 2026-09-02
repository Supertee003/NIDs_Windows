# AEGIS NIDS - NSIS Installer Script (G45)
# ============================================================
# Builds a Windows installer (.exe) for AEGIS NIDS.
# Requires NSIS (https://nsis.sourceforge.io/) installed.
#
# Usage:
#   makensis installer/aegis_nids_installer.nsi
#
# Output:
#   installer/aegis_nids_v1.0.0_setup.exe
# ============================================================

!define APP_NAME "AEGIS NIDS"
!define APP_VERSION "1.0.0"
!define APP_PUBLISHER "AEGIS Project"
!define APP_URL "https://github.com/Supertee003/NIds_Windows"
!define APP_EXE "aegisctl.py"
!define APP_REGKEY "Software\AEGIS\NIDS"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "aegis_nids_v${APP_VERSION}_setup.exe"
Unicode True
RequestExecutionLevel admin
InstallDir "$PROGRAMFILES64\AEGIS_NIDS"
InstallDirRegKey HKLM "${APP_REGKEY}" "InstallDir"

# --- Pages ---
Page directory
Page components
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

# --- Sections ---
Section "Core Components (Required)" SecCore
    SectionIn RO
    SetOutPath "$INSTDIR"

    # Core scripts
    File /oname=aegisctl.py "..\scripts\aegisctl.py"
    File /oname=aegis_event_gen.py "..\scripts\aegis_event_gen.py"
    File /oname=build_all.bat "..\scripts\build_all.bat"
    File /oname=run_aegis.bat "..\scripts\run_aegis.bat"
    File /oname=stop_aegis.bat "..\scripts\stop_aegis.bat"

    # Config
    SetOutPath "$INSTDIR\config"
    File "..\config\Rules.json"
    File "..\config\canary_tests.json"
    File "..\config\aegis.conf"

    # Runtime docs
    SetOutPath "$INSTDIR\docs\runtime"
    File "..\docs\runtime\RUNTIME_CONTRACT.md"
    File "..\docs\runtime\COMPONENT_MATRIX.md"
    File "..\docs\runtime\LIFECYCLE.md"
    File "..\docs\runtime\LOCAL_RUNBOOK.md"

    # Tests
    SetOutPath "$INSTDIR\tests\runtime"
    File "..\tests\runtime\conftest.py"
    File "..\tests\runtime\test_*.py"

    # Create directories
    CreateDirectory "$INSTDIR\logs"
    CreateDirectory "$INSTDIR\logs\pids"
    CreateDirectory "$INSTDIR\logs\runtime"
    CreateDirectory "$INSTDIR\dist"
    CreateDirectory "$INSTDIR\build"

    # Registry entries
    WriteRegStr HKLM "${APP_REGKEY}" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "${APP_REGKEY}" "Version" "${APP_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS_NIDS" "DisplayName" "${APP_NAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS_NIDS" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS_NIDS" "DisplayVersion" "${APP_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS_NIDS" "Publisher" "${APP_PUBLISHER}"

    # Uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Source Code" SecSource
    SetOutPath "$INSTDIR\src"
    File /r /x target /x .zig-cache /x build "..\core\*.zig"
    File /r /x target "..\bridge\*.cpp"
    File /r /x target "..\bridge\*.hpp"
    File /r /x target "..\brain\*.py"
    File /r /x target "..\nose\*.go"
    File /r /x target "..\mouth\*.rs"
    File /r /x target "..\go\aggregator\*.go"
    File /r /x target "..\shield\*.rs"
    File /r /x target "..\aegis_dashboard\src\*.rs"
SectionEnd

Section "Build Configuration" SecBuild
    SetOutPath "$INSTDIR"
    File "..\build.zig"
    File "..\CMakeLists.txt"
    File "..\Makefile"
    SetOutPath "$INSTDIR\shield"
    File "..\shield\Cargo.toml"
    SetOutPath "$INSTDIR\aegis_dashboard"
    File "..\aegis_dashboard\Cargo.toml"
    SetOutPath "$INSTDIR\go\aggregator"
    File "..\go\aggregator\go.mod"
SectionEnd

Section "Start Menu Shortcuts" SecShortcuts
    CreateDirectory "$SMPROGRAMS\AEGIS NIDS"
    CreateShortcut "$SMPROGRAMS\AEGIS NIDS\AEGIS NIDS Diagnose.lnk" \
        "$INSTDIR\aegisctl.py" "diagnose"
    CreateShortcut "$SMPROGRAMS\AEGIS NIDS\AEGIS NIDS Build.lnk" \
        "$INSTDIR\build_all.bat" ""
    CreateShortcut "$SMPROGRAMS\AEGIS NIDS\AEGIS NIDS Start All.lnk" \
        "$INSTDIR\aegisctl.py" "start --all"
    CreateShortcut "$SMPROGRAMS\AEGIS NIDS\AEGIS NIDS Stop All.lnk" \
        "$INSTDIR\aegisctl.py" "stop --all"
    CreateShortcut "$SMPROGRAMS\AEGIS NIDS\Uninstall.lnk" \
        "$INSTDIR\uninstall.exe" ""
SectionEnd

# --- Uninstaller ---
Section "Uninstall"
    Delete "$INSTDIR\uninstall.exe"
    RMDir /r "$INSTDIR"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AEGIS_NIDS"
    DeleteRegKey HKLM "${APP_REGKEY}"
    RMDir /r "$SMPROGRAMS\AEGIS NIDS"
SectionEnd
