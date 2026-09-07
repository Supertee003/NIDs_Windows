#!/usr/bin/env python3
"""II18 - AEGIS NIDS Installer (NSIS generator + packaging)

Generates an NSIS .nsi script and (optionally) builds aegis_setup.exe.

Usage:
    python tools/installer.py --generate
    python tools/installer.py --package --output aegis_setup.exe
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

INSTALLER_TEMPLATE = """\
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Name "AEGIS NIDS v5.0+"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\\AEGIS"
Unicode True
RequestExecutionLevel admin
ShowInstDetails show

VIProductVersion "5.0.0.0"
VIAddVersionKey "ProductName" "AEGIS NIDS"
VIAddVersionKey "CompanyName" "AEGIS"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 AEGIS"
VIAddVersionKey "FileVersion" "5.0.0.0"
VIAddVersionKey "FileDescription" "AEGIS Network Intrusion Detection System"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Section "AEGIS Core Engine (Required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "zig-out\\bin\\aegis_nids.exe"
  File "target\\release\\aegis_pep.dll"
  File "build\\Release\\aegis_wfp_user.dll"
  File "build\\Release\\aegis_etw_helper.dll"
  File "build\\Release\\aegis_fim_helper.dll"
  File "tools\\aegisctl.py"
  File "configs\\schema.json"
  File "configs\\runtime.json"
  File "LICENSE.txt"

  ; Service registration
  nsExec::ExecToLog 'sc create AegisNids binPath= "$INSTDIR\\aegis_nids.exe" start= auto'
  nsExec::ExecToLog 'sc description AegisNIDS "AEGIS Network Intrusion Detection System"'
  nsExec::ExecToLog 'sc failure AegisNids reset= 86400 actions= restart/5000/restart/5000/restart/10000'

  ; Firewall rule for federation port 8443 (if enabled later)
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="AEGIS Federation" dir=in action=allow program="$INSTDIR\\aegis_nids.exe" enable=no'

  ; Start menu shortcuts
  CreateDirectory "$SMPROGRAMS\\AEGIS"
  CreateShortcut "$SMPROGRAMS\\AEGIS\\AEGIS Control.lnk" "$INSTDIR\\aegisctl.py"
  CreateShortcut "$SMPROGRAMS\\AEGIS\\Uninstall AEGIS.lnk" "$INSTDIR\\uninstall.exe"

  ; Registry uninstall entry
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "DisplayName" "AEGIS NIDS v5.0+"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "UninstallString" '"$INSTDIR\\uninstall.exe"'
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "Publisher" "AEGIS"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "DisplayVersion" "5.0.0.0"

  WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd

Section "ETW Real-time Telemetry" SecEtw
  SetOutPath "$INSTDIR"
  ; ETW session requires no special install; just DLLs (already in Core)
  ; Optionally install the WFP kernel-mode callout driver (signed)
  ; File "build\\Release\\aegis_wfp.sys"
  ; nsExec::ExecToLog 'sc create aegis_wfp type= kernel binPath= "$INSTDIR\\aegis_wfp.sys"'
  ; nsExec::ExecToLog 'sc start aegis_wfp'
SectionEnd

Section "Federation Cluster (Optional)" SecFederation
  SetOutPath "$INSTDIR"
  ; Config templates
  File "configs\\cluster.example.json"
  ; Generate self-signed cert on first run
  nsExec::ExecToLog 'powershell -Command "if (!(Test-Path $INSTDIR\\certs)) {{ New-Item -Path $INSTDIR\\certs -ItemType Directory }}"'
SectionEnd

Section "Start AEGIS Service Now" SecStart
  nsExec::ExecToLog 'sc start AegisNids'
SectionEnd

; Uninstaller
Section "Uninstall"
  nsExec::ExecToLog 'sc stop AegisNids'
  nsExec::ExecToLog 'sc delete AegisNids'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AEGIS Federation"'
  Delete "$SMPROGRAMS\\AEGIS\\AEGIS Control.lnk"
  Delete "$SMPROGRAMS\\AEGIS\\Uninstall AEGIS.lnk"
  RMDir "$SMPROGRAMS\\AEGIS"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids"
SectionEnd
"""


def generate_nsi(output_path: Path) -> int:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(INSTALLER_TEMPLATE, encoding="utf-8")
    print(f"âœ… NSIS script generated: {output_path}")
    return 0


NSIS_FALLBACK_PATHS = [
    r"C:\Program Files (x86)\NSIS\makensis.exe",
    r"C:\Program Files\NSIS\makensis.exe",
    r"C:\ProgramData\chocolatey\lib\nsis\tools\makensis.exe",
    "/usr/bin/makensis",
]


def find_makensis() -> str | None:
    found = shutil.which("makensis")
    if found:
        return found
    for candidate in NSIS_FALLBACK_PATHS:
        if os.path.isfile(candidate):
            return candidate
    return None


def package_installer(nsi_path: Path, output_exe: Path) -> int:
    makensis = find_makensis()
    if not makensis:
        print("❌ makensis (NSIS) not found in PATH.", file=sys.stderr)
        print("   Install NSIS from https://nsis.sourceforge.io/", file=sys.stderr)
        return 1
    root = os.getcwd().replace("\\", "/")
    script_text = nsi_path.read_text(encoding="utf-8")
    if "!cd" not in script_text:
        nsi_path.write_text(f'!cd "{root}"\n{script_text}', encoding="utf-8")
    cmd = [makensis, f"/DOUTPUT={output_exe}", str(nsi_path)]
    print(f"Running: {' '.join(cmd)}")
    rc = subprocess.run(cmd).returncode
    if rc != 0:
        print(f"âŒ makensis failed (rc={rc})", file=sys.stderr)
        return rc
    print(f"âœ… Installer built: {output_exe}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS NIDS installer generator")
    parser.add_argument("--generate", action="store_true", help="Generate NSIS .nsi script")
    parser.add_argument("--package", action="store_true", help="Build installer .exe")
    parser.add_argument("--nsi", type=Path, default=Path("installer/aegis.nsi"), help="NSI script path")
    parser.add_argument("--output", type=Path, default=Path("aegis_setup.exe"), help="Output installer .exe")
    args = parser.parse_args()

    if args.generate:
        return generate_nsi(args.nsi)

    if args.package:
        if not args.nsi.exists():
            generate_nsi(args.nsi)
        return package_installer(args.nsi, args.output)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
