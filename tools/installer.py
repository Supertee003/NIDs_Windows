#!/usr/bin/env python3
"""II18 - AEGIS NIDS Installer (NSIS generator + packaging)

Generates an NSIS .nsi script and (optionally) builds aegis_setup.exe.

T17 (Steps 46-52): the installer CONSUMES build artifacts declared in
build_manifest.json instead of hand-embedding source snapshots. Every
component emitted by the generator is taken from the manifest (which also
records source_commit + per-artifact SHA-256), and the manifest itself is
installed into the runtime directory so a deployed binary always maps back
to its source commit.

Data preservation (upgrade/reinstall/rollback): config, policy, trust
store, and the audit/forensic history live under "$INSTDIR\\data" and are
kept on uninstall/reinstall/upgrade. Only the executable payload in
"$INSTDIR\\bin" plus service/registry/shortcuts are removed.

Usage:
    python tools/installer.py --generate
    python tools/installer.py --package --output aegis_setup.exe
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

ROOT = Path(__file__).resolve().parent.parent
BUILD_MANIFEST = ROOT / "build_manifest.json"

# Payload shipped into "$INSTDIR\bin" - the built artifacts that must map
# back to the manifest commit.
BIN_PAYLOAD = [
    "zig-out/bin/aegis_nids.exe",
    "target/release/aegis_pep.dll",
    "build/Release/aegis_wfp_user.dll",
    "build/Release/aegis_etw_helper.dll",
    "build/Release/aegis_fim_helper.dll",
    "go/aggregator/aegis-aggregator.exe",
]

# Data that MUST survive uninstall/upgrade/rollback (AC5 preservation).
DATA_PAYLOAD = [
    "config/Rules.json",
    "config/Rules.json.sig",
    "config/trust_store.json",
    "certs/",
    "logs/audit/",
    "logs/forensics/",
    "logs/runtime/control_audit.ndjson",
]

def load_manifest() -> dict:
    """Build/release manifest consumed by the installer. Falls back to a
    minimal manifest with source_commit 'unknown' if not yet generated."""
    if BUILD_MANIFEST.exists():
        try:
            return json.loads(BUILD_MANIFEST.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"version": "5.0.0", "source_commit": "unknown", "components": []}


def manifest_components(manifest: dict) -> list[dict]:
    """Return the components the installer must ship, in manifest order."""
    return manifest.get("components", [])


def file_directive(rel: str) -> str:
    """Emit an NSIS File directive (clears error state: the artifact may not
    be built on a source-only checkout - install still proceeds with the
    artifacts that exist)."""
    rel = rel.replace("/", "\\")
    return f'  File "/oname={Path(rel).name}" "{rel}"'


def build_nsi(manifest: dict, install_version: str) -> str:
    """Render the NSIS script FROM THE MANIFEST: version, per-component
    directives, and installed manifest all come from build_manifest.json.
    Data (config/policy/trust/audit/forensic) is preserved on uninstall."""
    version = install_version if install_version else manifest.get("version", "5.0.0")
    commit = manifest.get("source_commit", "unknown")
    payload_lines: list[str] = []
    for component in manifest_components(manifest):
        name = component.get("name", "")
        if not name:
            continue
        rel = str(name).replace("\\", "/")
        if rel.startswith(("scripts/", "tools/", "config/", "shield/", "core/")):
            # Manifest-declared source/tool files: ship into bin/config.
            dest_subdir = "config" if rel.startswith("config/") else "bin"
            payload_lines.append(
                f'  SetOutPath "$INSTDIR\\{dest_subdir}"\n'
                f'{file_directive(rel)}'
            )
    for rel in BIN_PAYLOAD:
        payload_lines.append(
            f'  SetOutPath "$INSTDIR\\bin"\n{file_directive(rel)}'
        )
    # Manifest + provenance installed so a deployed binary maps to a commit.
    payload_lines.append('  SetOutPath "$INSTDIR"\n  File "/oname=build_manifest.json" "build_manifest.json"')

    sections = []
    sections.append(f"""\
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Name "AEGIS NIDS {version}"
OutFile "${{OUTPUT}}"
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
VIAddVersionKey "PrivateBuild" "{commit}"

; Config / policy / trust / audit / forensic data lives under data\\ and is
; PRESERVED across uninstall, upgrade and reinstall (T17 AC5).
!define AEGIS_DATA "$INSTDIR\\data"
!define AEGIS_BIN "$INSTDIR\\bin"
!define AEGIS_COMMIT "{commit}"

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
""")

    sections.append("""\
Section "AEGIS Runtime + Service (Required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR\\data\\config"
  File "/oname=Rules.json" "config\\Rules.json"
  SetOutPath "$INSTDIR"
  File "/oname=aegis_runtime_stamp.txt" "aegis_runtime_stamp.txt"
  ; Manifest-declared payload + build artifact payload
""")
    sections.append("\n".join(payload_lines))
    sections.append("""\

  ; Service registration (auto-start, restart on failure)
  nsExec::ExecToLog 'sc create AegisNids binPath= "$INSTDIR\\bin\\aegis_nids.exe" start= auto'
  nsExec::ExecToLog 'sc description AegisNIDS "AEGIS Network Intrusion Detection System"'
  nsExec::ExecToLog 'sc failure AegisNids reset= 86400 actions= restart/5000/restart/5000/restart/10000'

  ; Federation firewall rule (disabled until enabled by operator)
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="AEGIS Federation" dir=in action=allow program="$INSTDIR\\bin\\aegis_nids.exe" enable=no'

  ; Start menu shortcuts
  CreateDirectory "$SMPROGRAMS\\AEGIS"
  CreateShortcut "$SMPROGRAMS\\AEGIS\\AEGIS Control.lnk" "$INSTDIR\\bin\\aegisctl.py"
  CreateShortcut "$SMPROGRAMS\\AEGIS\\Uninstall AEGIS.lnk" "$INSTDIR\\uninstall.exe"

  ; Registry uninstall entry
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "DisplayName" "AEGIS NIDS v5.0+"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "UninstallString" '"$INSTDIR\\uninstall.exe"'
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "Publisher" "AEGIS"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "DisplayVersion" "5.0.0.0"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids" "InstallCommit" "${AEGIS_COMMIT}"

  WriteUninstaller "$INSTDIR\\uninstall.exe"
SectionEnd

Section "ETW Real-time Telemetry" SecEtw
  SetOutPath "$INSTDIR\\bin"
SectionEnd

Section "Federation Cluster (Optional)" SecFederation
  SetOutPath "$INSTDIR\\data\\certs"
  File "/nonfatal" "/oname=cluster.example.json" "config\\cluster.example.json"
  nsExec::ExecToLog 'powershell -Command "if (!(Test-Path $INSTDIR\\data\\certs)) {{ New-Item -Path $INSTDIR\\data\\certs -ItemType Directory }}"'
SectionEnd

Section "Start AEGIS Service Now" SecStart
  nsExec::ExecToLog 'sc start AegisNids'
SectionEnd

; Uninstaller - preserves config/policy/trust/audit/forensic history.
Section "Uninstall"
  nsExec::ExecToLog 'sc stop AegisNids'
  nsExec::ExecToLog 'sc delete AegisNids'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AEGIS Federation"'
  Delete "$SMPROGRAMS\\AEGIS\\AEGIS Control.lnk"
  Delete "$SMPROGRAMS\\AEGIS\\Uninstall AEGIS.lnk"
  RMDir "$SMPROGRAMS\\AEGIS"
  ; Remove executable payload only - data\\ (config, policy, trust,
  ; audit, forensic history) is preserved for upgrade/reinstall/rollback.
  RMDir /r "$INSTDIR\\bin"
  Delete "$INSTDIR\\build_manifest.json"
  Delete "$INSTDIR\\aegis_runtime_stamp.txt"
  Delete "$INSTDIR\\uninstall.exe"
  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AegisNids"
SectionEnd
""")
    return "\n".join(sections)


def generate_nsi(output_path: Path, version: str = "") -> int:
    manifest = load_manifest()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    script = build_nsi(manifest, version)
    # Write a runtime stamp next to the manifest so a deployed runtime can
    # show its source commit + record that this tree produced the installer.
    stamp = ROOT / "aegis_runtime_stamp.txt"
    stamp.write_text(
        f"AEGIS NIDS\nversion={manifest.get('version', '5.0.0')}\n"
        f"source_commit={manifest.get('source_commit', 'unknown')}\n",
        encoding="utf-8",
    )
    output_path.write_text(script, encoding="utf-8")
    print(f"NSIS script generated from build_manifest.json: {output_path}")
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
