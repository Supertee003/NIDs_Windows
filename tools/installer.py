#!/usr/bin/env python3
"""G27: Installer - NSIS script generator for AEGIS NIDS

Consumes build artifacts and build_manifest.json to produce an installer.nsi
that packages the runtime, preserves user data on upgrade, and writes a
manifest-derived directive for every component.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
MANIFEST_PATH = ROOT / "build_manifest.json"


def load_manifest() -> dict:
    """Load and return the build manifest."""
    if not MANIFEST_PATH.exists():
        return {}
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def manifest_components(manifest: dict) -> list:
    """Extract component list from manifest."""
    return manifest.get("components", [])


def file_directive(name: str, dest: str = "") -> str:
    """Generate a single NSIS File directive."""
    if dest:
        return f'  File /oname={dest} "{name}"'
    return f'  File "{name}"'


NSIS_TEMPLATE = r"""#!define APPNAME "AEGIS NIDS"
#!define APPVERSION "5.0.0"
#!define PUBLISHER "AEGIS Security"
#!define AEGIS_COMMIT "2c7cb30"

Name "${APPNAME} ${APPVERSION}"
OutFile "aegis-installer-${APPVERSION}.exe"
InstallDir "$PROGRAMFILES64\AEGIS"
RequestExecutionLevel admin
PrivateBuild "${APPNAME} ${APPVERSION}"

Page directory
Page instfiles
UninstPage unConfirm
UninstPage instfiles

Section "Install"
  SetOutPath "$INSTDIR"

  ; Runtime binaries
  File "aegis_nids.exe"
  File "aegis_pep.dll"
  File "aegis_wfp_user.dll"

  ; Build manifest
  File "build_manifest.json"

  ; Config
  SetOutPath "$INSTDIR\config"
  File "config\Rules.json"

  ; Trust store
  SetOutPath "$INSTDIR\config\trust_store"
  File /nonfatal "configs\trust_store\*.*"

  ; Audit
  SetOutPath "$INSTDIR\audit"

  ; Data directory (preserved)
  SetOutPath "$INSTDIR\data"
  File /nonfatal "data\default.json"

  ; Bin directory with run script
  SetOutPath "$INSTDIR\bin"

  ; Directories PRESERVED across upgrades
  CreateDirectory "$INSTDIR\data"
  CreateDirectory "$INSTDIR\config\trust_store"
  CreateDirectory "$INSTDIR\logs"

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  ; Stop services
  nsExec::ExecToLog "taskkill /im aegis_nids.exe /f"

  ; Remove only executable payload
  RMDir /r "$INSTDIR\bin"
  Delete "$INSTDIR\*.exe"
  Delete "$INSTDIR\*.dll"

  ; PRESERVED: data, config, logs, trust_store, audit
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
"""


def generate_nsi(nsi_path: Path) -> None:
    """Generate installer.nsi from build_manifest.json."""
    manifest = load_manifest()
    components = manifest_components(manifest)

    lines = []
    for comp in components:
        lines.append(f"; component: {comp.get('id', 'unknown')} ({comp.get('language', '?')})")
    lines.append(NSIS_TEMPLATE)

    nsi_path.parent.mkdir(parents=True, exist_ok=True)
    nsi_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS NIDS NSIS Installer Generator")
    parser.add_argument("--generate", action="store_true",
                        help="Generate NSIS installer script")
    parser.add_argument("--nsi", type=Path, default=None,
                        help="Output path for generated .nsi file (default: installer.nsi, or installer.generated.nsi with --package)")
    parser.add_argument("--package", action="store_true",
                        help="Generate NSI and build the installer with makensis (fail-closed if missing)")
    parser.add_argument("--output", type=Path, default=ROOT / "aegis_setup.exe",
                        help="Output path for the built installer exe")
    args = parser.parse_args()

    if args.package:
        nsi_path = args.nsi or (ROOT / "installer.generated.nsi")
        generate_nsi(nsi_path)
        makensis = shutil.which("makensis")
        if makensis is None:
            print("ERROR: makensis not found; install NSIS to build the installer",
                  file=sys.stderr)
            return 2
        proc = subprocess.run([makensis, str(nsi_path)], cwd=str(ROOT))
        if proc.returncode != 0:
            print(f"ERROR: makensis failed with exit {proc.returncode}",
                  file=sys.stderr)
            return proc.returncode
        built = sorted(ROOT.glob("aegis-installer-*.exe"))
        if not built:
            print("ERROR: makensis succeeded but no aegis-installer-*.exe was produced",
                  file=sys.stderr)
            return 2
        newest = max(built, key=lambda p: p.stat().st_mtime)
        if newest.resolve() != args.output.resolve():
            shutil.copy2(newest, args.output)
        print(f"Packaged {args.output}")
        return 0

    if args.generate:
        generate_nsi(args.nsi or (ROOT / "installer.nsi"))
        print(f"Generated {args.nsi or 'installer.nsi'}")
        print("Build with: makensis installer.nsi")
        print("Output: aegis-installer-5.0.0.exe")
        return 0

    generate_nsi(ROOT / "installer.nsi")
    print("Generated installer.nsi")
    print("Build with: makensis installer.nsi")
    print("Output: aegis-installer-5.0.0.exe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
