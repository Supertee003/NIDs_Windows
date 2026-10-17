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
BUILD_TRUTH_PATH = ROOT / "build_truth.json"

# Basenames already covered by the static template below. Manifest-derived
# lines dedupe against this set so nothing is packaged twice.
STATIC_FILES = {
    "rules.json", "policies.json", "aegis_nids.exe", "aegis_pep.dll",
    "aegis-nose.exe", "aegis_ipc.dll", "aegis_wfp_user.dll",
    "aegis_etw_helper.dll", "aegis_fim_helper.dll", "build_manifest.json",
}


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


def manifest_binaries() -> list[str]:
    """Manifest-derived installable outputs (DEPLOY-119, additive).

    Reads build_truth.json ``produces`` lists — the authoritative
    build-command-to-output map. SUPPORT-classified outputs (shield
    screening DLL, aggregator sidecar) and advisory-only entries (TS)
    are excluded: the installer packs the production runtime only.
    Only files present on disk are returned (never reference unbuilt
    outputs); basenames covered by the static template are deduped.
    Returns NSIS-style backslash paths, sorted. Empty (not error) when
    build_truth.json is missing or nothing is built yet.
    """
    try:
        truth = json.loads(BUILD_TRUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[str] = []
    seen = {name.lower() for name in STATIC_FILES}
    for entry in truth.get("build_commands", {}).values():
        if not isinstance(entry, dict):
            continue
        if entry.get("classification") == "SUPPORT":
            continue
        for prod in entry.get("produces", []) or []:
            full = ROOT / Path(str(prod).replace("/", os.sep))
            if not full.is_file():
                continue
            if full.name.lower() in seen:
                continue
            seen.add(full.name.lower())
            out.append(str(prod).replace("/", "\\"))
    return sorted(out)


NSIS_TEMPLATE = r"""!define APPNAME "AEGIS NIDS"
!define APPVERSION "5.0.0"
!define PUBLISHER "AEGIS Security"
!define AEGIS_COMMIT "@AEGIS_COMMIT@"

Name "${APPNAME} ${APPVERSION}"
OutFile "aegis-installer-${APPVERSION}.exe"
InstallDir "$PROGRAMFILES64\AEGIS NIDS"
Unicode True
RequestExecutionLevel admin
ShowInstDetails show
!include "MUI2.nsh"
VIAddVersionKey "PrivateBuild" "${APPNAME} ${APPVERSION} @AEGIS_COMMIT@"
VIProductVersion "5.0.0.0"
VIAddVersionKey "ProductName" "AEGIS NIDS"
VIAddVersionKey "CompanyName" "AEGIS"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 AEGIS"
VIAddVersionKey "FileVersion" "5.0.0.0"
VIAddVersionKey "FileDescription" "AEGIS Network Intrusion Detection System"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; Canonical install layout (matches src/core/runtime_paths.zig):
;   <install>\runtime\  binaries (service entrypoint + DLLs + nose)
;   <install>\configs\  Rules.json + policies.json
Section "Install"
  SetOutPath "$INSTDIR\configs"
  File /oname=Rules.json "configs\Rules.json"
  File /oname=policies.json "configs\policies.json"

  SetOutPath "$INSTDIR\runtime"
  File "zig-out\bin\aegis_nids.exe"
  File "target\release\aegis_pep.dll"
  File "nose\aegis-nose.exe"
  File "zig-out\bin\aegis_ipc.dll"
  File "zig-out\bin\aegis_wfp_user.dll"
  File "zig-out\bin\aegis_etw_helper.dll"
  File "zig-out\bin\aegis_fim_helper.dll"

  SetOutPath "$INSTDIR\drivers"
  File "/nonfatal" "/oname=aegis_wfp.sys" "drivers\wfp_callout\aegis_wfp.sys"

  SetOutPath "$INSTDIR"
  File "build_manifest.json"

  ; Service registration (auto-start, restart on failure)
  nsExec::ExecToLog 'sc create AegisNids binPath= "$INSTDIR\runtime\aegis_nids.exe" start= auto'
  nsExec::ExecToLog 'sc description AegisNids "AEGIS Network Intrusion Detection System"'
  nsExec::ExecToLog 'sc failure AegisNids reset= 86400 actions= restart/5000/restart/15000/restart/60000'

  ; Start menu shortcuts
  CreateDirectory "$SMPROGRAMS\AEGIS NIDS"
  CreateShortcut "$SMPROGRAMS\AEGIS NIDS\AEGIS Snapshot.lnk" "$INSTDIR\runtime\aegis_nids.exe"
  CreateShortcut "$SMPROGRAMS\AEGIS NIDS\Uninstall AEGIS.lnk" "$INSTDIR\uninstall.exe"

  ; Registry uninstall entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "DisplayName" "AEGIS NIDS v5.0+"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "Publisher" "AEGIS"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "DisplayVersion" "5.0.0.0"

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Start AEGIS Service Now"
  nsExec::ExecToLog 'sc start AegisNids'
SectionEnd

Section "Uninstall"
  nsExec::ExecToLog "sc stop AegisNids"
  nsExec::ExecToLog "sc delete AegisNids"
  Delete "$SMPROGRAMS\AEGIS NIDS\AEGIS Snapshot.lnk"
  Delete "$SMPROGRAMS\AEGIS NIDS\Uninstall AEGIS.lnk"
  RMDir "$SMPROGRAMS\AEGIS NIDS"
  RMDir /r "$INSTDIR\runtime"
  RMDir /r "$INSTDIR\drivers"
  Delete "$INSTDIR\build_manifest.json"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids"

  ; PRESERVED: configs (operator rules/policy survive reinstall)
  Delete "$INSTDIR\uninstall.exe"
SectionEnd
"""


def generate_nsi(nsi_path: Path) -> None:
    """Generate installer NSI from build_manifest.json."""
    manifest = load_manifest()
    components = manifest_components(manifest)

    try:
        head = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT), capture_output=True, text=True,
        ).stdout.strip() or "unknown"
    except Exception:
        head = "unknown"

    lines = []
    for comp in components:
        lines.append(f"; component: {comp.get('id', 'unknown')} ({comp.get('language', '?')})")
    body = NSIS_TEMPLATE.replace("@AEGIS_COMMIT@", head)
    # Manifest-derived runtime outputs (DEPLOY-119). The File lines MUST be
    # spliced INSIDE the Install section: NSIS rejects File outside any
    # Section, so the old append-after-SectionEnd shape produced silently
    # invalid installers whenever extra binaries were present on disk.
    # Header + count are always emitted so output shape is deterministic
    # even on a clean checkout.
    extra = manifest_binaries()
    block = [
        "; Manifest-derived runtime outputs (build_truth.json produces, "
        "present on disk at generation)",
        f"; manifest binaries included: {len(extra)}",
    ]
    if extra:
        block.append('SetOutPath "$INSTDIR\\runtime"')
        block.extend(file_directive(p) for p in extra)
    anchor = '  WriteUninstaller "$INSTDIR\\uninstall.exe"'
    body = body.replace(anchor, "\n".join(block) + "\n" + anchor)
    lines.append(body)

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
        out = args.nsi or (ROOT / "installer.generated.nsi")
        generate_nsi(out)
        print(f"Generated {out.name}")
        print(f"Build with: makensis {out.name}")
        print("Output: aegis-installer-5.0.0.exe")
        return 0

    generate_nsi(ROOT / "installer.generated.nsi")
    print("Generated installer.generated.nsi")
    print("Build with: makensis installer.generated.nsi")
    print("Output: aegis-installer-5.0.0.exe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
