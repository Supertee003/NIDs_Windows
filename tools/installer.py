#!/usr/bin/env python3
"""G27: Installer - NSIS script generator for AEGIS NIDS

Consumes build artifacts and build_manifest.json to produce an installer.nsi
that packages the runtime - including the kernel telemetry drivers (WFP
callout + minifilter, DEPLOY-120) - preserves user data on upgrade, and
writes a manifest-derived directive for every component.
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
    "aegis_wfp.sys", "aegis_minifilter.sys",
}

# Kernel telemetry drivers (DEPLOY-120, detection-only). The source paths are
# the canonical WDK build outputs that scripts/wfp_service.ps1 and
# scripts/minifilter_service.ps1 deploy to System32\drivers - the same
# binaries EVT-231/EVT-232 proved live (payload copy + rule match).
DRIVER_SOURCES = (
    ("wfp", "build\\x64\\wfp\\aegis_wfp.sys"),
    ("minifilter", "build\\x64\\minifilter\\aegis_minifilter.sys"),
)


def driver_presence() -> list:
    """(tag, nsis-source-path, present-on-disk) for each kernel driver."""
    return [
        (tag, rel, (ROOT / rel.replace("\\", "/")).is_file())
        for tag, rel in DRIVER_SOURCES
    ]


def _makensis_candidates() -> list:
    """Standard NSIS install locations, checked after PATH."""
    cands = []
    for env_name in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        base = os.environ.get(env_name)
        if base:
            cands.append(Path(base) / "NSIS" / "makensis.exe")
    return cands


def find_makensis() -> str | None:
    """PATH first, then the standard install dirs (NSIS is commonly installed
    without a PATH entry; the EVT-227 host drill packaged from the standard
    location). Returns the executable path or None (callers fail closed)."""
    found = shutil.which("makensis")
    if found:
        return found
    for cand in _makensis_candidates():
        if cand.is_file():
            return str(cand)
    return None


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
!include "LogicLib.nsh"
!include "FileFunc.nsh"
Var ExistingRoot
Var ExistingValid

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

; DEPLOY-120-PATHFIX: adopt an existing AegisNids service path instead of
; trusting $PROGRAMFILES64. A registered service is authoritative: setup
; must upgrade its actual runtime, never create a sibling duplicate.
Function .onInit
  StrCpy $ExistingRoot ""
  StrCpy $ExistingValid "0"
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\AegisNids" "ImagePath"
  ${If} $0 != ""
    ; Normalize surrounding quotes and the optional \??\ native prefix.
    StrCpy $1 $0 1
    ${If} $1 == '"'
      StrCpy $0 $0 "" 1
      StrCpy $0 $0 -1
    ${EndIf}
    StrCpy $1 $0 4
    ${If} $1 == "\??\"
      StrCpy $0 $0 "" 4
    ${EndIf}
    ${GetFileName} "$0" $1
    ${GetParent} "$0" $2
    ${GetFileName} "$2" $3
    ${GetParent} "$2" $4
    ${If} $1 == "aegis_nids.exe"
      ${If} $3 == "runtime"
        StrCpy $ExistingRoot $4
        StrCpy $ExistingValid "1"
        StrCpy $INSTDIR $ExistingRoot
      ${Else}
        MessageBox MB_ICONSTOP "AEGIS NIDS service path is not the canonical <install>\runtime\aegis_nids.exe: $0. Refusing to install over an unexpected service path."
        Abort
      ${EndIf}
    ${Else}
      MessageBox MB_ICONSTOP "AEGIS NIDS service path is not the canonical <install>\runtime\aegis_nids.exe: $0. Refusing to install over an unexpected service path."
      Abort
    ${EndIf}
  ${EndIf}
FunctionEnd

; Canonical install layout (matches src/core/runtime_paths.zig):
;   <install>\runtime\  binaries (service entrypoint + DLLs + nose)
;   <install>\configs\  Rules.json + policies.json
;   <install>\drivers\  kernel telemetry drivers (payload/provenance copy)
; The kernel drivers also get a System32\drivers copy plus a service so the
; daemon finds them where the proven scripts put them: AegisWfp (kernel,
; demand) and AegisMinifilter (filesys, demand, altitude 370000). Both are
; detection-only (observe/copy, never block) and TEST-SIGNED: loading needs
; test signing plus the signing cert trusted on the target machine, and
; setup logs each driver's signature status - see docs/DEPLOYMENT.md.
; Production signing (EV cert/HLK) is still pending.
Section "Install"
  ; DEPLOY-120-PATHFIX: .onInit adopts the registered service path. If the
  ; directory page is changed to a different path, abort before stopping the
  ; service or copying any file: a second runtime would diverge from the SCM
  ; binPath and its uninstaller would target shared services.
  ${If} $ExistingValid == "1"
    StrCpy $5 $INSTDIR 1 -1
    ${If} $5 == "\"
      StrCpy $INSTDIR $INSTDIR -1
    ${EndIf}
    ${If} $INSTDIR != $ExistingRoot
      MessageBox MB_ICONSTOP "AEGIS NIDS is already installed at $ExistingRoot. Setup must upgrade that existing path; refusing to create a duplicate runtime at $INSTDIR. Keep the detected directory or uninstall the existing service first."
      Abort
    ${EndIf}
  ${EndIf}

  ; Upgrade safety (EVT-221): a running service locks its own image, so a
  ; reinstall/upgrade over a live install fails mid-copy without this stop.
  ; Reinstall-safe: an absent service/process just logs and continues;
  ; "Start AEGIS Service Now" below restarts the service after the swap.
  nsExec::ExecToLog "sc stop AegisNids"
  nsExec::ExecToLog "taskkill /f /im aegis_nids.exe"
  Sleep 2000

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

  ; DEPLOY-120: kernel telemetry drivers from their canonical WDK build
  ; outputs (build\x64\wfp + build\x64\minifilter). /nonfatal keeps
  ; packaging possible on hosts that have not built the drivers yet;
  ; setup then skips the matching service registration below.
  SetOutPath "$INSTDIR\drivers"
  File "/nonfatal" "/oname=aegis_wfp.sys" "build\x64\wfp\aegis_wfp.sys"
  File "/nonfatal" "/oname=aegis_minifilter.sys" "build\x64\minifilter\aegis_minifilter.sys"

  SetOutPath "$INSTDIR"
  File "build_manifest.json"

  ; Service registration (auto-start, restart on failure)
  nsExec::ExecToLog 'sc create AegisNids binPath= "$INSTDIR\runtime\aegis_nids.exe" start= auto'
  nsExec::ExecToLog 'sc description AegisNids "AEGIS Network Intrusion Detection System"'
  nsExec::ExecToLog 'sc failure AegisNids reset= 86400 actions= restart/5000/restart/15000/restart/60000'

  ; ---- Kernel telemetry drivers (DEPLOY-120, detection-only) ----
  ; Registration mirrors the proven lifecycle scripts exactly
  ; (scripts\wfp_service.ps1: sc create type= kernel start= demand;
  ;  scripts\minifilter_service.ps1: type= filesys + DisplayName + altitude
  ;  370000 in both the service key and Instances\DefaultInstance).
  ; Fail-soft + reinstall-safe: every step logs and continues; a payload
  ; without a driver skips registration with an honest DetailPrint instead
  ; of leaving a broken service behind. Teardown runs first because a
  ; loaded driver image cannot be replaced on disk.
  nsExec::ExecToLog "fltmc unload AegisMinifilter"
  nsExec::ExecToLog "sc stop AegisMinifilter"
  nsExec::ExecToLog "sc delete AegisMinifilter"
  nsExec::ExecToLog "sc stop AegisWfp"
  nsExec::ExecToLog "sc delete AegisWfp"
  Sleep 1500
  ${If} ${FileExists} "$INSTDIR\drivers\aegis_wfp.sys"
    nsExec::ExecToLog 'cmd /c copy /y "$INSTDIR\drivers\aegis_wfp.sys" "$SYSDIR\drivers\aegis_wfp.sys"'
    nsExec::ExecToLog 'powershell -NoProfile -Command "Write-Host AEGIS_DRIVER_SIG_WFP (Get-AuthenticodeSignature $SYSDIR\drivers\aegis_wfp.sys).Status"'
    nsExec::ExecToLog 'sc create AegisWfp type= kernel start= demand binPath= "$SYSDIR\drivers\aegis_wfp.sys"'
  ${Else}
    DetailPrint "AEGIS: aegis_wfp.sys not in payload - AegisWfp service not registered (build it: scripts\wdk_build_production.ps1)"
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\drivers\aegis_minifilter.sys"
    nsExec::ExecToLog 'cmd /c copy /y "$INSTDIR\drivers\aegis_minifilter.sys" "$SYSDIR\drivers\aegis_minifilter.sys"'
    nsExec::ExecToLog 'powershell -NoProfile -Command "Write-Host AEGIS_DRIVER_SIG_FIM (Get-AuthenticodeSignature $SYSDIR\drivers\aegis_minifilter.sys).Status"'
    nsExec::ExecToLog 'sc create AegisMinifilter type= filesys start= demand binPath= "$SYSDIR\drivers\aegis_minifilter.sys" DisplayName= "AEGIS NIDS Minifilter Driver"'
    ; Altitude: both registration forms (FLTMGR consumes the service-key
    ; value or the Instances\DefaultInstance shape depending on the load
    ; path). WriteRegStr writes values only - it never recreates the key -
    ; so the SCM config sc create just wrote survives (the EVT-230 incident
    ; was PowerShell New-Item -Force wiping it).
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AegisMinifilter" "Altitude" "370000"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AegisMinifilter\Instances" "DefaultInstance" "AegisMinifilter Instance"
    WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\AegisMinifilter\Instances\AegisMinifilter Instance" "Altitude" "370000"
    WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\AegisMinifilter\Instances\AegisMinifilter Instance" "Flags" 0
  ${Else}
    DetailPrint "AEGIS: aegis_minifilter.sys not in payload - AegisMinifilter service not registered (build it: scripts\wdk_build_minifilter.ps1)"
  ${EndIf}

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
  ; Drivers first: the daemon opens the callout device and the filter comm
  ; port at startup. fltmc load is the proven minifilter path; sc start
  ; stays as the script's fallback - both are logged either way.
  nsExec::ExecToLog 'sc start AegisWfp'
  nsExec::ExecToLog "fltmc load AegisMinifilter"
  Sleep 1500
  nsExec::ExecToLog "sc start AegisMinifilter"
  nsExec::ExecToLog 'sc start AegisNids'
SectionEnd

Section "Uninstall"
  ; DEPLOY-120-PATHFIX: an uninstaller deletes the shared AegisNids service
  ; and the driver services. If the registered service does not live under
  ; this $INSTDIR, this is a duplicate/stale uninstaller: abort before
  ; deleting anything.
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\AegisNids" "ImagePath"
  ${If} $0 != ""
    StrCpy $1 $0 1
    ${If} $1 == '"'
      StrCpy $0 $0 "" 1
      StrCpy $0 $0 -1
    ${EndIf}
    StrCpy $1 $0 4
    ${If} $1 == "\??\"
      StrCpy $0 $0 "" 4
    ${EndIf}
    ${GetFileName} "$0" $1
    ${GetParent} "$0" $2
    ${GetFileName} "$2" $3
    ${GetParent} "$2" $4
    ${If} $1 == "aegis_nids.exe"
      ${If} $3 == "runtime"
        StrCpy $5 $INSTDIR 1 -1
        ${If} $5 == "\"
          StrCpy $INSTDIR $INSTDIR -1
        ${EndIf}
        ${If} $4 != $INSTDIR
          MessageBox MB_ICONSTOP "Refusing to uninstall: AegisNids service path $0 is not under $INSTDIR. Run the official uninstaller for the registered install; a duplicate runtime must not delete shared services."
          Abort
        ${EndIf}
      ${Else}
        MessageBox MB_ICONSTOP "Refusing to uninstall: AegisNids service path is not the canonical <install>\runtime\aegis_nids.exe: $0."
        Abort
      ${EndIf}
    ${Else}
      MessageBox MB_ICONSTOP "Refusing to uninstall: AegisNids service path is not the canonical <install>\runtime\aegis_nids.exe: $0."
      Abort
    ${EndIf}
  ${EndIf}

  nsExec::ExecToLog "sc stop AegisNids"
  nsExec::ExecToLog "taskkill /f /im aegis_nids.exe"
  Sleep 2000
  nsExec::ExecToLog "sc delete AegisNids"
  ; Kernel telemetry drivers (DEPLOY-120): unload before delete before
  ; removing the System32 copies. The altitude values live inside the
  ; service key and go with sc delete - never DeleteRegKey an SCM key.
  nsExec::ExecToLog "fltmc unload AegisMinifilter"
  Sleep 3000
  nsExec::ExecToLog "sc stop AegisMinifilter"
  nsExec::ExecToLog "sc delete AegisMinifilter"
  nsExec::ExecToLog "sc stop AegisWfp"
  Sleep 2000
  nsExec::ExecToLog "sc delete AegisWfp"
  ; 2026-10-20 E5 teardown: the first fixed installer deleted the services
  ; but raced the kernel image release, leaving aegis_wfp.sys and
  ; aegis_minifilter.sys in System32 (the services were already 1060).
  ; Wait for the unload to settle, then retry; a still-locked image is
  ; scheduled with /REBOOTOK rather than silently left behind.
  Sleep 6000
  Delete "$SYSDIR\drivers\aegis_wfp.sys"
  Delete "$SYSDIR\drivers\aegis_minifilter.sys"
  Sleep 1000
  ${If} ${FileExists} "$SYSDIR\drivers\aegis_wfp.sys"
    Delete /REBOOTOK "$SYSDIR\drivers\aegis_wfp.sys"
    DetailPrint "AEGIS: aegis_wfp.sys still locked; scheduled for deletion at reboot"
  ${EndIf}
  ${If} ${FileExists} "$SYSDIR\drivers\aegis_minifilter.sys"
    Delete /REBOOTOK "$SYSDIR\drivers\aegis_minifilter.sys"
    DetailPrint "AEGIS: aegis_minifilter.sys still locked; scheduled for deletion at reboot"
  ${EndIf}
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
    # DEPLOY-120: record which kernel drivers this generation can package.
    presence = driver_presence()
    for tag, rel, present in presence:
        state = "present" if present else "ABSENT - not packaged"
        lines.append(f"; kernel driver {tag}: {rel} ({state})")
    missing = [tag for tag, _rel, present in presence if not present]
    if missing:
        print(
            "WARN: kernel driver build output(s) missing: "
            + ", ".join(missing)
            + " - the installer ships without them and setup skips their "
            "service registration; build first: "
            "scripts\\wdk_build_production.ps1 + scripts\\wdk_build_minifilter.ps1",
            file=sys.stderr,
        )
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
        makensis = find_makensis()
        if makensis is None:
            print("ERROR: makensis not found (PATH or the standard NSIS "
                  "install dirs); install NSIS to build the installer",
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
