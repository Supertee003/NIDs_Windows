!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Name "AEGIS NIDS 5.0.0"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\AEGIS"
Unicode True
RequestExecutionLevel admin
ShowInstDetails show

VIProductVersion "5.0.0.0"
VIAddVersionKey "ProductName" "AEGIS NIDS"
VIAddVersionKey "CompanyName" "AEGIS"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2026 AEGIS"
VIAddVersionKey "FileVersion" "5.0.0.0"
VIAddVersionKey "FileDescription" "AEGIS Network Intrusion Detection System"
VIAddVersionKey "PrivateBuild" "f934f39"

; Config / policy / trust / audit / forensic data lives under data\ and is
; PRESERVED across uninstall, upgrade and reinstall (T17 AC5).
!define AEGIS_DATA "$INSTDIR\data"
!define AEGIS_BIN "$INSTDIR\bin"
!define AEGIS_COMMIT "f934f39"

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

Section "AEGIS Runtime + Service (Required)" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR\data\config"
  File "/oname=Rules.json" "config\Rules.json"
  SetOutPath "$INSTDIR"
  File "/oname=aegis_runtime_stamp.txt" "aegis_runtime_stamp.txt"
  ; Manifest-declared payload + build artifact payload

  SetOutPath "$INSTDIR\bin"
  File "/oname=aegisctl.py" "scripts\aegisctl.py"
  SetOutPath "$INSTDIR\bin"
  File "/oname=installer.py" "tools\installer.py"
  SetOutPath "$INSTDIR\bin"
  File "/oname=aegis_nids.exe" "zig-out\bin\aegis_nids.exe"
  SetOutPath "$INSTDIR\bin"
  File "/oname=aegis_pep.dll" "target\release\aegis_pep.dll"
  SetOutPath "$INSTDIR\bin"
  File "/oname=aegis_wfp_user.dll" "build\Release\aegis_wfp_user.dll"
  SetOutPath "$INSTDIR\bin"
  File "/oname=aegis_etw_helper.dll" "build\Release\aegis_etw_helper.dll"
  SetOutPath "$INSTDIR\bin"
  File "/oname=aegis_fim_helper.dll" "build\Release\aegis_fim_helper.dll"
  SetOutPath "$INSTDIR\bin"
  File "/oname=aegis-aggregator.exe" "go\aggregator\aegis-aggregator.exe"
  SetOutPath "$INSTDIR"
  File "/oname=build_manifest.json" "build_manifest.json"

  ; Service registration (auto-start, restart on failure)
  nsExec::ExecToLog 'sc create AegisNids binPath= "$INSTDIR\bin\aegis_nids.exe" start= auto'
  nsExec::ExecToLog 'sc description AegisNIDS "AEGIS Network Intrusion Detection System"'
  nsExec::ExecToLog 'sc failure AegisNids reset= 86400 actions= restart/5000/restart/5000/restart/10000'

  ; Federation firewall rule (disabled until enabled by operator)
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="AEGIS Federation" dir=in action=allow program="$INSTDIR\bin\aegis_nids.exe" enable=no'

  ; Start menu shortcuts
  CreateDirectory "$SMPROGRAMS\AEGIS"
  CreateShortcut "$SMPROGRAMS\AEGIS\AEGIS Control.lnk" "$INSTDIR\bin\aegisctl.py"
  CreateShortcut "$SMPROGRAMS\AEGIS\Uninstall AEGIS.lnk" "$INSTDIR\uninstall.exe"

  ; Registry uninstall entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "DisplayName" "AEGIS NIDS v5.0+"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "Publisher" "AEGIS"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "DisplayVersion" "5.0.0.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "InstallCommit" "${AEGIS_COMMIT}"

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "ETW Real-time Telemetry" SecEtw
  SetOutPath "$INSTDIR\bin"
SectionEnd

Section "Federation Cluster (Optional)" SecFederation
  SetOutPath "$INSTDIR\data\certs"
  File "/nonfatal" "/oname=cluster.example.json" "config\cluster.example.json"
  nsExec::ExecToLog 'powershell -Command "if (!(Test-Path $INSTDIR\data\certs)) {{ New-Item -Path $INSTDIR\data\certs -ItemType Directory }}"'
SectionEnd

Section "Start AEGIS Service Now" SecStart
  nsExec::ExecToLog 'sc start AegisNids'
SectionEnd

; Uninstaller - preserves config/policy/trust/audit/forensic history.
Section "Uninstall"
  nsExec::ExecToLog 'sc stop AegisNids'
  nsExec::ExecToLog 'sc delete AegisNids'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AEGIS Federation"'
  Delete "$SMPROGRAMS\AEGIS\AEGIS Control.lnk"
  Delete "$SMPROGRAMS\AEGIS\Uninstall AEGIS.lnk"
  RMDir "$SMPROGRAMS\AEGIS"
  ; Remove executable payload only - data\ (config, policy, trust,
  ; audit, forensic history) is preserved for upgrade/reinstall/rollback.
  RMDir /r "$INSTDIR\bin"
  Delete "$INSTDIR\build_manifest.json"
  Delete "$INSTDIR\aegis_runtime_stamp.txt"
  Delete "$INSTDIR\uninstall.exe"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids"
SectionEnd
