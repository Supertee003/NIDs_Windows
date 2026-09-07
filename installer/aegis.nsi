!cd "D:/NIDs_Windows"
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

Name "AEGIS NIDS v5.0+"
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
  File "zig-out\bin\aegis_nids.exe"
  File "target\release\aegis_pep.dll"
  File "build\Release\aegis_wfp_user.dll"
  File "build\Release\aegis_etw_helper.dll"
  File "build\Release\aegis_fim_helper.dll"
  File "tools\aegisctl.py"
  File "configs\schema.json"
  File "configs\runtime.json"
  File "LICENSE.txt"

  ; Service registration
  nsExec::ExecToLog 'sc create AegisNids binPath= "$INSTDIR\aegis_nids.exe" start= auto'
  nsExec::ExecToLog 'sc description AegisNIDS "AEGIS Network Intrusion Detection System"'
  nsExec::ExecToLog 'sc failure AegisNids reset= 86400 actions= restart/5000/restart/5000/restart/10000'

  ; Firewall rule for federation port 8443 (if enabled later)
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="AEGIS Federation" dir=in action=allow program="$INSTDIR\aegis_nids.exe" enable=no'

  ; Start menu shortcuts
  CreateDirectory "$SMPROGRAMS\AEGIS"
  CreateShortcut "$SMPROGRAMS\AEGIS\AEGIS Control.lnk" "$INSTDIR\aegisctl.py"
  CreateShortcut "$SMPROGRAMS\AEGIS\Uninstall AEGIS.lnk" "$INSTDIR\uninstall.exe"

  ; Registry uninstall entry
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "DisplayName" "AEGIS NIDS v5.0+"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "Publisher" "AEGIS"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids" "DisplayVersion" "5.0.0.0"

  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "ETW Real-time Telemetry" SecEtw
  SetOutPath "$INSTDIR"
  ; ETW session requires no special install; just DLLs (already in Core)
  ; Optionally install the WFP kernel-mode callout driver (signed)
  ; File "build\Release\aegis_wfp.sys"
  ; nsExec::ExecToLog 'sc create aegis_wfp type= kernel binPath= "$INSTDIR\aegis_wfp.sys"'
  ; nsExec::ExecToLog 'sc start aegis_wfp'
SectionEnd

Section "Federation Cluster (Optional)" SecFederation
  SetOutPath "$INSTDIR"
  ; Config templates
  File "configs\cluster.example.json"
  ; Generate self-signed cert on first run
  nsExec::ExecToLog 'powershell -Command "if (!(Test-Path $INSTDIR\certs)) {{ New-Item -Path $INSTDIR\certs -ItemType Directory }}"'
SectionEnd

Section "Start AEGIS Service Now" SecStart
  nsExec::ExecToLog 'sc start AegisNids'
SectionEnd

; Uninstaller
Section "Uninstall"
  nsExec::ExecToLog 'sc stop AegisNids'
  nsExec::ExecToLog 'sc delete AegisNids'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="AEGIS Federation"'
  Delete "$SMPROGRAMS\AEGIS\AEGIS Control.lnk"
  Delete "$SMPROGRAMS\AEGIS\Uninstall AEGIS.lnk"
  RMDir "$SMPROGRAMS\AEGIS"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisNids"
SectionEnd
