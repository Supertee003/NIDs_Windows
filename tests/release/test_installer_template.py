"""INST-107: generated installer template structural pins (EVT-107).

makensis is not available in unit-test environments, so these pins assert
the structural properties a valid installer needs directly on the template
and on generate_nsi output. All generation targets tmp_path (no tree
writes); module import is side-effect free (main guarded).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def _load():
    spec = importlib.util.spec_from_file_location(
        "installer", REPO / "tools" / "installer.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _file_lines_outside_sections(text: str) -> list[str]:
    """File directives NSIS would reject (outside any Section)."""
    bad: list[str] = []
    depth = 0
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Section ") and not s.startswith("SectionEnd"):
            depth += 1
        elif s == "SectionEnd":
            depth = max(0, depth - 1)
        elif s.startswith("File ") and depth == 0:
            bad.append(line)
    return bad


def test_file_directives_live_inside_sections():
    mod = _load()
    assert _file_lines_outside_sections(mod.NSIS_TEMPLATE) == []


def test_uninstall_covers_drivers_shortcuts_regkey_and_preserves_configs():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert 'RMDir /r "$INSTDIR\\drivers"' in tpl
    assert 'Delete "$SMPROGRAMS\\AEGIS NIDS\\Uninstall AEGIS.lnk"' in tpl
    assert "DeleteRegKey HKLM" in tpl
    assert 'RMDir /r "$INSTDIR\\configs"' not in tpl


def test_mui_pages_and_service_lifecycle_present():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert '!include "MUI2.nsh"' in tpl
    assert "MUI_PAGE_INSTFILES" in tpl
    assert "sc create AegisNids" in tpl
    assert 'Section "Start AEGIS Service Now"' in tpl


def test_generate_nsi_splices_manifest_block_inside_install(tmp_path):
    mod = _load()
    out = tmp_path / "t.nsi"
    mod.generate_nsi(out)
    text = out.read_text(encoding="utf-8")
    assert "; manifest binaries included:" in text
    assert _file_lines_outside_sections(text) == []


def test_preprocessor_defines_are_real_and_version_block_is_valid_nsis():
    """EVT-220: the template's four '#!define' lines were NSIS comments ('#'
    starts a comment), so APPNAME/APPVERSION/PUBLISHER/AEGIS_COMMIT never
    existed: makensis warned 'unknown variable {APPNAME}/{APPVERSION}' and
    OutFile wrote the literal 'aegis-installer-${APPVERSION}.exe'. Also pin
    the version-key syntax that actually compiles (bare 'PrivateBuild' is an
    invalid command - makensis v3.12 aborts on it)."""
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert "#!define" not in tpl
    for name in ("APPNAME", "APPVERSION", "PUBLISHER", "AEGIS_COMMIT"):
        assert f"!define {name} " in tpl, name
    assert 'VIAddVersionKey "PrivateBuild"' in tpl
    assert "\nPrivateBuild " not in tpl


def test_upgrade_stops_service_and_process_before_overwriting_runtime():
    """EVT-221: preparing the first host install/upgrade drill exposed that
    the Install section overwrites the runtime without stopping the running
    service/process first - a live image file is locked and File fails
    mid-copy on any reinstall over a live install. Pin the stop/kill
    ordering relative to the first runtime File directive."""
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    first_file = tpl.index('File "zig-out\\bin\\aegis_nids.exe"')
    assert tpl.index('nsExec::ExecToLog "sc stop AegisNids"') < first_file
    assert tpl.index("taskkill /f /im aegis_nids.exe") < first_file


# ---------------------------------------------------------------------
# DEPLOY-120: kernel telemetry drivers ride the installer
# ---------------------------------------------------------------------


def test_driver_file_lines_use_canonical_build_outputs():
    """The packaged sources are the exact WDK build outputs the lifecycle
    scripts deploy (the binaries EVT-231/EVT-232 proved live). The legacy
    in-tree copy drivers\\wfp_callout\\aegis_wfp.sys is a pre-EVT-231
    artifact and must never ship as the driver source again."""
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert 'File "/nonfatal" "/oname=aegis_wfp.sys" "build\\x64\\wfp\\aegis_wfp.sys"' in tpl
    assert ('File "/nonfatal" "/oname=aegis_minifilter.sys" '
            '"build\\x64\\minifilter\\aegis_minifilter.sys"') in tpl
    assert "drivers\\wfp_callout\\aegis_wfp.sys" not in tpl
    assert mod.DRIVER_SOURCES == (
        ("wfp", "build\\x64\\wfp\\aegis_wfp.sys"),
        ("minifilter", "build\\x64\\minifilter\\aegis_minifilter.sys"),
    )


def test_driver_sources_match_service_script_defaults():
    """One contract, two deploy paths: the NSIS install path and the proven
    scripts (which produced the live services) must agree on the driver
    source paths."""
    wfp = (REPO / "scripts" / "wfp_service.ps1").read_text(encoding="utf-8")
    mini = (REPO / "scripts" / "minifilter_service.ps1").read_text(encoding="utf-8")
    assert "build\\x64\\wfp\\aegis_wfp.sys" in wfp
    assert "build\\x64\\minifilter\\aegis_minifilter.sys" in mini


def test_driver_service_registration_matches_proven_scripts():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    # WFP: kernel/demand, System32 copy, no DisplayName (wfp_service.ps1).
    assert ('sc create AegisWfp type= kernel start= demand '
            'binPath= "$SYSDIR\\drivers\\aegis_wfp.sys"') in tpl
    # Minifilter: filesys/demand + DisplayName (minifilter_service.ps1).
    assert ('sc create AegisMinifilter type= filesys start= demand '
            'binPath= "$SYSDIR\\drivers\\aegis_minifilter.sys" '
            'DisplayName= "AEGIS NIDS Minifilter Driver"') in tpl


def test_proven_scripts_still_carry_the_mirrored_contract():
    """The other side of the parity pins: the scripts' commands must keep
    the parameters the installer mirrors."""
    wfp = (REPO / "scripts" / "wfp_service.ps1").read_text(encoding="utf-8")
    mini = (REPO / "scripts" / "minifilter_service.ps1").read_text(encoding="utf-8")
    assert 'type= kernel start= demand binPath= "$svcBin"' in wfp
    assert ('type= filesys start= demand binPath= "$SvcFile" '
            'DisplayName= "AEGIS NIDS Minifilter Driver"') in mini
    assert "$Altitude = '370000'" in mini


def test_minifilter_altitude_registration_matches_script():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    base = "SYSTEM\\CurrentControlSet\\Services\\AegisMinifilter"
    assert f'WriteRegStr HKLM "{base}" "Altitude" "370000"' in tpl
    assert f'WriteRegStr HKLM "{base}\\Instances" "DefaultInstance" "AegisMinifilter Instance"' in tpl
    assert f'WriteRegStr HKLM "{base}\\Instances\\AegisMinifilter Instance" "Altitude" "370000"' in tpl
    assert f'WriteRegDWORD HKLM "{base}\\Instances\\AegisMinifilter Instance" "Flags" 0' in tpl
    # sc delete is the only allowed removal path for an SCM service key.
    assert f'DeleteRegKey HKLM "{base}"' not in tpl


def test_driver_registration_guarded_and_signature_status_logged():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert '!include "LogicLib.nsh"' in tpl
    assert '${If} ${FileExists} "$INSTDIR\\drivers\\aegis_wfp.sys"' in tpl
    assert '${If} ${FileExists} "$INSTDIR\\drivers\\aegis_minifilter.sys"' in tpl
    assert "AegisWfp service not registered" in tpl
    assert "AegisMinifilter service not registered" in tpl
    assert "AEGIS_DRIVER_SIG_WFP" in tpl and "AEGIS_DRIVER_SIG_FIM" in tpl
    assert "Get-AuthenticodeSignature" in tpl


def test_driver_teardown_precedes_copy_and_create():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert tpl.index('nsExec::ExecToLog "fltmc unload AegisMinifilter"') < \
        tpl.index('copy /y "$INSTDIR\\drivers\\aegis_minifilter.sys"')
    assert tpl.index('nsExec::ExecToLog "sc stop AegisWfp"') < \
        tpl.index('copy /y "$INSTDIR\\drivers\\aegis_wfp.sys"')
    assert tpl.index('nsExec::ExecToLog "sc delete AegisMinifilter"') < \
        tpl.index("sc create AegisMinifilter type= filesys")


def test_driver_starts_ordered_before_daemon():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    start_sec = tpl.split('Section "Start AEGIS Service Now"', 1)[1]
    daemon = start_sec.index("sc start AegisNids")
    assert start_sec.index("sc start AegisWfp") < daemon
    assert start_sec.index("fltmc load AegisMinifilter") < daemon
    assert start_sec.index("sc start AegisMinifilter") < daemon


def test_uninstall_removes_driver_services_and_system32_copies():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    un = tpl.split('Section "Uninstall"', 1)[1]
    for cmd in ("fltmc unload AegisMinifilter", "sc delete AegisMinifilter",
                "sc delete AegisWfp"):
        assert cmd in un, cmd
    assert 'Delete "$SYSDIR\\drivers\\aegis_wfp.sys"' in un
    assert 'Delete "$SYSDIR\\drivers\\aegis_minifilter.sys"' in un


def test_uninstall_waits_for_kernel_image_release_before_delete():
    """2026-10-20 E5 teardown: services went 1060 but both System32 driver
    copies remained, because Delete raced the filter/driver unload. Pin the
    kill/wait/retry order and the reboot-safe fallback."""
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    un = tpl.split('Section "Uninstall"', 1)[1]
    wfp_stop = un.index('nsExec::ExecToLog "sc stop AegisWfp"')
    delete_wfp = un.index('Delete "$SYSDIR\\drivers\\aegis_wfp.sys"', wfp_stop)
    assert un.index("Sleep 2000", wfp_stop) < delete_wfp
    assert un.index("Sleep 6000", wfp_stop) < delete_wfp
    assert 'Delete /REBOOTOK "$SYSDIR\\drivers\\aegis_wfp.sys"' in un
    assert 'Delete /REBOOTOK "$SYSDIR\\drivers\\aegis_minifilter.sys"' in un
    assert 'taskkill /f /im aegis_nids.exe' in un
    assert un.index("taskkill /f /im aegis_nids.exe") < \
        un.index('nsExec::ExecToLog "sc delete AegisNids"')


def test_generate_nsi_annotates_driver_presence(tmp_path):
    mod = _load()
    out = tmp_path / "drivers.nsi"
    mod.generate_nsi(out)
    text = out.read_text(encoding="utf-8")
    assert "; kernel driver wfp: build\\x64\\wfp\\aegis_wfp.sys (" in text
    assert "; kernel driver minifilter: build\\x64\\minifilter\\aegis_minifilter.sys (" in text
    assert "(present)" in text or "(ABSENT - not packaged)" in text


def test_find_makensis_prefers_path_then_standard_dirs(tmp_path, monkeypatch):
    mod = _load()
    monkeypatch.setattr(mod.shutil, "which", lambda _name: r"C:\fake\makensis.exe")
    assert mod.find_makensis() == r"C:\fake\makensis.exe"

    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    for env_name in ("ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"):
        monkeypatch.setenv(env_name, str(tmp_path))
    assert mod.find_makensis() is None
    nsis = tmp_path / "NSIS"
    nsis.mkdir()
    fake = nsis / "makensis.exe"
    fake.write_text("", encoding="utf-8")
    assert mod.find_makensis() == str(fake)


# ---------------------------------------------------------------------
# DEPLOY-120-PATHFIX: never create a second runtime beside a live service
# ---------------------------------------------------------------------


def test_existing_service_path_is_detected_and_selected_on_init():
    """The installer must adopt the registered AegisNids ImagePath instead of
    blindly using $PROGRAMFILES64. The 2026-10-20 E5 attempt chose
    D:\\Program Files\\AEGIS NIDS while the service still ran from
    C:\\Program Files\\AEGIS NIDS, creating a duplicate runtime."""
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    assert '!include "FileFunc.nsh"' in tpl
    assert "Var ExistingRoot" in tpl
    assert "Var ExistingValid" in tpl
    assert ('ReadRegStr $0 HKLM "SYSTEM\\CurrentControlSet\\Services\\AegisNids" '
            '"ImagePath"') in tpl
    oninit = tpl.split("Function .onInit", 1)[1].split("FunctionEnd", 1)[0]
    assert "StrCpy $INSTDIR $ExistingRoot" in oninit
    assert "${GetFileName}" in oninit
    assert "${GetParent}" in oninit
    assert 'StrCpy $0 $0 "" 1' in oninit
    assert "StrCpy $0 $0 -1" in oninit


def test_install_aborts_before_stopping_when_directory_differs():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    install = tpl.split('Section "Install"', 1)[1]
    stop = install.index('nsExec::ExecToLog "sc stop AegisNids"')
    guard = install[:stop]
    assert '${If} $ExistingValid == "1"' in guard
    assert "${If} $INSTDIR != $ExistingRoot" in guard
    assert "duplicate runtime" in guard.lower()
    assert "Abort" in guard


def test_uninstall_aborts_before_service_delete_when_path_mismatches():
    mod = _load()
    tpl = mod.NSIS_TEMPLATE
    un = tpl.split('Section "Uninstall"', 1)[1]
    delete = un.index('nsExec::ExecToLog "sc stop AegisNids"')
    guard = un[:delete]
    assert ('ReadRegStr $0 HKLM "SYSTEM\\CurrentControlSet\\Services\\AegisNids" '
            '"ImagePath"') in guard
    assert "${If} $4 != $INSTDIR" in guard
    assert "Refusing to uninstall" in guard
    assert "Abort" in guard


def test_generate_nsi_carries_existing_service_guard(tmp_path):
    mod = _load()
    out = tmp_path / "pathguard.nsi"
    mod.generate_nsi(out)
    text = out.read_text(encoding="utf-8")
    assert "Function .onInit" in text
    assert "Var ExistingRoot" in text
    assert "duplicate runtime" in text.lower()
