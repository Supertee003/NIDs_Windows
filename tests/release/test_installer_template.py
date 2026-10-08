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
