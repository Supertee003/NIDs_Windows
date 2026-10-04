"""FIM-LONGPATH-044: native FIM accepts extended-length paths (static contract).

src/windows/fim_native.c converted UTF-8 with a 260-char buffer and an
unchecked MultiByteToWideChar: deep watch trees truncated into
CreateFileW failure, and invalid UTF-8 best-fit mapped. The fix converts
strictly (MB_ERR_INVALID_CHARS, fail closed) and escapes absolute paths
with the \\\\?\\ prefix (UNC -> \\\\?\\UNC\\). Compiles warning-free
(gcc -Wall -Wextra) and links as a DLL; this pins the source contract so
a future edit cannot silently reintroduce the 260 cap. E1.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIM = REPO / "src" / "windows" / "fim_native.c"


def src() -> str:
    return FIM.read_text(encoding="utf-8")


def test_strict_utf8_conversion():
    text = src()
    assert "MB_ERR_INVALID_CHARS" in text
    # No unchecked conversion remains: every MultiByteToWideChar return
    # value is tested (assigned then compared, not bare call).
    bare = [
        line.strip() for line in text.splitlines()
        if "MultiByteToWideChar(" in line and "=" not in line.split("MultiByteToWideChar(")[0]
    ]
    assert bare == [], f"unchecked conversions: {bare}"


def test_extended_length_prefix_paths():
    text = src()
    assert "FIM_PATH_WCHARS" in text
    assert "32768" in text
    assert "UNC" in text  # UNC -> \\?\UNC\ mapping present
    assert "_snwprintf" in text


def test_no_fixed_max_path_conversion_buffer():
    text = src()
    assert "wchar_t wpath[MAX_PATH]" not in text


def test_conversion_failure_fails_closed():
    text = src()
    assert "fim_to_wide" in text
    assert "path conversion failed" in text
