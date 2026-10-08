"""ETW-STR-046: native ETW start validates its session name (static contract).

aegis_etw_start converted the session name with an unchecked
MultiByteToWideChar into a fixed 64-wide buffer: a long name could
truncate without NUL-termination (or best-fit map invalid UTF-8) and hand
StartTraceW garbage. The fix checks the conversion (strict UTF-8, empty
and oversize fail closed with rc -5 before any handle exists). The Zig
caller passes a short constant, so this is defense-in-depth at the C
boundary, in the same class as FIM-LONGPATH-044.

Note: this mingw toolchain cannot fully compile etw_native.c (its
evntrace.h lacks PROCESSTRACE_HANDLE; canonical build is MSVC) — the pin
is source-contract level (E1), and the edited region produces zero
diagnostics where the pristine file's pre-existing header errors occur
elsewhere. E1.

GAP-012 bullet 5 extends the contract: aegis_etw_start must validate every
requested provider GUID against host registration (TDH manifest query)
before any session state exists, refusing ready (-6 unregistered, -7
inconclusive) instead of enabling a silent-loss session. Pinned below.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ETW = REPO / "src" / "windows" / "etw_native.c"


def src() -> str:
    return ETW.read_text(encoding="utf-8")


def test_session_name_conversion_is_checked():
    text = src()
    assert "MB_ERR_INVALID_CHARS" in text
    # No flags=0 (unchecked, best-fit mapping) conversion may remain: every
    # MultiByteToWideChar call must pass MB_ERR_INVALID_CHARS.
    lax = [
        line.strip() for line in text.splitlines()
        if "MultiByteToWideChar(CP_UTF8, 0," in line
    ]
    assert lax == [], f"unchecked (flags=0) conversions: {lax}"
    # The session-name call lives inside a fail-closed guard.
    assert "if (!session_name" in text


def test_bad_session_name_fails_closed():
    text = src()
    assert "invalid session name" in text
    assert "return -5" in text


def test_no_bare_session_copy_remains():
    text = src()
    assert "MultiByteToWideChar(CP_UTF8, 0, session_name" not in text


def test_provider_registration_is_validated_before_start():
    text = src()
    assert "TdhEnumerateManifestProviderEvents" in text
    assert "ERROR_NOT_FOUND" in text
    assert "return -6" in text
    # Validation must precede any session side effect: the manifest query
    # appears before the first StartTraceW call in source order.
    assert text.index("TdhEnumerateManifestProviderEvents") < text.index(
        "StartTraceW(&g_session.session_handle"
    )


def test_inconclusive_registration_fails_closed():
    text = src()
    assert "return -7" in text
