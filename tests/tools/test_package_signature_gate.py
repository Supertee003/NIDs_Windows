"""PACKAGING-GATE-001: a bundle may not ship a driver the kernel will refuse.

The 2026-11-09 host window found `scripts/package_release.ps1` copying
`build/x64/wfp/aegis_wfp.sys` unconditionally. The build output was
`NotSigned`, so the installer replaced a Valid-signed driver with one the
loader rejects -- while printing "Installed AEGIS NIDS" and exiting 0. The
minifilter had no entry in the artifact list at all, so the capture path
could not be deployed from a bundle.

These assertions are static: they read the packaging script, they do not run
PowerShell, sign anything, or touch the host.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGER = REPO / "scripts" / "package_release.ps1"


def _text() -> str:
    return PACKAGER.read_text(encoding="utf-8")


def test_both_drivers_are_packaged():
    text = _text()
    assert "drivers\\aegis_wfp.sys" in text
    assert "drivers\\aegis_minifilter.sys" in text, (
        "the minifilter is part of the capture path; a bundle without it "
        "cannot deploy the driver it claims to ship")


def test_unsigned_driver_aborts_packaging():
    text = _text()
    assert "Get-AuthenticodeSignature" in text, (
        "packaging must verify driver signatures, not assume the build is signed")
    assert "Status -ne \"Valid\"" in text, (
        "the gate must refuse anything that is not Valid")
    # The failure has to name the repair command, or the next operator signs by
    # hand and the gate is bypassed by folklore.
    assert "sign_wfp_driver_20261024.ps1" in text
    assert "minifilter_sign.ps1" in text


def test_minifilter_gate_entry_is_declared():
    text = _text()
    gate_block = text.split("$driverSignatures", 1)
    assert len(gate_block) == 2, "driver signature gate missing"
    assert "minifilter" in gate_block[1].split("}", 1)[0]
