"""DRIVER-SYNTAX-001: the last unexamined product files were the kernel drivers.

Six files under `drivers/` were named by no evidence entry: three minifilter C
sources, two INF files, and a quarantined WFP dispatch copy. Nothing in the
repository compiles any of them — the canonical driver build needs the WDK
build environment and test signing, neither of which a gate can assume.

What can be checked here is checked here:

* the three minifilter sources are put through a **syntax-only** compile
  (`cl -Zs`) against the installed WDK headers — that is a real parse of real
  driver code, and it passed with zero diagnostics;
* the quarantined `aegis_wfp_comm.c` header used to close its comment block
  early, leaving prose outside any comment, so the file did not parse at all
  (`error C2143: syntax error: missing '{' before ':'`). The defect was real
  and is fixed; the pin below makes sure the same break cannot come back
  without a compiler;
* both INF files still carry a `[Version]` section and the NT signature line;
* the quarantined copy stays out of the driver build scripts.

What is *not* checked, stated plainly: the WFP callout sources did not compile in
this ad-hoc harness — the WDK's own `fwpsk.h` rejects the invocation with
`UINT32` redefinition errors, which is a property of the harness (no kernel-mode
build environment), not a verdict on the file. Kernel-mode correctness, driver
loading, filter installation and unload remain unverified here.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DRIVERS = ROOT / "drivers"

MINIFILTER_SOURCES = [
    "drivers/minifilter/aegis_minifilter.c",
    "drivers/minifilter/aegis_minifilter_comm.c",
    "drivers/minifilter/aegis_minifilter_proc.c",
]
INFS = ["drivers/minifilter/aegis_minifilter.inf", "drivers/wfp_callout/aegis_wfp.inf"]
QUARANTINED = ROOT / "drivers" / "wfp_callout" / "quarantined" / "aegis_wfp_comm.c"

VS_ROOTS = [
    Path("C:/Program Files/Microsoft Visual Studio/2022"),
    Path("C:/Program Files (x86)/Microsoft Visual Studio/2022"),
]
KITS = Path("C:/Program Files (x86)/Windows Kits/10/Include")


def _cl() -> Path | None:
    for root in VS_ROOTS:
        for candidate in root.glob("*/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"):
            return candidate
    return None


def _wdk_include() -> Path | None:
    if not KITS.is_dir():
        return None
    versions = sorted((p for p in KITS.iterdir() if p.is_dir()), reverse=True)
    for version in versions:
        if (version / "km" / "fltKernel.h").exists():
            return version
    return None


CL = _cl()
INCLUDE = _wdk_include()


@pytest.mark.parametrize("rel", MINIFILTER_SOURCES)
def test_minifilter_sources_parse_against_the_wdk(rel: str) -> None:
    if CL is None or INCLUDE is None:
        pytest.skip("MSVC or WDK headers not installed")
    msvc_include = CL.parents[3] / "include"
    proc = subprocess.run(
        [
            str(CL), "-nologo", "-Zs",
            "-D_AMD64_", "-DAMD64", "-DWIN32=100", "-D_WIN32_WINNT=0x0A00",
            f"-I{INCLUDE / 'km'}", f"-I{INCLUDE / 'shared'}",
            f"-I{INCLUDE / 'ucrt'}", f"-I{msvc_include}",
            f"-I{ROOT / 'drivers' / 'minifilter'}",
            str(ROOT / rel),
        ],
        capture_output=True, text=True, errors="replace", timeout=600, cwd=ROOT,
    )
    output = proc.stdout + proc.stderr
    errors = [line for line in output.splitlines() if ": error" in line or ": fatal" in line]
    assert not errors, f"{rel} does not parse:\n" + "\n".join(errors[:10])


def test_the_quarantined_header_closes_exactly_once() -> None:
    """The break was a comment closed early; count the closes before the include."""
    text = QUARANTINED.read_text(encoding="utf-8", errors="replace")
    head = text.split("#include", 1)[0]
    assert head.count("*/") == 1, (
        "the quarantine header must be a single comment block; a second close "
        "leaves prose outside a comment and the file stops parsing"
    )
    assert head.lstrip().startswith("/**"), "the quarantine notice must stay the first thing in the file"
    assert "QUARANTINED" in head


def test_the_quarantined_copy_stays_out_of_the_driver_build() -> None:
    """A build script may *mention* the quarantined copy (to forbid it), never use it.

    `scripts/build_drivers.bat` carries a REM saying the file lives there and
    must not be compiled. That comment is the guard; a non-comment reference
    would be the regression.
    """
    offenders = []
    for script in (ROOT / "scripts").iterdir():
        if script.is_dir() or script.suffix.lower() not in {".ps1", ".bat", ".cmd"}:
            continue
        for lineno, line in enumerate(
            script.read_text(encoding="utf-8", errors="replace").splitlines(), 1
        ):
            stripped = line.strip()
            if stripped.startswith(("REM", "::", "#")):
                continue
            if "quarantined" in stripped.lower():
                offenders.append(f"{script.name}:{lineno}")
    assert not offenders, f"a driver build script uses the quarantined copy: {offenders}"


@pytest.mark.parametrize("rel", INFS)
def test_inf_files_keep_their_version_block(rel: str) -> None:
    """Both packages must keep a signed-driver header.

    Quotes around the signature are optional in INF syntax, and this repository
    writes it unquoted (`Signature = $Windows NT$`); the pin accepts either.
    `[Manufacturer]` is only required for a package that installs a root-enumerated
    device, which the WFP INF does and the minifilter INF (loaded with
    `fltmc load`) does not.
    """
    text = (ROOT / rel).read_text(encoding="utf-8-sig", errors="replace")
    assert "[Version]" in text, f"{rel} lost its [Version] section"
    assert "$Windows NT$" in text, f"{rel} lost the NT signature line"
    assert "CatalogFile" in text, f"{rel} lost its catalog reference"
    if "Root\\" in text:
        assert "[Manufacturer]" in text, f"{rel} installs a root device but has no [Manufacturer]"
