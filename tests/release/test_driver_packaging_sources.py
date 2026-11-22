"""S2-05 / DRIVER-SIGN-PAYLOAD-001: one driver source per packaging stage.

The tree once had two answers to "which aegis_wfp.sys do I install": the NSIS
path pointed at ``drivers\\wfp_callout\\aegis_wfp.sys`` (an Oct-16 image that no
build target refreshes) while the build/staging paths shipped
``build\\x64\\wfp\\aegis_wfp.sys``. Later, the NSIS generator still packaged the
raw WDK output, which is unsigned: Windows rejects it with 0x241/577, both
driver services stay STOPPED and the daemon reports DEGRADED.

The invariant now has two stages, never mixed: CI/CMake produce the raw build
outputs under ``build\\x64\\`` (the signing input), and the *installer* packages
only the hash-verified, owner-signed payload from the release candidate. No
packaging entry point may name the stale tree copy.
"""
from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Everything that can put a .sys into something an operator installs.
PACKAGING_ENTRY_POINTS = (
    "installer/aegis.nsi",
    "tools/installer.py",
    "tools/release_candidate.py",
    "scripts/package_release.ps1",
)

CANONICAL_DRIVERS = {
    "aegis_wfp.sys": r"build\x64\wfp\aegis_wfp.sys",
    "aegis_minifilter.sys": r"build\x64\minifilter\aegis_minifilter.sys",
}

STALE_IMAGE = re.compile(
    r"drivers[\\/]wfp_callout[\\/](aegis_wfp|aegis_minifilter)\.sys", re.IGNORECASE
)


def _text(rel: str) -> str:
    # Python sources hold the Windows path escaped; compare one form only.
    return (ROOT / rel).read_text(encoding="utf-8", errors="ignore").replace("\\\\", "\\")


def _code_only(text: str) -> str:
    """Drop comment lines: a comment that names the retired path is history, not
    a directive, and the sentence explaining the retirement is worth keeping."""
    kept = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith((";", "#", "//")):
            continue
        kept.append(line)
    return "\n".join(kept)


def _tracked(pattern: str) -> list[Path]:
    """Only tracked files: scratch copies under .work/ are not packaging paths."""
    out = subprocess.run(
        ["git", "ls-files", pattern],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [ROOT / rel for rel in out]


def _nsi_files() -> list[Path]:
    return _tracked("*.nsi")


def test_no_entry_point_ships_the_stale_tree_image() -> None:
    offenders = [
        rel
        for rel in PACKAGING_ENTRY_POINTS
        if STALE_IMAGE.search(_code_only(_text(rel)))
    ]
    assert not offenders, (
        "these packaging entry points source a driver from drivers/wfp_callout/, "
        f"which no build refreshes: {offenders}"
    )


def test_installers_ship_the_signed_wfp_image() -> None:
    """NSIS generation must resolve owner-signed payloads; the raw build
    output is the signing *input*, never a shippable driver image."""
    code = _code_only(_text("tools/installer.py"))
    for marker in ("signed_driver_sources()", "signed_drivers_available()",
                   "OWNER_PUBLIC_KEY", "@WFP_DRIVER_SOURCE@", "@FIM_DRIVER_SOURCE@"):
        assert marker in code, f"installer.py no longer enforces signed payloads: {marker}"
    missing = [
        rel
        for rel in ("installer/aegis.nsi", "scripts/package_release.ps1")
        if CANONICAL_DRIVERS["aegis_wfp.sys"] not in _text(rel)
    ]
    assert not missing, (
        "pre-signing staging paths no longer name the WDK build output "
        f"{CANONICAL_DRIVERS['aegis_wfp.sys']}: {missing}"
    )


def test_nsi_file_directives_only_reference_build_outputs() -> None:
    """A ``File`` directive that packages a .sys must take it from build\\x64\\."""
    directive = re.compile(r'^\s*File\s+(?:"[^"]*"\s+)*"([^"]+)"', re.IGNORECASE)
    bad: list[str] = []
    seen_pairing = 0
    for nsi in _nsi_files():
        for line in nsi.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = directive.match(line)
            if not m:
                continue
            source = m.group(1).replace("\\\\", "\\")
            if not source.lower().endswith(".sys"):
                continue
            canonical = source in CANONICAL_DRIVERS.values()
            if not canonical:
                bad.append(f"{nsi.relative_to(ROOT).as_posix()}: {source}")
            else:
                seen_pairing += 1
    assert not bad, "NSIS packages a driver that is not a build output:\n  " + "\n  ".join(bad)
    assert seen_pairing, "no NSIS file directive packages a driver at all"


def test_release_candidate_drivers_are_the_build_outputs() -> None:
    tree = ast.parse((ROOT / "tools/release_candidate.py").read_text(encoding="utf-8"))
    drivers = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "DRIVERS" for t in node.targets
        ):
            drivers = [str(e.value).replace("/", "\\") for e in node.value.elts]
    assert drivers is not None, "tools/release_candidate.py no longer defines DRIVERS"
    assert drivers == list(CANONICAL_DRIVERS.values()), (
        "release candidate copies drivers from a non-canonical path: "
        f"{drivers}"
    )


def test_stale_tree_image_is_not_a_build_target() -> None:
    """No build script may write a .sys back into drivers/wfp_callout/."""
    writers = re.compile(r"wfp_callout[\\/]\S*\.sys", re.IGNORECASE)
    bad: list[str] = []
    for pattern in ("scripts/*.ps1", "scripts/*.bat", "scripts/*.py", "build_drivers.bat"):
        for script in ROOT.glob(pattern):
            if writers.search(script.read_text(encoding="utf-8", errors="ignore")):
                bad.append(script.relative_to(ROOT).as_posix())
    assert not bad, (
        f"a build script still produces the retired drivers/wfp_callout image: {bad}"
    )
