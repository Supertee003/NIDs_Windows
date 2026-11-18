"""BOOT-MODEL-003: a bundle must carry every script its own installer runs.

`scripts/install_aegis.ps1` (the bundle installer) throws when
`$InstallRoot\\scripts\\install-boot-task.ps1` is absent, and
`install-boot-task.ps1` throws when its `boot-sequence.ps1` sibling is absent.
`scripts/package_release.ps1` copied only `install_aegis.ps1` and
`verify_release.ps1` into the bundle's `scripts\\` directory, so an install from
the zip bundle copied the runtime, created the AegisNids service, and then threw
"Boot-task installer missing" — the NSIS path worked (it ships both files with
`File "scripts\\..."` directives), which is why the hand-run deployment never
showed it. Same class as SERVICE-EXISTS-001: the bundle path was never a path
that had been run.

The pins are computed from the packaging sources, not from a list kept here, so
adding a script that install-time code executes forces both packagers to ship it.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
INSTALLER = ROOT / "tools" / "installer.py"
BUNDLE = SCRIPTS / "package_release.ps1"
INSTALL_AEGIS = SCRIPTS / "install_aegis.ps1"
INSTALL_BOOT = SCRIPTS / "install-boot-task.ps1"

# Suffixes that exist under scripts/ and the check each one gets. A new suffix
# has to be classified here rather than silently skipped.
PARSEABLE = {".py", ".ps1", ".json", ".bat", ".cmd", ".sh"}

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")


def _tracked_scripts() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "scripts"], capture_output=True, text=True, cwd=ROOT, check=True
    ).stdout
    return [p for p in out.splitlines() if p]


def _extract(text: str, marker: str) -> set[str]:
    """Names following `marker` up to the closing quote, per line.

    Plain string work on purpose: the packaging sources hold single backslashes
    and a regex over them is one escaping mistake away from matching nothing.
    """
    out: set[str] = set()
    for line in text.splitlines():
        if marker in line:
            out.add(line.split(marker, 1)[1].split('"', 1)[0])
    return out


def _nsis_shipped() -> set[str]:
    """Every script file the NSIS installer puts in the install dir."""
    return _extract(INSTALLER.read_text(encoding="utf-8"), 'File "scripts' + "\\")


def _nsis_executed() -> set[str]:
    """Every script the NSIS installer runs by path under the install dir."""
    marker = '-File "$INSTDIR' + "\\" + 'scripts' + "\\"
    return _extract(INSTALLER.read_text(encoding="utf-8"), marker)


def _bundle_shipped() -> set[str]:
    """Every script `package_release.ps1` copies into the bundle's scripts dir."""
    text = BUNDLE.read_text(encoding="utf-8")
    block = re.search(r"\$scriptPayload\s*=\s*@\((.*?)\)", text, re.S)
    assert block, "package_release.ps1 no longer declares a $scriptPayload list"
    return set(re.findall(r"'([^']+)'", block.group(1)))


def _bundle_executed() -> set[str]:
    """Every script the bundle installer runs by path under $InstallRoot."""
    text = INSTALL_AEGIS.read_text(encoding="utf-8")
    out: set[str] = set()
    marker = "Join-Path $InstallRoot 'scripts" + "\\"
    for line in text.splitlines():
        if marker in line:
            out.add(line.split(marker, 1)[1].split("'", 1)[0])
    return out


def test_every_script_the_bundle_installer_runs_is_in_the_bundle() -> None:
    executed = _bundle_executed()
    assert executed, "install_aegis.ps1 no longer runs any script by path"
    missing = sorted(executed - _bundle_shipped())
    assert not missing, (
        "package_release.ps1 leaves out scripts that install_aegis.ps1 executes: "
        f"{missing} - the bundle install throws after creating the service"
    )


def test_every_script_the_nsis_installer_runs_is_shipped() -> None:
    executed = _nsis_executed()
    assert executed, "the installer no longer runs any script by path"
    missing = sorted(executed - _nsis_shipped())
    assert not missing, f"installer.py runs scripts it does not ship: {missing}"


def test_the_boot_model_ships_as_a_pair_in_both_packagers() -> None:
    """install-boot-task.ps1 executes its own sibling; neither may travel alone."""
    text = INSTALL_BOOT.read_text(encoding="utf-8")
    assert "Join-Path $PSScriptRoot 'boot-sequence.ps1'" in text, (
        "the sibling dependency moved; update this pin and the payload lists"
    )
    for name, shipped in (
        ("bundle", _bundle_shipped()),
        ("nsis", _nsis_shipped()),
    ):
        assert {"install-boot-task.ps1", "boot-sequence.ps1"} <= shipped, (
            f"the {name} payload ships only one half of the boot model"
        )


def test_every_shipped_script_exists_and_is_tracked() -> None:
    tracked = set(_tracked_scripts())
    for name in sorted(_nsis_shipped() | _bundle_shipped()):
        rel = f"scripts/{name}"
        assert (ROOT / rel).exists(), f"a packager names a script that does not exist: {rel}"
        assert rel in tracked, (
            f"a packager names a script that is not in git: {rel} - a clean clone "
            "cannot build the installer"
        )


def test_every_script_file_has_a_classified_suffix() -> None:
    unknown = sorted(
        p for p in _tracked_scripts() if Path(p).suffix.lower() not in PARSEABLE
    )
    assert not unknown, (
        "classify this suffix in tests/release/test_packaged_scripts.py before "
        f"trusting it: {unknown}"
    )


def test_python_scripts_compile() -> None:
    proc = subprocess.run(
        ["python", "-m", "compileall", "-q", str(SCRIPTS)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_json_scripts_parse() -> None:
    bad = []
    for rel in _tracked_scripts():
        if rel.endswith(".json"):
            try:
                json.loads((ROOT / rel).read_text(encoding="utf-8-sig"))
            except ValueError as exc:
                bad.append(f"{rel}: {exc}")
    assert not bad, bad


def test_shell_and_batch_scripts_are_text() -> None:
    bad = []
    for rel in _tracked_scripts():
        if Path(rel).suffix.lower() in {".bat", ".cmd", ".sh"}:
            raw = (ROOT / rel).read_bytes()
            if b"\x00" in raw:
                bad.append(rel)  # a binary or UTF-16 file is not a runnable script
            if not raw.strip():
                bad.append(f"{rel} (empty)")
    assert not bad, bad


@needs_pwsh
def test_powershell_scripts_parse() -> None:
    files = [p for p in _tracked_scripts() if p.endswith(".ps1")]
    assert files, "no PowerShell scripts found"
    probe = "\n".join(
        [
            "$bad = @()",
            f"foreach ($f in @({','.join(repr(str((ROOT / f).resolve())) for f in files)})) {{",
            "  $e = $null",
            "  $null = [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$e)",
            "  if ($e.Count -gt 0) { $bad += ($f + ': ' + $e[0].Message) }",
            "}",
            "if ($bad.Count -gt 0) { $bad | ForEach-Object { Write-Error $_ }; exit 1 }",
            "exit 0",
        ]
    )
    proc = subprocess.run(
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", probe],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_install_aegis_fails_closed_on_a_missing_boot_installer() -> None:
    text = INSTALL_AEGIS.read_text(encoding="utf-8")
    assert "if (-not (Test-Path $bootSetup)) { throw" in text, (
        "the bundle installer must refuse to continue without the boot installer"
    )
