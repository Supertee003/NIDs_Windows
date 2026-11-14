"""E5-CLEAN-HOST-001 pins: the runbook must be safe and must not lie.

The remaining install/boot gate cannot be run from the development host, so the
only thing provable here is that the runbook (a) changes nothing in dry-run,
(b) never prints PASS for a check that did not execute, and (c) fails closed when
its input is missing. Those three are exactly how a checklist script turns into a
false E5 claim, so they are pinned rather than documented.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "e5-clean-host.ps1"
SOURCE = SCRIPT.read_text(encoding="utf-8")

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")

needs_pwsh = pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")


def run(*argv: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT), *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=ROOT,
    )


def test_runbook_wires_the_two_gates_it_claims() -> None:
    assert "host_preflight.py" in SOURCE
    assert "--min-uptime-min" in SOURCE, "a boot check without an uptime floor proves nothing"
    assert "host_soak_check.py" in SOURCE
    assert "--baseline" in SOURCE and "auto" in SOURCE, (
        "the 24 h window must be anchored on a counter snapshot, or a deploy "
        "burst spends the budget before the window starts (SOAK-BASELINE-001)"
    )


def test_runbook_refuses_to_claim_a_verdict_in_dry_run() -> None:
    # The defect this prevents: Invoke-External returns 0 without running, so a
    # naive script reports "preflight: PASS" for a check it never performed.
    assert "SKIPPED (dry run)" in SOURCE
    assert "RESULT: DRY-RUN" in SOURCE


@needs_pwsh
def test_verify_dry_run_changes_nothing_and_claims_nothing(tmp_path: Path) -> None:
    proc = run("-Stage", "Verify", "-DryRun", "-ArtifactDir", str(tmp_path / "art"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SKIPPED (dry run)" in proc.stdout
    assert "preflight: PASS" not in proc.stdout, (
        "dry-run output must not read like a host verdict"
    )
    assert "RESULT: DRY-RUN" in proc.stdout


@needs_pwsh
def test_install_dry_run_fails_closed_without_an_installer(tmp_path: Path) -> None:
    missing = tmp_path / "nope.exe"
    proc = run(
        "-Stage", "Install", "-DryRun",
        "-InstallerPath", str(missing),
        "-ArtifactDir", str(tmp_path / "art"),
    )
    assert proc.returncode != 0
    assert "installer not found" in (proc.stdout + proc.stderr)
