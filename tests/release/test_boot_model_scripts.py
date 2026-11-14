"""E2 pins for the boot scripts (BOOT-MODEL-002).

Two defects were found in the boot path by reading it, both of the same shape as
SERVICE-EXISTS-001 — a decision made from text where the exit code is the fact:

  * `install-boot-task.ps1` decided whether `sc.exe config AegisNids start=
    demand` succeeded by matching `'FAILED|denied'` in the output. sc.exe
    localises its messages, so on a non-English host a real failure can produce
    text that matches neither word, and the script would log DEMAND_START over a
    service it never changed — leaving AUTO_START and the 2026-11-11 boot order.
  * `boot-sequence.ps1` ended with an unconditional `exit 0`, so the
    `boot_task_last_result` that `tools/host_preflight.py` requires to be 0 meant
    "the loader reached its last line", not "the stack came up".

The behavioural half runs the real script under a `sc.exe` stub (a PowerShell
function shadows the application, so no executable has to be built) with
`PROGRAMDATA` redirected to `tmp_path`, and asserts the two verdicts.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BOOT = ROOT / "scripts" / "boot-sequence.ps1"
INSTALL = ROOT / "scripts" / "install-boot-task.ps1"
NSIS = ROOT / "tools" / "installer.py"

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")


def test_the_boot_task_installer_decides_on_the_exit_code() -> None:
    text = INSTALL.read_text(encoding="utf-8")
    assert "$LASTEXITCODE -ne 0" in text, (
        "sc config success must be judged by the exit code, not by message text: "
        "sc.exe localises 'FAILED', so a Thai/German host would pass the regex"
    )
    assert "if ($out -match 'FAILED|denied')" not in text, (
        "the localisation-dependent decision is back"
    )


def test_the_boot_loader_exits_non_zero_when_the_stack_is_not_up() -> None:
    text = BOOT.read_text(encoding="utf-8")
    assert "$ok = [bool]($wfpNow -and $daemonOk -and $fimNow)" in text, (
        "the boot verdict must be computed from all three services"
    )
    assert "if (-not $ok)" in text and "exit 1" in text, (
        "the loader must fail loudly instead of exiting 0 unconditionally"
    )
    assert text.index("if (-not $ok)") < text.rindex("exit 0"), (
        "the unconditional exit must come after the failure branch"
    )


def test_both_boot_scripts_ship_in_the_packaged_installer() -> None:
    text = NSIS.read_text(encoding="utf-8")
    assert 'File "scripts\\boot-sequence.ps1"' in text
    assert 'File "scripts\\install-boot-task.ps1"' in text
    assert "install-boot-task.ps1" in text.split("boot_model_ok")[0], (
        "setup must fail closed when the boot model cannot be installed"
    )


def _harness(tmp_path: Path, state: str) -> Path:
    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "function global:sc.exe {\n"
        "    param([Parameter(ValueFromRemainingArguments=$true)]$rest)\n"
        "    Write-Output ('SERVICE_NAME: ' + ($rest -join ' '))\n"
        f"    Write-Output '        STATE              : 4  {state}'\n"
        "    $global:LASTEXITCODE = 0\n"
        "}\n"
        f"& '{BOOT}' -StartAttempts 1 -StartDelaySeconds 0 -ReadyWaitSeconds 1\n"
        "exit $LASTEXITCODE\n",
        encoding="utf-8",
    )
    return harness


def _run(harness: Path, tmp_path: Path) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    env["PROGRAMDATA"] = str(tmp_path / "programdata")
    return subprocess.run(
        [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
        cwd=str(ROOT),
    )


@needs_pwsh
def test_a_boot_where_every_service_runs_reports_success(tmp_path: Path) -> None:
    proc = _run(_harness(tmp_path, "RUNNING"), tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    probe = json.loads(
        (tmp_path / "programdata" / "AEGIS" / "post-boot-probe.json").read_text(
            encoding="utf-8-sig"
        )
    )
    assert probe["ok"] is True
    assert probe["services"] == {
        "AegisNids": "RUNNING",
        "AegisAggregator": "RUNNING",
        "AegisWfp": "RUNNING",
        "AegisMinifilter": "RUNNING",
    }


@needs_pwsh
def test_a_boot_where_a_service_never_starts_fails_and_says_so(tmp_path: Path) -> None:
    proc = _run(_harness(tmp_path, "STOPPED"), tmp_path)
    assert proc.returncode == 1, (
        "a boot that did not bring the stack up must not report Last Result 0: "
        + proc.stdout
        + proc.stderr
    )
    probe = json.loads(
        (tmp_path / "programdata" / "AEGIS" / "post-boot-probe.json").read_text(
            encoding="utf-8-sig"
        )
    )
    assert probe["ok"] is False
    log = (tmp_path / "programdata" / "AEGIS" / "boot-sequence.log").read_text(
        encoding="utf-8-sig"
    )
    assert "NOT up" in log
