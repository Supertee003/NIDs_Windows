"""PORT-106: operator scripts carry no hardcoded machine paths.

Failure mode pinned: build_wfp_user_bridge.ps1 defaulted $Repo to a
literal drive path (a relocated checkout built the wrong tree or
failed), and run_aegis.bat produced a garbage timestamp on hosts
without wmic (deprecated/removed on current Windows) — both surface
only on machines unlike the author's. Contract:

  AC1. No script defaults to a literal drive-rooted repo path; repo
       roots derive from the script's own location ($PSScriptRoot /
       %~dp0 family) with explicit overrides kept.
  AC2. wmic-dependent lines have a non-wmic fallback (checked
       textually; batch has no unit runner — E1 evidence, stated).
  AC3. Lab-runner network expectations (Kali/VMware subnets) stay
       parameterized, not literals, in preflight scripts.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BRIDGE = REPO_ROOT / "scripts" / "build_wfp_user_bridge.ps1"
BAT = REPO_ROOT / "scripts" / "run_aegis.bat"
PREFLIGHT = REPO_ROOT / "scripts" / "run_vmware_lab_preflight.ps1"


def test_bridge_script_derives_repo_from_its_location():
    text = BRIDGE.read_text(encoding="utf-8", errors="replace")
    assert "D:\\NIDs_Windows" not in text and "D:/NIDs_Windows" not in text
    assert "$PSScriptRoot" in text
    assert "[string]$Repo" in text, "explicit -Repo override must survive"


def test_bridge_script_parses_without_execution():
    ps = (
        "$t=$null; $e=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{BRIDGE}', [ref]$t, [ref]$e) | Out-Null; "
        "if ($e.Count -gt 0) { $e | ForEach-Object { Write-Output $_.Message }; exit 1 } "
        "else { Write-Output 'PS_PARSE_OK' }"
    )
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PS_PARSE_OK" in proc.stdout


def test_bat_timestamp_survives_without_wmic():
    # Launcher shows a start time with zero wmic dependency (the old
    # v5.0 phases needed a fallback; the wrapper needs none at all).
    text = BAT.read_text(encoding="utf-8", errors="replace")
    assert "wmic" not in text.lower()
    assert "%DATE%" in text and "%TIME%" in text


def test_bat_unknown_flags_warn_and_help_exists():
    # A typo'd flag must never silently open the system: warn loudly.
    # --help prints usage without touching anything.
    text = BAT.read_text(encoding="utf-8", errors="replace")
    assert 'unknown flag' in text
    assert "--help" in text and ":usage" in text


def test_lab_preflight_subnet_is_parameterized():
    text = PREFLIGHT.read_text(encoding="utf-8", errors="replace")
    assert "param(" in text.lower() or "ExpectedLabSubnet" in text
    assert re.search(r"192\.168\.\d+\.0/24", text), "default lab subnet must be visible and documented"
